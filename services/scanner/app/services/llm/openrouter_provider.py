"""OpenRouter LLM provider using OpenAI-compatible client."""

from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncOpenAI

from app.core.config import get_settings
from app.services.llm.base import BaseLLMProvider
from app.services.llm.prompts import REPORT_SYSTEM_PROMPT, USER_REPORT_TEMPLATE

logger = logging.getLogger(__name__)


MAX_FINDINGS_FOR_AI_REPORT = 40
MAX_PAGES_FOR_AI_REPORT = 25
MAX_TECHNOLOGIES_FOR_AI_REPORT = 30
MAX_AI_OUTPUT_TOKENS = 4000


def _sanitise_scan_data(raw: dict) -> dict:
    """Return a copy of *raw* with sensitive fields stripped."""
    sensitive_keys = {
        "api_key",
        "token",
        "secret",
        "password",
        "cookie",
        "session",
        "authorization",
        "set-cookie",
        "raw_payload",
        "raw_body",
        "raw_response",
    }

    def _clean(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: _clean(v)
                for k, v in obj.items()
                if k.lower() not in sensitive_keys
            }
        if isinstance(obj, list):
            return [_clean(item) for item in obj]
        return obj

    return _clean(raw)


def _truncate(value: Any, limit: int = 600) -> Any:
    if value is None:
        return None

    text = str(value).strip()

    if len(text) <= limit:
        return text

    return text[:limit] + "... [truncated]"


def _severity_rank(value: Any) -> int:
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "informational": 4,
    }

    return order.get(str(value or "").lower(), 9)


def _confidence_rank(value: Any) -> int:
    order = {
        "confirmed": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "informational": 4,
    }
    return order.get(str(value or "").lower(), 9)


def _confidence_group(item: dict) -> str:
    confidence_level = str(item.get("confidence_level") or item.get("confidence") or "").lower()
    if confidence_level in {"confirmed", "high", "medium"}:
        return "main_security_findings"
    return "informational_observations"


def _as_dict_list(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []

    return [item for item in value if isinstance(item, dict)]


def _compact_scan_data(raw: dict) -> dict:
    """Reduce scan payload size before sending it to the LLM."""
    scan = raw.get("scan") if isinstance(raw.get("scan"), dict) else raw

    pages = _as_dict_list(raw.get("pages"))
    findings = _as_dict_list(raw.get("findings"))
    technologies = _as_dict_list(raw.get("technologies"))

    findings = sorted(
        findings,
        key=lambda item: (
            _confidence_rank(item.get("confidence_level") or item.get("confidence")),
            _severity_rank(item.get("severity")),
        ),
    )

    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}

    for finding in findings:
        severity = str(finding.get("severity") or "informational").lower()
        category = str(finding.get("category") or "security").lower()
        confidence_level = str(
            finding.get("confidence_level") or finding.get("confidence") or "info"
        ).lower()
        if confidence_level == "informational":
            confidence_level = "info"

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
        confidence_counts[confidence_level] = confidence_counts.get(confidence_level, 0) + 1

    grouped_findings = {
        "main_security_findings": [
            item for item in findings if _confidence_group(item) == "main_security_findings"
        ],
        "informational_observations": [
            item
            for item in findings
            if _confidence_group(item) == "informational_observations"
        ],
    }

    def _compact_finding(item: dict) -> dict:
        return {
            "title": _truncate(item.get("title"), 180),
            "severity": item.get("severity"),
            "category": item.get("category"),
            "description": _truncate(item.get("description"), 500),
            "evidence": _truncate(item.get("evidence"), 300),
            "remediation": _truncate(item.get("remediation"), 400),
            "confidence": item.get("confidence"),
            "confidence_level": item.get("confidence_level"),
            "confidence_score": item.get("confidence_score"),
            "evidence_type": item.get("evidence_type"),
            "verification_steps": item.get("verification_steps", [])[:5]
            if isinstance(item.get("verification_steps"), list)
            else [],
            "payload_used": _truncate(item.get("payload_used"), 160),
            "affected_parameter": _truncate(item.get("affected_parameter"), 120),
            "response_snippet": _truncate(item.get("response_snippet"), 240),
            "false_positive_notes": _truncate(item.get("false_positive_notes"), 240),
            "request_url": _truncate(item.get("request_url"), 220),
            "http_method": item.get("http_method"),
            "tested_parameter": _truncate(item.get("tested_parameter"), 120),
            "payload": _truncate(item.get("payload"), 160),
            "baseline_status_code": item.get("baseline_status_code"),
            "attack_status_code": item.get("attack_status_code"),
            "baseline_response_size": item.get("baseline_response_size"),
            "attack_response_size": item.get("attack_response_size"),
            "baseline_response_time_ms": item.get("baseline_response_time_ms"),
            "attack_response_time_ms": item.get("attack_response_time_ms"),
            "response_diff_summary": _truncate(item.get("response_diff_summary"), 240),
            "deduplication_key": _truncate(item.get("deduplication_key"), 120),
            "is_confirmed": item.get("is_confirmed"),
            "references": item.get("references", [])[:3]
            if isinstance(item.get("references"), list)
            else [],
        }

    return {
        "scan": {
            "id": scan.get("id"),
            "status": scan.get("status"),
            "scan_type": scan.get("scan_type"),
            "scan_profile": scan.get("scan_profile") or "standard",
            "target_id": scan.get("target_id"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
            "risk_score": scan.get("risk_score"),
        },
        "target": raw.get("target") or scan.get("target"),
        "summary": {
            "total_pages": len(pages),
            "total_findings": len(findings),
            "risk_score": scan.get("risk_score"),
            "total_technologies": len(technologies),
            "severity_counts": severity_counts,
            "confidence_counts": confidence_counts,
            "category_counts": category_counts,
            "included_findings": min(len(findings), MAX_FINDINGS_FOR_AI_REPORT),
            "included_pages_sample": min(len(pages), MAX_PAGES_FOR_AI_REPORT),
            "included_technologies": min(
                len(technologies),
                MAX_TECHNOLOGIES_FOR_AI_REPORT,
            ),
        },
        "finding_groups": {
            "main_security_findings": [
                _compact_finding(item)
                for item in grouped_findings["main_security_findings"][
                    :MAX_FINDINGS_FOR_AI_REPORT
                ]
            ],
            "informational_observations": [
                _compact_finding(item)
                for item in grouped_findings["informational_observations"][
                    :MAX_FINDINGS_FOR_AI_REPORT
                ]
            ],
        },
        "findings": [_compact_finding(item) for item in findings[:MAX_FINDINGS_FOR_AI_REPORT]],
        "pages_sample": [
            {
                "url": _truncate(item.get("url"), 220),
                "method": item.get("method"),
                "status_code": item.get("status_code"),
                "response_time_ms": item.get("response_time_ms"),
                "depth": item.get("depth"),
            }
            for item in pages[:MAX_PAGES_FOR_AI_REPORT]
        ],
        "technologies": [
            {
                "product_name": _truncate(item.get("product_name"), 120),
                "version": _truncate(item.get("version"), 80),
                "category": item.get("category"),
                "vendor": _truncate(item.get("vendor"), 120),
                "confidence_score": item.get("confidence_score"),
                "detection_method": item.get("detection_method"),
            }
            for item in technologies[:MAX_TECHNOLOGIES_FOR_AI_REPORT]
        ],
    }


class OpenRouterProvider(BaseLLMProvider):
    """Talks to OpenRouter via the OpenAI-compatible chat completions API."""

    def __init__(self) -> None:
        settings = get_settings()

        if settings.openrouter_api_key is None:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not configured. "
                "Set it in .env or as an environment variable."
            )

        api_key = settings.openrouter_api_key.get_secret_value()
        if not api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY is empty. "
                "Provide a valid key in .env or as an environment variable."
            )

        logger.info(
            "Initialising OpenRouterProvider  model=%s  base_url=%s",
            settings.openrouter_model,
            settings.openrouter_base_url,
        )

        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=settings.openrouter_base_url,
            default_headers={
                "HTTP-Referer": settings.app_public_url,
                "X-Title": settings.app_name,
            },
        )
        self._model = settings.openrouter_model

    async def generate_report(self, scan_data: dict) -> str:
        """Send compact sanitised scan data to OpenRouter and return Markdown report."""
        clean_data = _sanitise_scan_data(scan_data)
        compact_data = _compact_scan_data(clean_data)

        user_content = USER_REPORT_TEMPLATE.format(
            scan_data_json=json.dumps(compact_data, indent=2, default=str),
        )

        logger.info(
            "Requesting report generation  model=%s  input_chars=%d  findings=%d  pages=%d  technologies=%d",
            self._model,
            len(user_content),
            len(compact_data.get("findings", [])),
            len(compact_data.get("pages_sample", [])),
            len(compact_data.get("technologies", [])),
        )

        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            temperature=0.3,
            max_tokens=MAX_AI_OUTPUT_TOKENS,
            timeout=120,
        )

        if not response:
            logger.error("OpenRouter returned empty response  model=%s", self._model)
            raise RuntimeError(
                "AI provider returned an empty response. Please try again or switch model."
            )

        response_id = getattr(response, "id", None)

        logger.info(
            "OpenRouter response received  model=%s  response_id=%s",
            self._model,
            response_id,
        )

        if not getattr(response, "choices", None):
            logger.error(
                "OpenRouter returned no choices  model=%s  response_id=%s",
                self._model,
                response_id,
            )
            raise RuntimeError(
                "AI provider returned an empty response. Please try again or switch model."
            )

        choice = response.choices[0]
        finish_reason = getattr(choice, "finish_reason", None)

        logger.info(
            "OpenRouter choice  model=%s  finish_reason=%s",
            self._model,
            finish_reason,
        )

        if not getattr(choice, "message", None):
            logger.error(
                "OpenRouter returned no message  model=%s  response_id=%s",
                self._model,
                response_id,
            )
            raise RuntimeError(
                "AI provider returned an empty response. Please try again or switch model."
            )

        report = choice.message.content

        if not report:
            logger.error(
                "OpenRouter returned empty content  model=%s  response_id=%s  finish_reason=%s",
                self._model,
                response_id,
                finish_reason,
            )
            raise RuntimeError(
                "AI provider returned an empty response. Please try again or switch model."
            )

        logger.info(
            "Report generated  model=%s  output_chars=%d  response_id=%s",
            self._model,
            len(report),
            response_id,
        )

        return report
