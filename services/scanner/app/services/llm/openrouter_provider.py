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
        # NOTE: the API key is NEVER logged.

        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=settings.openrouter_base_url,
            default_headers={
                "HTTP-Referer": settings.app_public_url,
                "X-Title": settings.app_name,
            },
        )
        self._model = settings.openrouter_model

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_report(self, scan_data: dict) -> str:
        """Send sanitised scan data to OpenRouter and return Markdown report."""
        clean_data = _sanitise_scan_data(scan_data)
        user_content = USER_REPORT_TEMPLATE.format(
            scan_data_json=json.dumps(clean_data, indent=2, default=str),
        )

        logger.info(
            "Requesting report generation  model=%s  input_chars=%d",
            self._model,
            len(user_content),
        )

        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            temperature=0.3,
            timeout=120,
        )

        # --- Safe response validation ---------------------------------
        if not response:
            logger.error("OpenRouter returned empty response  model=%s", self._model)
            raise RuntimeError(
                "AI provider returned an empty response. Please try again or switch model."
            )

        # Log response metadata (never log content or API key)
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

        # Log finish_reason for debugging
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
