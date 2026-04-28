from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


SEVERITY_WEIGHTS = {
    "critical": 28,
    "high": 18,
    "medium": 9,
    "low": 3,
    "info": 1,
    "informational": 1,
}

CONFIDENCE_MULTIPLIERS = {
    "confirmed": 1.35,
    "high": 1.15,
    "medium": 0.85,
    "low": 0.45,
    "info": 0.2,
    "informational": 0.2,
}

EVIDENCE_BONUSES = {
    "exploit_confirmed": 8,
    "oob_callback_received": 8,
    "time_based_confirmation": 7,
    "time_based": 7,
    "validated_reflection": 4,
    "known_error_signature": 3,
    "response_diff": 3,
    "multiple_signals": 2,
}


@dataclass(frozen=True)
class RiskScoreResult:
    risk_score: int
    finding_count: int
    confirmed_or_high_count: int


def _normalized(value: object, default: str = "") -> str:
    return str(value or default).strip().lower()


def _confidence_score_factor(value: object) -> float:
    if value is None:
        return 0.85
    try:
        score = max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0.85
    return 0.35 + (score / 100)


def calculate_scan_risk_score(findings: Iterable[object]) -> RiskScoreResult:
    finding_list = list(findings)
    if not finding_list:
        return RiskScoreResult(
            risk_score=0,
            finding_count=0,
            confirmed_or_high_count=0,
        )

    total = 0.0
    confirmed_or_high_count = 0

    for finding in finding_list:
        severity = _normalized(getattr(finding, "severity", None), "info")
        confidence_level = _normalized(
            getattr(finding, "confidence_level", None)
            or getattr(finding, "confidence", None),
            "medium",
        )
        evidence_type = _normalized(getattr(finding, "evidence_type", None))

        severity_weight = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["low"])
        confidence_multiplier = CONFIDENCE_MULTIPLIERS.get(confidence_level, 0.75)
        confidence_factor = _confidence_score_factor(
            getattr(finding, "confidence_score", None)
        )
        evidence_bonus = EVIDENCE_BONUSES.get(evidence_type, 0)

        if confidence_level in {"confirmed", "high"}:
            confirmed_or_high_count += 1

        total += (
            severity_weight * confidence_multiplier * confidence_factor
        ) + evidence_bonus

    total += min(14, confirmed_or_high_count * 4)
    total += min(10, max(0, len(finding_list) - 3))

    return RiskScoreResult(
        risk_score=max(0, min(100, round(total))),
        finding_count=len(finding_list),
        confirmed_or_high_count=confirmed_or_high_count,
    )
