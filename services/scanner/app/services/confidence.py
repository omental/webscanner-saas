from typing import Any, Literal, NamedTuple


ConfidenceLevel = Literal["confirmed", "high", "medium", "low", "info"]
EvidenceType = Literal[
    "exploit_confirmed",
    "oob_callback",
    "time_based",
    "validated_reflection",
    "error_signature",
    "multiple_signals",
    "weak_signal",
    "informational",
]


class ConfidenceResult(NamedTuple):
    confidence_level: ConfidenceLevel
    confidence_score: int
    evidence_type: EvidenceType
    verification_steps: list[str]


def score_finding_confidence(
    *,
    exploit_confirmed: bool = False,
    oob_callback_received: bool = False,
    time_based_confirmation: bool = False,
    context_validated: bool = False,
    payload_reflected: bool = False,
    known_error_signature: bool = False,
    response_diff: bool = False,
    informational: bool = False,
    weak_signal_count: int = 0,
    verification_steps: list[str] | None = None,
    **extra_signals: Any,
) -> ConfidenceResult:
    steps = list(verification_steps or [])
    weak_signal_count = max(0, weak_signal_count)
    extra_signal_count = sum(1 for value in extra_signals.values() if value is True)

    if informational:
        return ConfidenceResult(
            confidence_level="info",
            confidence_score=10,
            evidence_type="informational",
            verification_steps=steps or ["Review informational scanner output."],
        )

    if exploit_confirmed:
        return ConfidenceResult(
            confidence_level="confirmed",
            confidence_score=98,
            evidence_type="exploit_confirmed",
            verification_steps=steps or ["Confirm the exploit result is reproducible."],
        )

    if oob_callback_received:
        return ConfidenceResult(
            confidence_level="confirmed",
            confidence_score=96,
            evidence_type="oob_callback",
            verification_steps=steps or ["Verify the out-of-band callback belongs to this scan."],
        )

    if time_based_confirmation:
        return ConfidenceResult(
            confidence_level="confirmed",
            confidence_score=92,
            evidence_type="time_based",
            verification_steps=steps or ["Repeat the timing probe and compare baseline latency."],
        )

    if context_validated and payload_reflected:
        return ConfidenceResult(
            confidence_level="high",
            confidence_score=85,
            evidence_type="validated_reflection",
            verification_steps=steps
            or ["Validate the reflected payload in the affected response context."],
        )

    if known_error_signature and response_diff:
        return ConfidenceResult(
            confidence_level="high",
            confidence_score=80,
            evidence_type="error_signature",
            verification_steps=steps
            or ["Compare the baseline and probe responses for the known signature."],
        )

    strong_signal_count = sum(
        [
            context_validated,
            payload_reflected,
            known_error_signature,
            response_diff,
        ]
    )
    signal_count = strong_signal_count + weak_signal_count + extra_signal_count

    if signal_count >= 2:
        return ConfidenceResult(
            confidence_level="medium",
            confidence_score=55,
            evidence_type="multiple_signals",
            verification_steps=steps or ["Manually validate the combined scanner signals."],
        )

    if signal_count == 1:
        return ConfidenceResult(
            confidence_level="low",
            confidence_score=30,
            evidence_type="weak_signal",
            verification_steps=steps or ["Manually verify the single scanner signal."],
        )

    return ConfidenceResult(
        confidence_level="info",
        confidence_score=5,
        evidence_type="informational",
        verification_steps=steps or ["Review scanner output for additional evidence."],
    )


def finding_confidence_metadata(
    *,
    payload_used: str | None = None,
    affected_parameter: str | None = None,
    response_snippet: str | None = None,
    false_positive_notes: str | None = None,
    request_url: str | None = None,
    http_method: str | None = None,
    tested_parameter: str | None = None,
    payload: str | None = None,
    baseline_status_code: int | None = None,
    attack_status_code: int | None = None,
    baseline_response_size: int | None = None,
    attack_response_size: int | None = None,
    baseline_response_time_ms: int | None = None,
    attack_response_time_ms: int | None = None,
    response_diff_summary: str | None = None,
    **signals: Any,
) -> dict[str, object]:
    result = score_finding_confidence(**signals)
    metadata: dict[str, object] = {
        "confidence_level": result.confidence_level,
        "confidence_score": result.confidence_score,
        "evidence_type": result.evidence_type,
        "verification_steps": result.verification_steps,
    }
    if payload_used is not None:
        metadata["payload_used"] = payload_used
    if affected_parameter is not None:
        metadata["affected_parameter"] = affected_parameter
    if response_snippet is not None:
        metadata["response_snippet"] = response_snippet
    if false_positive_notes is not None:
        metadata["false_positive_notes"] = false_positive_notes
    if request_url is not None:
        metadata["request_url"] = request_url
    if http_method is not None:
        metadata["http_method"] = http_method
    if tested_parameter is not None:
        metadata["tested_parameter"] = tested_parameter
    if payload is not None:
        metadata["payload"] = payload
    if baseline_status_code is not None:
        metadata["baseline_status_code"] = baseline_status_code
    if attack_status_code is not None:
        metadata["attack_status_code"] = attack_status_code
    if baseline_response_size is not None:
        metadata["baseline_response_size"] = baseline_response_size
    if attack_response_size is not None:
        metadata["attack_response_size"] = attack_response_size
    if baseline_response_time_ms is not None:
        metadata["baseline_response_time_ms"] = baseline_response_time_ms
    if attack_response_time_ms is not None:
        metadata["attack_response_time_ms"] = attack_response_time_ms
    if response_diff_summary is not None:
        metadata["response_diff_summary"] = response_diff_summary
    return metadata
