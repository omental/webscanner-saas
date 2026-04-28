from app.services.confidence import score_finding_confidence


def test_exploit_confirmed_scores_as_confirmed() -> None:
    result = score_finding_confidence(exploit_confirmed=True)

    assert result.confidence_level == "confirmed"
    assert result.confidence_score >= 90
    assert result.evidence_type == "exploit_confirmed"
    assert result.verification_steps


def test_oob_callback_scores_as_confirmed() -> None:
    result = score_finding_confidence(oob_callback_received=True)

    assert result.confidence_level == "confirmed"
    assert result.confidence_score >= 90
    assert result.evidence_type == "oob_callback"


def test_time_based_confirmation_scores_as_confirmed() -> None:
    result = score_finding_confidence(time_based_confirmation=True)

    assert result.confidence_level == "confirmed"
    assert result.confidence_score >= 90
    assert result.evidence_type == "time_based"


def test_context_validated_payload_reflected_scores_high() -> None:
    result = score_finding_confidence(
        context_validated=True,
        payload_reflected=True,
    )

    assert result.confidence_level == "high"
    assert result.confidence_score >= 80
    assert result.evidence_type == "validated_reflection"


def test_known_error_signature_with_response_diff_scores_high() -> None:
    result = score_finding_confidence(
        known_error_signature=True,
        response_diff=True,
    )

    assert result.confidence_level == "high"
    assert result.confidence_score >= 80
    assert result.evidence_type == "error_signature"


def test_single_weak_signal_scores_low() -> None:
    result = score_finding_confidence(weak_signal_count=1)

    assert result.confidence_level == "low"
    assert result.confidence_score < 50
    assert result.evidence_type == "weak_signal"


def test_multiple_weak_signals_score_medium() -> None:
    result = score_finding_confidence(weak_signal_count=2)

    assert result.confidence_level == "medium"
    assert 50 <= result.confidence_score < 80
    assert result.evidence_type == "multiple_signals"


def test_informational_check_scores_info() -> None:
    result = score_finding_confidence(informational=True)

    assert result.confidence_level == "info"
    assert result.confidence_score == 10
    assert result.evidence_type == "informational"


def test_custom_verification_steps_are_preserved() -> None:
    steps = ["Replay the request.", "Confirm the response body."]

    result = score_finding_confidence(
        context_validated=True,
        payload_reflected=True,
        verification_steps=steps,
    )

    assert result.verification_steps == steps
