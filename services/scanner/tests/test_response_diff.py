from app.services.response_diff import compare_responses


class DummyResponse:
    def __init__(self, status_code=200, body="", response_time_ms=100):
        self.status_code = status_code
        self.body = body
        self.response_time_ms = response_time_ms


def test_identical_responses_have_no_signal() -> None:
    baseline = DummyResponse(body="same")
    test = DummyResponse(body="same")

    result = compare_responses(baseline, test)

    assert result["changed"] is False
    assert result["confidence_signal"] == "none"


def test_status_code_change_is_detected() -> None:
    baseline = DummyResponse(status_code=200, body="same")
    test = DummyResponse(status_code=500, body="same")

    result = compare_responses(baseline, test)

    assert result["changed"] is True
    assert result["status_code_changed"] is True


def test_large_response_size_delta_produces_strong_signal() -> None:
    baseline = DummyResponse(body="x" * 100)
    test = DummyResponse(body="x" * 160)

    result = compare_responses(baseline, test)

    assert result["confidence_signal"] == "strong"


def test_normalized_timestamp_and_token_differences_are_ignored() -> None:
    baseline = DummyResponse(
        body="created 2026-04-29 at 12:30:45 token abcdef1234567890abcdef1234567890"
    )
    test = DummyResponse(
        body="created 2026-04-30 at 13:30:45 token zyxwvu1234567890zyxwvu1234567890"
    )

    result = compare_responses(baseline, test)

    assert result["content_changed"] is False
    assert result["confidence_signal"] == "none"


def test_large_timing_delta_produces_medium_signal() -> None:
    baseline = DummyResponse(body="same", response_time_ms=100)
    test = DummyResponse(body="same", response_time_ms=1200)

    result = compare_responses(baseline, test)

    assert result["timing_delta_ms"] == 1100.0
    assert result["confidence_signal"] == "medium"


def test_error_signature_is_detected() -> None:
    baseline = DummyResponse(body="Database error")
    test = DummyResponse(body="Database error")

    result = compare_responses(baseline, test)

    assert result["error_signature_detected"] is True
    assert result["confidence_signal"] == "medium"


def test_error_signature_with_content_change_produces_strong_signal() -> None:
    baseline = DummyResponse(body="ok")
    test = DummyResponse(body="SQL syntax error near SELECT")

    result = compare_responses(baseline, test)

    assert result["error_signature_detected"] is True
    assert result["content_changed"] is True
    assert result["confidence_signal"] == "strong"
