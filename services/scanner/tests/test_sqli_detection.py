from urllib.parse import parse_qs, urlsplit

import pytest

from app.scanner.checks.sqli import check_sqli


class FakeResponse:
    def __init__(self, status_code=200, body="ok", response_time_ms=100):
        self.status_code = status_code
        self.body = body
        self.response_time_ms = response_time_ms


class FakeHttpClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def get(self, url):
        self.calls.append(url)
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        payload = query.get("id", [""])[0]
        values = self.responses.get(payload, self.responses.get("*", []))
        if isinstance(values, list):
            if values:
                return values.pop(0)
            return FakeResponse()
        return values


@pytest.mark.anyio
async def test_error_based_sqli_produces_medium_or_high_confidence() -> None:
    client = FakeHttpClient(
        {
            "": [FakeResponse(body="normal")],
            "' OR '1'='1": [FakeResponse(body="SQL syntax error near SELECT")],
            "' AND '1'='2": [FakeResponse(body="normal")],
            "*": [FakeResponse(body="normal")],
        }
    )

    issues = await check_sqli(client, "https://example.com/item?id=1", ["id"])

    assert len(issues) == 1
    assert issues[0].confidence in {"medium", "high"}
    assert issues[0].confidence_level in {"medium", "high", "confirmed"}
    assert "sql_error_signature=true" in (issues[0].response_diff_summary or "")


@pytest.mark.anyio
async def test_response_diff_strong_signal_increases_confidence() -> None:
    client = FakeHttpClient(
        {
            "": [FakeResponse(body="x" * 100)],
            "' OR '1'='1": [FakeResponse(body="x" * 180)],
            "' AND '1'='2": [FakeResponse(body="x" * 180)],
            "*": [FakeResponse(body="x" * 100)],
        }
    )

    issues = await check_sqli(client, "https://example.com/item?id=1", ["id"])

    assert len(issues) == 1
    assert issues[0].confidence == "high"
    assert issues[0].confidence_level == "confirmed"
    assert "signal=strong" in (issues[0].response_diff_summary or "")


@pytest.mark.anyio
async def test_boolean_true_false_difference_increases_confidence() -> None:
    client = FakeHttpClient(
        {
            "": [FakeResponse(body="record one")],
            "' OR '1'='1": [FakeResponse(body="record one")],
            "' AND '1'='2": [FakeResponse(body="no results" + "x" * 300)],
            "*": [FakeResponse(body="record one")],
        }
    )

    issues = await check_sqli(client, "https://example.com/item?id=1", ["id"])

    assert len(issues) == 1
    assert issues[0].confidence == "high"
    assert issues[0].confidence_level == "confirmed"
    assert "true_false=" in (issues[0].response_diff_summary or "")


@pytest.mark.anyio
async def test_time_based_confirmation_requires_repeated_delay() -> None:
    client = FakeHttpClient(
        {
            "": [FakeResponse(body="ok", response_time_ms=100)],
            "' OR SLEEP(3)-- ": [
                FakeResponse(body="ok", response_time_ms=3200),
                FakeResponse(body="ok", response_time_ms=3300),
            ],
            "*": [FakeResponse(body="ok", response_time_ms=100)],
        }
    )

    issues = await check_sqli(client, "https://example.com/item?id=1", ["id"])

    assert len(issues) == 1
    assert issues[0].confidence_level == "confirmed"
    assert issues[0].confidence_score >= 90
    assert issues[0].evidence_type == "time_based"
    assert "confirmed=true" in (issues[0].response_diff_summary or "")


@pytest.mark.anyio
async def test_single_suspicious_timing_delay_is_not_confirmed() -> None:
    client = FakeHttpClient(
        {
            "": [FakeResponse(body="ok", response_time_ms=100)],
            "' OR SLEEP(3)-- ": [
                FakeResponse(body="ok", response_time_ms=3200),
                FakeResponse(body="ok", response_time_ms=120),
            ],
            "' OR '1'='1": [FakeResponse(body="ok")],
            "' AND '1'='2": [FakeResponse(body="ok")],
            "*": [FakeResponse(body="ok", response_time_ms=100)],
        }
    )

    issues = await check_sqli(client, "https://example.com/item?id=1", ["id"])

    assert len(issues) == 1
    assert issues[0].confidence_level != "confirmed"
    assert issues[0].confidence in {"medium", "high"}
    assert issues[0].false_positive_notes


@pytest.mark.anyio
async def test_finding_metadata_includes_detection_fields() -> None:
    client = FakeHttpClient(
        {
            "": [FakeResponse(body="ok", response_time_ms=100)],
            "' OR SLEEP(3)-- ": [
                FakeResponse(body="ok", response_time_ms=3200),
                FakeResponse(body="ok", response_time_ms=3300),
            ],
            "*": [FakeResponse(body="ok", response_time_ms=100)],
        }
    )

    issue = (await check_sqli(client, "https://example.com/item?id=1", ["id"]))[0]

    assert issue.confidence_level
    assert issue.confidence_score is not None
    assert issue.evidence_type
    assert issue.payload_used
    assert issue.response_diff_summary
    assert issue.baseline_response_time_ms == 100
    assert issue.attack_response_time_ms >= 3200
