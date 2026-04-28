from types import SimpleNamespace

from app.services.risk_score import calculate_scan_risk_score
from app.services.scan_service import mark_scan_completed


def _finding(
    severity: str,
    confidence_level: str,
    confidence_score: int | None = None,
    evidence_type: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        severity=severity,
        confidence_level=confidence_level,
        confidence=confidence_level,
        confidence_score=confidence_score,
        evidence_type=evidence_type,
    )


def test_empty_scan_has_zero_risk() -> None:
    result = calculate_scan_risk_score([])

    assert result.risk_score == 0
    assert result.finding_count == 0


def test_confirmed_critical_finding_scores_high() -> None:
    result = calculate_scan_risk_score(
        [
            _finding(
                "critical",
                "confirmed",
                confidence_score=95,
                evidence_type="exploit_confirmed",
            )
        ]
    )

    assert result.risk_score >= 55
    assert result.confirmed_or_high_count == 1


def test_low_and_info_findings_have_small_impact() -> None:
    result = calculate_scan_risk_score(
        [
            _finding("low", "low", confidence_score=35),
            _finding("info", "info", confidence_score=10),
        ]
    )

    assert 0 < result.risk_score < 10


def test_score_is_capped_at_100() -> None:
    findings = [
        _finding(
            "critical",
            "confirmed",
            confidence_score=100,
            evidence_type="oob_callback_received",
        )
        for _ in range(6)
    ]

    assert calculate_scan_risk_score(findings).risk_score == 100


def test_mark_scan_completed_stores_risk_score() -> None:
    import asyncio

    class Result:
        def scalars(self):
            return self

        def all(self):
            return [
                _finding(
                    "high",
                    "high",
                    confidence_score=90,
                    evidence_type="validated_reflection",
                )
            ]

    class Session:
        def __init__(self) -> None:
            self.committed = False

        async def execute(self, _query):
            return Result()

        async def commit(self):
            self.committed = True

        async def refresh(self, _scan):
            return None

    session = Session()
    scan = SimpleNamespace(id=7)

    completed = asyncio.run(
        mark_scan_completed(session, scan, total_pages_found=3, total_findings=1)
    )

    assert completed.status == "completed"
    assert completed.risk_score is not None
    assert completed.risk_score > 0
    assert session.committed is True
