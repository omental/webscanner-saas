from app.services.llm.openrouter_provider import _compact_scan_data
from app.services.llm.prompts import REPORT_SYSTEM_PROMPT
from app.services.report_service import (
    ReportFinding,
    _confidence_counts,
    _group_findings_by_confidence,
    build_scan_report_pdf,
)


def _finding(title: str, confidence_level: str) -> ReportFinding:
    return ReportFinding(
        severity="medium",
        category="security",
        title=title,
        description="Description",
        evidence="Evidence",
        remediation="Fix it",
        confidence=confidence_level,
        confidence_level=confidence_level,
        confidence_score=85 if confidence_level in {"confirmed", "high"} else 30,
        evidence_type="validated_reflection",
        verification_steps=["Replay the request."],
        payload_used="[safe marker]",
        affected_parameter="q",
        response_snippet="snippet",
        false_positive_notes="Check encoding.",
        request_url="https://example.com/search?q=test",
        http_method="GET",
        tested_parameter="q",
        payload="[safe marker]",
        baseline_status_code=200,
        attack_status_code=200,
        baseline_response_size=1000,
        attack_response_size=1200,
        baseline_response_time_ms=100,
        attack_response_time_ms=140,
        response_diff_summary="marker reflected in response",
        deduplication_key=f"finding:v1:{title.lower().replace(' ', '-')}",
        references=[],
    )


def test_report_findings_group_by_confidence() -> None:
    confirmed = _finding("Confirmed SQLi", "confirmed")
    medium = _finding("Reflected XSS", "medium")
    low = _finding("Missing header", "low")
    info = _finding("Server banner", "info")

    main, observations = _group_findings_by_confidence(
        [confirmed, medium, low, info]
    )
    counts = _confidence_counts([confirmed, medium, low, info])

    assert [finding.title for finding in main] == ["Confirmed SQLi", "Reflected XSS"]
    assert [finding.title for finding in observations] == ["Missing header", "Server banner"]
    assert counts == {"confirmed": 1, "high": 0, "medium": 1, "low": 1, "info": 1}


def test_compact_llm_payload_groups_and_preserves_metadata() -> None:
    compact = _compact_scan_data(
        {
            "scan": {
                "id": 1,
                "status": "completed",
                "scan_type": "full",
                "scan_profile": "aggressive",
                "risk_score": 88,
            },
            "target": {"base_url": "https://example.com"},
            "findings": [
                {
                    "title": "Confirmed SQLi",
                    "severity": "critical",
                    "category": "sqli",
                    "confidence_level": "confirmed",
                    "confidence_score": 98,
                    "evidence_type": "time_based",
                    "verification_steps": ["Replay timing probe."],
                    "payload_used": "timing_probe",
                    "affected_parameter": "id",
                    "response_snippet": "delayed response",
                    "false_positive_notes": "Repeat to verify.",
                    "request_url": "https://example.com/item?id=1",
                    "http_method": "GET",
                    "tested_parameter": "id",
                    "payload": "timing_probe",
                    "baseline_status_code": 200,
                    "attack_status_code": 200,
                    "baseline_response_size": 2,
                    "attack_response_size": 2,
                    "baseline_response_time_ms": 100,
                    "attack_response_time_ms": 3300,
                    "response_diff_summary": "timing_delta_ms=3200",
                    "deduplication_key": "finding:v1:sqli",
                },
                {
                    "title": "Missing header",
                    "severity": "low",
                    "category": "missing_security_header",
                    "confidence_level": "low",
                    "confidence_score": 30,
                    "evidence_type": "weak_signal",
                },
            ],
        }
    )

    main = compact["finding_groups"]["main_security_findings"]
    observations = compact["finding_groups"]["informational_observations"]

    assert main[0]["title"] == "Confirmed SQLi"
    assert main[0]["confidence_level"] == "confirmed"
    assert main[0]["affected_parameter"] == "id"
    assert main[0]["request_url"] == "https://example.com/item?id=1"
    assert main[0]["attack_response_time_ms"] == 3300
    assert main[0]["response_diff_summary"] == "timing_delta_ms=3200"
    assert main[0]["deduplication_key"] == "finding:v1:sqli"
    assert main[0]["verification_steps"] == ["Replay timing probe."]
    assert compact["scan"]["risk_score"] == 88
    assert compact["scan"]["scan_profile"] == "aggressive"
    assert compact["summary"]["risk_score"] == 88
    assert observations[0]["title"] == "Missing header"
    assert compact["summary"]["confidence_counts"]["confirmed"] == 1
    assert compact["summary"]["confidence_counts"]["low"] == 1


def test_prompt_mentions_confidence_handling() -> None:
    assert "confirmed and high-confidence" in REPORT_SYSTEM_PROMPT
    assert "medium-confidence findings as requiring verification" in REPORT_SYSTEM_PROMPT
    assert "Do not present low-confidence findings as confirmed" in REPORT_SYSTEM_PROMPT


def test_structured_pdf_renders_with_confidence_grouping() -> None:
    from datetime import datetime, timezone

    from app.services.report_service import ReportSnapshot

    snapshot = ReportSnapshot(
        scan_id=4,
        target_domain="example.com",
        target_base_url="https://example.com",
        status="completed",
        scan_type="full",
        scan_profile="standard",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        total_pages_found=2,
        total_findings=2,
        findings=[_finding("Confirmed SQLi", "high"), _finding("Missing header", "low")],
        technologies=[],
        pages=[],
    )

    pdf_bytes = build_scan_report_pdf(snapshot)

    assert pdf_bytes.startswith(b"%PDF")
