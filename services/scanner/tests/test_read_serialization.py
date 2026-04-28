from datetime import datetime, timezone

from app.api.routes.scans import (
    _serialize_detected_technology,
    _serialize_finding,
    _serialize_scan,
    _serialize_scan_page,
)
from app.api.routes.targets import _serialize_target
from app.models.detected_technology import DetectedTechnology
from app.models.finding import Finding
from app.models.finding_reference import FindingReference
from app.models.scan import Scan
from app.models.scan_page import ScanPage
from app.models.target import Target


def test_targets_list_serialization_succeeds() -> None:
    targets = [
        Target(
            id=1,
            user_id=7,
            base_url="https://example.com",
            normalized_domain="example.com",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
    ]

    serialized = [_serialize_target(target) for target in targets]

    assert len(serialized) == 1
    assert serialized[0].normalized_domain == "example.com"


def test_scans_list_serialization_defaults_nullable_totals() -> None:
    scans = [
        Scan(
            id=10,
            user_id=7,
            target_id=1,
            scan_type="full",
            scan_profile=None,
            status="queued",
            total_pages_found=None,
            total_findings=None,
            risk_score=42,
            started_at=None,
            finished_at=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
    ]

    serialized = [_serialize_scan(scan) for scan in scans]

    assert serialized[0].total_pages_found == 0
    assert serialized[0].total_findings == 0
    assert serialized[0].scan_profile == "standard"
    assert serialized[0].risk_score == 42


def test_scan_pages_list_serialization_succeeds() -> None:
    pages = [
        ScanPage(
            id=5,
            scan_id=10,
            url="https://example.com/login",
            method="GET",
            status_code=200,
            content_type="text/html",
            response_time_ms=123,
            page_title="Login",
            discovered_from="https://example.com",
            depth=1,
            created_at=datetime.now(timezone.utc),
        )
    ]

    serialized = [_serialize_scan_page(page) for page in pages]

    assert serialized[0].url.endswith("/login")
    assert serialized[0].response_time_ms == 123


def test_findings_list_serialization_succeeds() -> None:
    findings = [
        Finding(
            id=2,
            scan_id=10,
            scan_page_id=None,
            category="insecure_transport",
            title="HTTP without HTTPS redirect",
            description="The target serves HTTP without redirecting to HTTPS.",
            severity="high",
            confidence="high",
            confidence_level="medium",
            confidence_score=55,
            evidence_type="multiple_signals",
            verification_steps=["Replay request."],
            payload_used="single_quote",
            affected_parameter="id",
            response_snippet="SQL syntax error",
            false_positive_notes="Verify manually.",
            request_url="https://example.com/item?id=1",
            http_method="GET",
            tested_parameter="id",
            payload="'",
            baseline_status_code=200,
            attack_status_code=500,
            baseline_response_size=1000,
            attack_response_size=1200,
            baseline_response_time_ms=100,
            attack_response_time_ms=150,
            response_diff_summary="status changed",
            deduplication_key="finding:v1:test",
            evidence=None,
            remediation="Redirect all HTTP traffic to HTTPS.",
            is_confirmed=False,
            references=[
                FindingReference(
                    id=12,
                    finding_id=2,
                    ref_type="cve",
                    ref_value="CVE-2026-0001",
                    ref_url="https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
                    source="nvd",
                    created_at=datetime.now(timezone.utc),
                )
            ],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
    ]

    serialized = [_serialize_finding(finding) for finding in findings]

    assert serialized[0].severity == "high"
    assert serialized[0].scan_page_id is None
    assert serialized[0].request_url == "https://example.com/item?id=1"
    assert serialized[0].tested_parameter == "id"
    assert serialized[0].attack_status_code == 500
    assert serialized[0].response_diff_summary == "status changed"
    assert serialized[0].deduplication_key == "finding:v1:test"
    assert serialized[0].references[0].ref_type == "cve"


def test_technologies_list_serialization_succeeds() -> None:
    technologies = [
        DetectedTechnology(
            id=3,
            scan_id=10,
            scan_page_id=None,
            product_name="nginx",
            category="server",
            version="1.25.5",
            vendor=None,
            confidence_score=0.8,
            detection_method="response_header",
            created_at=datetime.now(timezone.utc),
        )
    ]

    serialized = [
        _serialize_detected_technology(technology) for technology in technologies
    ]

    assert serialized[0].product_name == "nginx"
    assert serialized[0].confidence_score == 0.8
