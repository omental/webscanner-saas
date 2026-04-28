"""Tests for app.services.report_sanitizer."""

from __future__ import annotations

import copy
from types import SimpleNamespace

from app.services.report_sanitizer import (
    build_sanitized_scan_report_data,
    mask_sensitive_text,
)


# -----------------------------------------------------------------------
# mask_sensitive_text
# -----------------------------------------------------------------------


class TestMaskSensitiveText:
    """Verify that credentials and raw payloads are masked."""

    def test_masks_bearer_token(self) -> None:
        text = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        result = mask_sensitive_text(text)
        assert "eyJhbGciOiJSUzI1NiJ9" not in result
        assert "[REDACTED" in result

    def test_masks_cookie_value(self) -> None:
        text = "Cookie: session=abc123; tracker=xyz"
        result = mask_sensitive_text(text)
        assert "abc123" not in result
        assert "xyz" not in result
        assert "[REDACTED]" in result

    def test_masks_set_cookie_value(self) -> None:
        text = "Set-Cookie: id=a3fWa; Expires=Thu, 21 Oct 2025 07:28:00 GMT"
        result = mask_sensitive_text(text)
        assert "a3fWa" not in result

    def test_masks_password_field(self) -> None:
        text = "password=SuperS3cret!"
        result = mask_sensitive_text(text)
        assert "SuperS3cret!" not in result
        assert "[REDACTED]" in result

    def test_masks_jwt_like_token(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.TJVA95OrM7E2c"
        text = f"token found: {jwt}"
        result = mask_sensitive_text(text)
        assert jwt not in result
        assert "[REDACTED_JWT]" in result

    def test_masks_api_key_pattern(self) -> None:
        text = "api_key=sk-proj-abc123def456ghi789"
        result = mask_sensitive_text(text)
        assert "sk-proj-abc123def456ghi789" not in result
        assert "[REDACTED" in result

    def test_masks_x_api_key_header(self) -> None:
        text = "x-api-key: live_1234567890abcdef"
        result = mask_sensitive_text(text)
        assert "live_1234567890abcdef" not in result

    def test_masks_session_id(self) -> None:
        text = "PHPSESSID=r2t5uvjq435r4q7ib3vtdjq120"
        result = mask_sensitive_text(text)
        assert "r2t5uvjq435r4q7ib3vtdjq120" not in result

    def test_masks_access_token(self) -> None:
        text = "access_token=ya29.a0AfH6SMBx"
        result = mask_sensitive_text(text)
        assert "ya29.a0AfH6SMBx" not in result

    def test_masks_refresh_token(self) -> None:
        text = "refresh_token=1//0dx7890-abcdef"
        result = mask_sensitive_text(text)
        assert "1//0dx7890-abcdef" not in result

    def test_masks_private_key(self) -> None:
        text = "private_key=MIIEvgIBADANBgkqhkiG9w"
        result = mask_sensitive_text(text)
        assert "MIIEvgIBADANBgkqhkiG9w" not in result

    def test_masks_secret_field(self) -> None:
        text = "secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCY"
        result = mask_sensitive_text(text)
        assert "wJalrXUtnFEMI" not in result

    def test_masks_sk_style_key(self) -> None:
        text = "Found key sk-or-v1-4579d02b36d777503b8f"
        result = mask_sensitive_text(text)
        assert "sk-or-v1-4579d02b36d777503b8f" not in result
        assert "[REDACTED_KEY]" in result

    def test_preserves_non_sensitive_text(self) -> None:
        text = "Missing X-Frame-Options header on /login page"
        assert mask_sensitive_text(text) == text

    def test_empty_string(self) -> None:
        assert mask_sensitive_text("") == ""

    def test_none_like_empty(self) -> None:
        # mask_sensitive_text expects str, but should handle empty gracefully
        assert mask_sensitive_text("") == ""


# -----------------------------------------------------------------------
# build_sanitized_scan_report_data
# -----------------------------------------------------------------------


def _make_scan(**overrides):
    defaults = {
        "id": 42,
        "status": "completed",
        "scan_type": "full",
        "scan_profile": "deep",
        "total_pages_found": 5,
        "total_findings": 2,
        "risk_score": 64,
        "created_at": None,
        "started_at": None,
        "finished_at": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_target(**overrides):
    defaults = {
        "id": 7,
        "base_url": "https://example.com",
        "normalized_domain": "example.com",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_finding(**overrides):
    defaults = {
        "id": 1,
        "title": "Missing X-Frame-Options",
        "severity": "low",
        "category": "missing_security_header",
        "confidence": "high",
        "confidence_level": "medium",
        "confidence_score": 55,
        "evidence_type": "multiple_signals",
        "verification_steps": ["Replay the request."],
        "payload_used": None,
        "affected_parameter": None,
        "response_snippet": None,
        "false_positive_notes": None,
        "request_url": "https://example.com/login",
        "http_method": "GET",
        "tested_parameter": None,
        "payload": None,
        "baseline_status_code": None,
        "attack_status_code": 200,
        "baseline_response_size": None,
        "attack_response_size": 512,
        "baseline_response_time_ms": None,
        "attack_response_time_ms": 50,
        "response_diff_summary": "missing_header=x-frame-options",
        "deduplication_key": "finding:v1:test",
        "description": "The X-Frame-Options header is not set.",
        "evidence": "Header not present in response.",
        "remediation": "Add X-Frame-Options: DENY.",
        "created_at": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_page(**overrides):
    defaults = {
        "url": "https://example.com/login",
        "status_code": 200,
        "content_type": "text/html",
        "depth": 1,
        # Fields that must NOT appear in output:
        "response_headers": {"Server": "nginx", "Set-Cookie": "sid=abc"},
        "response_body_excerpt": "<html>…</html>",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_tech(**overrides):
    defaults = {
        "product_name": "nginx",
        "category": "web-server",
        "version": "1.25.3",
        "vendor": "F5",
        # Fields that must NOT appear in output:
        "detection_method": "header",
        "confidence_score": 0.95,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestBuildSanitizedScanReportData:
    """Verify structure and field-level safety of the sanitized output."""

    def test_returns_safe_structure_with_empty_findings(self) -> None:
        result = build_sanitized_scan_report_data(
            scan=_make_scan(),
            target=_make_target(),
            findings=[],
            pages=None,
            technologies=None,
        )
        assert result["scan"]["id"] == 42
        assert result["scan"]["scan_profile"] == "deep"
        assert result["scan"]["risk_score"] == 64
        assert result["target"]["base_url"] == "https://example.com"
        assert result["findings"] == []
        assert result["pages"] == []
        assert result["technologies"] == []

    def test_returns_safe_structure_with_none_collections(self) -> None:
        result = build_sanitized_scan_report_data(
            scan=_make_scan(),
            target=_make_target(),
            findings=None,
        )
        assert result["findings"] == []
        assert result["pages"] == []
        assert result["technologies"] == []

    def test_finding_fields_present(self) -> None:
        finding = _make_finding()
        result = build_sanitized_scan_report_data(
            scan=_make_scan(),
            target=_make_target(),
            findings=[finding],
        )
        f = result["findings"][0]
        assert f["id"] == 1
        assert f["title"] == "Missing X-Frame-Options"
        assert f["severity"] == "low"
        assert f["category"] == "missing_security_header"
        assert f["confidence_level"] == "medium"
        assert f["confidence_score"] == 55
        assert f["evidence_type"] == "multiple_signals"
        assert f["verification_steps"] == ["Replay the request."]
        assert f["request_url"] == "https://example.com/login"
        assert f["http_method"] == "GET"
        assert f["attack_status_code"] == 200
        assert f["attack_response_size"] == 512
        assert f["response_diff_summary"] == "missing_header=x-frame-options"
        assert f["deduplication_key"] == "finding:v1:test"
        assert f["description"] is not None
        assert f["remediation"] is not None

    def test_findings_are_grouped_by_confidence(self) -> None:
        main = _make_finding(title="SQL injection", confidence_level="high")
        observation = _make_finding(
            id=2,
            title="Missing Referrer-Policy",
            confidence_level="low",
        )

        result = build_sanitized_scan_report_data(
            scan=_make_scan(),
            target=_make_target(),
            findings=[main, observation],
        )

        groups = result["finding_groups"]
        assert groups["main_security_findings"][0]["title"] == "SQL injection"
        assert groups["informational_observations"][0]["title"] == "Missing Referrer-Policy"

    def test_finding_evidence_is_masked(self) -> None:
        finding = _make_finding(
            evidence="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.TJVA95OrM7E2c"
        )
        result = build_sanitized_scan_report_data(
            scan=_make_scan(),
            target=_make_target(),
            findings=[finding],
        )
        ev = result["findings"][0]["evidence"]
        assert "eyJhbGciOiJIUzI1NiJ9" not in ev
        assert "[REDACTED" in ev

    def test_page_excludes_headers_and_body(self) -> None:
        page = _make_page()
        result = build_sanitized_scan_report_data(
            scan=_make_scan(),
            target=_make_target(),
            findings=[],
            pages=[page],
        )
        p = result["pages"][0]
        assert "response_headers" not in p
        assert "response_body_excerpt" not in p
        assert p["url"] == "https://example.com/login"
        assert p["status_code"] == 200

    def test_technology_excludes_detection_method(self) -> None:
        tech = _make_tech()
        result = build_sanitized_scan_report_data(
            scan=_make_scan(),
            target=_make_target(),
            findings=[],
            technologies=[tech],
        )
        t = result["technologies"][0]
        assert "detection_method" not in t
        assert "confidence_score" not in t
        assert t["product_name"] == "nginx"
        assert t["version"] == "1.25.3"

    def test_does_not_mutate_original_objects(self) -> None:
        finding = _make_finding(
            evidence="Cookie: session=abc123; tracker=xyz"
        )
        original_evidence = finding.evidence
        original_finding_copy = copy.copy(finding)

        build_sanitized_scan_report_data(
            scan=_make_scan(),
            target=_make_target(),
            findings=[finding],
        )

        # The original object must remain untouched.
        assert finding.evidence == original_evidence
        assert finding.title == original_finding_copy.title
        assert finding.severity == original_finding_copy.severity

    def test_dict_inputs_work(self) -> None:
        """The sanitizer should also accept plain dicts, not only objects."""
        scan = {"id": 1, "status": "completed", "scan_type": "quick"}
        target = {"id": 2, "base_url": "https://x.com", "normalized_domain": "x.com"}
        finding = {
            "id": 10,
            "title": "Open redirect",
            "severity": "medium",
            "category": "redirect",
            "description": "Unvalidated redirect found.",
        }
        result = build_sanitized_scan_report_data(
            scan=scan,
            target=target,
            findings=[finding],
        )
        assert result["scan"]["id"] == 1
        assert result["findings"][0]["title"] == "Open redirect"
