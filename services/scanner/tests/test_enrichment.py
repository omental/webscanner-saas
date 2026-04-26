from datetime import datetime, timezone

from app.api.routes.scans import _serialize_finding
from app.intel.matchers.version_matcher import match_technology_to_product
from app.models.finding import Finding
from app.models.finding_reference import FindingReference
from app.services.enrichment_service import (
    ExploitEntryRow,
    IntelReference,
    TechnologyRow,
    VulnerabilityMatch,
    WordfenceMatch,
    _enrich_from_wordfence,
    _get_or_create_wordfence_finding,
    _attach_references_if_missing,
    build_known_vulnerability_finding_values,
    build_references_for_match,
    build_wordfence_finding_values,
    build_wordfence_references,
    extract_wordpress_slug,
    severity_from_cvss,
    should_create_known_vulnerability_finding,
)


def test_exact_version_match_prefers_exact_product_version() -> None:
    result = match_technology_to_product(
        technology_product="WordPress",
        technology_version="6.5.2",
        technology_vendor="Automattic",
        product_name="wordpress",
        product_vendor="automattic",
        product_version_exact="6.5.2",
    )

    assert result.is_match is True
    assert result.confidence == "high"


def test_known_vulnerability_finding_creation() -> None:
    technology = TechnologyRow(
        id=1,
        scan_id=2,
        scan_page_id=3,
        product_name="WordPress",
        category="cms",
        version="6.5.2",
        vendor="WordPress Foundation",
    )
    match = VulnerabilityMatch(
        cve_id="CVE-2026-0001",
        description="WordPress vulnerable to a known issue.",
        cvss_score=9.8,
        has_kev=False,
        exploit_entries=[],
        match_result=type("Match", (), {"confidence": "high"})(),
    )

    values = build_known_vulnerability_finding_values(2, technology, match)

    assert values["category"] == "known_vulnerability"
    assert values["title"] == "Known vulnerability detected in WordPress"
    assert values["severity"] == "critical"
    assert "Detected technology: WordPress 6.5.2" in values["evidence"]
    assert values["remediation"] == "Upgrade WordPress to a non-vulnerable version."


def test_cve_reference_attachment() -> None:
    references = build_references_for_match(
        cve_id="CVE-2026-1000",
        has_kev=False,
        exploit_entries=[],
    )

    assert references[0].ref_type == "cve"
    assert references[0].ref_value == "CVE-2026-1000"


def test_kev_reference_propagation() -> None:
    references = build_references_for_match(
        cve_id="CVE-2026-0001",
        has_kev=True,
        exploit_entries=[],
    )

    assert [reference.ref_type for reference in references] == ["cve", "kev"]


def test_exploitdb_reference_propagation() -> None:
    exploit_entry = ExploitEntryRow(
        edb_id="12345",
        exploit_url="https://www.exploit-db.com/exploits/12345",
    )

    references = build_references_for_match(
        cve_id="CVE-2026-0002",
        has_kev=False,
        exploit_entries=[exploit_entry],
    )

    assert [reference.ref_type for reference in references] == ["cve", "edb"]
    assert references[1].ref_value == "12345"


def test_no_cve_finding_when_version_is_missing() -> None:
    technology = TechnologyRow(
        id=1,
        scan_id=2,
        scan_page_id=None,
        product_name="WordPress",
        category="cms",
        version=None,
        vendor="WordPress Foundation",
    )
    match = VulnerabilityMatch(
        cve_id="CVE-2026-0001",
        description="desc",
        cvss_score=7.5,
        has_kev=False,
        exploit_entries=[],
        match_result=type("Match", (), {"confidence": "low"})(),
    )

    assert should_create_known_vulnerability_finding(technology, match) is False


def test_build_references_does_not_require_orm_relationship_access() -> None:
    references = build_references_for_match(
        cve_id="CVE-2026-0005",
        has_kev=True,
        exploit_entries=[ExploitEntryRow(edb_id="99999", exploit_url=None)],
    )

    assert [reference.ref_type for reference in references] == ["cve", "kev", "edb"]


def test_reference_attachment_works_without_relationship_loading() -> None:
    class FakeResult:
        def __init__(self, value):
            self._value = value

        def scalar_one_or_none(self):
            return self._value

    class FakeSession:
        def __init__(self):
            self.inserts = 0
            self.calls = 0

        async def execute(self, _statement):
            self.calls += 1
            if self.calls == 1:
                return FakeResult(None)
            self.inserts += 1
            return FakeResult(None)

    fake_session = FakeSession()
    created = __import__("asyncio").run(
        _attach_references_if_missing(
            fake_session,
            1,
            [
                IntelReference(
                    ref_type="cve",
                    ref_value="CVE-2026-0007",
                    ref_url=None,
                    source="nvd",
                )
            ],
        )
    )

    assert created == 1
    assert fake_session.inserts == 1


def test_severity_from_cvss_mapping() -> None:
    assert severity_from_cvss(2.0) == "low"
    assert severity_from_cvss(5.5) == "medium"
    assert severity_from_cvss(8.0) == "high"
    assert severity_from_cvss(9.5) == "critical"


def test_duplicate_reference_serialization_keeps_existing_unique_values() -> None:
    finding = Finding(
        id=1,
        scan_id=2,
        scan_page_id=None,
        category="known_vulnerability",
        title="Known vulnerability detected in WordPress",
        description="desc",
        severity="low",
        confidence="high",
        evidence=None,
        remediation="review",
        is_confirmed=False,
        references=[
            FindingReference(
                id=1,
                finding_id=1,
                ref_type="cve",
                ref_value="CVE-2026-0003",
                ref_url=None,
                source="nvd",
                created_at=datetime.now(timezone.utc),
            )
        ],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    serialized = _serialize_finding(finding)

    assert len(serialized.references) == 1
    assert serialized.references[0].ref_value == "CVE-2026-0003"


def test_findings_response_includes_references() -> None:
    finding = Finding(
        id=4,
        scan_id=5,
        scan_page_id=None,
        category="known_vulnerability",
        title="Known vulnerability detected in Apache HTTP Server",
        description="desc",
        severity="high",
        confidence="high",
        evidence=None,
        remediation="review",
        is_confirmed=False,
        references=[
            FindingReference(
                id=9,
                finding_id=4,
                ref_type="edb",
                ref_value="54321",
                ref_url="https://www.exploit-db.com/exploits/54321",
                source="exploitdb",
                created_at=datetime.now(timezone.utc),
            )
        ],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    serialized = _serialize_finding(finding)

    assert serialized.references[0].source == "exploitdb"


def test_wordpress_slug_extraction() -> None:
    plugin = TechnologyRow(
        id=1,
        scan_id=1,
        scan_page_id=None,
        product_name="WordPress Plugin: elementor",
        category="cms_plugin",
        version="3.35.5",
        vendor=None,
    )
    theme = TechnologyRow(
        id=2,
        scan_id=1,
        scan_page_id=None,
        product_name="WordPress Theme: hello-elementor",
        category="cms_theme",
        version="1.0.0",
        vendor=None,
    )
    direct = TechnologyRow(
        id=3,
        scan_id=1,
        scan_page_id=None,
        product_name="Elementor",
        category="cms_plugin",
        version="3.35.5",
        vendor=None,
    )

    assert extract_wordpress_slug(plugin) == "elementor"
    assert extract_wordpress_slug(theme) == "hello-elementor"
    assert extract_wordpress_slug(direct) == "elementor"


def test_wordpress_slug_extraction_ignores_case() -> None:
    plugin = TechnologyRow(
        id=1,
        scan_id=1,
        scan_page_id=None,
        product_name="wOrDpReSs PlUgIn: Elementor",
        category="cms_plugin",
        version="3.35.5",
        vendor=None,
    )

    assert extract_wordpress_slug(plugin) == "elementor"


def test_wordfence_vulnerable_version_match_builds_finding() -> None:
    from app.intel.matchers.version_matcher import is_version_in_range

    technology = TechnologyRow(
        id=1,
        scan_id=2,
        scan_page_id=3,
        product_name="Elementor",
        category="cms_plugin",
        version="3.35.5",
        vendor=None,
    )
    match = WordfenceMatch(
        wordfence_id="wf-100",
        cve_id="CVE-2026-5000",
        slug="elementor",
        software_type="plugin",
        title="Elementor privilege escalation",
        description="Wordfence matched Elementor as vulnerable.",
        severity="high",
        cvss_score=8.1,
        affected_version_start=None,
        affected_version_end="3.35.5",
        patched_version="3.35.6",
        references=["https://www.wordfence.com/blog/example"],
    )

    assert (
        is_version_in_range(
            version=technology.version,
            version_start=match.affected_version_start,
            version_end=match.affected_version_end,
        )
        is True
    )

    values = build_wordfence_finding_values(2, technology, match)

    assert values["category"] == "wordpress_vulnerability"
    assert values["title"] == "Elementor privilege escalation"
    assert values["severity"] == "high"
    assert "Detected plugin slug: elementor" in values["evidence"]
    assert values["remediation"] == "Update Elementor to 3.35.6 or later."


def test_wordfence_non_vulnerable_version_no_match() -> None:
    from app.intel.matchers.version_matcher import is_version_in_range

    assert (
        is_version_in_range(
            version="3.35.6",
            version_start=None,
            version_end="3.35.5",
        )
        is False
    )


def test_wordfence_reference_attachment() -> None:
    match = WordfenceMatch(
        wordfence_id="wf-100",
        cve_id="CVE-2026-5000",
        slug="elementor",
        software_type="plugin",
        title="Elementor issue",
        description="desc",
        severity="high",
        cvss_score=8.1,
        affected_version_start=None,
        affected_version_end="3.35.5",
        patched_version="3.35.6",
        references=["https://example.com/reference"],
    )

    references = build_wordfence_references(match)

    assert [reference.ref_type for reference in references] == [
        "cve",
        "wordfence",
        "reference",
    ]
    assert references[1].source == "wordfence"


def test_wordfence_duplicate_reference_prevention() -> None:
    class FakeResult:
        def __init__(self, value):
            self._value = value

        def scalar_one_or_none(self):
            return self._value

    class FakeSession:
        def __init__(self):
            self.calls = 0
            self.inserts = 0

        async def execute(self, _statement):
            self.calls += 1
            if self.calls == 1:
                return FakeResult(None)
            if self.calls == 2:
                self.inserts += 1
                return FakeResult(None)
            return FakeResult(1)

    created = __import__("asyncio").run(
        _attach_references_if_missing(
            FakeSession(),
            7,
            [
                IntelReference(
                    ref_type="wordfence",
                    ref_value="wf-100",
                    ref_url="https://www.wordfence.com/threat-intel/vulnerabilities/id/wf-100",
                    source="wordfence",
                ),
                IntelReference(
                    ref_type="wordfence",
                    ref_value="wf-100",
                    ref_url="https://www.wordfence.com/threat-intel/vulnerabilities/id/wf-100",
                    source="wordfence",
                ),
            ],
        )
    )

    assert created == 1


def test_wordfence_match_short_circuits_generic_enrichment(monkeypatch) -> None:
    import asyncio

    technology = TechnologyRow(
        id=1,
        scan_id=2,
        scan_page_id=3,
        product_name="WordPress Plugin: elementor",
        category="cms_plugin",
        version="3.35.5",
        vendor=None,
    )
    match = WordfenceMatch(
        wordfence_id="wf-100",
        cve_id="CVE-2026-5000",
        slug="elementor",
        software_type="plugin",
        title="Elementor issue",
        description="desc",
        severity="high",
        cvss_score=8.1,
        affected_version_start=None,
        affected_version_end="3.35.5",
        patched_version="3.35.6",
        references=["https://example.com/reference"],
    )

    async def fake_find_best_wordfence_match(_session, _technology):
        return match

    async def fake_get_or_create_wordfence_finding(_session, _scan_id, _technology, _match):
        return 77

    async def fake_attach(_session, finding_id, references):
        assert finding_id == 77
        assert references[0].ref_type == "cve"
        return 0

    monkeypatch.setattr(
        "app.services.enrichment_service._find_best_wordfence_match",
        fake_find_best_wordfence_match,
    )
    monkeypatch.setattr(
        "app.services.enrichment_service._get_or_create_wordfence_finding",
        fake_get_or_create_wordfence_finding,
    )
    monkeypatch.setattr(
        "app.services.enrichment_service._attach_references_if_missing",
        fake_attach,
    )

    matched, created = asyncio.run(_enrich_from_wordfence(object(), 2, technology))

    assert matched is True
    assert created == 0


def test_wordpress_core_matching_uses_final_core_version() -> None:
    technology = TechnologyRow(
        id=5,
        scan_id=2,
        scan_page_id=9,
        product_name="WordPress",
        category="cms",
        version="6.9.4",
        vendor="WordPress Foundation",
    )
    match = WordfenceMatch(
        wordfence_id="wf-core-1",
        cve_id=None,
        slug="wordpress",
        software_type="core",
        title="WordPress core issue",
        description="Core vulnerability",
        severity="medium",
        cvss_score=5.0,
        affected_version_start="6.0.0",
        affected_version_end="6.9.4",
        patched_version="6.9.5",
        references=["https://example.com/core"],
    )

    values = build_wordfence_finding_values(2, technology, match)

    assert values["category"] == "wordpress_vulnerability"
    assert "Detected core slug: wordpress; detected version: 6.9.4" in values["evidence"]


def test_duplicate_wordfence_finding_prevention() -> None:
    class FakeResult:
        def __init__(self, value):
            self._value = value

        def scalar_one_or_none(self):
            return self._value

        def scalar_one(self):
            return self._value

    class FakeSession:
        def __init__(self):
            self.calls = 0

        async def execute(self, _statement):
            self.calls += 1
            if self.calls == 1:
                return FakeResult(55)
            return FakeResult(99)

    technology = TechnologyRow(
        id=1,
        scan_id=2,
        scan_page_id=3,
        product_name="WordPress Plugin: elementor",
        category="cms_plugin",
        version="3.35.5",
        vendor=None,
    )
    match = WordfenceMatch(
        wordfence_id="wf-100",
        cve_id="CVE-2026-5000",
        slug="elementor",
        software_type="plugin",
        title="Elementor issue",
        description="desc",
        severity="high",
        cvss_score=8.1,
        affected_version_start=None,
        affected_version_end="3.35.5",
        patched_version="3.35.6",
        references=[],
    )

    finding_id = __import__("asyncio").run(
        _get_or_create_wordfence_finding(FakeSession(), 2, technology, match)
    )

    assert finding_id == 55
