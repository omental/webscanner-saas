import asyncio
from types import SimpleNamespace

from app.services.finding_service import (
    build_finding_deduplication_key,
    create_findings_if_missing,
)


class DummyIssue:
    def __init__(self, title: str, category: str, evidence: str | None) -> None:
        self.title = title
        self.category = category
        self.description = "desc"
        self.severity = "low"
        self.remediation = "fix"
        self.confidence = "high"
        self.evidence = evidence


class DedupingSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.commits = 0

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def execute(self, query):
        params = query.compile().params
        scan_id = params.get("scan_id_1")
        deduplication_key = params.get("deduplication_key_1")
        exact_scan_page_id = params.get("scan_page_id_1")
        category = params.get("category_1")
        title = params.get("title_1")
        evidence = params.get("evidence_1")
        duplicate_parameter = params.get("tested_parameter_1") or params.get(
            "affected_parameter_1"
        )

        for finding in self.added:
            if finding.scan_id != scan_id:
                continue
            if finding.deduplication_key == deduplication_key:
                return SimpleNamespace(scalar_one_or_none=lambda finding=finding: finding)
            if (
                finding.scan_page_id == exact_scan_page_id
                and finding.category == category
                and finding.title == title
                and finding.evidence == evidence
                and (
                    not duplicate_parameter
                    or finding.tested_parameter == duplicate_parameter
                    or finding.affected_parameter == duplicate_parameter
                )
            ):
                return SimpleNamespace(scalar_one_or_none=lambda finding=finding: finding)

        return SimpleNamespace(scalar_one_or_none=lambda: None)


def _issue(
    *,
    scan_url: str = "https://example.com/search?q=test",
    parameter: str | None = "q",
    evidence: str | None = "evidence",
) -> DummyIssue:
    issue = DummyIssue("Possible reflected XSS", "reflected_xss", evidence)
    issue.severity = "medium"
    issue.request_url = scan_url
    if parameter is not None:
        issue.tested_parameter = parameter
        issue.affected_parameter = parameter
    return issue


def test_missing_header_finding_created_once_per_scan() -> None:
    added = []

    class Result:
        def __init__(self, exists: bool) -> None:
            self._exists = exists

        def scalar_one_or_none(self):
            return object() if self._exists else None

    state = {"calls": 0}

    async def execute(query):
        state["calls"] += 1
        exists = state["calls"] > 1
        return Result(exists)

    async def commit():
        return None

    session = SimpleNamespace(add=added.append, commit=commit, execute=execute)
    issue = DummyIssue("Missing Content-Security-Policy", "missing_security_header", "content-security-policy")

    asyncio.run(create_findings_if_missing(session, scan_id=1, scan_page_id=10, issues=[issue]))
    asyncio.run(create_findings_if_missing(session, scan_id=1, scan_page_id=11, issues=[issue]))

    assert len(added) == 1
    assert added[0].scan_page_id is None


def test_server_banner_finding_created_once_per_scan() -> None:
    added = []

    class Result:
        def __init__(self, exists: bool) -> None:
            self._exists = exists

        def scalar_one_or_none(self):
            return object() if self._exists else None

    state = {"calls": 0}

    async def execute(query):
        state["calls"] += 1
        exists = state["calls"] > 1
        return Result(exists)

    async def commit():
        return None

    session = SimpleNamespace(add=added.append, commit=commit, execute=execute)
    issue = DummyIssue("Exposed server banner", "information_disclosure", "Apache/2.4.58")

    asyncio.run(create_findings_if_missing(session, scan_id=1, scan_page_id=10, issues=[issue]))
    asyncio.run(create_findings_if_missing(session, scan_id=1, scan_page_id=12, issues=[issue]))

    assert len(added) == 1
    assert added[0].scan_page_id is None


def test_same_scan_same_issue_is_deduplicated() -> None:
    session = DedupingSession()
    issue = _issue()

    first = asyncio.run(
        create_findings_if_missing(session, scan_id=1, scan_page_id=10, issues=[issue])
    )
    second = asyncio.run(
        create_findings_if_missing(session, scan_id=1, scan_page_id=10, issues=[issue])
    )

    assert first == 1
    assert second == 0
    assert len(session.added) == 1
    assert session.added[0].deduplication_key


def test_same_issue_on_different_scans_is_not_deduplicated() -> None:
    session = DedupingSession()
    issue = _issue()

    first = asyncio.run(
        create_findings_if_missing(session, scan_id=1, scan_page_id=10, issues=[issue])
    )
    second = asyncio.run(
        create_findings_if_missing(session, scan_id=2, scan_page_id=10, issues=[issue])
    )

    assert first == 1
    assert second == 1
    assert len(session.added) == 2
    assert session.added[0].deduplication_key != session.added[1].deduplication_key


def test_same_issue_with_different_parameter_is_not_deduplicated() -> None:
    session = DedupingSession()

    first = asyncio.run(
        create_findings_if_missing(
            session,
            scan_id=1,
            scan_page_id=10,
            issues=[_issue(parameter="q")],
        )
    )
    second = asyncio.run(
        create_findings_if_missing(
            session,
            scan_id=1,
            scan_page_id=10,
            issues=[_issue(parameter="search")],
        )
    )

    assert first == 1
    assert second == 1
    assert len(session.added) == 2
    assert session.added[0].deduplication_key != session.added[1].deduplication_key


def test_finding_without_rich_metadata_still_saves_safely() -> None:
    session = DedupingSession()
    issue = _issue(scan_url="", parameter=None, evidence=None)

    created = asyncio.run(
        create_findings_if_missing(session, scan_id=3, scan_page_id=None, issues=[issue])
    )

    assert created == 1
    assert len(session.added) == 1
    assert session.added[0].deduplication_key


def test_deduplication_key_is_stable_and_uses_scan_and_parameter() -> None:
    base = dict(
        scan_id=1,
        check_type="reflected_xss",
        severity="medium",
        title="Possible reflected XSS",
        request_url="https://example.com/search?b=2&a=1#frag",
    )

    first = build_finding_deduplication_key(**base, tested_parameter="q")
    second = build_finding_deduplication_key(
        **{**base, "request_url": "https://EXAMPLE.com/search?a=1&b=2"},
        tested_parameter="q",
    )
    different_scan = build_finding_deduplication_key(
        **{**base, "scan_id": 2}, tested_parameter="q"
    )
    different_param = build_finding_deduplication_key(**base, tested_parameter="search")

    assert first == second
    assert first != different_scan
    assert first != different_param
