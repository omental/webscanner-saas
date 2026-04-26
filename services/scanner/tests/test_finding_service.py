import asyncio
from types import SimpleNamespace

from app.services.finding_service import create_findings_if_missing


class DummyIssue:
    def __init__(self, title: str, category: str, evidence: str | None) -> None:
        self.title = title
        self.category = category
        self.description = "desc"
        self.severity = "low"
        self.remediation = "fix"
        self.confidence = "high"
        self.evidence = evidence


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
