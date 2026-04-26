from types import SimpleNamespace
from unittest.mock import Mock

import app.services.fingerprint_service as fingerprint_service
from app.services.fingerprint_service import detect_and_store_page_technologies


async def _run_service() -> int:
    async def execute(_query: object) -> SimpleNamespace:
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def commit() -> None:
        return None

    session = SimpleNamespace(add=Mock(), commit=commit, execute=execute)
    return await detect_and_store_page_technologies(
        session,
        scan_id=1,
        scan_page_id=2,
        headers=None,
        body_excerpt=(
            '<script src="/static/js/jquery.min.js"></script>'
            '<script src="/static/js/jquery.min.js"></script>'
        ),
    )


def test_duplicate_prevention_logic_if_practical() -> None:
    import asyncio

    created_count = asyncio.run(_run_service())
    assert created_count == 1


def test_apache_technology_deduplicated(monkeypatch) -> None:
    import asyncio

    async def execute(_query: object) -> SimpleNamespace:
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def commit() -> None:
        return None

    added: list[object] = []
    session = SimpleNamespace(add=added.append, commit=commit, execute=execute)
    state = {"calls": 0}

    async def fake_exists(_session, **_kwargs) -> bool:
        state["calls"] += 1
        return state["calls"] > 1

    monkeypatch.setattr(fingerprint_service, "_technology_exists", fake_exists)

    first = asyncio.run(
        detect_and_store_page_technologies(
            session,
            scan_id=1,
            scan_page_id=10,
            headers={"server": "Apache/2.4.58"},
            body_excerpt=None,
        )
    )
    second = asyncio.run(
        detect_and_store_page_technologies(
            session,
            scan_id=1,
            scan_page_id=11,
            headers={"server": "Apache/2.4.58"},
            body_excerpt=None,
        )
    )

    assert first == 1
    assert second == 0
    apache_rows = [row for row in added if row.product_name == "Apache HTTP Server"]
    assert len(apache_rows) == 1
    assert apache_rows[0].scan_page_id is None


def test_full_html_is_used_when_excerpt_misses_plugin_evidence() -> None:
    import asyncio

    async def execute(_query: object) -> SimpleNamespace:
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def commit() -> None:
        return None

    added: list[object] = []
    session = SimpleNamespace(add=added.append, commit=commit, execute=execute)
    full_html = (
        "<html><body>"
        + ("a" * 12050)
        + '<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.27.3"></script>'
        + "</body></html>"
    )
    excerpt = full_html[:10000]

    created = asyncio.run(
        detect_and_store_page_technologies(
            session,
            scan_id=1,
            scan_page_id=2,
            headers=None,
            body_excerpt=excerpt,
            full_html=full_html,
        )
    )

    assert created >= 1
    elementor_rows = [row for row in added if row.product_name == "Elementor"]
    assert len(elementor_rows) == 1
    assert elementor_rows[0].version == "3.27.3"


def test_jquery_query_string_does_not_create_wordpress_core_version() -> None:
    import asyncio

    async def execute(_query: object) -> SimpleNamespace:
        return SimpleNamespace(
            scalar_one_or_none=lambda: None,
            scalars=lambda: SimpleNamespace(all=lambda: []),
        )

    async def commit() -> None:
        return None

    added: list[object] = []
    session = SimpleNamespace(add=added.append, commit=commit, execute=execute)

    created = asyncio.run(
        detect_and_store_page_technologies(
            session,
            scan_id=1,
            scan_page_id=2,
            headers=None,
            body_excerpt='<script src="/assets/jquery.min.js?ver=3.7.1"></script>',
        )
    )

    assert created == 1
    wordpress_core_rows = [
        row
        for row in added
        if row.product_name == "WordPress" and row.category == "cms"
    ]
    assert wordpress_core_rows == []


def test_wordpress_core_detection_keeps_final_best_version(monkeypatch) -> None:
    import asyncio

    class FakeScalarResult:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class FakeResult:
        def __init__(self, row=None, rows=None):
            self._row = row
            self._rows = rows or []

        def scalar_one_or_none(self):
            return self._row

        def scalars(self):
            return FakeScalarResult(self._rows)

    class FakeSession:
        def __init__(self):
            self.added: list[object] = []
            self.execute_calls = 0

        def add(self, obj):
            self.added.append(obj)

        async def commit(self):
            return None

        async def execute(self, _query):
            self.execute_calls += 1
            if self.execute_calls == 1:
                return FakeResult(rows=[])
            return FakeResult(rows=self.added)

    session = FakeSession()

    first = asyncio.run(
        detect_and_store_page_technologies(
            session,
            scan_id=1,
            scan_page_id=10,
            headers=None,
            body_excerpt='<img src="/wp-content/uploads/site.png">',
        )
    )
    second = asyncio.run(
        detect_and_store_page_technologies(
            session,
            scan_id=1,
            scan_page_id=11,
            headers=None,
            body_excerpt='<meta name="generator" content="WordPress 6.9.4">',
        )
    )

    assert first == 1
    assert second == 1
    wordpress_core_rows = [
        row
        for row in session.added
        if row.product_name == "WordPress" and row.category == "cms"
    ]
    assert len(wordpress_core_rows) == 1
    assert wordpress_core_rows[0].version == "6.9.4"
    assert wordpress_core_rows[0].detection_method == "meta_generator"
