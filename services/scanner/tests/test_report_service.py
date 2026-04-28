from datetime import datetime, timezone

from reportlab.platypus import Paragraph, Table

from app.services.pdf_rendering import sanitize_pdf_text
from app.services.report_service import ReportSnapshot, build_scan_report_pdf
from app.services.scan_report_pdf_service import (
    ReportMeta,
    _md_to_flowables,
    _styles,
    build_ai_report_pdf,
)


def test_sanitize_pdf_text_replaces_problematic_unicode() -> None:
    raw = "public\u25a0facing Cross\u2011Site 2026\u201104\u201128 A\u00a0B soft\u00adhyphen \u2192 \ufffd"

    assert sanitize_pdf_text(raw) == "public-facing Cross-Site 2026-04-28 A B softhyphen ->"


def test_markdown_table_block_renders_as_table_not_raw_pipe_paragraph() -> None:
    markdown = """## Risk Overview

| Severity | Count |
| --- | --- |
| High | 1 |
| Medium | 2 |

After table.
"""

    flowables = _md_to_flowables(markdown, _styles(), usable_width=450)

    assert any(isinstance(flowable, Table) for flowable in flowables)
    paragraph_text = "\n".join(
        flowable.getPlainText()
        for flowable in flowables
        if isinstance(flowable, Paragraph)
    )
    assert "| Severity | Count |" not in paragraph_text
    assert "| --- | --- |" not in paragraph_text


def test_ai_report_pdf_generation_completes_with_markdown_tables() -> None:
    markdown = """# Security Report

| # | Title | Severity | Confidence |
| --- | --- | --- | --- |
| 1 | Very long Cross\u2011Site Scripting title that should wrap in a PDF table | High | Confirmed |

## Conclusion & Next Steps

| Priority | Action |
| --- | --- |
| 1 | Remediate high severity issues, then re-run the scan. |
"""
    meta = ReportMeta(
        scan_id=12,
        target_domain="example.com",
        organization_name="Example",
        generated_at="2026\u201104\u201128 10:00 UTC",
        model="test",
        provider="test",
    )

    pdf_bytes = build_ai_report_pdf(markdown, meta)

    assert pdf_bytes.startswith(b"%PDF")


def test_structured_pdf_generation_completes_with_sanitized_text() -> None:
    snapshot = ReportSnapshot(
        scan_id=4,
        target_domain="example.com",
        target_base_url="https://example.com",
        status="completed",
        scan_type="full",
        scan_profile="standard",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        total_pages_found=1,
        total_findings=0,
        findings=[],
        technologies=[],
        pages=[],
    )

    pdf_bytes = build_scan_report_pdf(snapshot)

    assert pdf_bytes.startswith(b"%PDF")
