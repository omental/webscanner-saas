from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from io import BytesIO

from fastapi import HTTPException, status
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detected_technology import DetectedTechnology
from app.models.finding import Finding
from app.models.finding_reference import FindingReference
from app.models.scan import Scan
from app.models.scan_page import ScanPage
from app.models.target import Target
from app.services.pdf_rendering import build_pdf_table, pdf_escape
from app.services.comparison_service import get_comparison_summary


@dataclass(slots=True)
class ReportReference:
    ref_type: str
    ref_value: str
    ref_url: str | None
    source: str | None


@dataclass(slots=True)
class ReportFinding:
    severity: str
    category: str
    title: str
    description: str
    evidence: str | None
    remediation: str | None
    confidence: str | None
    confidence_level: str | None
    confidence_score: int | None
    evidence_type: str | None
    verification_steps: list[str] | None
    payload_used: str | None
    affected_parameter: str | None
    response_snippet: str | None
    false_positive_notes: str | None
    request_url: str | None
    http_method: str | None
    tested_parameter: str | None
    payload: str | None
    baseline_status_code: int | None
    attack_status_code: int | None
    baseline_response_size: int | None
    attack_response_size: int | None
    baseline_response_time_ms: int | None
    attack_response_time_ms: int | None
    response_diff_summary: str | None
    deduplication_key: str | None
    references: list[ReportReference]
    comparison_status: str | None = None


@dataclass(slots=True)
class ReportTechnology:
    product_name: str
    category: str
    version: str | None
    vendor: str | None
    confidence_score: float | None


@dataclass(slots=True)
class ReportPage:
    url: str
    status_code: int | None
    content_type: str | None
    response_time_ms: int | None
    depth: int


@dataclass(slots=True)
class ReportSnapshot:
    scan_id: int
    target_domain: str
    target_base_url: str
    status: str
    scan_type: str
    scan_profile: str | None
    started_at: datetime | None
    finished_at: datetime | None
    total_pages_found: int
    total_findings: int
    findings: list[ReportFinding]
    technologies: list[ReportTechnology]
    pages: list[ReportPage]
    risk_score: int | None = None
    comparison_summary: dict[str, int] | None = None


def _format_dt(value: datetime | None) -> str:
    if value is None:
        return "Not available"
    return value.strftime("%Y-%m-%d %H:%M:%S %Z")


def _severity_counts(findings: list[ReportFinding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        key = finding.severity.lower()
        if key in counts:
            counts[key] += 1
    return counts


def _confidence_group(finding: ReportFinding) -> str:
    normalized = (finding.confidence_level or finding.confidence or "").lower()
    if normalized in {"confirmed", "high", "medium"}:
        return "main"
    return "observations"


def _group_findings_by_confidence(
    findings: list[ReportFinding],
) -> tuple[list[ReportFinding], list[ReportFinding]]:
    main = [finding for finding in findings if _confidence_group(finding) == "main"]
    observations = [
        finding for finding in findings if _confidence_group(finding) == "observations"
    ]
    return main, observations


def _confidence_counts(findings: list[ReportFinding]) -> dict[str, int]:
    counts = {"confirmed": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = (finding.confidence_level or finding.confidence or "info").lower()
        if key == "informational":
            key = "info"
        if key in counts:
            counts[key] += 1
    return counts


def _severity_color(severity: str) -> str:
    normalized = severity.lower()
    if normalized == "critical":
        return "#dc2626"
    if normalized == "high":
        return "#ea580c"
    if normalized == "medium":
        return "#d97706"
    return "#2563eb"


def _build_styles() -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=sample["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            alignment=TA_CENTER,
            spaceAfter=14,
        ),
        "section": ParagraphStyle(
            "ReportSection",
            parent=sample["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=14,
            spaceAfter=8,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#334155"),
            spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#475569"),
            spaceAfter=4,
        ),
        "table_header": ParagraphStyle(
            "ReportTableHeader",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.2,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        ),
        "table_cell": ParagraphStyle(
            "ReportTableCell",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8.2,
            leading=10,
            textColor=colors.HexColor("#334155"),
        ),
    }


def _table(
    data: list[list[object]],
    styles: dict[str, ParagraphStyle],
    col_widths: list[float] | None = None,
) -> Table:
    return build_pdf_table(data, styles, col_widths)


def _pdf_escape(value: object) -> str:
    return pdf_escape(value)


def _append_finding(
    story: list, styles: dict[str, ParagraphStyle], finding: ReportFinding
) -> None:
    severity_color = _severity_color(finding.severity)
    confidence_label = finding.confidence_level or finding.confidence or "not set"
    confidence_suffix = (
        f" / {finding.confidence_score}"
        if finding.confidence_score is not None
        else ""
    )
    story.append(
        Paragraph(
            f"<font color='{severity_color}'><b>{finding.severity.upper()}</b></font> "
            f"&nbsp; <b>{_pdf_escape(finding.title)}</b> ({_pdf_escape(finding.category)})",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            f"<b>Confidence:</b> {_pdf_escape(confidence_label)}{confidence_suffix}"
            + (
                f" &nbsp; <b>Evidence type:</b> {_pdf_escape(finding.evidence_type)}"
                if finding.evidence_type
                else ""
            ),
            styles["small"],
        )
    )
    story.append(
        Paragraph(
            _pdf_escape(finding.description or "No description provided."),
            styles["body"],
        )
    )
    if finding.affected_parameter:
        story.append(
            Paragraph(
                f"<b>Affected parameter:</b> {_pdf_escape(finding.affected_parameter)}",
                styles["small"],
            )
        )
    if finding.request_url:
        story.append(
            Paragraph(
                f"<b>Request:</b> {_pdf_escape(finding.http_method or '-')} {_pdf_escape(finding.request_url)}",
                styles["small"],
            )
        )
    if finding.tested_parameter:
        story.append(
            Paragraph(
                f"<b>Tested parameter:</b> {_pdf_escape(finding.tested_parameter)}",
                styles["small"],
            )
        )
    if finding.response_diff_summary:
        story.append(
            Paragraph(
                f"<b>Response diff:</b> {_pdf_escape(finding.response_diff_summary)}",
                styles["small"],
            )
        )
    if finding.deduplication_key:
        story.append(
            Paragraph(
                f"<b>Deduplication key:</b> {_pdf_escape(finding.deduplication_key)}",
                styles["small"],
            )
        )
    if finding.comparison_status:
        story.append(
            Paragraph(
                f"<b>Retest status:</b> {_pdf_escape(finding.comparison_status)}",
                styles["small"],
            )
        )
    status_bits = []
    if finding.baseline_status_code is not None:
        status_bits.append(f"baseline={finding.baseline_status_code}")
    if finding.attack_status_code is not None:
        status_bits.append(f"attack={finding.attack_status_code}")
    if status_bits:
        story.append(
            Paragraph(
                f"<b>Status codes:</b> {_pdf_escape('; '.join(status_bits))}",
                styles["small"],
            )
        )
    size_bits = []
    if finding.baseline_response_size is not None:
        size_bits.append(f"baseline={finding.baseline_response_size} bytes")
    if finding.attack_response_size is not None:
        size_bits.append(f"attack={finding.attack_response_size} bytes")
    if size_bits:
        story.append(
            Paragraph(
                f"<b>Response sizes:</b> {_pdf_escape('; '.join(size_bits))}",
                styles["small"],
            )
        )
    time_bits = []
    if finding.baseline_response_time_ms is not None:
        time_bits.append(f"baseline={finding.baseline_response_time_ms} ms")
    if finding.attack_response_time_ms is not None:
        time_bits.append(f"attack={finding.attack_response_time_ms} ms")
    if time_bits:
        story.append(
            Paragraph(
                f"<b>Response times:</b> {_pdf_escape('; '.join(time_bits))}",
                styles["small"],
            )
        )
    if finding.evidence:
        story.append(
            Paragraph(f"<b>Evidence:</b> {_pdf_escape(finding.evidence)}", styles["small"])
        )
    if finding.response_snippet:
        story.append(
            Paragraph(
                f"<b>Response snippet:</b> {_pdf_escape(finding.response_snippet)}",
                styles["small"],
            )
        )
    if finding.payload_used:
        story.append(
            Paragraph(f"<b>Payload used:</b> {_pdf_escape(finding.payload_used)}", styles["small"])
        )
    if finding.verification_steps:
        story.append(
            Paragraph(
                f"<b>Verification steps:</b> {_pdf_escape('; '.join(finding.verification_steps))}",
                styles["small"],
            )
        )
    if finding.false_positive_notes:
        story.append(
            Paragraph(
                f"<b>False positive notes:</b> {_pdf_escape(finding.false_positive_notes)}",
                styles["small"],
            )
        )
    if finding.remediation:
        story.append(
            Paragraph(
                f"<b>Remediation:</b> {_pdf_escape(finding.remediation)}",
                styles["small"],
            )
        )
    if finding.references:
        references = []
        for reference in finding.references:
            ref_text = reference.ref_value
            if reference.ref_url:
                ref_text = f"{reference.ref_value} ({reference.ref_url})"
            elif reference.source:
                ref_text = f"{reference.ref_value} ({reference.source})"
            references.append(_pdf_escape(ref_text))
        story.append(
            Paragraph(
                f"<b>References:</b> {'; '.join(references)}",
                styles["small"],
            )
        )
    story.append(Spacer(1, 8))


def _draw_page_chrome(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.drawString(doc.leftMargin, A4[1] - 30, "Web Vulnerability Scan Report")
    canvas.drawRightString(A4[0] - doc.rightMargin, 20, f"Page {doc.page}")
    canvas.restoreState()


def build_scan_report_pdf(snapshot: ReportSnapshot) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.55 * inch,
        title=f"Scan {snapshot.scan_id} Report",
    )
    styles = _build_styles()
    story = []

    story.append(Paragraph("Web Vulnerability Scan Report", styles["title"]))
    story.append(
        Paragraph(
            f"<b>Target:</b> {_pdf_escape(snapshot.target_domain)}<br/>"
            f"<b>Base URL:</b> {_pdf_escape(snapshot.target_base_url)}<br/>"
            f"<b>Scan ID:</b> {_pdf_escape(snapshot.scan_id)}<br/>"
            f"<b>Status:</b> {_pdf_escape(snapshot.status)}<br/>"
            f"<b>Scan Type:</b> {_pdf_escape(snapshot.scan_type)}<br/>"
            f"<b>Scan Profile:</b> {_pdf_escape(snapshot.scan_profile or 'standard')}<br/>"
            f"<b>Risk Score:</b> {_pdf_escape(snapshot.risk_score if snapshot.risk_score is not None else 'Not available')}<br/>"
            f"<b>Started:</b> {_pdf_escape(_format_dt(snapshot.started_at))}<br/>"
            f"<b>Finished:</b> {_pdf_escape(_format_dt(snapshot.finished_at))}",
            styles["body"],
        )
    )

    counts = _severity_counts(snapshot.findings)
    confidence_counts = _confidence_counts(snapshot.findings)
    main_findings, observation_findings = _group_findings_by_confidence(
        snapshot.findings
    )
    story.append(Paragraph("Executive Summary", styles["section"]))
    story.append(
        _table(
            [
                ["Metric", "Value"],
                ["Pages Scanned", str(snapshot.total_pages_found)],
                ["Findings", str(snapshot.total_findings)],
                [
                    "Risk Score",
                    str(snapshot.risk_score) if snapshot.risk_score is not None else "-",
                ],
                ["Technologies", str(len(snapshot.technologies))],
                ["Main Security Findings", str(len(main_findings))],
                ["Informational Observations", str(len(observation_findings))],
            ],
            styles,
            [2.4 * inch, 1.2 * inch],
        )
    )
    if snapshot.comparison_summary is not None:
        story.append(
            _table(
                [
                    ["Fixed", "Still Vulnerable", "New", "Existing", "Not Retested"],
                    [
                        str(snapshot.comparison_summary.get("fixed", 0)),
                        str(snapshot.comparison_summary.get("still_vulnerable", 0)),
                        str(snapshot.comparison_summary.get("new", 0)),
                        str(snapshot.comparison_summary.get("existing", 0)),
                        str(snapshot.comparison_summary.get("not_retested", 0)),
                    ],
                ],
                styles,
            )
        )
    story.append(Paragraph("Risk Overview", styles["section"]))
    story.append(
        _table(
            [
                ["Severity", "Count"],
                ["Critical", str(counts["critical"])],
                ["High", str(counts["high"])],
                ["Medium", str(counts["medium"])],
                ["Low", str(counts["low"])],
            ],
            styles,
            [2.0 * inch, 1.0 * inch],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        _table(
            [
                ["Confidence", "Count"],
                ["Confirmed", str(confidence_counts["confirmed"])],
                ["High", str(confidence_counts["high"])],
                ["Medium", str(confidence_counts["medium"])],
                ["Low", str(confidence_counts["low"])],
                ["Info", str(confidence_counts["info"])],
            ],
            styles,
            [2.0 * inch, 1.0 * inch],
        )
    )

    story.append(Paragraph("Main Security Findings", styles["section"]))
    if main_findings:
        story.append(
            _table(
                [
                    ["#", "Title", "Severity", "Confidence"],
                    *[
                        [
                            str(index),
                            finding.title,
                            finding.severity,
                            finding.confidence_level or finding.confidence or "not set",
                        ]
                        for index, finding in enumerate(main_findings, 1)
                    ],
                ],
                styles,
                [0.35 * inch, 4.0 * inch, 0.9 * inch, 1.0 * inch],
            )
        )
        story.append(Spacer(1, 10))
        for finding in main_findings:
            _append_finding(story, styles, finding)
    else:
        story.append(
            Paragraph("No confirmed, high, or medium confidence findings were recorded.", styles["body"])
        )

    story.append(Paragraph("Informational Observations", styles["section"]))
    if observation_findings:
        story.append(
            _table(
                [
                    ["#", "Observation", "Severity", "Confidence"],
                    *[
                        [
                            str(index),
                            finding.title,
                            finding.severity,
                            finding.confidence_level or finding.confidence or "not set",
                        ]
                        for index, finding in enumerate(observation_findings, 1)
                    ],
                ],
                styles,
                [0.35 * inch, 4.0 * inch, 0.9 * inch, 1.0 * inch],
            )
        )
        story.append(Spacer(1, 10))
        for finding in observation_findings:
            _append_finding(story, styles, finding)
    else:
        story.append(Paragraph("No low-confidence or informational observations were recorded.", styles["body"]))

    story.append(Paragraph("Technologies", styles["section"]))
    if snapshot.technologies:
        story.append(
            _table(
                [
                    [
                        "Product",
                        "Category",
                        "Version",
                        "Vendor",
                        "Confidence",
                    ],
                    *[
                        [
                            technology.product_name,
                            technology.category,
                            technology.version or "-",
                            technology.vendor or "-",
                            (
                                f"{technology.confidence_score:.2f}"
                                if technology.confidence_score is not None
                                else "-"
                            ),
                        ]
                        for technology in snapshot.technologies
                    ],
                ],
                styles,
                [2.0 * inch, 1.15 * inch, 0.9 * inch, 1.45 * inch, 0.8 * inch],
            )
        )
    else:
        story.append(
            Paragraph("No technologies were detected for this scan.", styles["body"])
        )

    story.append(Paragraph("Pages Scanned", styles["section"]))
    if snapshot.pages:
        story.append(
            _table(
                [
                    [
                        "URL",
                        "Status",
                        "Content Type",
                        "Response ms",
                        "Depth",
                    ],
                    *[
                        [
                            page.url,
                            str(page.status_code or "-"),
                            page.content_type or "-",
                            str(page.response_time_ms or "-"),
                            str(page.depth),
                        ]
                        for page in snapshot.pages
                    ],
                ],
                styles,
                [3.4 * inch, 0.6 * inch, 1.3 * inch, 0.8 * inch, 0.4 * inch],
            )
        )
    else:
        story.append(Paragraph("No pages were recorded for this scan.", styles["body"]))

    doc.build(story, onFirstPage=_draw_page_chrome, onLaterPages=_draw_page_chrome)
    return buffer.getvalue()


async def get_scan_report_snapshot(
    session: AsyncSession, scan_id: int
) -> ReportSnapshot:
    scan_result = await session.execute(
        select(Scan, Target).join(Target, Target.id == Scan.target_id).where(Scan.id == scan_id)
    )
    row = scan_result.first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    scan, target = row
    if scan.status.lower() != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan must be completed before downloading a report",
        )

    pages_result = await session.execute(
        select(ScanPage)
        .where(ScanPage.scan_id == scan_id)
        .order_by(ScanPage.depth.asc(), ScanPage.id.asc())
    )
    pages = list(pages_result.scalars().all())

    findings_result = await session.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id.asc())
    )
    findings = list(findings_result.scalars().all())
    finding_ids = [finding.id for finding in findings]

    references_by_finding: dict[int, list[ReportReference]] = {}
    if finding_ids:
        references_result = await session.execute(
            select(FindingReference)
            .where(FindingReference.finding_id.in_(finding_ids))
            .order_by(FindingReference.id.asc())
        )
        for reference in references_result.scalars().all():
            references_by_finding.setdefault(reference.finding_id, []).append(
                ReportReference(
                    ref_type=reference.ref_type,
                    ref_value=reference.ref_value,
                    ref_url=reference.ref_url,
                    source=reference.source,
                )
            )

    technologies_result = await session.execute(
        select(DetectedTechnology)
        .where(DetectedTechnology.scan_id == scan_id)
        .order_by(DetectedTechnology.product_name.asc(), DetectedTechnology.id.asc())
    )
    technologies = list(technologies_result.scalars().all())

    return ReportSnapshot(
        scan_id=scan.id,
        target_domain=target.normalized_domain,
        target_base_url=target.base_url,
        status=scan.status,
        scan_type=scan.scan_type,
        scan_profile=scan.scan_profile or "standard",
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        total_pages_found=scan.total_pages_found or len(pages),
        total_findings=scan.total_findings or len(findings),
        risk_score=scan.risk_score,
        comparison_summary=await get_comparison_summary(session, scan),
        findings=[
            ReportFinding(
                severity=finding.severity,
                category=finding.category,
                title=finding.title,
                description=finding.description,
                evidence=finding.evidence,
                remediation=finding.remediation,
                confidence=finding.confidence,
                confidence_level=finding.confidence_level,
                confidence_score=finding.confidence_score,
                evidence_type=finding.evidence_type,
                verification_steps=finding.verification_steps,
                payload_used=finding.payload_used,
                affected_parameter=finding.affected_parameter,
                response_snippet=finding.response_snippet,
                false_positive_notes=finding.false_positive_notes,
                request_url=finding.request_url,
                http_method=finding.http_method,
                tested_parameter=finding.tested_parameter,
                payload=finding.payload,
                baseline_status_code=finding.baseline_status_code,
                attack_status_code=finding.attack_status_code,
                baseline_response_size=finding.baseline_response_size,
                attack_response_size=finding.attack_response_size,
                baseline_response_time_ms=finding.baseline_response_time_ms,
                attack_response_time_ms=finding.attack_response_time_ms,
                response_diff_summary=finding.response_diff_summary,
                deduplication_key=finding.deduplication_key,
                comparison_status=finding.comparison_status,
                references=references_by_finding.get(finding.id, []),
            )
            for finding in findings
        ],
        technologies=[
            ReportTechnology(
                product_name=technology.product_name,
                category=technology.category,
                version=technology.version,
                vendor=technology.vendor,
                confidence_score=technology.confidence_score,
            )
            for technology in technologies
        ],
        pages=[
            ReportPage(
                url=page.url,
                status_code=page.status_code,
                content_type=page.content_type,
                response_time_ms=page.response_time_ms,
                depth=page.depth,
            )
            for page in pages
        ],
    )


async def get_scan_report_pdf(session: AsyncSession, scan_id: int) -> bytes:
    snapshot = await get_scan_report_snapshot(session, scan_id)
    return build_scan_report_pdf(snapshot)
