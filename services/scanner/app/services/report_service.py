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
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detected_technology import DetectedTechnology
from app.models.finding import Finding
from app.models.finding_reference import FindingReference
from app.models.scan import Scan
from app.models.scan_page import ScanPage
from app.models.target import Target


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
    references: list[ReportReference]


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
    started_at: datetime | None
    finished_at: datetime | None
    total_pages_found: int
    total_findings: int
    findings: list[ReportFinding]
    technologies: list[ReportTechnology]
    pages: list[ReportPage]


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
    }


def _table(data: list[list[str]], col_widths: list[float] | None = None) -> Table:
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("LEADING", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


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
            f"<b>Target:</b> {snapshot.target_domain}<br/>"
            f"<b>Base URL:</b> {snapshot.target_base_url}<br/>"
            f"<b>Scan ID:</b> {snapshot.scan_id}<br/>"
            f"<b>Status:</b> {snapshot.status}<br/>"
            f"<b>Scan Type:</b> {snapshot.scan_type}<br/>"
            f"<b>Started:</b> {_format_dt(snapshot.started_at)}<br/>"
            f"<b>Finished:</b> {_format_dt(snapshot.finished_at)}",
            styles["body"],
        )
    )

    counts = _severity_counts(snapshot.findings)
    story.append(Paragraph("Executive Summary", styles["section"]))
    story.append(
        _table(
            [
                [
                    "Pages Scanned",
                    "Findings",
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "Technologies",
                ],
                [
                    str(snapshot.total_pages_found),
                    str(snapshot.total_findings),
                    str(counts["critical"]),
                    str(counts["high"]),
                    str(counts["medium"]),
                    str(counts["low"]),
                    str(len(snapshot.technologies)),
                ],
            ]
        )
    )

    story.append(Paragraph("Findings", styles["section"]))
    if snapshot.findings:
        for finding in snapshot.findings:
            severity_color = _severity_color(finding.severity)
            story.append(
                Paragraph(
                    f"<font color='{severity_color}'><b>{finding.severity.upper()}</b></font> "
                    f"&nbsp; <b>{finding.title}</b> ({finding.category})",
                    styles["body"],
                )
            )
            story.append(
                Paragraph(
                    finding.description or "No description provided.", styles["body"]
                )
            )
            if finding.evidence:
                story.append(
                    Paragraph(f"<b>Evidence:</b> {finding.evidence}", styles["small"])
                )
            if finding.remediation:
                story.append(
                    Paragraph(
                        f"<b>Remediation:</b> {finding.remediation}",
                        styles["small"],
                    )
                )
            if finding.confidence:
                story.append(
                    Paragraph(f"<b>Confidence:</b> {finding.confidence}", styles["small"])
                )
            if finding.references:
                references = []
                for reference in finding.references:
                    ref_text = reference.ref_value
                    if reference.ref_url:
                        ref_text = f"{reference.ref_value} ({reference.ref_url})"
                    elif reference.source:
                        ref_text = f"{reference.ref_value} ({reference.source})"
                    references.append(ref_text)
                story.append(
                    Paragraph(
                        f"<b>References:</b> {'; '.join(references)}",
                        styles["small"],
                    )
                )
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No findings were recorded for this scan.", styles["body"]))

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
                [2.1 * inch, 1.1 * inch, 0.9 * inch, 1.4 * inch, 0.8 * inch],
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
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        total_pages_found=scan.total_pages_found or len(pages),
        total_findings=scan.total_findings or len(findings),
        findings=[
            ReportFinding(
                severity=finding.severity,
                category=finding.category,
                title=finding.title,
                description=finding.description,
                evidence=finding.evidence,
                remediation=finding.remediation,
                confidence=finding.confidence,
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
