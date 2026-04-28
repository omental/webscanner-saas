"""Generate a professional pentest-style PDF from AI report Markdown text.

Uses ReportLab (already in requirements.txt).  The PDF is built entirely
from the saved ``report_text`` — no LLM call is made during PDF generation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    Flowable,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    Frame,
)

from app.services.pdf_rendering import (
    markdown_table_to_pdf_table,
    sanitize_pdf_text,
    strip_markdown_table_pipes,
)

PAGE_W, PAGE_H = A4

# ── Colour palette ────────────────────────────────────────────────────
NAVY = colors.HexColor("#0f172a")
DARK_SLATE = colors.HexColor("#1e293b")
CYAN_ACCENT = colors.HexColor("#06b6d4")
CYAN_LIGHT = colors.HexColor("#67e8f9")
SLATE_300 = colors.HexColor("#cbd5e1")
SLATE_500 = colors.HexColor("#64748b")
WHITE = colors.white


# ── Data container ────────────────────────────────────────────────────
@dataclass
class ReportMeta:
    scan_id: int
    target_domain: str
    organization_name: str | None
    generated_at: str
    model: str
    provider: str


# ── Custom flowables ──────────────────────────────────────────────────
class AccentLine(Flowable):
    """Thin cyan horizontal line used as a visual divider."""

    def __init__(self, width: float, thickness: float = 1.5) -> None:
        super().__init__()
        self.width = width
        self.height = thickness

    def draw(self) -> None:
        self.canv.setStrokeColor(CYAN_ACCENT)
        self.canv.setLineWidth(self.height)
        self.canv.line(0, 0, self.width, 0)


# ── Style factory ────────────────────────────────────────────────────
def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=WHITE,
            alignment=TA_CENTER,
            spaceAfter=12,
        ),
        "cover_sub": ParagraphStyle(
            "CoverSub",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=13,
            leading=18,
            textColor=CYAN_LIGHT,
            alignment=TA_CENTER,
            spaceAfter=6,
        ),
        "h1": ParagraphStyle(
            "RH1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=NAVY,
            spaceBefore=18,
            spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "RH2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=NAVY,
            spaceBefore=14,
            spaceAfter=8,
        ),
        "h3": ParagraphStyle(
            "RH3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=DARK_SLATE,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "h4": ParagraphStyle(
            "RH4",
            parent=base["Heading4"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=DARK_SLATE,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "RBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=DARK_SLATE,
            spaceAfter=6,
        ),
        "bullet": ParagraphStyle(
            "RBullet",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=DARK_SLATE,
            leftIndent=18,
            bulletIndent=8,
            spaceAfter=4,
        ),
        "disclaimer": ParagraphStyle(
            "RDisclaimer",
            parent=base["BodyText"],
            fontName="Helvetica-Oblique",
            fontSize=9,
            leading=13,
            textColor=SLATE_500,
            spaceAfter=6,
            spaceBefore=12,
        ),
        "footer": ParagraphStyle(
            "RFooter",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=SLATE_500,
            alignment=TA_RIGHT,
        ),
        "table_header": ParagraphStyle(
            "RTableHeader",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=NAVY,
        ),
        "table_cell": ParagraphStyle(
            "RTableCell",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.3,
            leading=10.5,
            textColor=DARK_SLATE,
        ),
    }


# ── Page chrome ──────────────────────────────────────────────────────
def _draw_content_page(canvas, doc) -> None:
    """Header line + footer on every content page."""
    canvas.saveState()

    # Top accent line
    canvas.setStrokeColor(CYAN_ACCENT)
    canvas.setLineWidth(2)
    canvas.line(
        doc.leftMargin,
        PAGE_H - 30,
        PAGE_W - doc.rightMargin,
        PAGE_H - 30,
    )

    # Header text
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(SLATE_500)
    canvas.drawString(doc.leftMargin, PAGE_H - 26, "AI Vulnerability Scan Report")

    # Footer
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(SLATE_500)
    canvas.drawString(doc.leftMargin, 22, "Web Vulnerability Scanner")
    canvas.drawRightString(PAGE_W - doc.rightMargin, 22, f"Page {doc.page}")

    canvas.restoreState()


def _draw_cover_page(canvas, doc) -> None:
    """Full navy background for the cover page."""
    canvas.saveState()

    # Full-page navy background
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=True, stroke=False)

    # Accent line near top
    canvas.setStrokeColor(CYAN_ACCENT)
    canvas.setLineWidth(3)
    y_line = PAGE_H - 60
    canvas.line(60, y_line, PAGE_W - 60, y_line)

    # Accent line near bottom
    y_bot = 80
    canvas.setStrokeColor(CYAN_ACCENT)
    canvas.setLineWidth(1.5)
    canvas.line(60, y_bot, PAGE_W - 60, y_bot)

    canvas.restoreState()


# ── HTML safety for ReportLab ─────────────────────────────────────────
from html import escape as _html_escape

# Matches raw HTML tags that ReportLab cannot parse
_RAW_HTML_TAG = re.compile(r"<(?!/?(?:b|i|u|a|font|br|para|super|sub)\b)[^>]+>", re.IGNORECASE)


def _escape_html(text: str) -> str:
    """Escape raw HTML so ReportLab does not try to parse unsupported tags.

    ReportLab's Paragraph supports a small subset of XML-like tags
    (b, i, u, a, font, br, para, super, sub).  Everything else — especially
    raw HTML from AI output like ``<link rel="canonical" …>`` or
    ``<script>…</script>`` — must be entity-escaped so it renders as
    visible text instead of crashing the parser.
    """
    if not text:
        return ""
    text = sanitize_pdf_text(text)
    # First: escape ALL HTML entities (< > & ")
    text = _html_escape(text, quote=False)
    return text


def _safe_para(text: str, style: ParagraphStyle) -> Paragraph:
    """Create a Paragraph with a fallback if the text still causes errors."""
    try:
        return Paragraph(text, style)
    except Exception:
        # Nuclear fallback: fully escape everything
        return Paragraph(_html_escape(text, quote=False), style)


# ── Markdown → flowables ─────────────────────────────────────────────
_INLINE_BOLD = re.compile(r"\*\*(.+?)\*\*")
_INLINE_CODE = re.compile(r"`(.+?)`")
_INLINE_LINK = re.compile(r"\[(.+?)\]\((.+?)\)")

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "informational": "#64748b",
}


def _md_inline(text: str) -> str:
    """Convert inline Markdown to ReportLab XML-like markup.

    **Important**: raw HTML is escaped FIRST so that tags like
    ``<link rel=…>`` become visible text instead of crashing ReportLab.
    Markdown links ``[text](url)`` are converted to plain ``text (url)``
    to avoid generating ReportLab ``<a>`` tags with potentially unsafe
    URL content.
    """
    text = sanitize_pdf_text(text)

    # Step 1: convert markdown links to plain text BEFORE escaping
    text = _INLINE_LINK.sub(r"\1 (\2)", text)

    # Step 2: extract bold and code segments, escape everything else
    # We process bold/code markers before escaping so ** and ` are
    # recognised, but their CONTENT is escaped.
    segments: list[str] = []
    last = 0
    combined = re.compile(r"\*\*(.+?)\*\*|`(.+?)`")
    for m in combined.finditer(text):
        # Escape the text before this match
        segments.append(_escape_html(text[last:m.start()]))
        if m.group(1) is not None:
            # Bold
            segments.append(f"<b>{_escape_html(m.group(1))}</b>")
        elif m.group(2) is not None:
            # Inline code
            segments.append(
                f'<font face="Courier" size="9" color="#0f172a">'
                f"{_escape_html(m.group(2))}</font>"
            )
        last = m.end()
    segments.append(_escape_html(text[last:]))
    text = "".join(segments)

    # Step 3: severity badges (safe — we control these strings)
    for sev, col in _SEVERITY_COLORS.items():
        pattern = re.compile(rf"\b({sev})\b", re.IGNORECASE)
        text = pattern.sub(rf'<font color="{col}"><b>\1</b></font>', text)

    return text


def _md_to_flowables(
    markdown_text: str, styles: dict[str, ParagraphStyle], usable_width: float
) -> list:
    """Parse Markdown text into a list of ReportLab flowables."""
    flowables: list = []
    lines = sanitize_pdf_text(markdown_text).split("\n")
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        # Blank line
        if not stripped:
            flowables.append(Spacer(1, 4))
            index += 1
            continue

        if "|" in stripped and index + 1 < len(lines):
            table_lines = [line]
            cursor = index + 1
            while cursor < len(lines) and "|" in lines[cursor].strip():
                table_lines.append(lines[cursor])
                cursor += 1

            table = markdown_table_to_pdf_table(table_lines, styles, usable_width)
            if table is not None:
                flowables.append(table)
                flowables.append(Spacer(1, 8))
                index = cursor
                continue

            fallback_text = strip_markdown_table_pipes(table_lines)
            if fallback_text:
                flowables.append(_safe_para(_md_inline(fallback_text), styles["body"]))
                index = cursor
                continue

        # Horizontal rule
        if re.match(r"^[-*_]{3,}\s*$", stripped):
            flowables.append(Spacer(1, 4))
            flowables.append(AccentLine(usable_width))
            flowables.append(Spacer(1, 4))
            index += 1
            continue

        # Headings
        if stripped.startswith("#### "):
            flowables.append(
                _safe_para(_md_inline(stripped[5:]), styles["h4"])
            )
            index += 1
            continue
        if stripped.startswith("### "):
            flowables.append(
                _safe_para(_md_inline(stripped[4:]), styles["h3"])
            )
            index += 1
            continue
        if stripped.startswith("## "):
            flowables.append(Spacer(1, 6))
            flowables.append(AccentLine(usable_width * 0.4))
            flowables.append(
                _safe_para(_md_inline(stripped[3:]), styles["h2"])
            )
            index += 1
            continue
        if stripped.startswith("# "):
            flowables.append(Spacer(1, 8))
            flowables.append(AccentLine(usable_width * 0.5))
            flowables.append(
                _safe_para(_md_inline(stripped[2:]), styles["h1"])
            )
            index += 1
            continue

        # Bullet list
        bullet_match = re.match(r"^\s*[-*+]\s(.+)$", stripped)
        if bullet_match:
            flowables.append(
                _safe_para(
                    f"- {_md_inline(bullet_match.group(1))}",
                    styles["bullet"],
                )
            )
            index += 1
            continue

        # Numbered list
        num_match = re.compile(r"^\s*\d+[.)]\s(.+)$").match(stripped)
        if num_match:
            flowables.append(
                _safe_para(
                    f"- {_md_inline(num_match.group(1))}",
                    styles["bullet"],
                )
            )
            index += 1
            continue

        # Default paragraph
        flowables.append(_safe_para(_md_inline(stripped), styles["body"]))
        index += 1

    return flowables



# ── Cover page story ─────────────────────────────────────────────────
def _build_cover(meta: ReportMeta, styles: dict[str, ParagraphStyle]) -> list:
    story: list = []
    story.append(Spacer(1, 100))
    story.append(Paragraph("Web Vulnerability", styles["cover_title"]))
    story.append(Paragraph("Assessment Report", styles["cover_title"]))
    story.append(Spacer(1, 20))
    story.append(AccentLine(300))
    story.append(Spacer(1, 20))
    story.append(
        Paragraph(
            f"Target: {_escape_html(sanitize_pdf_text(meta.target_domain))}",
            styles["cover_sub"],
        )
    )
    story.append(
        Paragraph(
            f"Scan ID: {_escape_html(sanitize_pdf_text(meta.scan_id))}",
            styles["cover_sub"],
        )
    )
    if meta.organization_name:
        story.append(
            Paragraph(
                f"Organization: {_escape_html(sanitize_pdf_text(meta.organization_name))}",
                styles["cover_sub"],
            )
        )
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            f"Generated: {_escape_html(sanitize_pdf_text(meta.generated_at))}",
            styles["cover_sub"],
        )
    )

    story.append(Spacer(1, 140))
    story.append(
        Paragraph(
            "CONFIDENTIAL",
            ParagraphStyle(
                "CoverConf",
                fontName="Helvetica-Bold",
                fontSize=11,
                textColor=CYAN_LIGHT,
                alignment=TA_CENTER,
            ),
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            "For authorised recipients only. Do not distribute.",
            ParagraphStyle(
                "CoverConfSub",
                fontName="Helvetica-Oblique",
                fontSize=9,
                textColor=SLATE_500,
                alignment=TA_CENTER,
            ),
        )
    )
    return story


# ── Risk Rating Guide table ──────────────────────────────────────────
def _build_risk_table(styles: dict[str, ParagraphStyle], usable_width: float) -> list:
    story: list = []
    story.append(Paragraph("Risk Rating Guide", styles["h2"]))
    story.append(Spacer(1, 6))

    sev_data = [
        ["Rating", "Description"],
        [
            Paragraph('<font color="#dc2626"><b>Critical</b></font>', styles["body"]),
            Paragraph("Immediate exploitation risk. Requires urgent remediation.", styles["body"]),
        ],
        [
            Paragraph('<font color="#ea580c"><b>High</b></font>', styles["body"]),
            Paragraph("Serious weakness that could lead to significant compromise. Fix as priority.", styles["body"]),
        ],
        [
            Paragraph('<font color="#d97706"><b>Medium</b></font>', styles["body"]),
            Paragraph("Important weakness that should be addressed in the near term.", styles["body"]),
        ],
        [
            Paragraph('<font color="#2563eb"><b>Low</b></font>', styles["body"]),
            Paragraph("Minor weakness. Improve hardening when resources allow.", styles["body"]),
        ],
        [
            Paragraph('<font color="#64748b"><b>Informational</b></font>', styles["body"]),
            Paragraph("Best-practice observation or visibility issue. No direct risk.", styles["body"]),
        ],
    ]

    col_widths = [usable_width * 0.2, usable_width * 0.8]
    tbl = Table(sev_data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), WHITE]),
        ("GRID", (0, 0), (-1, -1), 0.5, SLATE_300),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
    ]))
    story.append(tbl)
    return story


# ── Disclaimer + Remediation Roadmap ─────────────────────────────────
def _build_closing(styles: dict[str, ParagraphStyle], usable_width: float) -> list:
    story: list = []
    story.append(Spacer(1, 20))
    story.append(AccentLine(usable_width))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Remediation Roadmap", styles["h2"]))

    roadmap = [
        "Address all <b>Critical</b> and <b>High</b> severity findings immediately.",
        "Apply missing security headers across all endpoints.",
        "Validate and sanitise all user inputs to prevent injection attacks.",
        "Review authentication and session management controls.",
        "Re-run the vulnerability scan after applying fixes to confirm remediation.",
    ]
    for i, item in enumerate(roadmap, 1):
        story.append(Paragraph(f"{i}. {item}", styles["bullet"]))

    story.append(Spacer(1, 16))
    story.append(AccentLine(usable_width * 0.6))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Disclaimer", styles["h3"]))
    story.append(
        Paragraph(
            "This report was generated from automated scan results and "
            "AI-assisted analysis. It should be reviewed by a qualified "
            "security professional before being used as the sole basis "
            "for risk decisions.",
            styles["disclaimer"],
        )
    )
    story.append(
        Paragraph(
            "Recommended next step: Re-run the scan after remediation "
            "to confirm that all identified vulnerabilities have been "
            "successfully addressed.",
            styles["disclaimer"],
        )
    )
    return story


# ── Public API ───────────────────────────────────────────────────────
def build_ai_report_pdf(report_text: str, meta: ReportMeta) -> bytes:
    """Render *report_text* (Markdown) into a professional PDF.

    This function **never** calls an LLM.  It only formats the already-
    generated text.
    """
    buffer = BytesIO()
    styles = _styles()

    left_margin = 0.7 * inch
    right_margin = 0.7 * inch
    top_margin = 0.85 * inch
    bottom_margin = 0.6 * inch
    usable_width = PAGE_W - left_margin - right_margin

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=left_margin,
        rightMargin=right_margin,
        topMargin=top_margin,
        bottomMargin=bottom_margin,
        title=f"Scan {meta.scan_id} — Vulnerability Assessment Report",
    )

    # Two page templates: cover (navy bg) and content (white bg)
    cover_frame = Frame(
        left_margin, bottom_margin,
        usable_width, PAGE_H - top_margin - bottom_margin,
        id="cover_frame",
    )
    content_frame = Frame(
        left_margin, bottom_margin,
        usable_width, PAGE_H - top_margin - bottom_margin,
        id="content_frame",
    )
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=_draw_cover_page),
        PageTemplate(id="content", frames=[content_frame], onPage=_draw_content_page),
    ])

    story: list = []

    # ── Cover page ────────────────────────────────────────────────
    story.extend(_build_cover(meta, styles))
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    # ── Risk Rating Guide ─────────────────────────────────────────
    story.extend(_build_risk_table(styles, usable_width))
    story.append(PageBreak())

    # ── Body: parsed Markdown (findings, exec summary, etc.) ──────
    story.extend(_md_to_flowables(report_text, styles, usable_width))

    # ── Closing: roadmap + disclaimer ─────────────────────────────
    story.extend(_build_closing(styles, usable_width))

    doc.build(story)
    return buffer.getvalue()
