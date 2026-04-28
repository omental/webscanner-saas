from __future__ import annotations

import re
import unicodedata
from html import escape
from typing import Any

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Table, TableStyle


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"[ \t\r\f\v]+")
_PIPE_TABLE_SEPARATOR = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
_ASCII_FALLBACKS = {
    "\u00b0": " deg ",
    "\u00b1": "+/-",
    "\u00d7": "x",
    "\u00f7": "/",
    "\u2264": "<=",
    "\u2265": ">=",
    "\u2260": "!=",
    "\u2248": "~=",
}


def sanitize_pdf_text(value: Any) -> str:
    """Return text that is safe to feed into ReportLab's base PDF fonts."""
    if value is None:
        return ""

    text = str(value)
    replacements = {
        "\u00a0": " ",
        "\u00ad": "",
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2015": "-",
        "\u2212": "-",
        "\u2043": "-",
        "\u2022": "-",
        "\u2023": "-",
        "\u25e6": "-",
        "\u2219": "-",
        "\u25aa": "-",
        "\u25ab": "-",
        "\u25cf": "-",
        "\u25cb": "-",
        "\u25a0": "-",
        "\u25a1": "-",
        "\u25fd": "-",
        "\u25fe": "-",
        "\ufffd": "",
        "\u2192": "->",
        "\u21d2": "=>",
        "\u2190": "<-",
        "\u21d0": "<=",
        "\u2194": "<->",
        "\u21d4": "<=>",
        "\u2713": "yes",
        "\u2714": "yes",
        "\u2717": "no",
        "\u2718": "no",
        "\u2018": "'",
        "\u2019": "'",
        "\u201a": "'",
        "\u201b": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u201e": '"',
        "\u2026": "...",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    for source, target in _ASCII_FALLBACKS.items():
        text = text.replace(source, target)

    text = unicodedata.normalize("NFKC", text)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = "".join(ch if ch == "\n" or ord(ch) < 128 else " " for ch in text)
    text = "".join(ch if ch == "\n" or ord(ch) >= 32 else " " for ch in text)
    text = _CONTROL_CHARS.sub(" ", text)
    text = "\n".join(_WHITESPACE.sub(" ", line).strip() for line in text.splitlines())
    return text.strip()


def pdf_escape(value: Any) -> str:
    return escape(sanitize_pdf_text(value), quote=False)


def paragraph_cell(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(pdf_escape(value), style)


def build_pdf_table(
    data: list[list[Any]],
    styles: dict[str, ParagraphStyle],
    col_widths: list[float] | None = None,
    *,
    header_background=colors.HexColor("#e2e8f0"),
    header_text=colors.HexColor("#0f172a"),
    grid_color=colors.HexColor("#cbd5e1"),
) -> Table:
    table_data: list[list[Any]] = []
    for row in data:
        cell_style = styles["table_header" if not table_data else "table_cell"]
        table_data.append([paragraph_cell(cell, cell_style) for cell in row])

    table = Table(table_data, colWidths=col_widths, repeatRows=1, splitByRow=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), header_background),
                ("TEXTCOLOR", (0, 0), (-1, 0), header_text),
                ("GRID", (0, 0), (-1, -1), 0.35, grid_color),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f8fafc")],
                ),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def is_markdown_table_block(lines: list[str]) -> bool:
    if len(lines) < 2:
        return False
    first = sanitize_pdf_text(lines[0])
    second = sanitize_pdf_text(lines[1])
    return "|" in first and _PIPE_TABLE_SEPARATOR.match(second) is not None


def _split_markdown_table_row(line: str) -> list[str]:
    line = sanitize_pdf_text(line).strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [cell.strip() for cell in line.split("|")]


def parse_markdown_table(lines: list[str]) -> list[list[str]] | None:
    if not is_markdown_table_block(lines):
        return None

    rows: list[list[str]] = []
    expected_width: int | None = None
    for index, line in enumerate(lines):
        if index == 1:
            continue
        if "|" not in line:
            break
        row = _split_markdown_table_row(line)
        if not any(row):
            continue
        if expected_width is None:
            expected_width = len(row)
        if len(row) != expected_width:
            return None
        rows.append(row)

    if len(rows) < 2:
        return None
    return rows


def markdown_table_to_pdf_table(
    lines: list[str],
    styles: dict[str, ParagraphStyle],
    usable_width: float,
) -> Table | None:
    rows = parse_markdown_table(lines)
    if not rows:
        return None

    column_count = len(rows[0])
    if column_count <= 0:
        return None

    if column_count == 2:
        col_widths = [usable_width * 0.35, usable_width * 0.65]
    elif column_count == 3:
        col_widths = [usable_width * 0.32, usable_width * 0.28, usable_width * 0.40]
    elif column_count == 4:
        col_widths = [0.35 * inch, usable_width * 0.52, usable_width * 0.22, usable_width * 0.18]
    else:
        col_widths = [usable_width / column_count] * column_count

    total_width = sum(col_widths)
    if total_width > usable_width:
        scale = usable_width / total_width
        col_widths = [width * scale for width in col_widths]

    return build_pdf_table(rows, styles, col_widths)


def strip_markdown_table_pipes(lines: list[str]) -> str:
    parsed = parse_markdown_table(lines)
    if not parsed:
        return " ".join(
            sanitize_pdf_text(line).replace("|", " ").strip()
            for line in lines
            if line.strip()
        )
    return "; ".join(" - ".join(cell for cell in row if cell) for row in parsed)
