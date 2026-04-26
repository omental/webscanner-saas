"""Routes for AI-generated scan reports (download, history, metadata)."""

import logging
import os
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, require_authenticated_user
from app.models.organization import Organization
from app.models.scan import Scan
from app.models.scan_report import ScanReport
from app.models.user import User
from app.services.scan_report_pdf_service import ReportMeta, build_ai_report_pdf
from app.services.scan_service import require_scan_access
from app.services.target_service import get_target_by_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan-reports", tags=["scan-reports"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[User, Depends(require_authenticated_user)]

# Directory where cached PDFs are stored
PDF_CACHE_DIR = Path(__file__).resolve().parents[3] / "data" / "report_pdfs"


async def _get_report_with_access(
    session: AsyncSession, report_id: int, actor: User
) -> ScanReport:
    """Load a ScanReport and enforce org-level permission."""
    result = await session.execute(
        select(ScanReport).where(ScanReport.id == report_id)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not found"
        )

    # Permission gate
    if actor.role == "super_admin":
        return report

    if report.organization_id != actor.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this report.",
        )

    return report


async def _build_meta(
    session: AsyncSession, report: ScanReport
) -> ReportMeta:
    """Build ReportMeta from a ScanReport and its related objects."""
    target_domain = "unknown"
    scan_result = await session.execute(
        select(Scan).where(Scan.id == report.scan_id)
    )
    scan = scan_result.scalar_one_or_none()
    if scan:
        target = await get_target_by_id(session, scan.target_id)
        if target:
            target_domain = target.normalized_domain

    org_name: str | None = None
    if report.organization_id:
        org_result = await session.execute(
            select(Organization).where(
                Organization.id == report.organization_id
            )
        )
        org = org_result.scalar_one_or_none()
        if org:
            org_name = org.name

    return ReportMeta(
        scan_id=report.scan_id,
        target_domain=target_domain,
        organization_name=org_name,
        generated_at=(
            report.created_at.strftime("%Y-%m-%d %H:%M UTC")
            if report.created_at
            else "N/A"
        ),
        model=report.model,
        provider=report.provider,
    )


def _ensure_pdf_cached(
    report: ScanReport, meta: ReportMeta
) -> str:
    """Generate the PDF, write it to disk, and return the file path.

    If the file already exists on disk, returns the existing path immediately.
    """
    # If pdf_path already set and file exists → return immediately
    if report.pdf_path and os.path.isfile(report.pdf_path):
        return report.pdf_path

    PDF_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"scan-{report.scan_id}-report-{report.id}.pdf"
    filepath = PDF_CACHE_DIR / filename

    # If file exists but pdf_path wasn't set (edge case after restart)
    if filepath.is_file():
        return str(filepath)

    # Generate fresh PDF
    pdf_bytes = build_ai_report_pdf(report.report_text, meta)
    filepath.write_bytes(pdf_bytes)
    return str(filepath)


# ── Download endpoint ────────────────────────────────────────────────


@router.get("/{report_id}/download")
async def download_scan_report_pdf(
    report_id: int, session: DbSession, current_user: CurrentUser
) -> FileResponse:
    """Download the AI scan report as a professional PDF."""

    report = await _get_report_with_access(session, report_id, current_user)
    meta = await _build_meta(session, report)

    try:
        pdf_path = _ensure_pdf_cached(report, meta)
    except Exception:
        logger.exception(
            "PDF generation failed  report_id=%s  user_id=%s",
            report_id,
            current_user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to generate PDF report.",
        )

    # Persist the cached path if not already saved
    if report.pdf_path != pdf_path:
        report.pdf_path = pdf_path
        session.add(report)
        await session.commit()
        logger.info(
            "PDF generated and cached  report_id=%s  scan_id=%s  path=%s",
            report_id,
            report.scan_id,
            pdf_path,
        )
    else:
        logger.info(
            "PDF served from cached file  report_id=%s  scan_id=%s  user_id=%s",
            report_id,
            report.scan_id,
            current_user.id,
        )

    filename = f"scan-{report.scan_id}-ai-report-{report.id}.pdf"
    return FileResponse(
        path=pdf_path,
        filename=filename,
        media_type="application/pdf",
    )


# ── Report metadata endpoint ────────────────────────────────────────


@router.get("/{report_id}")
async def get_scan_report_detail(
    report_id: int, session: DbSession, current_user: CurrentUser
) -> dict:
    """Return metadata and text of a single AI scan report."""

    report = await _get_report_with_access(session, report_id, current_user)

    return {
        "id": report.id,
        "scan_id": report.scan_id,
        "model": report.model,
        "provider": report.provider,
        "status": report.status,
        "report_text": report.report_text,
        "download_url": f"/api/v1/scan-reports/{report.id}/download",
        "has_pdf": bool(report.pdf_path and os.path.isfile(report.pdf_path)),
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }
