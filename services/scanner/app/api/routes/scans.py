import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_db_session,
    require_admin_or_super_admin,
    require_authenticated_user,
)
from app.core.config import get_settings
from app.models.detected_technology import DetectedTechnology
from app.models.finding import Finding
from app.models.finding_reference import FindingReference
from app.models.scan import Scan
from app.models.scan_page import ScanPage
from app.models.target import Target
from app.models.user import User
from app.schemas.detected_technology import DetectedTechnologyRead
from app.schemas.finding import FindingRead
from app.schemas.finding_reference import FindingReferenceRead
from app.schemas.scan import (
    ScanComparisonRead,
    ScanCreate,
    ScanDetailRead,
    ScanRead,
)
from app.schemas.scan_page import ScanPageRead
from app.schemas.target import TargetRead
from app.services.comparison_service import (
    compare_scan_findings,
    get_comparison_summary,
)
from app.services.llm.factory import get_llm_provider
from app.services.report_sanitizer import build_sanitized_scan_report_data
from app.services.report_service import get_scan_report_pdf
from app.services.scan_runner_service import run_scan
from app.services.scan_service import (
    cancel_scan_for_actor,
    create_scan_for_actor,
    list_detected_technologies,
    list_findings,
    list_scan_pages,
    list_scans_for_actor,
    require_scan_access,
)
from app.services.target_service import get_target_by_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[User, Depends(require_authenticated_user)]
AdminUser = Annotated[User, Depends(require_admin_or_super_admin)]


def _serialize_scan(
    scan: Scan, comparison_summary: dict[str, int] | None = None
) -> ScanRead:
    return ScanRead.model_validate(
        {
            "id": scan.id,
            "user_id": scan.user_id,
            "organization_id": scan.organization_id,
            "target_id": scan.target_id,
            "scan_type": scan.scan_type,
            "scan_profile": scan.scan_profile or "standard",
            "status": scan.status,
            "total_pages_found": scan.total_pages_found or 0,
            "total_findings": scan.total_findings or 0,
            "risk_score": scan.risk_score,
            "max_depth": scan.max_depth,
            "max_pages": scan.max_pages,
            "timeout_seconds": scan.timeout_seconds,
            "previous_scan_id": scan.previous_scan_id,
            "comparison_summary": comparison_summary,
            "error_message": scan.error_message,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "created_at": scan.created_at,
            "updated_at": scan.updated_at,
        }
    )


def _serialize_target(target: Target | None) -> TargetRead | None:
    if target is None:
        return None
    return TargetRead.model_validate(
        {
            "id": target.id,
            "user_id": target.user_id,
            "organization_id": target.organization_id,
            "base_url": target.base_url,
            "normalized_domain": target.normalized_domain,
            "created_at": target.created_at,
            "updated_at": target.updated_at,
        }
    )


def _serialize_scan_page(page: ScanPage) -> ScanPageRead:
    return ScanPageRead.model_validate(
        {
            "id": page.id,
            "scan_id": page.scan_id,
            "url": page.url,
            "method": page.method,
            "status_code": page.status_code,
            "content_type": page.content_type,
            "response_time_ms": page.response_time_ms,
            "page_title": page.page_title,
            "discovered_from": page.discovered_from,
            "depth": page.depth,
            "created_at": page.created_at,
        }
    )


def _serialize_finding(finding: Finding) -> FindingRead:
    return FindingRead.model_validate(
        {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "scan_page_id": finding.scan_page_id,
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "confidence_level": finding.confidence_level,
            "confidence_score": finding.confidence_score,
            "evidence_type": finding.evidence_type,
            "verification_steps": finding.verification_steps,
            "payload_used": finding.payload_used,
            "affected_parameter": finding.affected_parameter,
            "response_snippet": finding.response_snippet,
            "false_positive_notes": finding.false_positive_notes,
            "request_url": finding.request_url,
            "http_method": finding.http_method,
            "tested_parameter": finding.tested_parameter,
            "payload": finding.payload,
            "baseline_status_code": finding.baseline_status_code,
            "attack_status_code": finding.attack_status_code,
            "baseline_response_size": finding.baseline_response_size,
            "attack_response_size": finding.attack_response_size,
            "baseline_response_time_ms": finding.baseline_response_time_ms,
            "attack_response_time_ms": finding.attack_response_time_ms,
            "response_diff_summary": finding.response_diff_summary,
            "deduplication_key": finding.deduplication_key,
            "comparison_status": finding.comparison_status,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "is_confirmed": finding.is_confirmed,
            "references": [
                _serialize_finding_reference(reference)
                for reference in finding.references or []
            ],
            "created_at": finding.created_at,
            "updated_at": finding.updated_at,
        }
    )


def _serialize_scan_comparison(comparison) -> ScanComparisonRead:
    return ScanComparisonRead.model_validate(
        {
            "previous_scan_id": comparison.previous_scan_id,
            "current_scan_id": comparison.current_scan_id,
            "fixed_findings": [
                _serialize_finding(finding)
                for finding in comparison.fixed_findings
            ],
            "still_vulnerable_findings": [
                _serialize_finding(finding)
                for finding in comparison.still_vulnerable_findings
            ],
            "new_findings": [
                _serialize_finding(finding)
                for finding in comparison.new_findings
            ],
            "existing_findings": [
                _serialize_finding(finding)
                for finding in comparison.existing_findings
            ],
            "not_retested_findings": [
                _serialize_finding(finding)
                for finding in comparison.not_retested_findings
            ],
            "summary": comparison.summary,
        }
    )


def _serialize_finding_reference(reference: FindingReference) -> FindingReferenceRead:
    return FindingReferenceRead.model_validate(
        {
            "id": reference.id,
            "finding_id": reference.finding_id,
            "ref_type": reference.ref_type,
            "ref_value": reference.ref_value,
            "ref_url": reference.ref_url,
            "source": reference.source,
            "created_at": reference.created_at,
        }
    )


def _serialize_detected_technology(
    technology: DetectedTechnology,
) -> DetectedTechnologyRead:
    return DetectedTechnologyRead.model_validate(
        {
            "id": technology.id,
            "scan_id": technology.scan_id,
            "scan_page_id": technology.scan_page_id,
            "product_name": technology.product_name,
            "category": technology.category,
            "version": technology.version,
            "vendor": technology.vendor,
            "confidence_score": technology.confidence_score,
            "detection_method": technology.detection_method,
            "created_at": technology.created_at,
        }
    )


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan_endpoint(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    session: DbSession,
    admin: AdminUser,
) -> ScanRead:
    scan = await create_scan_for_actor(session, payload, admin)
    background_tasks.add_task(run_scan, scan.id)
    return _serialize_scan(scan)


@router.get("", response_model=list[ScanRead])
async def list_scans_endpoint(
    session: DbSession, current_user: CurrentUser
) -> list[ScanRead]:
    scans = await list_scans_for_actor(session, current_user)
    scan_reads: list[ScanRead] = []
    for scan in scans:
        comparison_summary = await get_comparison_summary(session, scan)
        scan_reads.append(_serialize_scan(scan, comparison_summary))
    return scan_reads


@router.get("/{scan_id}", response_model=ScanDetailRead)
async def get_scan_detail_endpoint(
    scan_id: int, session: DbSession, current_user: CurrentUser
) -> ScanDetailRead:
    scan = await require_scan_access(session, scan_id, current_user)
    target = await get_target_by_id(session, scan.target_id)
    pages = await list_scan_pages(session, scan_id)
    findings = await list_findings(session, scan_id)
    technologies = await list_detected_technologies(session, scan_id)
    comparison_summary = await get_comparison_summary(session, scan)
    scan_read = _serialize_scan(scan, comparison_summary).model_dump()
    return ScanDetailRead.model_validate(
        {
            **scan_read,
            "target": _serialize_target(target),
            "completed_at": scan.finished_at,
            "pages": [_serialize_scan_page(page) for page in pages],
            "findings": [_serialize_finding(finding) for finding in findings],
            "technologies": [
                _serialize_detected_technology(technology)
                for technology in technologies
            ],
        }
    )


@router.post(
    "/{scan_id}/retest",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
)
async def retest_scan_endpoint(
    scan_id: int,
    background_tasks: BackgroundTasks,
    session: DbSession,
    admin: AdminUser,
) -> ScanRead:
    previous_scan = await require_scan_access(session, scan_id, admin)
    payload = ScanCreate(
        user_id=previous_scan.user_id,
        target_id=previous_scan.target_id,
        scan_type=previous_scan.scan_type,
        scan_profile=previous_scan.scan_profile or "standard",
        max_depth=previous_scan.max_depth,
        max_pages=previous_scan.max_pages,
        timeout_seconds=previous_scan.timeout_seconds,
        previous_scan_id=previous_scan.id,
    )
    scan = await create_scan_for_actor(session, payload, admin)
    background_tasks.add_task(run_scan, scan.id)
    return _serialize_scan(scan)


@router.get("/{scan_id}/compare", response_model=ScanComparisonRead)
async def compare_scan_endpoint(
    scan_id: int, session: DbSession, current_user: CurrentUser
) -> ScanComparisonRead:
    scan = await require_scan_access(session, scan_id, current_user)
    comparison = await compare_scan_findings(session, scan, persist=True)
    return _serialize_scan_comparison(comparison)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
async def cancel_scan_endpoint(
    scan_id: int, session: DbSession, admin: AdminUser
) -> ScanRead:
    scan = await cancel_scan_for_actor(session, scan_id, admin)
    return _serialize_scan(scan)


@router.get("/{scan_id}/pages", response_model=list[ScanPageRead])
async def list_scan_pages_endpoint(
    scan_id: int, session: DbSession, current_user: CurrentUser
) -> list[ScanPageRead]:
    await require_scan_access(session, scan_id, current_user)
    pages = await list_scan_pages(session, scan_id)
    return [_serialize_scan_page(page) for page in pages]


@router.get("/{scan_id}/findings", response_model=list[FindingRead])
async def list_findings_endpoint(
    scan_id: int, session: DbSession, current_user: CurrentUser
) -> list[FindingRead]:
    await require_scan_access(session, scan_id, current_user)
    findings = await list_findings(session, scan_id)
    return [_serialize_finding(finding) for finding in findings]


@router.get("/{scan_id}/technologies", response_model=list[DetectedTechnologyRead])
async def list_technologies_endpoint(
    scan_id: int, session: DbSession, current_user: CurrentUser
) -> list[DetectedTechnologyRead]:
    await require_scan_access(session, scan_id, current_user)
    technologies = await list_detected_technologies(session, scan_id)
    return [
        _serialize_detected_technology(technology)
        for technology in technologies
    ]


@router.get("/{scan_id}/report.pdf")
async def download_scan_report_endpoint(
    scan_id: int, session: DbSession, current_user: CurrentUser
) -> Response:
    await require_scan_access(session, scan_id, current_user)
    pdf_bytes = await get_scan_report_pdf(session, scan_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan_id}-report.pdf"'
        },
    )


@router.post("/{scan_id}/ai-report")
async def generate_ai_report_endpoint(
    scan_id: int, session: DbSession, current_user: CurrentUser
) -> dict:
    """Generate an AI-powered vulnerability report for a completed scan."""

    # --- auth / permission (same gate as every other scan sub-route) ---
    scan = await require_scan_access(session, scan_id, current_user)

    # --- load related data ---
    target = await get_target_by_id(session, scan.target_id)
    findings = await list_findings(session, scan_id)
    pages = await list_scan_pages(session, scan_id)
    technologies = await list_detected_technologies(session, scan_id)

    # --- sanitize for LLM consumption ---
    sanitized_data = build_sanitized_scan_report_data(
        scan=scan,
        target=target,
        findings=findings,
        pages=pages,
        technologies=technologies,
    )

    # --- call LLM ---
    try:
        provider = get_llm_provider()
    except RuntimeError:
        logger.warning(
            "AI report generation not configured  scan_id=%s  user_id=%s",
            scan_id,
            current_user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI report generation is not configured.",
        )

    try:
        report_text = await provider.generate_report(sanitized_data)
    except Exception:
        logger.exception(
            "AI report generation failed  scan_id=%s  user_id=%s",
            scan_id,
            current_user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate AI report.",
        )

    settings = get_settings()

    # --- persist report ---
    from app.models.scan_report import ScanReport

    scan_report = ScanReport(
        scan_id=scan.id,
        organization_id=scan.organization_id or current_user.organization_id,
        generated_by_user_id=current_user.id,
        provider="openrouter",
        model=settings.openrouter_model,
        report_text=report_text,
        status="completed",
    )
    session.add(scan_report)
    await session.commit()
    await session.refresh(scan_report)

    # --- eagerly generate and cache PDF ---
    try:
        from app.api.routes.scan_reports import _build_meta, _ensure_pdf_cached

        meta = await _build_meta(session, scan_report)
        pdf_path = _ensure_pdf_cached(scan_report, meta)
        scan_report.pdf_path = pdf_path
        session.add(scan_report)
        await session.commit()
        logger.info(
            "PDF pre-generated  report_id=%s  scan_id=%s",
            scan_report.id,
            scan.id,
        )
    except Exception:
        logger.warning(
            "PDF pre-generation failed (non-fatal)  report_id=%s  scan_id=%s",
            scan_report.id,
            scan.id,
            exc_info=True,
        )

    logger.info(
        "AI report generated  scan_id=%s  user_id=%s  report_id=%s  chars=%d",
        scan_id,
        current_user.id,
        scan_report.id,
        len(report_text),
    )

    return {
        "report_id": scan_report.id,
        "scan_id": scan.id,
        "model": settings.openrouter_model,
        "report_text": report_text,
        "download_url": f"/api/v1/scan-reports/{scan_report.id}/download",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{scan_id}/reports")
async def list_scan_reports_endpoint(
    scan_id: int, session: DbSession, current_user: CurrentUser
) -> list[dict]:
    """List previously generated AI reports for a scan."""
    import os

    from sqlalchemy import select as sa_select

    from app.models.scan_report import ScanReport

    # Permission gate — reuse existing scan access check
    await require_scan_access(session, scan_id, current_user)

    result = await session.execute(
        sa_select(ScanReport)
        .where(ScanReport.scan_id == scan_id)
        .order_by(ScanReport.created_at.desc())
    )
    reports = result.scalars().all()

    return [
        {
            "id": r.id,
            "scan_id": r.scan_id,
            "model": r.model,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "download_url": f"/api/v1/scan-reports/{r.id}/download",
            "has_pdf": bool(r.pdf_path and os.path.isfile(r.pdf_path)),
        }
        for r in reports
    ]
