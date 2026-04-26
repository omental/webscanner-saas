from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding

SITE_WIDE_FINDING_TITLES = {
    "Missing Content-Security-Policy",
    "Missing X-Frame-Options",
    "Missing X-Content-Type-Options",
    "Missing Referrer-Policy",
    "Missing Strict-Transport-Security",
    "Exposed server banner",
}


def _effective_scan_page_id(issue: object, scan_page_id: int | None) -> int | None:
    if getattr(issue, "title", None) in SITE_WIDE_FINDING_TITLES:
        return None
    return scan_page_id


async def create_findings_if_missing(
    session: AsyncSession,
    *,
    scan_id: int,
    scan_page_id: int | None,
    issues: list[object],
) -> int:
    created_count = 0

    for issue in issues:
        effective_scan_page_id = _effective_scan_page_id(issue, scan_page_id)
        query: Select[tuple[Finding]] = select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.scan_page_id == effective_scan_page_id,
            Finding.category == issue.category,
            Finding.title == issue.title,
            Finding.evidence == issue.evidence,
        )
        existing = await session.execute(query)
        if existing.scalar_one_or_none() is not None:
            continue

        finding = Finding(
            scan_id=scan_id,
            scan_page_id=effective_scan_page_id,
            category=issue.category,
            title=issue.title,
            description=issue.description,
            severity=issue.severity,
            confidence=issue.confidence,
            evidence=issue.evidence,
            remediation=issue.remediation,
            is_confirmed=False,
        )
        session.add(finding)
        created_count += 1

    if created_count:
        await session.commit()

    return created_count


async def count_findings_for_scan(session: AsyncSession, scan_id: int) -> int:
    result = await session.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    return len(list(result.scalars().all()))
