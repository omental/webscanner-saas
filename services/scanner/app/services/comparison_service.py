from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.finding import Finding
from app.models.scan import Scan
from app.services.finding_service import build_finding_deduplication_key

FIXED = "fixed"
STILL_VULNERABLE = "still_vulnerable"
NOT_RETESTED = "not_retested"
NEW = "new"
EXISTING = "existing"


@dataclass(slots=True)
class ScanComparison:
    previous_scan_id: int | None
    current_scan_id: int
    fixed_findings: list[Finding] = field(default_factory=list)
    still_vulnerable_findings: list[Finding] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    existing_findings: list[Finding] = field(default_factory=list)
    not_retested_findings: list[Finding] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "fixed": len(self.fixed_findings),
            "still_vulnerable": len(self.still_vulnerable_findings),
            "new": len(self.new_findings),
            "existing": len(self.existing_findings),
            "not_retested": len(self.not_retested_findings),
        }


def finding_comparison_key(finding: Finding) -> str:
    if finding.deduplication_key and not finding.deduplication_key.startswith(
        "finding:v1:"
    ):
        return finding.deduplication_key

    return build_finding_deduplication_key(
        scan_id=0,
        check_type=finding.category,
        severity=finding.severity,
        title=finding.title,
        request_url=finding.request_url,
        affected_url=None,
        tested_parameter=finding.tested_parameter,
        affected_parameter=finding.affected_parameter,
        scan_page_id=finding.scan_page_id,
    )


async def _list_findings_with_references(
    session: AsyncSession, scan_id: int
) -> list[Finding]:
    result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.references))
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.id.asc())
    )
    return list(result.scalars().all())


def _group_by_comparison_key(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding_comparison_key(finding), []).append(finding)
    return grouped


def compare_finding_sets(
    *,
    previous_scan_id: int | None,
    current_scan_id: int,
    previous_findings: list[Finding],
    current_findings: list[Finding],
    current_scan_status: str = "completed",
    update_statuses: bool = True,
) -> ScanComparison:
    if previous_scan_id is None:
        return ScanComparison(previous_scan_id=None, current_scan_id=current_scan_id)

    if current_scan_status.lower() != "completed":
        if update_statuses:
            for finding in previous_findings:
                finding.comparison_status = NOT_RETESTED
        return ScanComparison(
            previous_scan_id=previous_scan_id,
            current_scan_id=current_scan_id,
            not_retested_findings=previous_findings,
        )

    previous_by_key = _group_by_comparison_key(previous_findings)
    current_by_key = _group_by_comparison_key(current_findings)

    comparison = ScanComparison(
        previous_scan_id=previous_scan_id,
        current_scan_id=current_scan_id,
    )

    current_keys = set(current_by_key)
    previous_keys = set(previous_by_key)

    for key, findings in previous_by_key.items():
        if key in current_keys:
            comparison.still_vulnerable_findings.extend(findings)
            if update_statuses:
                for finding in findings:
                    finding.comparison_status = STILL_VULNERABLE
        else:
            comparison.fixed_findings.extend(findings)
            if update_statuses:
                for finding in findings:
                    finding.comparison_status = FIXED

    for key, findings in current_by_key.items():
        if key in previous_keys:
            comparison.existing_findings.extend(findings)
            if update_statuses:
                for finding in findings:
                    finding.comparison_status = EXISTING
        else:
            comparison.new_findings.extend(findings)
            if update_statuses:
                for finding in findings:
                    finding.comparison_status = NEW

    return comparison


async def mark_previous_findings_not_retested(
    session: AsyncSession, scan: Scan
) -> ScanComparison:
    if scan.previous_scan_id is None:
        return ScanComparison(previous_scan_id=None, current_scan_id=scan.id)

    previous_findings = await _list_findings_with_references(
        session, scan.previous_scan_id
    )
    for finding in previous_findings:
        finding.comparison_status = NOT_RETESTED

    if previous_findings:
        await session.commit()

    return ScanComparison(
        previous_scan_id=scan.previous_scan_id,
        current_scan_id=scan.id,
        not_retested_findings=previous_findings,
    )


async def compare_scan_findings(
    session: AsyncSession, scan: Scan, *, persist: bool = True
) -> ScanComparison:
    if scan.previous_scan_id is None:
        return ScanComparison(previous_scan_id=None, current_scan_id=scan.id)

    previous_findings = await _list_findings_with_references(
        session, scan.previous_scan_id
    )
    current_findings = await _list_findings_with_references(session, scan.id)

    if scan.status.lower() != "completed":
        comparison = ScanComparison(
            previous_scan_id=scan.previous_scan_id,
            current_scan_id=scan.id,
            not_retested_findings=previous_findings,
        )
        if persist:
            for finding in previous_findings:
                finding.comparison_status = NOT_RETESTED
            if previous_findings:
                await session.commit()
        return comparison

    comparison = compare_finding_sets(
        previous_scan_id=scan.previous_scan_id,
        current_scan_id=scan.id,
        previous_findings=previous_findings,
        current_findings=current_findings,
        current_scan_status=scan.status,
        update_statuses=persist,
    )
    if persist:
        await session.commit()

    return comparison


async def get_scan_comparison(
    session: AsyncSession, scan: Scan
) -> ScanComparison:
    return await compare_scan_findings(session, scan, persist=False)


async def get_comparison_summary(
    session: AsyncSession, scan: Scan
) -> dict[str, int] | None:
    if scan.previous_scan_id is None:
        return None
    comparison = await get_scan_comparison(session, scan)
    return comparison.summary
