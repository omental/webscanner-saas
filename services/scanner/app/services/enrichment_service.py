from dataclasses import dataclass

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intel.matchers.version_matcher import (
    VersionMatchResult,
    is_version_in_range,
    match_technology_to_product,
    normalize_name,
)
from app.models.detected_technology import DetectedTechnology
from app.models.exploitdb_entry import ExploitDbEntry
from app.models.finding import Finding
from app.models.finding_reference import FindingReference
from app.models.kev_entry import KevEntry
from app.models.vuln_affected_product import VulnAffectedProduct
from app.models.vuln_record import VulnRecord
from app.models.wordfence_vulnerability import WordfenceVulnerability


@dataclass(frozen=True)
class IntelReference:
    ref_type: str
    ref_value: str
    ref_url: str | None
    source: str


@dataclass(frozen=True)
class TechnologyRow:
    id: int
    scan_id: int
    scan_page_id: int | None
    product_name: str
    category: str
    version: str | None
    vendor: str | None


@dataclass(frozen=True)
class FindingRow:
    id: int


@dataclass(frozen=True)
class VulnerabilityMatch:
    cve_id: str | None
    description: str
    cvss_score: float | None
    has_kev: bool
    exploit_entries: list["ExploitEntryRow"]
    match_result: VersionMatchResult


@dataclass(frozen=True)
class ExploitEntryRow:
    edb_id: str
    exploit_url: str | None


@dataclass(frozen=True)
class WordfenceMatch:
    wordfence_id: str | None
    cve_id: str | None
    slug: str
    software_type: str | None
    title: str
    description: str
    severity: str | None
    cvss_score: float | None
    affected_version_start: str | None
    affected_version_end: str | None
    patched_version: str | None
    references: list[str]


def build_reference_url(ref_type: str, ref_value: str) -> str | None:
    if ref_type == "cve":
        return f"https://nvd.nist.gov/vuln/detail/{ref_value}"
    if ref_type == "kev":
        return "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    if ref_type == "edb":
        return f"https://www.exploit-db.com/exploits/{ref_value}"
    if ref_type == "wordfence":
        return f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{ref_value}"
    return None


def build_references_for_match(
    *,
    cve_id: str | None,
    has_kev: bool,
    exploit_entries: list[ExploitEntryRow],
) -> list[IntelReference]:
    references: list[IntelReference] = []
    if cve_id:
        references.append(
            IntelReference(
                ref_type="cve",
                ref_value=cve_id,
                ref_url=build_reference_url("cve", cve_id),
                source="nvd",
            )
        )
    if cve_id and has_kev:
        references.append(
            IntelReference(
                ref_type="kev",
                ref_value=cve_id,
                ref_url=build_reference_url("kev", cve_id),
                source="cisa",
            )
        )
    for exploit_entry in exploit_entries:
        references.append(
            IntelReference(
                ref_type="edb",
                ref_value=exploit_entry.edb_id,
                ref_url=exploit_entry.exploit_url
                or build_reference_url("edb", exploit_entry.edb_id),
                source="exploitdb",
            )
        )
    return references


async def enrich_scan_findings(session: AsyncSession, scan_id: int) -> int:
    technologies = await _list_scan_technologies(session, scan_id)
    created_count = 0

    for technology in technologies:
        wordfence_matched, wordfence_created_count = await _enrich_from_wordfence(
            session,
            scan_id,
            technology,
        )
        if wordfence_matched:
            created_count += wordfence_created_count
            continue

        match = await _find_best_vulnerability_match(session, technology)
        if match is None or not should_create_known_vulnerability_finding(technology, match):
            continue

        finding_id = await _get_or_create_known_vulnerability_finding(
            session, scan_id, technology, match
        )
        if finding_id is None:
            continue

        references = build_references_for_match(
            cve_id=match.cve_id,
            has_kev=match.has_kev,
            exploit_entries=match.exploit_entries,
        )
        created_count += await _attach_references_if_missing(
            session, finding_id, references
        )

    if created_count:
        await session.commit()

    return created_count


def severity_from_cvss(cvss_score: float | None) -> str:
    if cvss_score is None or cvss_score <= 0:
        return "medium"
    if cvss_score < 4.0:
        return "low"
    if cvss_score < 7.0:
        return "medium"
    if cvss_score < 9.0:
        return "high"
    return "critical"


def normalize_severity(value: str | None, cvss_score: float | None) -> str:
    normalized = value.strip().lower() if isinstance(value, str) and value.strip() else None
    if normalized in {"low", "medium", "high", "critical"}:
        return normalized
    return severity_from_cvss(cvss_score)


def should_create_known_vulnerability_finding(
    technology: TechnologyRow, match: VulnerabilityMatch
) -> bool:
    if technology.version:
        return True
    return match.match_result.confidence == "high"


def build_known_vulnerability_finding_values(
    scan_id: int, technology: TechnologyRow, match: VulnerabilityMatch
) -> dict[str, object]:
    version_label = technology.version or "unknown version"
    evidence = (
        f"Detected technology: {technology.product_name} {version_label}; "
        f"matched CVE: {match.cve_id or 'unknown'}"
    )
    return {
        "scan_id": scan_id,
        "scan_page_id": technology.scan_page_id,
        "category": "known_vulnerability",
        "title": f"Known vulnerability detected in {technology.product_name}",
        "description": match.description,
        "severity": severity_from_cvss(match.cvss_score),
        "confidence": match.match_result.confidence,
        "evidence": evidence,
        "remediation": f"Upgrade {technology.product_name} to a non-vulnerable version.",
        "is_confirmed": False,
    }


def extract_wordpress_slug(technology: TechnologyRow) -> str | None:
    if technology.category == "cms" and normalize_name(technology.product_name) == "wordpress":
        return "wordpress"

    lower_product_name = technology.product_name.lower()
    prefixes = [
        "wordpress plugin: ",
        "wordpress theme: ",
    ]
    for prefix in prefixes:
        if lower_product_name.startswith(prefix):
            slug = technology.product_name[len(prefix) :].strip().lower()
            return slug or None

    if technology.category in {"cms_plugin", "cms_theme"}:
        normalized = normalize_name(technology.product_name)
        return normalized

    return None


def build_wordfence_finding_values(
    scan_id: int, technology: TechnologyRow, match: WordfenceMatch
) -> dict[str, object]:
    detected_version = technology.version or "unknown version"
    software_label = match.software_type or technology.category
    if match.affected_version_end:
        affected_label = f"<= {match.affected_version_end}"
    elif match.affected_version_start:
        affected_label = f">= {match.affected_version_start}"
    else:
        affected_label = "documented vulnerable range"

    remediation = (
        f"Update {technology.product_name} to {match.patched_version} or later."
        if match.patched_version
        else f"Update {technology.product_name} to a non-vulnerable version."
    )

    return {
        "scan_id": scan_id,
        "scan_page_id": technology.scan_page_id,
        "category": "wordpress_vulnerability",
        "title": match.title,
        "description": match.description,
        "severity": normalize_severity(match.severity, match.cvss_score),
        "confidence": "high",
        "evidence": (
            f"Detected {software_label} slug: {match.slug}; detected version: {detected_version}; "
            f"affected range: {affected_label}; wordfence_id: {match.wordfence_id or 'unknown'}"
        ),
        "remediation": remediation,
        "is_confirmed": False,
    }


def build_wordfence_references(match: WordfenceMatch) -> list[IntelReference]:
    references: list[IntelReference] = []
    if match.cve_id:
        references.append(
            IntelReference(
                ref_type="cve",
                ref_value=match.cve_id,
                ref_url=build_reference_url("cve", match.cve_id),
                source="wordfence",
            )
        )

    wordfence_ref_value = match.wordfence_id or f"{match.slug}:{match.title}"
    references.append(
        IntelReference(
            ref_type="wordfence",
            ref_value=wordfence_ref_value,
            ref_url=build_reference_url("wordfence", match.wordfence_id)
            if match.wordfence_id
            else None,
            source="wordfence",
        )
    )

    for reference_url in match.references:
        references.append(
            IntelReference(
                ref_type="reference",
                ref_value=reference_url,
                ref_url=reference_url,
                source="wordfence",
            )
        )

    return references


async def _get_or_create_known_vulnerability_finding(
    session: AsyncSession,
    scan_id: int,
    technology: TechnologyRow,
    match: VulnerabilityMatch,
) -> int | None:
    values = build_known_vulnerability_finding_values(scan_id, technology, match)
    existing = await session.execute(
        select(Finding.id).where(
            Finding.scan_id == scan_id,
            Finding.category == "known_vulnerability",
            Finding.title == values["title"],
            Finding.evidence == values["evidence"],
        )
    )
    existing_id = existing.scalar_one_or_none()
    if existing_id is not None:
        return existing_id

    result = await session.execute(insert(Finding).values(**values).returning(Finding.id))
    return result.scalar_one()


async def _get_or_create_wordfence_finding(
    session: AsyncSession,
    scan_id: int,
    technology: TechnologyRow,
    match: WordfenceMatch,
) -> int | None:
    values = build_wordfence_finding_values(scan_id, technology, match)
    existing = await session.execute(
        select(Finding.id).where(
            Finding.scan_id == scan_id,
            Finding.category == "wordpress_vulnerability",
            Finding.title == values["title"],
            Finding.evidence == values["evidence"],
        )
    )
    existing_id = existing.scalar_one_or_none()
    if existing_id is not None:
        return existing_id

    result = await session.execute(insert(Finding).values(**values).returning(Finding.id))
    return result.scalar_one()


async def _find_best_vulnerability_match(
    session: AsyncSession, technology: TechnologyRow
) -> VulnerabilityMatch | None:
    normalized_product = normalize_name(technology.product_name)
    if normalized_product is None:
        return None

    result = await session.execute(
        select(
            VulnAffectedProduct.product_name,
            VulnAffectedProduct.vendor,
            VulnAffectedProduct.version_exact,
            VulnRecord.cve_id,
            VulnRecord.description,
            VulnRecord.cvss_score,
            VulnRecord.has_kev,
        )
        .join(VulnRecord, VulnAffectedProduct.vuln_record_id == VulnRecord.id)
        .where(func.lower(VulnAffectedProduct.product_name) == normalized_product)
    )

    best_match: VulnerabilityMatch | None = None
    confidence_rank = {"high": 3, "medium": 2, "low": 1, None: 0}

    for row in result.all():
        match_result = match_technology_to_product(
            technology_product=technology.product_name,
            technology_version=technology.version,
            technology_vendor=technology.vendor,
            product_name=row.product_name,
            product_vendor=row.vendor,
            product_version_exact=row.version_exact,
        )
        if not match_result.is_match:
            continue

        has_kev = row.has_kev or await _has_kev_entry(session, row.cve_id)
        exploit_entries = await _list_exploit_entries(session, row.cve_id)
        candidate = VulnerabilityMatch(
            cve_id=row.cve_id,
            description=row.description or "Known vulnerability intelligence matched this technology.",
            cvss_score=row.cvss_score,
            has_kev=has_kev,
            exploit_entries=exploit_entries,
            match_result=match_result,
        )
        if best_match is None:
            best_match = candidate
            continue
        if confidence_rank[match_result.confidence] > confidence_rank[
            best_match.match_result.confidence
        ]:
            best_match = candidate

    return best_match


async def _enrich_from_wordfence(
    session: AsyncSession, scan_id: int, technology: TechnologyRow
) -> tuple[bool, int]:
    wordfence_match = await _find_best_wordfence_match(session, technology)
    if wordfence_match is None:
        return False, 0

    finding_id = await _get_or_create_wordfence_finding(
        session,
        scan_id,
        technology,
        wordfence_match,
    )
    if finding_id is None:
        return True, 0

    return True, await _attach_references_if_missing(
        session,
        finding_id,
        build_wordfence_references(wordfence_match),
    )


async def _find_best_wordfence_match(
    session: AsyncSession, technology: TechnologyRow
) -> WordfenceMatch | None:
    if technology.category not in {"cms", "cms_plugin", "cms_theme"}:
        return None

    slug = extract_wordpress_slug(technology)
    if slug is None or technology.version is None:
        return None

    result = await session.execute(
        select(
            WordfenceVulnerability.wordfence_id,
            WordfenceVulnerability.cve_id,
            WordfenceVulnerability.slug,
            WordfenceVulnerability.software_type,
            WordfenceVulnerability.title,
            WordfenceVulnerability.description,
            WordfenceVulnerability.severity,
            WordfenceVulnerability.cvss_score,
            WordfenceVulnerability.affected_version_start,
            WordfenceVulnerability.affected_version_end,
            WordfenceVulnerability.patched_version,
            WordfenceVulnerability.references,
        ).where(func.lower(WordfenceVulnerability.slug) == slug)
    )

    best_match: WordfenceMatch | None = None
    for row in result.all():
        if not _wordfence_software_type_matches(technology.category, row.software_type):
            continue
        if not is_version_in_range(
            version=technology.version,
            version_start=row.affected_version_start,
            version_end=row.affected_version_end,
        ):
            continue

        candidate = WordfenceMatch(
            wordfence_id=row.wordfence_id,
            cve_id=row.cve_id,
            slug=row.slug,
            software_type=row.software_type,
            title=row.title,
            description=row.description
            or "Wordfence intelligence matched this WordPress component.",
            severity=row.severity,
            cvss_score=row.cvss_score,
            affected_version_start=row.affected_version_start,
            affected_version_end=row.affected_version_end,
            patched_version=row.patched_version,
            references=_normalize_wordfence_references(row.references),
        )
        if best_match is None:
            best_match = candidate
            continue
        if _wordfence_match_rank(candidate) > _wordfence_match_rank(best_match):
            best_match = candidate

    return best_match


def _wordfence_match_rank(match: WordfenceMatch) -> tuple[int, float]:
    version_specificity = 2 if match.affected_version_start and match.affected_version_end else 1
    cvss_score = match.cvss_score or 0.0
    return (version_specificity, cvss_score)


def _wordfence_software_type_matches(
    technology_category: str, software_type: str | None
) -> bool:
    normalized_type = normalize_name(software_type)
    if technology_category == "cms":
        return normalized_type in {None, "core"}
    if technology_category == "cms_plugin":
        return normalized_type in {None, "plugin"}
    if technology_category == "cms_theme":
        return normalized_type in {None, "theme"}
    return False


def _normalize_wordfence_references(references: list[str] | dict | None) -> list[str]:
    if isinstance(references, list):
        return [value for value in references if isinstance(value, str) and value]
    if isinstance(references, dict):
        values: list[str] = []
        for value in references.values():
            if isinstance(value, str) and value:
                values.append(value)
            elif isinstance(value, list):
                values.extend(
                    item for item in value if isinstance(item, str) and item
                )
        return values
    return []


async def _has_kev_entry(session: AsyncSession, cve_id: str | None) -> bool:
    if not cve_id:
        return False
    result = await session.execute(
        select(KevEntry.id).where(KevEntry.cve_id == cve_id).limit(1)
    )
    return result.scalar_one_or_none() is not None


async def _list_exploit_entries(
    session: AsyncSession, cve_id: str | None
) -> list[ExploitEntryRow]:
    if not cve_id:
        return []
    result = await session.execute(
        select(ExploitDbEntry.edb_id, ExploitDbEntry.exploit_url).where(
            ExploitDbEntry.cve_id == cve_id
        )
    )
    return [
        ExploitEntryRow(edb_id=row.edb_id, exploit_url=row.exploit_url)
        for row in result.all()
    ]


async def _list_scan_technologies(
    session: AsyncSession, scan_id: int
) -> list[TechnologyRow]:
    result = await session.execute(
        select(
            DetectedTechnology.id,
            DetectedTechnology.scan_id,
            DetectedTechnology.scan_page_id,
            DetectedTechnology.product_name,
            DetectedTechnology.category,
            DetectedTechnology.version,
            DetectedTechnology.vendor,
        )
        .where(DetectedTechnology.scan_id == scan_id)
        .order_by(DetectedTechnology.id.asc())
    )
    return [
        TechnologyRow(
            id=row.id,
            scan_id=row.scan_id,
            scan_page_id=row.scan_page_id,
            product_name=row.product_name,
            category=row.category,
            version=row.version,
            vendor=row.vendor,
        )
        for row in result.all()
    ]


async def _attach_references_if_missing(
    session: AsyncSession, finding_id: int, references: list[IntelReference]
) -> int:
    created_count = 0
    for reference in references:
        existing = await session.execute(
            select(FindingReference.id).where(
                FindingReference.finding_id == finding_id,
                FindingReference.ref_type == reference.ref_type,
                FindingReference.ref_value == reference.ref_value,
                FindingReference.source == reference.source,
            )
        )
        if existing.scalar_one_or_none() is not None:
            continue

        await session.execute(
            insert(FindingReference).values(
                finding_id=finding_id,
                ref_type=reference.ref_type,
                ref_value=reference.ref_value,
                ref_url=reference.ref_url,
                source=reference.source,
            )
        )
        created_count += 1
    return created_count
