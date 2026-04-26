import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.exploitdb_entry import ExploitDbEntry
from app.models.ghsa_record import GhsaRecord
from app.models.kev_entry import KevEntry
from app.models.osv_record import OsvRecord
from app.models.vuln_affected_product import VulnAffectedProduct
from app.models.vuln_alias import VulnAlias
from app.models.vuln_record import VulnRecord
from app.models.wordfence_vulnerability import WordfenceVulnerability

SOURCE_PRIORITIES = {
    "nvd": 1,
    "mitre": 2,
    "kev": 3,
    "ghsa": 4,
    "osv": 5,
    "exploitdb": 6,
    "wordfence": 7,
}


@dataclass(frozen=True)
class AffectedProductInput:
    product_name: str
    vendor: str | None = None
    ecosystem: str | None = None
    package_name: str | None = None
    version_exact: str | None = None
    version_start: str | None = None
    version_end: str | None = None
    cpe: str | None = None
    purl: str | None = None


def load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def load_csv_rows(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def parse_cpe(cpe: str) -> tuple[str | None, str | None]:
    parts = cpe.split(":")
    if len(parts) >= 6:
        return parts[3] or None, parts[4] or None
    return None, None


async def upsert_vuln_record(
    session: AsyncSession,
    *,
    primary_id: str,
    source_name: str,
    title: str,
    description: str,
    severity: str | None = None,
    cvss_score: float | None = None,
    published_at: datetime | None = None,
    source_updated_at: datetime | None = None,
    cve_id: str | None = None,
    has_kev: bool = False,
    has_public_exploit: bool = False,
) -> VulnRecord:
    record = await _find_vuln_record(session, primary_id=primary_id, cve_id=cve_id)
    source_priority = SOURCE_PRIORITIES[source_name]

    if record is None:
        record = VulnRecord(
            primary_id=primary_id,
            source_priority=source_priority,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            published_at=published_at,
            source_updated_at=source_updated_at,
            has_cve=bool(cve_id),
            cve_id=cve_id,
            has_kev=has_kev,
            has_public_exploit=has_public_exploit,
        )
        session.add(record)
        await session.flush()
        return record

    if source_priority <= record.source_priority:
        record.primary_id = primary_id
        record.source_priority = source_priority
        record.title = title
        record.description = description
        record.severity = severity or record.severity
        record.cvss_score = cvss_score if cvss_score is not None else record.cvss_score
        record.published_at = published_at or record.published_at
        record.source_updated_at = source_updated_at or record.source_updated_at

    if cve_id:
        record.has_cve = True
        record.cve_id = cve_id
    record.has_kev = record.has_kev or has_kev
    record.has_public_exploit = record.has_public_exploit or has_public_exploit
    await session.flush()
    return record


async def upsert_alias(
    session: AsyncSession, *, vuln_record_id: int, alias_type: str, alias_value: str
) -> VulnAlias:
    existing = await session.execute(
        select(VulnAlias).where(
            VulnAlias.vuln_record_id == vuln_record_id,
            VulnAlias.alias_type == alias_type,
            VulnAlias.alias_value == alias_value,
        )
    )
    alias = existing.scalar_one_or_none()
    if alias is not None:
        return alias

    alias = VulnAlias(
        vuln_record_id=vuln_record_id,
        alias_type=alias_type,
        alias_value=alias_value,
    )
    session.add(alias)
    await session.flush()
    return alias


async def upsert_affected_product(
    session: AsyncSession, *, vuln_record_id: int, product: AffectedProductInput
) -> VulnAffectedProduct:
    existing = await session.execute(
        select(VulnAffectedProduct).where(
            VulnAffectedProduct.vuln_record_id == vuln_record_id,
            VulnAffectedProduct.product_name == product.product_name,
            VulnAffectedProduct.vendor == product.vendor,
            VulnAffectedProduct.ecosystem == product.ecosystem,
            VulnAffectedProduct.package_name == product.package_name,
            VulnAffectedProduct.version_exact == product.version_exact,
            VulnAffectedProduct.version_start == product.version_start,
            VulnAffectedProduct.version_end == product.version_end,
            VulnAffectedProduct.cpe == product.cpe,
            VulnAffectedProduct.purl == product.purl,
        )
    )
    row = existing.scalar_one_or_none()
    if row is not None:
        return row

    row = VulnAffectedProduct(vuln_record_id=vuln_record_id, **product.__dict__)
    session.add(row)
    await session.flush()
    return row


async def upsert_kev_entry(session: AsyncSession, **payload: Any) -> KevEntry:
    existing = await session.execute(
        select(KevEntry).where(KevEntry.cve_id == payload["cve_id"])
    )
    row = existing.scalar_one_or_none()
    if row is None:
        row = KevEntry(**payload)
        session.add(row)
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    await session.flush()
    return row


async def upsert_ghsa_record(session: AsyncSession, **payload: Any) -> GhsaRecord:
    existing = await session.execute(
        select(GhsaRecord).where(GhsaRecord.ghsa_id == payload["ghsa_id"])
    )
    row = existing.scalar_one_or_none()
    if row is None:
        row = GhsaRecord(**payload)
        session.add(row)
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    await session.flush()
    return row


async def upsert_osv_record(session: AsyncSession, **payload: Any) -> OsvRecord:
    existing = await session.execute(
        select(OsvRecord).where(OsvRecord.osv_id == payload["osv_id"])
    )
    row = existing.scalar_one_or_none()
    if row is None:
        row = OsvRecord(**payload)
        session.add(row)
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    await session.flush()
    return row


async def upsert_exploitdb_entry(
    session: AsyncSession, **payload: Any
) -> ExploitDbEntry:
    existing = await session.execute(
        select(ExploitDbEntry).where(ExploitDbEntry.edb_id == payload["edb_id"])
    )
    row = existing.scalar_one_or_none()
    if row is None:
        row = ExploitDbEntry(**payload)
        session.add(row)
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    await session.flush()
    return row


async def upsert_wordfence_vulnerability(
    session: AsyncSession, **payload: Any
) -> WordfenceVulnerability:
    wordfence_id = payload.get("wordfence_id")
    existing = None
    if wordfence_id:
        result = await session.execute(
            select(WordfenceVulnerability).where(
                WordfenceVulnerability.wordfence_id == wordfence_id,
                WordfenceVulnerability.slug == payload["slug"],
                WordfenceVulnerability.affected_version_start
                == payload.get("affected_version_start"),
                WordfenceVulnerability.affected_version_end
                == payload.get("affected_version_end"),
            )
        )
        existing = result.scalar_one_or_none()

    if existing is None:
        result = await session.execute(
            select(WordfenceVulnerability).where(
                WordfenceVulnerability.slug == payload["slug"],
                WordfenceVulnerability.title == payload["title"],
                WordfenceVulnerability.affected_version_start
                == payload.get("affected_version_start"),
                WordfenceVulnerability.affected_version_end
                == payload.get("affected_version_end"),
            )
        )
        existing = result.scalar_one_or_none()

    if existing is None:
        existing = WordfenceVulnerability(**payload)
        session.add(existing)
    else:
        for key, value in payload.items():
            setattr(existing, key, value)

    await session.flush()
    return existing


async def finalize_import(session: AsyncSession) -> None:
    await session.commit()


async def _find_vuln_record(
    session: AsyncSession, *, primary_id: str, cve_id: str | None
) -> VulnRecord | None:
    direct = await session.execute(
        select(VulnRecord).where(VulnRecord.primary_id == primary_id)
    )
    record = direct.scalar_one_or_none()
    if record is not None:
        return record

    if cve_id:
        by_cve = await session.execute(
            select(VulnRecord).where(VulnRecord.cve_id == cve_id)
        )
        return by_cve.scalar_one_or_none()

    return None
