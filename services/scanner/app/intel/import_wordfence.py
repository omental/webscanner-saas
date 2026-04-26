import argparse
import asyncio
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.intel.common import (
    finalize_import,
    load_json,
    parse_datetime,
    upsert_wordfence_vulnerability,
)


def _normalize_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _normalize_version(value: Any) -> str | None:
    normalized = _normalize_string(value)
    if normalized in {None, "*", "-"}:
        return None
    return normalized


def _normalize_references(value: Any) -> list[str] | dict | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        normalized = [item for item in value if isinstance(item, str) and item.strip()]
        return normalized or None
    return None


def _coerce_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_wordfence_records(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    return [record for record in payload.values() if isinstance(record, dict)]


def iter_wordfence_rows(record: dict[str, Any]) -> list[dict[str, Any]]:
    software_entries = record.get("software")
    if not isinstance(software_entries, list):
        return []

    cvss = record.get("cvss") if isinstance(record.get("cvss"), dict) else {}
    references = _normalize_references(record.get("references"))
    wordfence_id = _normalize_string(record.get("id"))
    title = _normalize_string(record.get("title"))
    if title is None:
        return []

    rows: list[dict[str, Any]] = []
    for software in software_entries:
        if not isinstance(software, dict):
            continue

        slug = _normalize_string(software.get("slug"))
        if slug is None:
            continue

        software_type = _normalize_string(software.get("type"))
        remediation = _normalize_string(software.get("remediation"))
        patched_versions = software.get("patched_versions")
        patched_version = None
        if isinstance(patched_versions, list) and patched_versions:
            patched_version = _normalize_version(patched_versions[0])
        if patched_version is None:
            patched_version = _normalize_version(software.get("patched"))

        affected_versions = software.get("affected_versions")
        if isinstance(affected_versions, dict) and affected_versions:
            for affected in affected_versions.values():
                if not isinstance(affected, dict):
                    continue
                rows.append(
                    {
                        "wordfence_id": wordfence_id,
                        "cve_id": _normalize_string(record.get("cve")),
                        "slug": slug.lower(),
                        "software_type": software_type,
                        "title": title,
                        "description": _normalize_string(record.get("description")),
                        "severity": _normalize_string(cvss.get("rating")),
                        "cvss_score": _coerce_float(cvss.get("score")),
                        "affected_version_start": _normalize_version(
                            affected.get("from_version")
                        ),
                        "affected_version_end": _normalize_version(
                            affected.get("to_version")
                        ),
                        "patched_version": patched_version,
                        "remediation": remediation,
                        "references": references,
                        "published_at": parse_datetime(record.get("published")),
                        "source_updated_at": parse_datetime(record.get("updated")),
                    }
                )
            continue

        rows.append(
            {
                "wordfence_id": wordfence_id,
                "cve_id": _normalize_string(record.get("cve")),
                "slug": slug.lower(),
                "software_type": software_type,
                "title": title,
                "description": _normalize_string(record.get("description")),
                "severity": _normalize_string(cvss.get("rating")),
                "cvss_score": _coerce_float(cvss.get("score")),
                "affected_version_start": None,
                "affected_version_end": None,
                "patched_version": patched_version,
                "remediation": remediation,
                "references": references,
                "published_at": parse_datetime(record.get("published")),
                "source_updated_at": parse_datetime(record.get("updated")),
            }
        )

    return rows


async def import_wordfence_file(
    session: AsyncSession, path: str | Path
) -> dict[str, int]:
    payload = load_json(path)
    records_read = 0
    software_entries_imported = 0
    skipped_records = 0

    for record in extract_wordfence_records(payload):
        records_read += 1
        rows = iter_wordfence_rows(record)
        if not rows:
            skipped_records += 1
            continue
        for row in rows:
            await upsert_wordfence_vulnerability(session, **row)
            software_entries_imported += 1

    await finalize_import(session)
    return {
        "records_read": records_read,
        "software_entries_imported": software_entries_imported,
        "skipped_records": skipped_records,
    }


async def _run(path: str | None) -> None:
    settings = get_settings()
    import_path = path or settings.wordfence_import_path
    if not import_path:
        raise SystemExit("Wordfence import path is required")

    async with AsyncSessionLocal() as session:
        result = await import_wordfence_file(session, import_path)
        print(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?")
    args = parser.parse_args()
    asyncio.run(_run(args.path))


if __name__ == "__main__":
    main()
