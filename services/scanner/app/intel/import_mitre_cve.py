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
    upsert_alias,
    upsert_vuln_record,
)


def extract_mitre_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and "containers" in payload:
        return [payload]
    if isinstance(payload, dict) and "cveMetadata" in payload:
        return [payload]
    return []


def normalize_mitre_item(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("cveMetadata", {})
    cna = item.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    description = next(
        (entry.get("value", "") for entry in descriptions if entry.get("value")), ""
    )
    cve_id = metadata.get("cveId", "")
    return {
        "primary_id": cve_id,
        "title": cna.get("title") or cve_id,
        "description": description,
        "published_at": parse_datetime(metadata.get("datePublished")),
        "source_updated_at": parse_datetime(metadata.get("dateUpdated")),
        "cve_id": cve_id,
    }


async def import_mitre_cve_file(
    session: AsyncSession, path: str | Path
) -> dict[str, int]:
    payload = load_json(path)
    imported = 0

    for item in extract_mitre_items(payload):
        normalized = normalize_mitre_item(item)
        if not normalized["primary_id"]:
            continue
        record = await upsert_vuln_record(
            session,
            primary_id=normalized["primary_id"],
            source_name="mitre",
            title=normalized["title"],
            description=normalized["description"],
            published_at=normalized["published_at"],
            source_updated_at=normalized["source_updated_at"],
            cve_id=normalized["cve_id"],
        )
        await upsert_alias(
            session,
            vuln_record_id=record.id,
            alias_type="cve",
            alias_value=normalized["cve_id"],
        )
        imported += 1

    await finalize_import(session)
    return {"records": imported}


async def _run(path: str | None) -> None:
    settings = get_settings()
    import_path = path or settings.mitre_import_path
    if not import_path:
        raise SystemExit("MITRE import path is required")

    async with AsyncSessionLocal() as session:
        result = await import_mitre_cve_file(session, import_path)
        print(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?")
    args = parser.parse_args()
    asyncio.run(_run(args.path))


if __name__ == "__main__":
    main()
