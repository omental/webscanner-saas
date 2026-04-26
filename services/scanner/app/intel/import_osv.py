import argparse
import asyncio
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.intel.common import (
    AffectedProductInput,
    finalize_import,
    load_json,
    parse_datetime,
    upsert_affected_product,
    upsert_alias,
    upsert_osv_record,
    upsert_vuln_record,
)


def extract_osv_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and "vulns" in payload:
        return payload["vulns"]
    if isinstance(payload, dict) and "id" in payload:
        return [payload]
    return []


def _extract_version_window(ranges: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    start = None
    end = None
    for range_item in ranges:
        for event in range_item.get("events", []):
            if "introduced" in event and event["introduced"] not in {"0", ""}:
                start = event["introduced"]
            if "fixed" in event:
                end = event["fixed"]
    return start, end


async def import_osv_file(session: AsyncSession, path: str | Path) -> dict[str, int]:
    payload = load_json(path)
    imported = 0

    for item in extract_osv_items(payload):
        osv_id = item.get("id")
        if not osv_id:
            continue
        aliases = item.get("aliases", [])
        cve_id = next((alias for alias in aliases if alias.startswith("CVE-")), None)

        await upsert_osv_record(
            session,
            osv_id=osv_id,
            summary=item.get("summary"),
            details=item.get("details"),
            published_at=parse_datetime(item.get("published")),
            modified_at=parse_datetime(item.get("modified")),
            ecosystem_specific=item.get("ecosystem_specific"),
        )
        record = await upsert_vuln_record(
            session,
            primary_id=cve_id or osv_id,
            source_name="osv",
            title=item.get("summary") or osv_id,
            description=item.get("details") or item.get("summary") or "",
            published_at=parse_datetime(item.get("published")),
            source_updated_at=parse_datetime(item.get("modified")),
            cve_id=cve_id,
        )
        await upsert_alias(
            session, vuln_record_id=record.id, alias_type="osv", alias_value=osv_id
        )
        for alias in aliases:
            await upsert_alias(
                session,
                vuln_record_id=record.id,
                alias_type="cve" if alias.startswith("CVE-") else "alias",
                alias_value=alias,
            )

        for affected in item.get("affected", []):
            package = affected.get("package", {})
            version_start, version_end = _extract_version_window(affected.get("ranges", []))
            await upsert_affected_product(
                session,
                vuln_record_id=record.id,
                product=AffectedProductInput(
                    product_name=package.get("name") or package.get("purl") or "unknown",
                    ecosystem=package.get("ecosystem"),
                    package_name=package.get("name"),
                    version_start=version_start,
                    version_end=version_end,
                    purl=package.get("purl"),
                ),
            )
        imported += 1

    await finalize_import(session)
    return {"osv_records": imported}


async def _run(path: str | None) -> None:
    settings = get_settings()
    import_path = path or settings.osv_import_path
    if not import_path:
        raise SystemExit("OSV import path is required")

    async with AsyncSessionLocal() as session:
        result = await import_osv_file(session, import_path)
        print(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?")
    args = parser.parse_args()
    asyncio.run(_run(args.path))


if __name__ == "__main__":
    main()
