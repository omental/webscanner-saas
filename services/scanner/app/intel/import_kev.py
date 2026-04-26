import argparse
import asyncio
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.intel.common import (
    finalize_import,
    load_csv_rows,
    load_json,
    parse_datetime,
    upsert_alias,
    upsert_kev_entry,
    upsert_vuln_record,
)


def load_kev_rows(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if path.suffix.lower() == ".json":
        payload = load_json(path)
        if isinstance(payload, dict):
            return payload.get("vulnerabilities", [])
        return []
    return load_csv_rows(path)


def normalize_kev_row(row: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = row.get("cveID") or row.get("cve_id")
    if not cve_id:
        return None

    vendor_project = row.get("vendorProject") or row.get("vendor_project")
    product = row.get("product")
    vulnerability_name = row.get("vulnerabilityName") or row.get("vulnerability_name")
    date_added = parse_datetime(row.get("dateAdded") or row.get("date_added"))
    due_date = parse_datetime(row.get("dueDate") or row.get("due_date"))
    required_action = row.get("requiredAction") or row.get("required_action")
    notes = row.get("notes")
    short_description = row.get("shortDescription") or row.get("short_description")

    description = required_action or short_description or notes or ""

    return {
        "cve_id": cve_id,
        "vendor_project": vendor_project,
        "product": product,
        "vulnerability_name": vulnerability_name,
        "date_added": date_added,
        "due_date": due_date,
        "required_action": required_action,
        "notes": notes,
        "description": description,
    }


async def import_kev_file(session: AsyncSession, path: str | Path) -> dict[str, int]:
    rows = load_kev_rows(path)
    imported = 0

    for row in rows:
        normalized = normalize_kev_row(row)
        if normalized is None:
            continue

        await upsert_kev_entry(
            session,
            cve_id=normalized["cve_id"],
            vendor_project=normalized["vendor_project"],
            product=normalized["product"],
            vulnerability_name=normalized["vulnerability_name"],
            date_added=normalized["date_added"],
            due_date=normalized["due_date"],
            required_action=normalized["required_action"],
            notes=normalized["notes"],
        )

        record = await upsert_vuln_record(
            session,
            primary_id=normalized["cve_id"],
            source_name="kev",
            title=normalized["vulnerability_name"] or normalized["cve_id"],
            description=normalized["description"],
            published_at=normalized["date_added"],
            cve_id=normalized["cve_id"],
            has_kev=True,
        )
        await upsert_alias(
            session,
            vuln_record_id=record.id,
            alias_type="cve",
            alias_value=normalized["cve_id"],
        )
        imported += 1

    await finalize_import(session)
    return {"kev_entries": imported}


async def _run(path: str | None) -> None:
    settings = get_settings()
    import_path = path or settings.kev_import_path
    if not import_path:
        raise SystemExit("KEV import path is required")

    async with AsyncSessionLocal() as session:
        result = await import_kev_file(session, import_path)
        print(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?")
    args = parser.parse_args()
    asyncio.run(_run(args.path))


if __name__ == "__main__":
    main()
