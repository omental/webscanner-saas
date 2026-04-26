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
    upsert_ghsa_record,
    upsert_vuln_record,
)


def extract_ghsa_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and "advisories" in payload:
        return payload["advisories"]
    if isinstance(payload, dict) and ("ghsaId" in payload or "ghsa_id" in payload):
        return [payload]
    return []


async def import_github_advisories_file(
    session: AsyncSession, path: str | Path
) -> dict[str, int]:
    payload = load_json(path)
    imported = 0

    for item in extract_ghsa_items(payload):
        ghsa_id = item.get("ghsaId") or item.get("ghsa_id")
        if not ghsa_id:
            continue
        cve_id = item.get("cveId") or item.get("cve_id")
        summary = item.get("summary") or item.get("description") or ""

        await upsert_ghsa_record(
            session,
            ghsa_id=ghsa_id,
            cve_id=cve_id,
            summary=summary or None,
            severity=(item.get("severity") or "").lower() or None,
            published_at=parse_datetime(item.get("publishedAt") or item.get("published_at")),
            updated_at=parse_datetime(item.get("updatedAt") or item.get("updated_at")),
            permalink=item.get("permalink"),
        )
        record = await upsert_vuln_record(
            session,
            primary_id=cve_id or ghsa_id,
            source_name="ghsa",
            title=summary or ghsa_id,
            description=summary,
            severity=(item.get("severity") or "").lower() or None,
            published_at=parse_datetime(item.get("publishedAt") or item.get("published_at")),
            source_updated_at=parse_datetime(item.get("updatedAt") or item.get("updated_at")),
            cve_id=cve_id,
        )
        await upsert_alias(
            session, vuln_record_id=record.id, alias_type="ghsa", alias_value=ghsa_id
        )
        if cve_id:
            await upsert_alias(
                session,
                vuln_record_id=record.id,
                alias_type="cve",
                alias_value=cve_id,
            )
        imported += 1

    await finalize_import(session)
    return {"ghsa_records": imported}


async def _run(path: str | None) -> None:
    settings = get_settings()
    import_path = path or settings.ghsa_import_path
    if not import_path:
        raise SystemExit("GHSA import path is required")

    async with AsyncSessionLocal() as session:
        result = await import_github_advisories_file(session, import_path)
        print(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?")
    args = parser.parse_args()
    asyncio.run(_run(args.path))


if __name__ == "__main__":
    main()
