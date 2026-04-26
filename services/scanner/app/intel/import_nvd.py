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
    upsert_vuln_record,
)


def extract_nvd_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if "vulnerabilities" in payload:
        return [item["cve"] for item in payload["vulnerabilities"] if item.get("cve")]
    if "CVE_Items" in payload:
        return payload["CVE_Items"]
    if "cve" in payload:
        return [payload["cve"]]
    return []


def parse_cpe23_criteria(criteria: str) -> tuple[str | None, str | None, str | None]:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None, None, None

    vendor = parts[3] or None
    product_name = parts[4] or None
    version = parts[5] or None

    if version in {"*", "-"}:
        version = None

    return vendor, product_name, version


def extract_affected_products(item: dict[str, Any]) -> list[AffectedProductInput]:
    configurations = item.get("configurations") or []
    products: list[AffectedProductInput] = []

    if isinstance(configurations, dict):
        configurations = [configurations]

    for configuration in configurations:
        nodes = configuration.get("nodes", []) if isinstance(configuration, dict) else []
        for node in nodes:
            cpe_matches = node.get("cpeMatch", []) if isinstance(node, dict) else []
            for match in cpe_matches:
                if not match.get("vulnerable", False):
                    continue

                criteria = match.get("criteria") or match.get("cpe23Uri")
                if not criteria:
                    continue

                vendor, product_name, version_exact = parse_cpe23_criteria(criteria)
                products.append(
                    AffectedProductInput(
                        product_name=product_name or "unknown",
                        vendor=vendor,
                        version_exact=version_exact,
                        version_start=match.get("versionStartIncluding")
                        or match.get("versionStartExcluding"),
                        version_end=match.get("versionEndIncluding")
                        or match.get("versionEndExcluding"),
                        cpe=criteria,
                    )
                )

    return products


def normalize_nvd_item(item: dict[str, Any]) -> dict[str, Any]:
    cve_id = (
        item.get("id")
        or item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        or ""
    )
    descriptions = item.get("descriptions") or item.get("cve", {}).get(
        "description", {}
    ).get("description_data", [])
    description = next(
        (entry.get("value", "") for entry in descriptions if entry.get("value")), ""
    )
    metrics = item.get("metrics", {})
    severity = None
    cvss_score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key) or []
        if metric_list:
            metric = metric_list[0]
            severity = (
                metric.get("baseSeverity")
                or metric.get("cvssData", {}).get("baseSeverity")
            )
            cvss_score = metric.get("cvssData", {}).get("baseScore")
            break

    return {
        "primary_id": cve_id,
        "title": cve_id,
        "description": description,
        "severity": severity.lower() if isinstance(severity, str) else severity,
        "cvss_score": cvss_score,
        "published_at": parse_datetime(item.get("published")),
        "source_updated_at": parse_datetime(item.get("lastModified")),
        "cve_id": cve_id,
        "products": extract_affected_products(item),
    }


async def import_nvd_file(session: AsyncSession, path: str | Path) -> dict[str, int]:
    payload = load_json(path)
    created_records = 0
    created_products = 0

    for item in extract_nvd_items(payload):
        normalized = normalize_nvd_item(item)
        if not normalized["primary_id"]:
            continue

        record = await upsert_vuln_record(
            session,
            primary_id=normalized["primary_id"],
            source_name="nvd",
            title=normalized["title"],
            description=normalized["description"],
            severity=normalized["severity"],
            cvss_score=normalized["cvss_score"],
            published_at=normalized["published_at"],
            source_updated_at=normalized["source_updated_at"],
            cve_id=normalized["cve_id"],
        )
        created_records += 1
        await upsert_alias(
            session,
            vuln_record_id=record.id,
            alias_type="cve",
            alias_value=normalized["cve_id"],
        )
        for product in normalized["products"]:
            await upsert_affected_product(
                session, vuln_record_id=record.id, product=product
            )
            created_products += 1

    await finalize_import(session)
    return {"records": created_records, "products": created_products}


async def _run(path: str | None) -> None:
    settings = get_settings()
    import_path = path or settings.nvd_import_path
    if not import_path:
        raise SystemExit("NVD import path is required")

    async with AsyncSessionLocal() as session:
        result = await import_nvd_file(session, import_path)
        print(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?")
    args = parser.parse_args()
    asyncio.run(_run(args.path))


if __name__ == "__main__":
    main()
