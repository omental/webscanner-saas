from sqlalchemy import Select, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detected_technology import DetectedTechnology
from app.scanner.fingerprints.headers import detect_from_headers
from app.scanner.fingerprints.html import detect_from_html
from app.scanner.fingerprints.scripts import detect_from_script_src


async def detect_and_store_page_technologies(
    session: AsyncSession,
    *,
    scan_id: int,
    scan_page_id: int | None,
    headers: dict[str, str] | None,
    body_excerpt: str | None,
    full_html: str | None = None,
) -> int:
    header_detections = detect_from_headers(headers or {})
    html_source = full_html if full_html is not None else body_excerpt
    body_detections = detect_from_html(html_source) + detect_from_script_src(html_source)

    created_count = 0
    seen_keys: set[tuple[str, str, str | None, str | None, str]] = set()
    for detection, effective_scan_page_id in [
        *[(detection, None) for detection in header_detections],
        *[(detection, scan_page_id) for detection in body_detections],
    ]:
        dedupe_tuple = (
            detection.product_name,
            detection.category,
            detection.version,
            detection.vendor,
            detection.detection_method,
        )
        if dedupe_tuple in seen_keys:
            continue
        seen_keys.add(dedupe_tuple)

        if _is_wordpress_core_detection(
            product_name=detection.product_name,
            category=detection.category,
        ):
            created_count += await _upsert_wordpress_core_detection(
                session,
                scan_id=scan_id,
                scan_page_id=effective_scan_page_id,
                detection=detection,
            )
            continue

        if await _technology_exists(
            session,
            scan_id=scan_id,
            product_name=detection.product_name,
            category=detection.category,
            version=detection.version,
            vendor=detection.vendor,
            detection_method=detection.detection_method,
        ):
            continue

        session.add(
            DetectedTechnology(
                scan_id=scan_id,
                scan_page_id=effective_scan_page_id,
                product_name=detection.product_name,
                category=detection.category,
                version=detection.version,
                vendor=detection.vendor,
                confidence_score=detection.confidence_score,
                detection_method=detection.detection_method,
            )
        )
        created_count += 1

    if created_count:
        await session.commit()

    return created_count


async def _technology_exists(
    session: AsyncSession,
    *,
    scan_id: int,
    product_name: str,
    category: str,
    version: str | None,
    vendor: str | None,
    detection_method: str,
) -> bool:
    query: Select[tuple[DetectedTechnology]] = select(DetectedTechnology).where(
        DetectedTechnology.scan_id == scan_id,
        DetectedTechnology.product_name == product_name,
        DetectedTechnology.category == category,
        DetectedTechnology.version == version,
        DetectedTechnology.vendor == vendor,
        DetectedTechnology.detection_method == detection_method,
    )
    result = await session.execute(query)
    return result.scalar_one_or_none() is not None


def _is_wordpress_core_detection(*, product_name: str, category: str) -> bool:
    return product_name == "WordPress" and category == "cms"


def _wordpress_core_rank(
    *,
    version: str | None,
    confidence_score: float | None,
    detection_method: str | None,
) -> tuple[int, int, float]:
    method_rank = {
        "meta_generator": 3,
        "html_pattern": 2,
        "script_src": 1,
    }.get(detection_method, 0)
    version_rank = 1 if version else 0
    confidence_rank = confidence_score or 0.0
    return (method_rank, version_rank, confidence_rank)


async def _upsert_wordpress_core_detection(
    session: AsyncSession,
    *,
    scan_id: int,
    scan_page_id: int | None,
    detection,
) -> int:
    result = await session.execute(
        select(DetectedTechnology).where(
            DetectedTechnology.scan_id == scan_id,
            DetectedTechnology.product_name == "WordPress",
            DetectedTechnology.category == "cms",
        )
    )
    existing_rows = list(result.scalars().all())
    if not existing_rows:
        session.add(
            DetectedTechnology(
                scan_id=scan_id,
                scan_page_id=scan_page_id,
                product_name=detection.product_name,
                category=detection.category,
                version=detection.version,
                vendor=detection.vendor,
                confidence_score=detection.confidence_score,
                detection_method=detection.detection_method,
            )
        )
        return 1

    best_existing = max(
        existing_rows,
        key=lambda row: _wordpress_core_rank(
            version=row.version,
            confidence_score=row.confidence_score,
            detection_method=row.detection_method,
        ),
    )
    new_rank = _wordpress_core_rank(
        version=detection.version,
        confidence_score=detection.confidence_score,
        detection_method=detection.detection_method,
    )
    existing_rank = _wordpress_core_rank(
        version=best_existing.version,
        confidence_score=best_existing.confidence_score,
        detection_method=best_existing.detection_method,
    )

    mutated = False
    if new_rank > existing_rank:
        best_existing.scan_page_id = scan_page_id
        best_existing.version = detection.version
        best_existing.vendor = detection.vendor
        best_existing.confidence_score = detection.confidence_score
        best_existing.detection_method = detection.detection_method
        mutated = True

    duplicate_ids = [row.id for row in existing_rows if row.id != best_existing.id]
    if duplicate_ids:
        await session.execute(
            delete(DetectedTechnology).where(DetectedTechnology.id.in_(duplicate_ids))
        )
        mutated = True

    return 1 if mutated else 0
