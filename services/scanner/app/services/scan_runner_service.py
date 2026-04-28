import logging
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.models.scan import Scan
from app.scanner.checks.auth_advanced import check_auth_advanced
from app.scanner.checks.auth_surface import check_auth_surface
from app.scanner.checks.cors import TEST_ORIGINS, check_cors_headers
from app.scanner.checks.crawl import (
    check_crawl_page,
    check_redirect_chains,
    summarize_crawl_issues,
)
from app.scanner.checks.csrf import check_csrf_forms
from app.scanner.checks.cookies import check_cookie_security
from app.scanner.checks.exposure_paths import (
    EXPOSURE_PATHS,
    build_exposure_url,
    classify_exposure_path,
)
from app.scanner.checks.file_upload_advanced import check_file_upload_advanced
from app.scanner.checks.file_upload import check_file_upload_forms
from app.scanner.checks.headers import check_security_headers
from app.scanner.checks.https import (
    check_mixed_content,
    classify_transport,
    http_variant,
    https_variant,
)
from app.scanner.checks.info_disclosure import (
    check_banner_exposure,
    check_debug_exposure,
    check_directory_listing,
)
from app.scanner.checks.waf_detection import (
    WafProbeSnapshot,
    build_waf_probe_url,
    detect_waf_behavior,
    detect_waf_from_headers,
    extract_title,
)
from app.scanner.checks.performance import check_performance
from app.scanner.checks.open_redirect import (
    REDIRECT_PROBE_URL,
    build_redirect_probe_url,
    check_open_redirect,
    extract_redirect_parameters,
)
from app.scanner.checks.reflected_xss import (
    build_reflection_marker,
    build_reflection_probe_url,
    check_reflected_xss,
    extract_reflection_parameters,
)
from app.scanner.checks.rce import (
    RCE_PROBES,
    build_rce_probe_url,
    check_rce_response,
    extract_rce_parameters,
)
from app.scanner.checks.sqli_light import (
    SQLI_LIGHT_PROBES,
    build_sqli_probe_url,
    check_sqli_light,
    extract_sqli_parameters,
)
from app.scanner.checks.ssrf import (
    build_ssrf_probe_url,
    check_ssrf_response,
    extract_ssrf_parameters,
)
from app.scanner.checks.sqli_advanced import (
    TIMING_PROBES,
    ResponseSnapshot,
    build_advanced_sqli_probe_url,
    boolean_probe_pairs_for_budget,
    check_boolean_sqli,
    check_timing_sqli,
    extract_advanced_sqli_parameters,
    is_same_origin as is_same_origin_url,
)
from app.scanner.checks.stored_xss import (
    build_stored_xss_marker,
    build_stored_xss_submission,
    check_stored_xss_response,
    is_same_origin,
    select_safe_stored_xss_forms,
    verify_stored_xss_execution,
)
from app.scanner.checks.subdomains import discover_subdomains_from_page
from app.scanner.checks.seo import check_seo
from app.scanner.crawler import SafeCrawler
from app.scanner.http_client import HttpClient
from app.services.finding_service import count_findings_for_scan, create_findings_if_missing
from app.services.enrichment_service import enrich_scan_findings
from app.services.fingerprint_service import detect_and_store_page_technologies
from app.services.scan_profiles import (
    crawl_profile_for_scan,
    normalize_scan_profile,
    should_run_scan_module,
)
from app.services.scan_service import (
    get_scan_by_id,
    list_scan_pages,
    mark_scan_completed,
    mark_scan_failed,
    mark_scan_running,
)
from app.services.target_service import get_target_by_id

logger = logging.getLogger(__name__)
settings = get_settings()


class ScanCancelled(Exception):
    pass


async def _is_scan_cancelled(session: AsyncSession, scan_id: int) -> bool:
    result = await session.execute(select(Scan.status).where(Scan.id == scan_id))
    status = result.scalar_one_or_none()
    return bool(status and status.lower() == "cancelled")


async def _ensure_not_cancelled(session: AsyncSession, scan_id: int) -> None:
    if await _is_scan_cancelled(session, scan_id):
        raise ScanCancelled()


async def _create_findings_if_not_cancelled(
    session: AsyncSession,
    *,
    scan_id: int,
    scan_page_id: int | None,
    issues: list[object],
) -> int:
    await _ensure_not_cancelled(session, scan_id)
    return await create_findings_if_missing(
        session,
        scan_id=scan_id,
        scan_page_id=scan_page_id,
        issues=issues,
    )


async def _run_profiled_check(
    session: AsyncSession,
    scan_id: int,
    scan_profile: str,
    module_name: str,
    runner,
) -> None:
    if not should_run_scan_module(scan_profile, module_name):
        logger.info(
            "scan module skipped scan_id=%s profile=%s module=%s",
            scan_id,
            scan_profile,
            module_name,
        )
        return
    await runner()
    await _ensure_not_cancelled(session, scan_id)


async def run_scan(scan_id: int) -> None:
    async with AsyncSessionLocal() as session:
        await _run_scan(session, scan_id)


async def _run_scan(session: AsyncSession, scan_id: int) -> None:
    logger.info("scan start scan_id=%s", scan_id)
    scan = await get_scan_by_id(session, scan_id)
    if scan is None:
        logger.warning("scan missing scan_id=%s", scan_id)
        return

    stored_scan_id = scan.id
    target_id = scan.target_id

    target = await get_target_by_id(session, target_id)
    if target is None:
        logger.error("scan target missing scan_id=%s target_id=%s", scan_id, target_id)
        await mark_scan_failed(
            session,
            scan,
            total_pages_found=0,
            total_findings=0,
            error_message="Target not found",
        )
        return

    target_base_url = target.base_url
    scan_profile = normalize_scan_profile(getattr(scan, "scan_profile", None))
    crawl_profile = crawl_profile_for_scan(
        scan_profile,
        max_depth=getattr(scan, "max_depth", None),
        max_pages=getattr(scan, "max_pages", None),
        timeout_seconds=getattr(scan, "timeout_seconds", None),
    )

    if await _is_scan_cancelled(session, stored_scan_id):
        logger.info("scan cancelled before start scan_id=%s", scan_id)
        return

    await mark_scan_running(session, scan)
    logger.info("target fetch start scan_id=%s base_url=%s", scan_id, target_base_url)

    try:
        crawler = SafeCrawler(
            session=session,
            scan_id=stored_scan_id,
            base_url=target_base_url,
            max_depth=crawl_profile.max_depth,
            max_pages=crawl_profile.max_pages,
            timeout_seconds=crawl_profile.timeout_seconds,
            should_cancel=lambda: _is_scan_cancelled(session, stored_scan_id),
        )
        result = await crawler.crawl()
        await _ensure_not_cancelled(session, stored_scan_id)
        html_bodies_by_page_id = getattr(result, "html_bodies_by_page_id", {})
        logger.info(
            "target fetch success scan_id=%s total_pages_found=%s",
            scan_id,
            result.total_pages_found,
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "transport",
            lambda: _run_transport_checks(session, stored_scan_id, target_base_url),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "crawl",
            lambda: _run_crawl_checks(session, stored_scan_id),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "subdomain_discovery",
            lambda: _run_subdomain_discovery_checks(
                session,
                stored_scan_id,
                target_base_url,
                html_bodies_by_page_id,
            ),
        )
        if should_run_scan_module(scan_profile, "waf_detection"):
            try:
                await _run_waf_detection_checks(session, stored_scan_id)
            except ScanCancelled:
                raise
            except Exception:
                logger.exception("waf detection checks failed scan_id=%s", scan_id)
            await _ensure_not_cancelled(session, stored_scan_id)
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "csrf",
            lambda: _run_csrf_checks(session, stored_scan_id, html_bodies_by_page_id),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "file_upload",
            lambda: _run_file_upload_checks(
                session, stored_scan_id, html_bodies_by_page_id
            ),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "file_upload_advanced",
            lambda: _run_file_upload_advanced_checks(
                session, stored_scan_id, html_bodies_by_page_id
            ),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "cookies",
            lambda: _run_cookie_checks(session, stored_scan_id),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "auth_surface",
            lambda: _run_auth_surface_checks(
                session, stored_scan_id, html_bodies_by_page_id
            ),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "auth_advanced",
            lambda: _run_auth_advanced_checks(
                session, stored_scan_id, html_bodies_by_page_id
            ),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "cors",
            lambda: _run_cors_checks(session, stored_scan_id, target_base_url),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "headers",
            lambda: _run_header_checks(session, stored_scan_id),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "info_disclosure",
            lambda: _run_info_disclosure_checks(
                session, stored_scan_id, target_base_url
            ),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "exposure_paths",
            lambda: _run_exposure_path_checks(session, stored_scan_id, target_base_url),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "fingerprinting",
            lambda: _run_fingerprinting(
                session,
                stored_scan_id,
                html_bodies_by_page_id,
            ),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "performance",
            lambda: _run_performance_checks(session, stored_scan_id),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "seo",
            lambda: _run_seo_checks(session, stored_scan_id, html_bodies_by_page_id),
        )
        await _run_profiled_check(
            session,
            stored_scan_id,
            scan_profile,
            "active",
            lambda: _run_active_checks(session, stored_scan_id),
        )
        try:
            if should_run_scan_module(scan_profile, "rce"):
                await _run_rce_checks(session, stored_scan_id)
        except ScanCancelled:
            raise
        except Exception:
            logger.exception("rce checks failed scan_id=%s", scan_id)
        await _ensure_not_cancelled(session, stored_scan_id)
        try:
            if should_run_scan_module(scan_profile, "ssrf"):
                await _run_ssrf_checks(session, stored_scan_id)
        except ScanCancelled:
            raise
        except Exception:
            logger.exception("ssrf checks failed scan_id=%s", scan_id)
        await _ensure_not_cancelled(session, stored_scan_id)
        try:
            if should_run_scan_module(scan_profile, "stored_xss"):
                await _run_stored_xss_checks(
                    session,
                    stored_scan_id,
                    html_bodies_by_page_id,
                )
        except ScanCancelled:
            raise
        except Exception:
            logger.exception("stored xss checks failed scan_id=%s", scan_id)
        await _ensure_not_cancelled(session, stored_scan_id)
        logger.info("enrichment start scan_id=%s", scan_id)
        await enrich_scan_findings(session, stored_scan_id)
        await _ensure_not_cancelled(session, stored_scan_id)
        logger.info("enrichment end scan_id=%s", scan_id)
        total_findings = await count_findings_for_scan(session, stored_scan_id)
        await mark_scan_completed(
            session,
            scan,
            result.total_pages_found,
            total_findings,
        )
        logger.info(
            "scan complete scan_id=%s total_pages_found=%s total_findings=%s",
            scan_id,
            result.total_pages_found,
            total_findings,
        )
    except ScanCancelled:
        logger.info("scan cancelled scan_id=%s", scan_id)
    except Exception as exc:
        logger.exception("scan failed scan_id=%s", scan_id)
        await session.rollback()
        refreshed_scan = await get_scan_by_id(session, stored_scan_id)
        if refreshed_scan is None:
            return
        persisted_pages = len(await list_scan_pages(session, stored_scan_id))
        total_findings = await count_findings_for_scan(session, stored_scan_id)
        await mark_scan_failed(
            session,
            refreshed_scan,
            total_pages_found=max(refreshed_scan.total_pages_found, persisted_pages),
            total_findings=total_findings,
            error_message=str(exc),
        )
    finally:
        logger.info("scan end scan_id=%s", scan_id)


async def _run_header_checks(session: AsyncSession, scan_id: int) -> None:
    pages = await list_scan_pages(session, scan_id)

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        if page.status_code is None:
            continue
        issues = check_security_headers(page.url, page.response_headers or {})
        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_crawl_checks(session: AsyncSession, scan_id: int) -> None:
    pages = await list_scan_pages(session, scan_id)
    seen_page_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        issues = [
            issue
            for issue in check_crawl_page(page)
            if issue.dedupe_key not in seen_page_issue_keys
        ]
        seen_page_issue_keys.update(issue.dedupe_key for issue in issues)

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )

    await _create_findings_if_not_cancelled(
        session,
        scan_id=scan_id,
        scan_page_id=None,
        issues=check_redirect_chains(pages) + summarize_crawl_issues(pages),
    )


async def _run_waf_detection_checks(session: AsyncSession, scan_id: int) -> None:
    if not settings.enable_waf_detection:
        return

    pages = await list_scan_pages(session, scan_id)
    seen_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        issues = [
            issue
            for issue in detect_waf_from_headers(page.url, page.response_headers or {})
            if issue.dedupe_key not in seen_issue_keys
        ]
        seen_issue_keys.update(issue.dedupe_key for issue in issues)
        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=None,
            issues=issues,
        )

    if not settings.waf_detection_safe_probes or not pages:
        return

    baseline_page = next((page for page in pages if page.status_code is not None), None)
    if baseline_page is None:
        return

    baseline = WafProbeSnapshot(
        url=baseline_page.url,
        status_code=baseline_page.status_code,
        headers=baseline_page.response_headers or {},
        body=baseline_page.response_body_excerpt,
        page_title=baseline_page.page_title,
    )

    async with HttpClient(
        timeout_seconds=settings.waf_detection_timeout_seconds
    ) as client:
        probe_result = await client.get(build_waf_probe_url(baseline_page.url))
    if probe_result.error:
        logger.info(
            "waf detection probe skipped scan_id=%s url=%s error=%s",
            scan_id,
            baseline_page.url,
            probe_result.error,
        )
        return

    probe = WafProbeSnapshot(
        url=probe_result.url,
        status_code=probe_result.status_code,
        headers=probe_result.headers,
        body=probe_result.body,
        page_title=extract_title(probe_result.body),
    )
    behavior_issues = [
        issue
        for issue in detect_waf_behavior(baseline, probe)
        if issue.dedupe_key not in seen_issue_keys
    ]
    await _create_findings_if_not_cancelled(
        session,
        scan_id=scan_id,
        scan_page_id=None,
        issues=behavior_issues,
    )


async def _run_subdomain_discovery_checks(
    session: AsyncSession,
    scan_id: int,
    target_base_url: str,
    html_bodies_by_page_id: dict[int, str] | None = None,
) -> None:
    if not settings.enable_subdomain_discovery:
        return

    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}
    seen_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        html_content = html_bodies_by_page_id.get(page.id) or page.response_body_excerpt
        issues = [
            issue
            for issue in discover_subdomains_from_page(
                target_base_url,
                page.url,
                html_content,
                page.response_headers or {},
                max_results=settings.subdomain_discovery_max_results,
            )
            if issue.dedupe_key not in seen_issue_keys
        ]
        seen_issue_keys.update(issue.dedupe_key for issue in issues)
        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=None,
            issues=issues,
        )

        if len(seen_issue_keys) >= settings.subdomain_discovery_max_results:
            break


async def _run_csrf_checks(
    session: AsyncSession,
    scan_id: int,
    html_bodies_by_page_id: dict[int, str] | None = None,
) -> None:
    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}
    seen_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        html_content = html_bodies_by_page_id.get(page.id) or page.response_body_excerpt
        issues = [
            issue
            for issue in check_csrf_forms(page.url, html_content)
            if issue.dedupe_key not in seen_issue_keys
        ]
        seen_issue_keys.update(issue.dedupe_key for issue in issues)

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_file_upload_checks(
    session: AsyncSession,
    scan_id: int,
    html_bodies_by_page_id: dict[int, str] | None = None,
) -> None:
    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}
    seen_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        html_content = html_bodies_by_page_id.get(page.id) or page.response_body_excerpt
        issues = [
            issue
            for issue in check_file_upload_forms(page.url, html_content)
            if issue.dedupe_key not in seen_issue_keys
        ]
        seen_issue_keys.update(issue.dedupe_key for issue in issues)

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_file_upload_advanced_checks(
    session: AsyncSession,
    scan_id: int,
    html_bodies_by_page_id: dict[int, str] | None = None,
) -> None:
    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}
    seen_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        html_content = html_bodies_by_page_id.get(page.id) or page.response_body_excerpt
        issues = [
            issue
            for issue in check_file_upload_advanced(page.url, html_content)
            if issue.dedupe_key not in seen_issue_keys
        ]
        seen_issue_keys.update(issue.dedupe_key for issue in issues)

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_auth_surface_checks(
    session: AsyncSession,
    scan_id: int,
    html_bodies_by_page_id: dict[int, str] | None = None,
) -> None:
    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}
    seen_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        html_content = html_bodies_by_page_id.get(page.id) or page.response_body_excerpt
        issues = [
            issue
            for issue in check_auth_surface(
                page.url,
                html_content,
                page.response_headers or {},
            )
            if issue.dedupe_key not in seen_issue_keys
        ]
        seen_issue_keys.update(issue.dedupe_key for issue in issues)

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_auth_advanced_checks(
    session: AsyncSession,
    scan_id: int,
    html_bodies_by_page_id: dict[int, str] | None = None,
) -> None:
    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}
    seen_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        html_content = html_bodies_by_page_id.get(page.id) or page.response_body_excerpt
        issues = [
            issue
            for issue in check_auth_advanced(
                page.url,
                html_content,
                page.response_headers or {},
                page.status_code,
            )
            if issue.dedupe_key not in seen_issue_keys
        ]
        seen_issue_keys.update(issue.dedupe_key for issue in issues)

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_cors_checks(
    session: AsyncSession, scan_id: int, base_url: str
) -> None:
    pages = await list_scan_pages(session, scan_id)
    urls = []
    seen_urls = set()

    for url in [base_url, *(page.url for page in pages)]:
        if url not in seen_urls:
            urls.append(url)
            seen_urls.add(url)

    seen_issue_keys: set[str] = set()
    async with HttpClient() as client:
        for url in urls[:5]:
            await _ensure_not_cancelled(session, scan_id)
            for origin in TEST_ORIGINS:
                await _ensure_not_cancelled(session, scan_id)
                fetch_result = await client.get(url, headers={"Origin": origin})
                if fetch_result.error:
                    continue

                issues = [
                    issue
                    for issue in check_cors_headers(
                        fetch_result.url,
                        origin,
                        fetch_result.headers,
                    )
                    if issue.dedupe_key not in seen_issue_keys
                ]
                seen_issue_keys.update(issue.dedupe_key for issue in issues)

                await _create_findings_if_not_cancelled(
                    session,
                    scan_id=scan_id,
                    scan_page_id=None,
                    issues=issues,
                )


async def _run_cookie_checks(session: AsyncSession, scan_id: int) -> None:
    pages = await list_scan_pages(session, scan_id)
    seen_issue_keys: set[str] = set()

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        issues = [
            issue
            for issue in check_cookie_security(page.url, page.response_headers or {})
            if issue.dedupe_key not in seen_issue_keys
        ]
        seen_issue_keys.update(issue.dedupe_key for issue in issues)

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_transport_checks(
    session: AsyncSession, scan_id: int, base_url: str
) -> None:
    base_scheme = urlsplit(base_url).scheme.lower()
    target_http_url = http_variant(base_url)
    target_https_url = https_variant(base_url)

    async with HttpClient() as client:
        https_result = await client.get(target_https_url)
        https_available = not https_result.error and urlsplit(https_result.url).scheme == "https"
        http_result = await client.get(target_http_url)

    issues = []
    if base_scheme == "http" and not https_available:
        issues.extend(
            classify_transport(base_url, http_result.url, https_available=False)
        )
    elif not http_result.error:
        issues.extend(
            classify_transport(
                target_http_url,
                http_result.url,
                https_available=https_available,
            )
        )

    await _create_findings_if_not_cancelled(
        session,
        scan_id=scan_id,
        scan_page_id=None,
        issues=issues,
    )

    pages = await list_scan_pages(session, scan_id)
    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        mixed_content_issues = check_mixed_content(
            page.url, page.response_body_excerpt
        )
        if not mixed_content_issues:
            continue

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=None,
            issues=mixed_content_issues,
        )
        break


async def _run_info_disclosure_checks(
    session: AsyncSession, scan_id: int, base_url: str
) -> None:
    pages = await list_scan_pages(session, scan_id)

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        if page.status_code is None:
            continue

        banner_issues = check_banner_exposure(page.url, page.response_headers or {})
        debug_issues = check_debug_exposure(
            page.url, page.page_title, page.response_body_excerpt
        )
        directory_issues = check_directory_listing(
            page.url, page.page_title, page.response_body_excerpt
        )

        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=banner_issues + debug_issues + directory_issues,
        )


async def _run_exposure_path_checks(
    session: AsyncSession, scan_id: int, base_url: str
) -> None:
    seen_paths: set[str] = set()

    async with HttpClient() as client:
        for path in EXPOSURE_PATHS:
            await _ensure_not_cancelled(session, scan_id)
            if path in seen_paths:
                continue
            seen_paths.add(path)

            url = build_exposure_url(base_url, path)
            fetch_result = await client.get(url)
            if fetch_result.error:
                continue

            issues = classify_exposure_path(
                path,
                fetch_result.url,
                fetch_result.status_code,
                fetch_result.body,
                fetch_result.content_type,
            )
            await _create_findings_if_not_cancelled(
                session,
                scan_id=scan_id,
                scan_page_id=None,
                issues=issues,
            )


async def _run_fingerprinting(
    session: AsyncSession, scan_id: int, html_bodies_by_page_id: dict[int, str] | None = None
) -> None:
    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        try:
            await detect_and_store_page_technologies(
                session,
                scan_id=scan_id,
                scan_page_id=page.id,
                headers=page.response_headers,
                body_excerpt=page.response_body_excerpt,
                full_html=html_bodies_by_page_id.get(page.id),
            )
        except Exception:
            continue


async def _run_performance_checks(session: AsyncSession, scan_id: int) -> None:
    pages = await list_scan_pages(session, scan_id)

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        issues = check_performance(
            page_url=page.url,
            status_code=page.status_code,
            content_type=page.content_type,
            response_time_ms=page.response_time_ms,
            headers=page.response_headers or {},
        )
        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_seo_checks(
    session: AsyncSession,
    scan_id: int,
    html_bodies_by_page_id: dict[int, str] | None = None,
) -> None:
    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        issues = check_seo(
            page_url=page.url,
            status_code=page.status_code,
            content_type=page.content_type,
            page_title=page.page_title,
            html_content=html_bodies_by_page_id.get(page.id) or page.response_body_excerpt,
        )
        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_active_checks(session: AsyncSession, scan_id: int) -> None:
    pages = await list_scan_pages(session, scan_id)

    async with HttpClient() as client:
        for page in pages:
            await _ensure_not_cancelled(session, scan_id)
            try:
                await _run_open_redirect_checks_for_page(session, client, scan_id, page)
                await _run_reflected_xss_checks_for_page(session, client, scan_id, page)
                await _run_sqli_light_checks_for_page(session, client, scan_id, page)
                await _run_sqli_advanced_checks_for_page(session, scan_id, page)
            except Exception:
                logger.exception(
                    "active checks failed scan_id=%s page_id=%s",
                    scan_id,
                    getattr(page, "id", None),
                )
                continue


async def _run_open_redirect_checks_for_page(
    session: AsyncSession, client: HttpClient, scan_id: int, page: object
) -> None:
    for param_name in extract_redirect_parameters(page.url, page.response_body_excerpt):
        await _ensure_not_cancelled(session, scan_id)
        fetch_result = await client.get(
            build_redirect_probe_url(page.url, param_name, REDIRECT_PROBE_URL),
            follow_redirects=False,
        )
        if fetch_result.error:
            continue

        issues = check_open_redirect(
            page.url,
            param_name,
            fetch_result.headers.get("location"),
            fetch_result.url,
        )
        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_reflected_xss_checks_for_page(
    session: AsyncSession, client: HttpClient, scan_id: int, page: object
) -> None:
    for param_name in extract_reflection_parameters(page.url, page.response_body_excerpt)[:5]:
        await _ensure_not_cancelled(session, scan_id)
        marker = build_reflection_marker()
        fetch_result = await client.get(
            build_reflection_probe_url(page.url, param_name, marker)
        )
        if fetch_result.error:
            continue

        issues = check_reflected_xss(
            page.url,
            param_name,
            marker,
            fetch_result.body,
        )
        await _create_findings_if_not_cancelled(
            session,
            scan_id=scan_id,
            scan_page_id=page.id,
            issues=issues,
        )


async def _run_sqli_light_checks_for_page(
    session: AsyncSession, client: HttpClient, scan_id: int, page: object
) -> None:
    for param_name in extract_sqli_parameters(page.url, page.response_body_excerpt)[:3]:
        await _ensure_not_cancelled(session, scan_id)
        baseline_result = await client.get(page.url)
        if baseline_result.error:
            continue

        for probe in SQLI_LIGHT_PROBES:
            await _ensure_not_cancelled(session, scan_id)
            fetch_result = await client.get(build_sqli_probe_url(page.url, param_name, probe))
            if fetch_result.error:
                continue

            issues = check_sqli_light(
                page.url,
                param_name,
                probe,
                fetch_result.body,
                baseline_status_code=baseline_result.status_code,
                baseline_body=baseline_result.body,
                probe_status_code=fetch_result.status_code,
            )
            await _create_findings_if_not_cancelled(
                session,
                scan_id=scan_id,
                scan_page_id=page.id,
                issues=issues,
            )
            if issues:
                break


async def _run_ssrf_checks(
    session: AsyncSession, scan_id: int
) -> None:
    if not settings.enable_ssrf_checks or not settings.ssrf_callback_url:
        return

    pages = await list_scan_pages(session, scan_id)
    seen_issue_keys: set[str] = set()
    tested_params = 0
    async with HttpClient(timeout_seconds=settings.ssrf_timeout_seconds) as client:
        for page in pages:
            await _ensure_not_cancelled(session, scan_id)
            remaining = settings.ssrf_max_params - tested_params
            if remaining <= 0:
                return

            param_names = extract_ssrf_parameters(
                page.url,
                page.response_body_excerpt,
                max_params=remaining,
            )
            for param_name in param_names:
                await _ensure_not_cancelled(session, scan_id)
                if tested_params >= settings.ssrf_max_params:
                    return
                tested_params += 1

                probe_url = build_ssrf_probe_url(
                    page.url,
                    param_name,
                    settings.ssrf_callback_url,
                )
                if probe_url is None:
                    continue

                fetch_result = await client.get(probe_url)
                if fetch_result.error:
                    continue

                issues = [
                    issue
                    for issue in check_ssrf_response(
                        page_url=page.url,
                        param_name=param_name,
                        callback_url=settings.ssrf_callback_url,
                        response_body=fetch_result.body,
                        callback_confirmed=False,
                    )
                    if issue.dedupe_key not in seen_issue_keys
                ]
                seen_issue_keys.update(issue.dedupe_key for issue in issues)
                await _create_findings_if_not_cancelled(
                    session,
                    scan_id=scan_id,
                    scan_page_id=page.id,
                    issues=issues,
                )


async def _run_rce_checks(
    session: AsyncSession, scan_id: int
) -> None:
    if not settings.enable_rce_checks:
        return

    pages = await list_scan_pages(session, scan_id)
    seen_issue_keys: set[str] = set()
    tested_params = 0

    async with HttpClient(timeout_seconds=settings.rce_timeout_seconds) as client:
        for page in pages:
            await _ensure_not_cancelled(session, scan_id)
            remaining = settings.rce_max_params - tested_params
            if remaining <= 0:
                return

            param_names = extract_rce_parameters(
                page.url,
                page.response_body_excerpt,
                max_params=remaining,
            )
            for param_name in param_names:
                await _ensure_not_cancelled(session, scan_id)
                if tested_params >= settings.rce_max_params:
                    return
                tested_params += 1

                for probe_family, probe in RCE_PROBES:
                    await _ensure_not_cancelled(session, scan_id)
                    fetch_result = await client.get(
                        build_rce_probe_url(page.url, param_name, probe)
                    )
                    if fetch_result.error:
                        continue

                    issues = [
                        issue
                        for issue in check_rce_response(
                            page_url=page.url,
                            param_name=param_name,
                            probe_family=probe_family,
                            response_body=fetch_result.body,
                        )
                        if issue.dedupe_key not in seen_issue_keys
                    ]
                    seen_issue_keys.update(issue.dedupe_key for issue in issues)
                    await _create_findings_if_not_cancelled(
                        session,
                        scan_id=scan_id,
                        scan_page_id=page.id,
                        issues=issues,
                    )
                    if issues:
                        break


async def _run_sqli_advanced_checks_for_page(
    session: AsyncSession, scan_id: int, page: object
) -> None:
    if not settings.enable_advanced_sqli_checks:
        return

    param_names = extract_advanced_sqli_parameters(
        page.url,
        page.response_body_excerpt,
        max_params=settings.advanced_sqli_max_params,
    )
    if not param_names:
        return

    probe_limit = max(settings.advanced_sqli_max_probes_per_param, 0)
    seen_issue_keys: set[str] = set()
    async with HttpClient(timeout_seconds=settings.advanced_sqli_timeout_seconds) as client:
        baseline_result = await client.get(page.url)
        if baseline_result.error or not is_same_origin_url(page.url, baseline_result.url):
            return

        baseline = ResponseSnapshot(
            baseline_result.status_code,
            baseline_result.body,
            baseline_result.response_time_ms,
        )

        for param_name in param_names:
            await _ensure_not_cancelled(session, scan_id)
            probes_used = 0
            boolean_issue_found = False

            for dbms_hint, true_probe, false_probe in boolean_probe_pairs_for_budget(
                probe_limit
            ):
                if probes_used + 2 > probe_limit:
                    break

                true_result = await client.get(
                    build_advanced_sqli_probe_url(page.url, param_name, true_probe)
                )
                false_result = await client.get(
                    build_advanced_sqli_probe_url(page.url, param_name, false_probe)
                )
                probes_used += 2
                if (
                    true_result.error
                    or false_result.error
                    or not is_same_origin_url(page.url, true_result.url)
                    or not is_same_origin_url(page.url, false_result.url)
                ):
                    continue

                repeat_confirmed = False
                if probes_used + 2 <= probe_limit:
                    repeat_true = await client.get(
                        build_advanced_sqli_probe_url(page.url, param_name, true_probe)
                    )
                    repeat_false = await client.get(
                        build_advanced_sqli_probe_url(page.url, param_name, false_probe)
                    )
                    probes_used += 2
                    if (
                        not repeat_true.error
                        and not repeat_false.error
                        and is_same_origin_url(page.url, repeat_true.url)
                        and is_same_origin_url(page.url, repeat_false.url)
                    ):
                        repeat_issues = check_boolean_sqli(
                            page.url,
                            param_name,
                            baseline,
                            ResponseSnapshot(
                                repeat_true.status_code,
                                repeat_true.body,
                                repeat_true.response_time_ms,
                            ),
                            ResponseSnapshot(
                                repeat_false.status_code,
                                repeat_false.body,
                                repeat_false.response_time_ms,
                            ),
                            repeat_confirmed=True,
                            dbms_hint=dbms_hint,
                        )
                        repeat_confirmed = bool(repeat_issues)

                issues = [
                    issue
                    for issue in check_boolean_sqli(
                        page.url,
                        param_name,
                        baseline,
                        ResponseSnapshot(
                            true_result.status_code,
                            true_result.body,
                            true_result.response_time_ms,
                        ),
                        ResponseSnapshot(
                            false_result.status_code,
                            false_result.body,
                            false_result.response_time_ms,
                        ),
                        repeat_confirmed=repeat_confirmed,
                        dbms_hint=dbms_hint,
                    )
                    if issue.dedupe_key not in seen_issue_keys
                ]
                seen_issue_keys.update(issue.dedupe_key for issue in issues)
                await _create_findings_if_not_cancelled(
                    session,
                    scan_id=scan_id,
                    scan_page_id=page.id,
                    issues=issues,
                )
                if issues:
                    boolean_issue_found = True
                    break

            if boolean_issue_found or probes_used >= probe_limit:
                continue

            timing_probe = TIMING_PROBES[0]
            dbms_hint, probe = timing_probe
            timing_result = await client.get(
                build_advanced_sqli_probe_url(page.url, param_name, probe)
            )
            probes_used += 1
            if (
                timing_result.error
                or not is_same_origin_url(page.url, timing_result.url)
            ):
                continue

            repeat_result = None
            first_timing_issues = check_timing_sqli(
                page.url,
                param_name,
                baseline,
                ResponseSnapshot(
                    timing_result.status_code,
                    timing_result.body,
                    timing_result.response_time_ms,
                ),
                dbms_hint=dbms_hint,
            )
            if first_timing_issues and probes_used < probe_limit:
                repeat_result = await client.get(
                    build_advanced_sqli_probe_url(page.url, param_name, probe)
                )
                probes_used += 1

            issues = [
                issue
                for issue in check_timing_sqli(
                    page.url,
                    param_name,
                    baseline,
                    ResponseSnapshot(
                        timing_result.status_code,
                        timing_result.body,
                        timing_result.response_time_ms,
                    ),
                    repeat_response=ResponseSnapshot(
                        repeat_result.status_code,
                        repeat_result.body,
                        repeat_result.response_time_ms,
                    )
                    if repeat_result
                    and not repeat_result.error
                    and is_same_origin_url(page.url, repeat_result.url)
                    else None,
                    dbms_hint=dbms_hint,
                )
                if issue.dedupe_key not in seen_issue_keys
            ]
            seen_issue_keys.update(issue.dedupe_key for issue in issues)
            await _create_findings_if_not_cancelled(
                session,
                scan_id=scan_id,
                scan_page_id=page.id,
                issues=issues,
            )


async def _run_stored_xss_checks(
    session: AsyncSession,
    scan_id: int,
    html_bodies_by_page_id: dict[int, str] | None = None,
) -> None:
    if not settings.enable_stored_xss_checks:
        return

    pages = await list_scan_pages(session, scan_id)
    html_bodies_by_page_id = html_bodies_by_page_id or {}
    selected_forms = []

    for page in pages:
        await _ensure_not_cancelled(session, scan_id)
        if len(selected_forms) >= settings.stored_xss_max_forms:
            break

        html_content = html_bodies_by_page_id.get(page.id) or page.response_body_excerpt
        remaining = settings.stored_xss_max_forms - len(selected_forms)
        forms = select_safe_stored_xss_forms(
            page.url,
            html_content,
            max_forms=remaining,
        )
        selected_forms.extend((page, form) for form in forms)

    if not selected_forms:
        return

    seen_issue_keys: set[str] = set()
    async with HttpClient() as client:
        for page, form in selected_forms:
            await _ensure_not_cancelled(session, scan_id)
            marker = build_stored_xss_marker()
            submission = build_stored_xss_submission(form, marker)
            if submission is None:
                continue

            try:
                submit_result = await client.post(
                    form.action_url,
                    data=submission,
                    follow_redirects=True,
                )
            except Exception:
                logger.exception(
                    "stored xss submit failed scan_id=%s url=%s",
                    scan_id,
                    form.action_url,
                )
                continue

            if submit_result.error:
                continue

            revisit_urls = _stored_xss_revisit_urls(
                form.page_url,
                submit_result.url,
                [candidate.url for candidate in pages],
                max_pages=settings.stored_xss_revisit_max_pages,
            )
            verified_urls = await verify_stored_xss_execution(
                revisit_urls,
                marker,
                enabled=settings.enable_stored_xss_browser_verify,
            )

            for revisit_url in revisit_urls:
                await _ensure_not_cancelled(session, scan_id)
                fetch_result = await client.get(revisit_url)
                if fetch_result.error:
                    continue

                issues = [
                    issue
                    for issue in check_stored_xss_response(
                        form=form,
                        marker=marker,
                        revisit_url=fetch_result.url,
                        response_body=fetch_result.body,
                        browser_verified=revisit_url in verified_urls
                        or fetch_result.url in verified_urls,
                    )
                    if issue.dedupe_key not in seen_issue_keys
                ]
                seen_issue_keys.update(issue.dedupe_key for issue in issues)

                await _create_findings_if_not_cancelled(
                    session,
                    scan_id=scan_id,
                    scan_page_id=page.id,
                    issues=issues,
                )


def _stored_xss_revisit_urls(
    form_page_url: str,
    response_url: str,
    crawled_urls: list[str],
    *,
    max_pages: int,
) -> list[str]:
    urls: list[str] = []
    seen_urls: set[str] = set()

    for url in [form_page_url, response_url, *crawled_urls[:max_pages]]:
        if not url or url in seen_urls:
            continue
        if not is_same_origin(form_page_url, url):
            continue
        urls.append(url)
        seen_urls.add(url)

    return urls
