from __future__ import annotations

from dataclasses import dataclass


ALLOWED_SCAN_PROFILES = frozenset(
    {"passive", "quick", "standard", "deep", "aggressive"}
)
DEFAULT_SCAN_PROFILE = "standard"

PASSIVE_CHECKS = frozenset(
    {
        "transport",
        "crawl",
        "cookies",
        "cors",
        "headers",
        "info_disclosure",
        "fingerprinting",
        "performance",
        "seo",
    }
)
QUICK_CHECKS = PASSIVE_CHECKS | frozenset(
    {
        "subdomain_discovery",
        "waf_detection",
        "csrf",
        "file_upload",
        "auth_surface",
    }
)
FULL_CHECKS = QUICK_CHECKS | frozenset(
    {
        "file_upload_advanced",
        "auth_advanced",
        "exposure_paths",
        "active",
        "rce",
        "ssrf",
        "stored_xss",
    }
)


@dataclass(frozen=True)
class CrawlProfile:
    max_depth: int | None
    max_pages: int | None
    timeout_seconds: int | None


def normalize_scan_profile(value: object) -> str:
    profile = str(value or DEFAULT_SCAN_PROFILE).strip().lower()
    if profile not in ALLOWED_SCAN_PROFILES:
        return DEFAULT_SCAN_PROFILE
    return profile


def should_run_scan_module(profile: object, module_name: str) -> bool:
    normalized = normalize_scan_profile(profile)
    if normalized == "passive":
        return module_name in PASSIVE_CHECKS
    if normalized == "quick":
        return module_name in QUICK_CHECKS
    return module_name in FULL_CHECKS


def crawl_profile_for_scan(
    profile: object,
    *,
    max_depth: int | None,
    max_pages: int | None,
    timeout_seconds: int | None,
) -> CrawlProfile:
    normalized = normalize_scan_profile(profile)
    defaults = {
        "passive": (1, 10),
        "quick": (1, 15),
        "standard": (None, None),
        "deep": (4, 100),
        "aggressive": (5, 250),
    }
    profile_depth, profile_pages = defaults[normalized]
    return CrawlProfile(
        max_depth=max_depth if max_depth is not None else profile_depth,
        max_pages=max_pages if max_pages is not None else profile_pages,
        timeout_seconds=timeout_seconds,
    )
