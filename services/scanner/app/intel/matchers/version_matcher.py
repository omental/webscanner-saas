from dataclasses import dataclass
import re


def normalize_name(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


def normalize_version(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


def parse_version_parts(value: str | None) -> tuple[int, ...] | None:
    normalized = normalize_version(value)
    if normalized is None:
        return None

    parts: list[int] = []
    for token in re.split(r"[^0-9]+", normalized):
        if not token:
            continue
        parts.append(int(token))

    return tuple(parts) or None


def compare_versions(left: str | None, right: str | None) -> int | None:
    left_parts = parse_version_parts(left)
    right_parts = parse_version_parts(right)
    if left_parts is None or right_parts is None:
        return None

    max_len = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (max_len - len(left_parts))
    padded_right = right_parts + (0,) * (max_len - len(right_parts))

    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def is_version_in_range(
    *,
    version: str | None,
    version_start: str | None,
    version_end: str | None,
) -> bool:
    if normalize_version(version) is None:
        return False

    if version_start is not None:
        start_cmp = compare_versions(version, version_start)
        if start_cmp is None or start_cmp < 0:
            return False

    if version_end is not None:
        end_cmp = compare_versions(version, version_end)
        if end_cmp is None or end_cmp > 0:
            return False

    return version_start is not None or version_end is not None


@dataclass(frozen=True)
class VersionMatchResult:
    is_match: bool
    confidence: str | None = None


def match_technology_to_product(
    *,
    technology_product: str,
    technology_version: str | None,
    technology_vendor: str | None,
    product_name: str,
    product_vendor: str | None,
    product_version_exact: str | None,
) -> VersionMatchResult:
    normalized_technology_product = normalize_name(technology_product)
    normalized_product_name = normalize_name(product_name)
    if normalized_technology_product != normalized_product_name:
        return VersionMatchResult(is_match=False)

    normalized_technology_version = normalize_version(technology_version)
    normalized_product_version = normalize_version(product_version_exact)
    normalized_technology_vendor = normalize_name(technology_vendor)
    normalized_product_vendor = normalize_name(product_vendor)

    if normalized_technology_version and normalized_product_version:
        if normalized_technology_version != normalized_product_version:
            return VersionMatchResult(is_match=False)
        if (
            normalized_technology_vendor
            and normalized_product_vendor
            and normalized_technology_vendor == normalized_product_vendor
        ):
            return VersionMatchResult(is_match=True, confidence="high")
        return VersionMatchResult(is_match=True, confidence="medium")

    if normalized_technology_version and not normalized_product_version:
        return VersionMatchResult(is_match=False)

    if normalized_technology_vendor and normalized_product_vendor:
        if normalized_technology_vendor != normalized_product_vendor:
            return VersionMatchResult(is_match=False)
        return VersionMatchResult(is_match=True, confidence="low")

    return VersionMatchResult(is_match=True, confidence="low")
