import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit


@dataclass(frozen=True)
class TechnologyMatch:
    product_name: str
    category: str
    version: str | None
    vendor: str | None
    confidence_score: float | None
    detection_method: str


GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9_-]+)/", re.IGNORECASE)
THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9_-]+)/", re.IGNORECASE)
ASSET_URL_RE = re.compile(
    r"""(?:src|href)=["']([^"']+)["']""",
    re.IGNORECASE,
)
ELEMENTOR_CLASS_RE = re.compile(
    r"""class=["'][^"']*\belementor(?:-[a-z0-9_-]+)?\b[^"']*["']""",
    re.IGNORECASE,
)
ELEMENTOR_ASSET_RE = re.compile(
    r"""(?:^|/)(?:elementor(?:/|[-_.]))""",
    re.IGNORECASE,
)
WP_CORE_ASSET_VERSION_RE = re.compile(
    r"""(?:wp-(?:includes|admin)/[^"'?#]+\.(?:css|js)\?[^"'#]*\bver=)([0-9]+(?:\.[0-9]+)+)""",
    re.IGNORECASE,
)
QUERY_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")


def detect_from_html(body_excerpt: str | None) -> list[TechnologyMatch]:
    if not body_excerpt:
        return []

    matches: list[TechnologyMatch] = []
    lower_body = body_excerpt.lower()

    generator_match = GENERATOR_RE.search(body_excerpt)
    if generator_match:
        matches.extend(_detect_from_generator(generator_match.group(1)))

    wp_asset_version = _detect_wordpress_asset_version(body_excerpt)
    if wp_asset_version:
        matches.append(
            TechnologyMatch(
                product_name="WordPress",
                category="cms",
                version=wp_asset_version,
                vendor="WordPress Foundation",
                confidence_score=0.8,
                detection_method="html_pattern",
            )
        )

    asset_urls = ASSET_URL_RE.findall(body_excerpt)
    matches.extend(_detect_wordpress_plugins(asset_urls))
    matches.extend(_detect_wordpress_theme(asset_urls))
    matches.extend(_detect_elementor(asset_urls, body_excerpt))

    html_patterns = [
        ("wp-content/", "WordPress", "cms", "WordPress Foundation"),
        ("wp-includes/", "WordPress", "cms", "WordPress Foundation"),
        ("/sites/default/", "Drupal", "cms", "Drupal Association"),
        ("joomla!", "Joomla", "cms", "Open Source Matters"),
        ("cdn.shopify.com", "Shopify", "platform", "Shopify"),
        ("static.wixstatic.com", "Wix", "platform", "Wix"),
    ]

    for pattern, product_name, category, vendor in html_patterns:
        if pattern in lower_body:
            matches.append(
                TechnologyMatch(
                    product_name=product_name,
                    category=category,
                    version=None,
                    vendor=vendor,
                    confidence_score=0.6,
                    detection_method="html_pattern",
                )
            )

    return _dedupe_matches(matches)


def _detect_wordpress_asset_version(body_excerpt: str) -> str | None:
    match = WP_CORE_ASSET_VERSION_RE.search(body_excerpt)
    return match.group(1) if match else None


def _detect_from_generator(generator_content: str) -> list[TechnologyMatch]:
    lower_content = generator_content.lower()
    products = [
        ("wordpress", "WordPress", "cms", "WordPress Foundation"),
        ("drupal", "Drupal", "cms", "Drupal Association"),
        ("joomla", "Joomla", "cms", "Open Source Matters"),
        ("shopify", "Shopify", "platform", "Shopify"),
        ("wix", "Wix", "platform", "Wix"),
    ]

    matches: list[TechnologyMatch] = []
    for needle, product_name, category, vendor in products:
        if needle in lower_content:
            version_match = re.search(r"([0-9]+(?:\.[0-9]+)+)", generator_content)
            matches.append(
                TechnologyMatch(
                    product_name=product_name,
                    category=category,
                    version=version_match.group(1) if version_match else None,
                    vendor=vendor,
                    confidence_score=0.95 if version_match else 0.9,
                    detection_method="meta_generator",
                )
            )
    return matches


def _extract_query_version(asset_url: str) -> str | None:
    query_values = parse_qs(urlsplit(asset_url).query)
    for value in query_values.get("ver", []):
        if QUERY_VERSION_RE.fullmatch(value):
            return value
    return None


def _detect_wordpress_plugins(asset_urls: list[str]) -> list[TechnologyMatch]:
    slug_versions: dict[str, str | None] = {}
    for asset_url in asset_urls:
        match = PLUGIN_RE.search(asset_url)
        if not match:
            continue
        slug = match.group(1).lower()
        version = _extract_query_version(asset_url)
        if slug not in slug_versions or (slug_versions[slug] is None and version):
            slug_versions[slug] = version

    return [
        TechnologyMatch(
            product_name=f"WordPress Plugin: {slug}",
            category="cms_plugin",
            version=version,
            vendor=None,
            confidence_score=0.9 if version else 0.8,
            detection_method="html_pattern",
        )
        for slug, version in sorted(slug_versions.items())
    ]


def _detect_wordpress_theme(asset_urls: list[str]) -> list[TechnologyMatch]:
    slug_versions: dict[str, str | None] = {}
    for asset_url in asset_urls:
        match = THEME_RE.search(asset_url)
        if not match:
            continue
        slug = match.group(1).lower()
        version = _extract_query_version(asset_url)
        if slug not in slug_versions or (slug_versions[slug] is None and version):
            slug_versions[slug] = version

    return [
        TechnologyMatch(
            product_name=f"WordPress Theme: {slug}",
            category="cms_theme",
            version=version,
            vendor=None,
            confidence_score=0.9 if version else 0.8,
            detection_method="html_pattern",
        )
        for slug, version in sorted(slug_versions.items())
    ]


def _detect_elementor(
    asset_urls: list[str], body_excerpt: str
) -> list[TechnologyMatch]:
    elementor_version: str | None = None
    has_direct_asset_evidence = False

    for asset_url in asset_urls:
        lower_asset_url = asset_url.lower()
        if (
            "/wp-content/plugins/elementor/" in lower_asset_url
            or "/wp-content/uploads/elementor/" in lower_asset_url
            or ELEMENTOR_ASSET_RE.search(lower_asset_url)
        ):
            has_direct_asset_evidence = True
            version = _extract_query_version(asset_url)
            if elementor_version is None and version:
                elementor_version = version

    if has_direct_asset_evidence:
        return [
            TechnologyMatch(
                product_name="Elementor",
                category="cms_plugin",
                version=elementor_version,
                vendor=None,
                confidence_score=0.9 if elementor_version else 0.8,
                detection_method="html_pattern",
            )
        ]

    if ELEMENTOR_CLASS_RE.search(body_excerpt):
        return [
            TechnologyMatch(
                product_name="Elementor",
                category="cms_plugin",
                version=None,
                vendor=None,
                confidence_score=0.6,
                detection_method="html_pattern",
            )
        ]

    return []


def _dedupe_matches(matches: list[TechnologyMatch]) -> list[TechnologyMatch]:
    deduped: dict[tuple[str, str, str | None, str], TechnologyMatch] = {}
    for match in matches:
        key = (
            match.product_name,
            match.category,
            match.version,
            match.detection_method,
        )
        existing = deduped.get(key)
        if existing is None or (match.confidence_score or 0) > (
            existing.confidence_score or 0
        ):
            deduped[key] = match
    return _collapse_wordpress_core_matches(list(deduped.values()))


def _collapse_wordpress_core_matches(
    matches: list[TechnologyMatch],
) -> list[TechnologyMatch]:
    core_matches = [
        match
        for match in matches
        if match.product_name == "WordPress" and match.category == "cms"
    ]
    if len(core_matches) <= 1:
        return matches

    best_core_match = max(core_matches, key=_wordpress_core_rank)
    return [
        match
        for match in matches
        if not (match.product_name == "WordPress" and match.category == "cms")
    ] + [best_core_match]


def _wordpress_core_rank(match: TechnologyMatch) -> tuple[int, int, float]:
    method_rank = {
        "meta_generator": 3,
        "html_pattern": 2,
        "script_src": 1,
    }.get(match.detection_method, 0)
    version_rank = 1 if match.version else 0
    confidence_rank = match.confidence_score or 0.0
    return (method_rank, version_rank, confidence_rank)
