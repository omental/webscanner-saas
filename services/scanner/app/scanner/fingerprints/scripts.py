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


SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
VERSION_RE = re.compile(r"([0-9]+(?:\.[0-9]+)+)")
QUERY_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")


def detect_from_script_src(body_excerpt: str | None) -> list[TechnologyMatch]:
    if not body_excerpt:
        return []

    script_sources = SCRIPT_RE.findall(body_excerpt)
    matches: list[TechnologyMatch] = []

    patterns = [
        ("jquery-migrate", "jQuery Migrate", "js_library", "OpenJS Foundation"),
        ("jquery", "jQuery", "js_library", "OpenJS Foundation"),
        ("react", "React", "js_library", "Meta"),
        ("vue", "Vue.js", "js_library", "Vue"),
        ("alpine", "Alpine.js", "js_library", "Alpine"),
        ("bootstrap", "Bootstrap", "js_library", "Bootstrap"),
        ("slick", "Slick", "js_library", "kenwheeler"),
        ("swiper", "Swiper", "js_library", "Swiper"),
    ]

    for script_src in script_sources:
        lower_src = script_src.lower()
        for needle, product_name, category, vendor in patterns:
            if needle in lower_src:
                version = _extract_script_version(script_src, lower_src, product_name)
                matches.append(
                    TechnologyMatch(
                        product_name=product_name,
                        category=category,
                        version=version,
                        vendor=vendor,
                        confidence_score=0.95 if version else 0.75,
                        detection_method="script_src",
                    )
                )

    return matches


def _extract_script_version(
    script_src: str, lower_src: str, product_name: str
) -> str | None:
    parsed = urlsplit(script_src)
    filename = parsed.path.rsplit("/", 1)[-1]
    version_match = VERSION_RE.search(filename)
    if version_match:
        return version_match.group(1)

    query_values = parse_qs(parsed.query)
    version_values = query_values.get("ver", [])
    for value in version_values:
        if QUERY_VERSION_RE.fullmatch(value):
            return value

    version_match = VERSION_RE.search(lower_src)
    return version_match.group(1) if version_match else None
