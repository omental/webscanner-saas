import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass(frozen=True)
class WafIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class WafProbeSnapshot:
    url: str
    status_code: int | None
    headers: Mapping[str, str]
    body: str | None = None
    page_title: str | None = None


PROBE_PARAM_NAME = "webscanner_waf_probe"
PROBE_PARAM_VALUE = "SCANNER_TEST_MARKER"
BLOCK_STATUS_CODES = {403, 406, 429}
CHALLENGE_PATTERNS = (
    "access denied",
    "attention required",
    "blocked by",
    "bot detection",
    "captcha",
    "challenge",
    "cloudflare ray id",
    "incapsula incident id",
    "request blocked",
    "security check",
    "sucuri website firewall",
    "temporarily blocked",
    "the requested url was rejected",
    "web application firewall",
    "wordfence",
)

HEADER_VENDOR_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("cf-ray", "Cloudflare", ()),
    ("cf-cache-status", "Cloudflare", ()),
    ("server", "Cloudflare", ("cloudflare",)),
    ("set-cookie", "Cloudflare", ("__cf_bm", "cf_clearance", "__cflb")),
    ("x-sucuri-id", "Sucuri", ()),
    ("x-sucuri-cache", "Sucuri", ()),
    ("server", "Sucuri", ("sucuri",)),
    ("set-cookie", "Sucuri", ("sucuri_cloudproxy_uuid",)),
    ("x-akamai", "Akamai", ()),
    ("server", "Akamai", ("akamai",)),
    ("via", "Akamai", ("akamai",)),
    ("x-cache", "Akamai", ("akamai",)),
    ("x-amz-cf-id", "AWS CloudFront", ()),
    ("via", "AWS CloudFront", ("cloudfront",)),
    ("x-cache", "AWS CloudFront", ("cloudfront",)),
    ("server", "AWS CloudFront", ("cloudfront",)),
    ("x-cache", "Fastly", ("fastly",)),
    ("via", "Fastly", ("fastly",)),
    ("x-cdn", "Fastly", ("fastly",)),
    ("server", "Fastly", ("fastly",)),
    ("set-cookie", "Imperva / Incapsula", ("incap_ses", "visid_incap")),
    ("x-cdn", "Imperva / Incapsula", ("incapsula", "imperva")),
    ("server", "Imperva / Incapsula", ("incapsula", "imperva")),
    ("x-firewall", "Wordfence", ("wordfence",)),
    ("x-waf", "Wordfence", ("wordfence",)),
    ("x-powered-by", "Wordfence", ("wordfence",)),
    ("set-cookie", "Wordfence", ("wordfence", "wfvt_", "wfwaf-authcookie")),
    ("x-firewall", "ModSecurity", ("mod_security", "modsecurity")),
    ("x-waf", "ModSecurity", ("mod_security", "modsecurity")),
    ("server", "ModSecurity", ("mod_security", "modsecurity")),
    ("server", "LiteSpeed", ("litespeed", "openlitespeed")),
    ("x-firewall", "LiteSpeed", ("litespeed",)),
    ("x-waf", "LiteSpeed", ("litespeed",)),
    ("x-firewall", "nginx security module", ("nginx", "naxsi")),
    ("x-waf", "nginx security module", ("nginx", "naxsi")),
    ("x-firewall", "Apache security module", ("apache", "mod_security")),
    ("x-waf", "Apache security module", ("apache", "mod_security")),
)


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._inside_title = False
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self._inside_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            self._parts.append(data)

    @property
    def title(self) -> str | None:
        title = " ".join("".join(self._parts).split())
        return title or None


def build_waf_probe_url(url: str) -> str:
    parts = urlsplit(url)
    query_items = parse_qsl(parts.query, keep_blank_values=True)
    query_items.append((PROBE_PARAM_NAME, PROBE_PARAM_VALUE))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", urlencode(query_items), "")
    )


def extract_title(body: str | None) -> str | None:
    if not body:
        return None
    parser = _TitleParser()
    parser.feed(body[:5000])
    return parser.title


def detect_waf_from_headers(
    page_url: str, headers: Mapping[str, str]
) -> list[WafIssue]:
    normalized_headers = _normalize_headers(headers)
    issues: list[WafIssue] = []
    seen_vendors: set[str] = set()

    for header_name, vendor, required_values in HEADER_VENDOR_RULES:
        value = normalized_headers.get(header_name)
        if not value:
            continue
        value_lower = value.lower()
        if required_values and not any(token in value_lower for token in required_values):
            continue
        if vendor in seen_vendors:
            continue
        seen_vendors.add(vendor)
        issues.append(_vendor_issue(page_url, vendor, header_name, value))

    return issues


def detect_waf_behavior(
    baseline: WafProbeSnapshot,
    probe: WafProbeSnapshot,
) -> list[WafIssue]:
    if probe.status_code is None:
        return []

    title = probe.page_title or extract_title(probe.body)
    snippet = _challenge_snippet(title, probe.body)
    status_changed_to_block = (
        probe.status_code in BLOCK_STATUS_CODES
        and probe.status_code != baseline.status_code
    )

    if not status_changed_to_block and not snippet:
        return []

    evidence_parts = [f"status_code={probe.status_code}"]
    if baseline.status_code is not None:
        evidence_parts.append(f"baseline_status_code={baseline.status_code}")
    if snippet:
        evidence_parts.append(f"snippet={snippet}")

    return [
        WafIssue(
            category="waf_detection",
            title="Possible WAF challenge or block page detected",
            description=(
                "A single harmless WAF probe changed the response in a way that "
                "resembles a block or challenge page."
            ),
            severity="informational",
            remediation=(
                "Review the security gateway configuration if legitimate scanner "
                "traffic should be allowed."
            ),
            confidence="medium",
            evidence=" ".join(evidence_parts)[:500],
            dedupe_key="waf:behavior",
        )
    ]


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def _vendor_issue(
    page_url: str, vendor: str, matched_name: str, matched_value: str
) -> WafIssue:
    return WafIssue(
        category="waf_detection",
        title="WAF/CDN detected",
        description=f"The response includes headers or cookies associated with {vendor}.",
        severity="informational",
        remediation=(
            "No action is required. Use this signal as inventory context when "
            "reviewing scan results."
        ),
        confidence="high",
        evidence=(
            f"vendor={vendor} matched={matched_name} value={_shorten(matched_value)}"
        ),
        dedupe_key=f"waf:vendor:{vendor.lower()}",
    )


def _challenge_snippet(title: str | None, body: str | None) -> str | None:
    candidates = [title or "", body or ""]
    for candidate in candidates:
        candidate_lower = candidate.lower()
        for pattern in CHALLENGE_PATTERNS:
            index = candidate_lower.find(pattern)
            if index == -1:
                continue
            start = max(index - 60, 0)
            end = min(index + len(pattern) + 120, len(candidate))
            return _shorten(candidate[start:end])
    return None


def _shorten(value: str, limit: int = 180) -> str:
    return re.sub(r"\s+", " ", value).strip()[:limit]
