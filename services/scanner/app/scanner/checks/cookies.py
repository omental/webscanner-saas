from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Mapping
from urllib.parse import urlsplit


SESSION_COOKIE_NAMES = {
    "session",
    "sid",
    "auth",
    "token",
    "jwt",
    "wordpress_logged_in",
    "phpsessid",
    "laravel_session",
}


@dataclass(frozen=True)
class CookieIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


def _header_values(headers: Mapping[str, object], header_name: str) -> list[str]:
    for key, value in headers.items():
        if key.lower() != header_name:
            continue
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        return [item for item in str(value).splitlines() if item.strip()]
    return []


def _is_session_like(cookie_name: str) -> bool:
    normalized = cookie_name.lower()
    return any(name in normalized for name in SESSION_COOKIE_NAMES)


def _severity(cookie_name: str, issue_type: str) -> str:
    session_like = _is_session_like(cookie_name)
    if issue_type == "secure":
        return "high" if session_like else "medium"
    if issue_type == "httponly":
        return "high" if session_like else "low"
    if issue_type == "samesite":
        return "medium" if session_like else "low"
    if issue_type == "samesite-none-secure":
        return "high"
    if issue_type == "domain":
        return "medium" if session_like else "low"
    return "low"


def _redacted_evidence(
    url: str,
    cookie_name: str,
    attribute: str,
    extra: str | None = None,
) -> str:
    evidence = f"url={url} cookie={cookie_name} issue={attribute} value=[redacted]"
    if extra:
        evidence = f"{evidence} {extra}"
    return evidence[:500]


def _domain_is_overly_broad(domain: str) -> bool:
    normalized = domain.strip().lstrip(".").lower()
    if not normalized:
        return False
    if normalized in {"com", "net", "org", "edu", "gov", "co.uk"}:
        return True
    return "." not in normalized


def check_cookie_security(
    page_url: str,
    headers: Mapping[str, object],
) -> list[CookieIssue]:
    set_cookie_headers = _header_values(headers, "set-cookie")
    if not set_cookie_headers:
        return []

    is_https = urlsplit(page_url).scheme.lower() == "https"
    issues: list[CookieIssue] = []

    for header in set_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            continue

        for cookie_name, morsel in cookie.items():
            has_secure = bool(morsel["secure"])
            has_httponly = bool(morsel["httponly"])
            samesite = morsel["samesite"]
            domain = morsel["domain"]

            if is_https and not has_secure:
                issues.append(
                    CookieIssue(
                        category="cookie_security",
                        title="Cookie missing Secure attribute",
                        description="A cookie set over HTTPS does not include the Secure attribute.",
                        severity=_severity(cookie_name, "secure"),
                        remediation="Set the Secure attribute on cookies delivered over HTTPS.",
                        confidence="high",
                        evidence=_redacted_evidence(page_url, cookie_name, "missing_secure"),
                        dedupe_key=f"{cookie_name.lower()}:missing-secure",
                    )
                )

            if not has_httponly:
                issues.append(
                    CookieIssue(
                        category="cookie_security",
                        title="Cookie missing HttpOnly attribute",
                        description="A cookie does not include the HttpOnly attribute.",
                        severity=_severity(cookie_name, "httponly"),
                        remediation="Set HttpOnly on cookies that do not need JavaScript access.",
                        confidence="high",
                        evidence=_redacted_evidence(page_url, cookie_name, "missing_httponly"),
                        dedupe_key=f"{cookie_name.lower()}:missing-httponly",
                    )
                )

            if not samesite:
                issues.append(
                    CookieIssue(
                        category="cookie_security",
                        title="Cookie missing SameSite attribute",
                        description="A cookie does not include a SameSite attribute.",
                        severity=_severity(cookie_name, "samesite"),
                        remediation="Set SameSite=Lax or SameSite=Strict unless cross-site use is required.",
                        confidence="high",
                        evidence=_redacted_evidence(page_url, cookie_name, "missing_samesite"),
                        dedupe_key=f"{cookie_name.lower()}:missing-samesite",
                    )
                )

            if samesite.lower() == "none" and not has_secure:
                issues.append(
                    CookieIssue(
                        category="cookie_security",
                        title="Cookie uses SameSite=None without Secure",
                        description="A cookie marked SameSite=None is not also marked Secure.",
                        severity=_severity(cookie_name, "samesite-none-secure"),
                        remediation="Add Secure when SameSite=None is required.",
                        confidence="high",
                        evidence=_redacted_evidence(
                            page_url,
                            cookie_name,
                            "samesite_none_without_secure",
                        ),
                        dedupe_key=f"{cookie_name.lower()}:samesite-none-without-secure",
                    )
                )

            if domain and _domain_is_overly_broad(domain):
                issues.append(
                    CookieIssue(
                        category="cookie_security",
                        title="Cookie Domain appears overly broad",
                        description="A cookie uses an obviously broad Domain attribute.",
                        severity=_severity(cookie_name, "domain"),
                        remediation="Scope cookie Domain to the narrowest required host.",
                        confidence="medium",
                        evidence=_redacted_evidence(
                            page_url,
                            cookie_name,
                            "overly_broad_domain",
                            f"domain={domain}",
                        ),
                        dedupe_key=f"{cookie_name.lower()}:broad-domain",
                    )
                )

    return issues
