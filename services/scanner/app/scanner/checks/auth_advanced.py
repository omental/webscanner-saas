from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Mapping
from urllib.parse import urljoin, urlsplit

from app.scanner.checks.cookies import SESSION_COOKIE_NAMES
from app.scanner.checks.csrf import TOKEN_NAME_MARKERS

AUTH_URL_PATTERNS = (
    "/login",
    "/wp-login.php",
    "/wp-admin",
    "/admin",
    "/account/login",
    "/user/login",
)
ADMIN_URL_PATTERNS = ("/wp-login.php", "/wp-admin", "/admin")
LOGIN_INDICATORS = (
    "password",
    "log in",
    "login",
    "sign in",
    "wp-submit",
    "csrf",
    "nonce",
)


@dataclass(frozen=True)
class AuthAdvancedIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class LoginInput:
    name: str
    input_type: str
    autocomplete: str


@dataclass(frozen=True)
class LoginForm:
    method: str
    action: str
    input_names: tuple[str, ...]
    inputs: tuple[LoginInput, ...]


class _LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[LoginForm] = []
        self.iframe_count = 0
        self._current_form: dict[str, object] | None = None
        self._has_password = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attributes = {key.lower(): value or "" for key, value in attrs}

        if tag_name == "iframe":
            self.iframe_count += 1
            return

        if tag_name == "form":
            self._current_form = {
                "method": (attributes.get("method") or "get").lower(),
                "action": attributes.get("action") or "",
                "input_names": [],
                "inputs": [],
            }
            self._has_password = False
            return

        if tag_name != "input" or self._current_form is None:
            return

        input_name = attributes.get("name") or ""
        input_type = (attributes.get("type") or "text").lower()
        autocomplete = (attributes.get("autocomplete") or "").lower()
        if input_name:
            input_names = self._current_form["input_names"]
            assert isinstance(input_names, list)
            input_names.append(input_name)

        inputs = self._current_form["inputs"]
        assert isinstance(inputs, list)
        inputs.append(
            LoginInput(
                name=input_name,
                input_type=input_type,
                autocomplete=autocomplete,
            )
        )

        if input_type == "password":
            self._has_password = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current_form is None:
            return

        if self._has_password:
            input_names = self._current_form["input_names"]
            inputs = self._current_form["inputs"]
            assert isinstance(input_names, list)
            assert isinstance(inputs, list)
            self.forms.append(
                LoginForm(
                    method=str(self._current_form["method"]),
                    action=str(self._current_form["action"]),
                    input_names=tuple(input_names),
                    inputs=tuple(inputs),
                )
            )

        self._current_form = None
        self._has_password = False


def _parse_login_forms(html_content: str | None) -> tuple[list[LoginForm], int]:
    if not html_content:
        return [], 0
    parser = _LoginFormParser()
    parser.feed(html_content)
    return parser.forms, parser.iframe_count


def _normalized_headers(headers: Mapping[str, object]) -> dict[str, str]:
    return {key.lower(): str(value) for key, value in headers.items()}


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
    return any(marker in normalized for marker in SESSION_COOKIE_NAMES)


def _session_cookie_weaknesses(
    page_url: str, headers: Mapping[str, object]
) -> dict[str, set[str]]:
    weaknesses: dict[str, set[str]] = {}
    is_https = urlsplit(page_url).scheme.lower() == "https"

    for header in _header_values(headers, "set-cookie"):
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            continue

        for cookie_name, morsel in cookie.items():
            if not _is_session_like(cookie_name):
                continue

            missing = set()
            if is_https and not morsel["secure"]:
                missing.add("Secure")
            if not morsel["httponly"]:
                missing.add("HttpOnly")
            if not morsel["samesite"]:
                missing.add("SameSite")
            if missing:
                weaknesses[cookie_name] = missing

    return weaknesses


def _is_auth_url(page_url: str) -> bool:
    path = urlsplit(page_url).path.lower()
    return any(pattern in path for pattern in AUTH_URL_PATTERNS)


def _is_admin_url(page_url: str) -> bool:
    path = urlsplit(page_url).path.lower()
    return any(pattern in path for pattern in ADMIN_URL_PATTERNS)


def _has_login_indicator(html_content: str | None, forms: list[LoginForm]) -> bool:
    if forms:
        return True
    html = (html_content or "").lower()
    return any(indicator in html for indicator in LOGIN_INDICATORS)


def _has_csrf_token(input_names: tuple[str, ...]) -> bool:
    return any(
        marker in input_name.lower()
        for input_name in input_names
        for marker in TOKEN_NAME_MARKERS
    )


def _input_names_evidence(input_names: tuple[str, ...]) -> str:
    return ",".join(sorted({name for name in input_names if name})) or "-"


def _issue(
    *,
    page_url: str,
    title: str,
    description: str,
    severity: str,
    remediation: str,
    evidence: str,
    issue_type: str,
) -> AuthAdvancedIssue:
    return AuthAdvancedIssue(
        category="authentication_security",
        title=title,
        description=description,
        severity=severity,
        remediation=remediation,
        confidence="medium",
        evidence=evidence[:500],
        dedupe_key=f"{page_url}:{issue_type}",
    )


def check_auth_advanced(
    page_url: str,
    html_content: str | None,
    response_headers: Mapping[str, object] | None = None,
    status_code: int | None = None,
) -> list[AuthAdvancedIssue]:
    headers = response_headers or {}
    normalized_headers = _normalized_headers(headers)
    forms, iframe_count = _parse_login_forms(html_content)
    is_auth_page = _is_auth_url(page_url) or bool(forms)
    if not is_auth_page:
        return []

    issues: list[AuthAdvancedIssue] = []
    seen_keys: set[str] = set()
    is_https = urlsplit(page_url).scheme.lower() == "https"

    def add(issue: AuthAdvancedIssue) -> None:
        if issue.dedupe_key in seen_keys:
            return
        seen_keys.add(issue.dedupe_key)
        issues.append(issue)

    for form in forms:
        action_url = urljoin(page_url, form.action)
        form_evidence = (
            f"url={page_url} method={form.method.upper()} action={action_url} "
            f"inputs={_input_names_evidence(form.input_names)}"
        )

        if not is_https:
            add(
                _issue(
                    page_url=page_url,
                    title="Login form submitted over insecure HTTP",
                    description="A login form was served over HTTP.",
                    severity="high",
                    remediation="Serve authentication pages only over HTTPS.",
                    evidence=form_evidence,
                    issue_type="login-form-http-page",
                )
            )

        if urlsplit(action_url).scheme.lower() == "http":
            add(
                _issue(
                    page_url=page_url,
                    title="Login form posts to insecure HTTP",
                    description="A login form action submits credentials to an HTTP URL.",
                    severity="high",
                    remediation="Use HTTPS for login form actions.",
                    evidence=form_evidence,
                    issue_type="login-form-http-action",
                )
            )

        if not _has_csrf_token(form.input_names):
            add(
                _issue(
                    page_url=page_url,
                    title="Login form missing CSRF token",
                    description="A login form does not include an obvious CSRF or nonce field.",
                    severity="medium",
                    remediation="Add a server-validated CSRF token to login forms.",
                    evidence=form_evidence,
                    issue_type="login-form-missing-csrf",
                )
            )

        password_inputs = [
            input_record
            for input_record in form.inputs
            if input_record.input_type == "password"
        ]
        if any(
            input_record.autocomplete not in {"off", "current-password"}
            for input_record in password_inputs
        ):
            add(
                _issue(
                    page_url=page_url,
                    title="Login password autocomplete policy not explicit",
                    description="A password field does not explicitly declare autocomplete off or current-password.",
                    severity="info",
                    remediation="Use autocomplete=\"current-password\" or a deliberate autocomplete policy for login forms.",
                    evidence=form_evidence,
                    issue_type="login-form-password-autocomplete",
                )
            )

        if iframe_count:
            add(
                _issue(
                    page_url=page_url,
                    title="Login form appears in embedded context",
                    description="A login form was observed on a page containing iframe elements.",
                    severity="low",
                    remediation="Avoid embedding login forms unless framing is intentional and protected.",
                    evidence=f"{form_evidence} iframe_count={iframe_count}",
                    issue_type="login-form-iframe-context",
                )
            )

    if _is_admin_url(page_url):
        path = urlsplit(page_url).path.lower()
        login_indicator = _has_login_indicator(html_content, forms)
        if status_code == 200 and not login_indicator:
            add(
                _issue(
                    page_url=page_url,
                    title="Admin interface exposed",
                    description="An admin URL returned HTTP 200 without obvious login indicators.",
                    severity="medium",
                    remediation="Require authentication for admin interfaces and restrict access where possible.",
                    evidence=f"url={page_url} status_code={status_code} pattern={path}",
                    issue_type="admin-exposed-no-login",
                )
            )
        else:
            title = (
                "WordPress login endpoint reachable"
                if "wp-login.php" in path
                else "Admin surface reachable"
            )
            add(
                _issue(
                    page_url=page_url,
                    title=title,
                    description="An administration or login URL was reachable during passive crawling.",
                    severity="info",
                    remediation="Confirm this admin surface is expected and monitored.",
                    evidence=f"url={page_url} status_code={status_code or '-'} pattern={path}",
                    issue_type="admin-surface-reachable",
                )
            )

    missing_auth_headers: list[str] = []
    if "content-security-policy" not in normalized_headers:
        missing_auth_headers.append("content-security-policy")
        add(
            _issue(
                page_url=page_url,
                title="Auth page missing Content-Security-Policy",
                description="An authentication page does not include a Content-Security-Policy header.",
                severity="medium",
                remediation="Add a CSP header to reduce script injection and framing risk.",
                evidence=f"url={page_url} missing_headers=content-security-policy",
                issue_type="auth-missing-csp",
            )
        )

    has_clickjacking_protection = (
        "x-frame-options" in normalized_headers
        or "frame-ancestors" in normalized_headers.get("content-security-policy", "").lower()
    )
    if not has_clickjacking_protection:
        missing_auth_headers.append("x-frame-options/frame-ancestors")
        add(
            _issue(
                page_url=page_url,
                title="Auth page missing clickjacking protection",
                description="An authentication page lacks X-Frame-Options or CSP frame-ancestors.",
                severity="medium",
                remediation="Set X-Frame-Options or a CSP frame-ancestors directive.",
                evidence=f"url={page_url} missing_headers=x-frame-options,frame-ancestors",
                issue_type="auth-missing-clickjacking",
            )
        )

    if is_https and "strict-transport-security" not in normalized_headers:
        missing_auth_headers.append("strict-transport-security")
        add(
            _issue(
                page_url=page_url,
                title="Auth page missing Strict-Transport-Security",
                description="An HTTPS authentication page does not include HSTS.",
                severity="medium",
                remediation="Enable HSTS for HTTPS authentication pages.",
                evidence=f"url={page_url} missing_headers=strict-transport-security",
                issue_type="auth-missing-hsts",
            )
        )

    cookie_weaknesses = _session_cookie_weaknesses(page_url, headers)
    if cookie_weaknesses:
        cookie_names = ",".join(sorted(cookie_weaknesses))
        missing = ",".join(
            sorted({item for values in cookie_weaknesses.values() for item in values})
        )
        add(
            _issue(
                page_url=page_url,
                title="Session cookie weaknesses observed on auth surface",
                description="Session-like cookies set by an auth page are missing one or more hardening attributes.",
                severity="medium",
                remediation="Set Secure, HttpOnly, and SameSite on session cookies where appropriate.",
                evidence=f"url={page_url} cookies={cookie_names} missing_attributes={missing}",
                issue_type="auth-session-cookie-summary",
            )
        )

    return issues
