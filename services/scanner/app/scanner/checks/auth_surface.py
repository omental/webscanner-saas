from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Mapping
from urllib.parse import urljoin, urlsplit

from app.scanner.checks.cookies import SESSION_COOKIE_NAMES


LOGIN_PATTERNS = (
    "/login",
    "/user/login",
    "/account/login",
)
ADMIN_PATTERNS = (
    "/admin",
    "/wp-admin",
)
WORDPRESS_LOGIN_PATTERNS = (
    "/wp-login.php",
    "/wp-admin",
)


@dataclass(frozen=True)
class AuthSurfaceIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class PasswordFormRecord:
    method: str
    action: str
    input_names: tuple[str, ...]


class _PasswordFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[PasswordFormRecord] = []
        self._current_form: dict[str, object] | None = None
        self._has_password = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._current_form = {
                "method": (attributes.get("method") or "get").lower(),
                "action": attributes.get("action") or "",
                "input_names": [],
            }
            self._has_password = False
            return

        if tag.lower() != "input" or self._current_form is None:
            return

        input_name = attributes.get("name") or ""
        input_type = (attributes.get("type") or "").lower()
        if input_name:
            input_names = self._current_form["input_names"]
            assert isinstance(input_names, list)
            input_names.append(input_name)
        if input_type == "password":
            self._has_password = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current_form is None:
            return

        if self._has_password:
            input_names = self._current_form["input_names"]
            assert isinstance(input_names, list)
            self.forms.append(
                PasswordFormRecord(
                    method=str(self._current_form["method"]),
                    action=str(self._current_form["action"]),
                    input_names=tuple(input_names),
                )
            )

        self._current_form = None
        self._has_password = False


def _header_values(headers: Mapping[str, object], header_name: str) -> list[str]:
    for key, value in headers.items():
        if key.lower() != header_name:
            continue
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        return [item for item in str(value).splitlines() if item.strip()]
    return []


def _session_cookie_names(headers: Mapping[str, object]) -> list[str]:
    names = []
    for header in _header_values(headers, "set-cookie"):
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            continue
        for cookie_name in cookie:
            normalized = cookie_name.lower()
            if any(marker in normalized for marker in SESSION_COOKIE_NAMES):
                names.append(cookie_name)
    return sorted(set(names))


def _password_forms(html_content: str | None) -> list[PasswordFormRecord]:
    if not html_content:
        return []
    parser = _PasswordFormParser()
    parser.feed(html_content)
    return parser.forms


def _wordpress_indicator(page_url: str, html_content: str | None) -> str | None:
    path = urlsplit(page_url).path.lower()
    if any(pattern in path for pattern in WORDPRESS_LOGIN_PATTERNS):
        return path
    html = (html_content or "").lower()
    if "wp-submit" in html or "wordpress" in html and "wp-login" in html:
        return "html:wordpress-login"
    return None


def _input_names_evidence(input_names: tuple[str, ...]) -> str:
    return ",".join(sorted({name for name in input_names if name})) or "-"


def _issue(
    *,
    title: str,
    severity: str,
    evidence: str,
    dedupe_key: str,
) -> AuthSurfaceIssue:
    return AuthSurfaceIssue(
        category="authentication_surface",
        title=title,
        description="An authentication or administration surface was observed during crawling.",
        severity=severity,
        remediation="Review authentication surfaces for expected exposure, monitoring, and hardening.",
        confidence="medium",
        evidence=evidence[:500],
        dedupe_key=dedupe_key,
    )


def check_auth_surface(
    page_url: str,
    html_content: str | None,
    response_headers: Mapping[str, object] | None = None,
) -> list[AuthSurfaceIssue]:
    headers = response_headers or {}
    session_cookie_names = _session_cookie_names(headers)
    session_note = (
        f" session_cookies_observed={','.join(session_cookie_names)}"
        if session_cookie_names
        else ""
    )
    path = urlsplit(page_url).path.lower()
    issues: list[AuthSurfaceIssue] = []
    seen_keys: set[str] = set()

    def add(issue: AuthSurfaceIssue) -> None:
        if issue.dedupe_key in seen_keys:
            return
        seen_keys.add(issue.dedupe_key)
        issues.append(issue)

    wordpress_indicator = _wordpress_indicator(page_url, html_content)
    if wordpress_indicator:
        add(
            _issue(
                title="WordPress login surface detected",
                severity="low",
                evidence=f"url={page_url} pattern={wordpress_indicator}{session_note}",
                dedupe_key=f"{page_url}:wordpress-login-surface",
            )
        )

    if any(pattern in path for pattern in ADMIN_PATTERNS):
        add(
            _issue(
                title="Admin surface detected",
                severity="low",
                evidence=f"url={page_url} pattern={path}{session_note}",
                dedupe_key=f"{page_url}:admin-surface",
            )
        )

    if any(pattern in path for pattern in LOGIN_PATTERNS):
        add(
            _issue(
                title="Login surface detected",
                severity="low",
                evidence=f"url={page_url} pattern={path}{session_note}",
                dedupe_key=f"{page_url}:login-surface",
            )
        )

    for form in _password_forms(html_content):
        action_url = urljoin(page_url, form.action)
        add(
            _issue(
                title="Login surface detected",
                severity="low",
                evidence=(
                    f"url={page_url} pattern=password_form "
                    f"form_method={form.method.upper()} action={action_url} "
                    f"inputs={_input_names_evidence(form.input_names)}{session_note}"
                ),
                dedupe_key=f"{page_url}:password-form-surface",
            )
        )

    return issues
