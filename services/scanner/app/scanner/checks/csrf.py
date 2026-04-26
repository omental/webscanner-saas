from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


STATE_CHANGING_METHODS = {"post", "put", "patch", "delete"}
TOKEN_NAME_MARKERS = {
    "csrf",
    "token",
    "nonce",
    "_token",
    "authenticity_token",
    "wpnonce",
    "_wpnonce",
}
LOW_RISK_FORM_MARKERS = {"login", "signin", "sign-in", "contact", "newsletter"}
SEARCH_FORM_MARKERS = {"search", "q", "query"}


@dataclass(frozen=True)
class CsrfIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class FormRecord:
    method: str
    action: str
    input_names: tuple[str, ...]
    form_markers: tuple[str, ...]


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[FormRecord] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._current_form = {
                "method": (attributes.get("method") or "get").lower(),
                "action": attributes.get("action") or "",
                "input_names": [],
                "form_markers": [
                    attributes.get("id") or "",
                    attributes.get("class") or "",
                    attributes.get("name") or "",
                    attributes.get("action") or "",
                ],
            }
            return

        if tag.lower() != "input" or self._current_form is None:
            return

        input_name = attributes.get("name") or ""
        input_type = (attributes.get("type") or "").lower()
        if input_name:
            input_names = self._current_form["input_names"]
            assert isinstance(input_names, list)
            input_names.append(input_name)

        markers = self._current_form["form_markers"]
        assert isinstance(markers, list)
        markers.extend(
            [
                input_name,
                attributes.get("id") or "",
                attributes.get("class") or "",
                input_type,
            ]
        )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current_form is None:
            return

        input_names = self._current_form["input_names"]
        form_markers = self._current_form["form_markers"]
        assert isinstance(input_names, list)
        assert isinstance(form_markers, list)

        self.forms.append(
            FormRecord(
                method=str(self._current_form["method"]),
                action=str(self._current_form["action"]),
                input_names=tuple(input_names),
                form_markers=tuple(form_markers),
            )
        )
        self._current_form = None


def _parse_forms(html_content: str) -> list[FormRecord]:
    parser = _FormParser()
    parser.feed(html_content)
    return parser.forms


def _is_same_host(page_url: str, action_url: str) -> bool:
    action_host = urlsplit(action_url).hostname
    if not action_host:
        return True
    return action_host.lower() == (urlsplit(page_url).hostname or "").lower()


def _has_csrf_token(input_names: tuple[str, ...]) -> bool:
    return any(
        marker in input_name.lower()
        for input_name in input_names
        for marker in TOKEN_NAME_MARKERS
    )


def _is_search_form(form: FormRecord) -> bool:
    markers = " ".join([*form.input_names, *form.form_markers]).lower()
    return any(marker in markers for marker in SEARCH_FORM_MARKERS)


def _is_low_risk_form(form: FormRecord) -> bool:
    markers = " ".join([*form.input_names, *form.form_markers]).lower()
    return any(marker in markers for marker in LOW_RISK_FORM_MARKERS)


def _evidence(page_url: str, method: str, action_url: str, input_names: tuple[str, ...]) -> str:
    names = ",".join(sorted({name for name in input_names if name}))
    return f"url={page_url} method={method.upper()} action={action_url} inputs={names}"[:500]


def check_csrf_forms(page_url: str, html_content: str | None) -> list[CsrfIssue]:
    if not html_content:
        return []

    issues: list[CsrfIssue] = []
    seen_keys: set[str] = set()
    for form in _parse_forms(html_content):
        method = form.method.lower()
        if method not in STATE_CHANGING_METHODS:
            continue

        action_url = urljoin(page_url, form.action)
        if not _is_same_host(page_url, action_url):
            continue

        if _is_search_form(form):
            continue

        if _has_csrf_token(form.input_names):
            continue

        severity = "low" if _is_low_risk_form(form) else "medium"
        dedupe_key = f"{page_url}:{method}:{action_url}:csrf"
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)

        issues.append(
            CsrfIssue(
                category="csrf",
                title="Missing CSRF token in form",
                description="A state-changing same-site form does not include an obvious CSRF token field.",
                severity=severity,
                remediation="Add a server-validated CSRF token to state-changing forms.",
                confidence="medium",
                evidence=_evidence(page_url, method, action_url, form.input_names),
                dedupe_key=dedupe_key,
            )
        )

    return issues
