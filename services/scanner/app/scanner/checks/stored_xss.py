import html
import re
import secrets
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.scanner.checks.csrf import TOKEN_NAME_MARKERS
from app.services.confidence import finding_confidence_metadata
from app.services.xss_context import classify_xss_context

STORED_XSS_MARKER_PREFIX = "SCANNER_STORED_XSS_MARKER_"
SAFE_FORM_MARKERS = {"contact", "feedback", "comment", "review", "testimonial"}
SKIP_FORM_MARKERS = {
    "account",
    "admin",
    "cart",
    "checkout",
    "delete",
    "login",
    "payment",
    "register",
    "remove",
    "update",
    "wp-admin",
    "wp-login.php",
}
DESTRUCTIVE_BUTTON_MARKERS = {
    "delete",
    "remove",
    "update",
    "checkout",
    "pay",
    "purchase",
    "order",
}
SAFE_TEXT_INPUT_TYPES = {
    "",
    "text",
    "search",
    "email",
    "url",
    "tel",
    "number",
    "textarea",
}
HIDDEN_PRESERVE_MARKERS = TOKEN_NAME_MARKERS | {"nonce"}
_SCRIPT_PATTERN = re.compile(
    r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL
)
_TAG_PATTERN = re.compile(r"<[^>]*>")
_ATTRIBUTE_PATTERN = re.compile(
    r"""[\w:-]+\s*=\s*(?:"[^"]*{marker}[^"]*"|'[^']*{marker}[^']*'|[^\s"'=<>`]*{marker}[^\s"'=<>`]*)"""
)
_SNIPPET_RADIUS = 90


@dataclass(frozen=True)
class StoredXssIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str
    confidence_level: str | None = None
    confidence_score: int | None = None
    evidence_type: str | None = None
    verification_steps: list[str] | None = None
    payload_used: str | None = None
    affected_parameter: str | None = None
    response_snippet: str | None = None
    false_positive_notes: str | None = None
    request_url: str | None = None
    http_method: str | None = None
    tested_parameter: str | None = None
    payload: str | None = None
    baseline_status_code: int | None = None
    attack_status_code: int | None = None
    baseline_response_size: int | None = None
    attack_response_size: int | None = None
    baseline_response_time_ms: int | None = None
    attack_response_time_ms: int | None = None
    response_diff_summary: str | None = None


@dataclass(frozen=True)
class StoredXssInput:
    name: str
    input_type: str
    value: str
    required: bool


@dataclass(frozen=True)
class StoredXssForm:
    page_url: str
    method: str
    action_url: str
    inputs: tuple[StoredXssInput, ...]
    markers: tuple[str, ...]
    button_labels: tuple[str, ...]

    @property
    def field_names(self) -> tuple[str, ...]:
        return tuple(sorted({input_record.name for input_record in self.inputs if input_record.name}))


@dataclass(frozen=True)
class StoredXssDetection:
    context: str
    raw_reflection: bool
    evidence_marker: str
    severity: str
    confidence: str


class _StoredXssFormParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__()
        self.page_url = page_url
        self.forms: list[StoredXssForm] = []
        self._current_form: dict[str, object] | None = None
        self._current_textarea_name: str | None = None
        self._current_button_text: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        tag_name = tag.lower()

        if tag_name == "form":
            self._current_form = {
                "method": (attributes.get("method") or "get").lower(),
                "action": attributes.get("action") or "",
                "inputs": [],
                "markers": [
                    attributes.get("id") or "",
                    attributes.get("class") or "",
                    attributes.get("name") or "",
                    attributes.get("action") or "",
                ],
                "button_labels": [],
            }
            return

        if self._current_form is None:
            return

        if tag_name == "input":
            input_record = StoredXssInput(
                name=attributes.get("name") or "",
                input_type=(attributes.get("type") or "text").lower(),
                value=attributes.get("value") or "",
                required="required" in attributes,
            )
            self._append_input(input_record)
            self._append_markers(
                input_record.name,
                input_record.input_type,
                attributes.get("id") or "",
                attributes.get("class") or "",
                attributes.get("placeholder") or "",
                attributes.get("autocomplete") or "",
            )
            return

        if tag_name == "textarea":
            self._current_textarea_name = attributes.get("name") or ""
            self._append_input(
                StoredXssInput(
                    name=self._current_textarea_name,
                    input_type="textarea",
                    value="",
                    required="required" in attributes,
                )
            )
            self._append_markers(
                self._current_textarea_name,
                attributes.get("id") or "",
                attributes.get("class") or "",
                attributes.get("placeholder") or "",
            )
            return

        if tag_name == "button":
            self._current_button_text = []

    def handle_data(self, data: str) -> None:
        if self._current_form is None:
            return

        text = data.strip()
        if not text:
            return

        if self._current_button_text is not None:
            self._current_button_text.append(text)
        self._append_markers(text)

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()
        if tag_name == "textarea":
            self._current_textarea_name = None
            return

        if tag_name == "button" and self._current_button_text is not None:
            label = " ".join(self._current_button_text).strip()
            if label and self._current_form is not None:
                button_labels = self._current_form["button_labels"]
                assert isinstance(button_labels, list)
                button_labels.append(label)
            self._current_button_text = None
            return

        if tag_name != "form" or self._current_form is None:
            return

        inputs = self._current_form["inputs"]
        markers = self._current_form["markers"]
        button_labels = self._current_form["button_labels"]
        assert isinstance(inputs, list)
        assert isinstance(markers, list)
        assert isinstance(button_labels, list)

        self.forms.append(
            StoredXssForm(
                page_url=self.page_url,
                method=str(self._current_form["method"]),
                action_url=urljoin(self.page_url, str(self._current_form["action"])),
                inputs=tuple(inputs),
                markers=tuple(markers),
                button_labels=tuple(button_labels),
            )
        )
        self._current_form = None

    def _append_input(self, input_record: StoredXssInput) -> None:
        assert self._current_form is not None
        inputs = self._current_form["inputs"]
        assert isinstance(inputs, list)
        inputs.append(input_record)

    def _append_markers(self, *markers: str) -> None:
        assert self._current_form is not None
        form_markers = self._current_form["markers"]
        assert isinstance(form_markers, list)
        form_markers.extend(marker for marker in markers if marker)


def build_stored_xss_marker() -> str:
    return f"{STORED_XSS_MARKER_PREFIX}{secrets.token_hex(8)}"


def build_stored_xss_payload(marker: str) -> str:
    return f'<script>window.__WEBSCANNER_STORED_XSS__="{marker}";</script>'


def parse_stored_xss_forms(page_url: str, html_content: str | None) -> list[StoredXssForm]:
    if not html_content:
        return []

    parser = _StoredXssFormParser(page_url)
    parser.feed(html_content)
    return parser.forms


def is_same_origin(left_url: str, right_url: str) -> bool:
    left = urlsplit(left_url)
    right = urlsplit(right_url)
    return (
        left.scheme.lower(),
        (left.hostname or "").lower(),
        left.port,
    ) == (
        right.scheme.lower(),
        (right.hostname or "").lower(),
        right.port,
    )


def is_safe_stored_xss_form(form: StoredXssForm) -> bool:
    if form.method.lower() != "post":
        return False
    if not is_same_origin(form.page_url, form.action_url):
        return False

    marker_text = " ".join([*form.markers, *form.button_labels, form.action_url]).lower()
    if not any(marker in marker_text for marker in SAFE_FORM_MARKERS):
        return False
    if any(marker in marker_text for marker in SKIP_FORM_MARKERS):
        return False
    if any(
        marker in " ".join(form.button_labels).lower()
        for marker in DESTRUCTIVE_BUTTON_MARKERS
    ):
        return False
    if any(input_record.input_type in {"password", "file"} for input_record in form.inputs):
        return False
    if any(
        marker in input_record.name.lower()
        for input_record in form.inputs
        for marker in {"card", "cc", "cvv", "payment"}
    ):
        return False

    return True


def select_safe_stored_xss_forms(
    page_url: str,
    html_content: str | None,
    *,
    max_forms: int,
) -> list[StoredXssForm]:
    forms = parse_stored_xss_forms(page_url, html_content)
    selected: list[StoredXssForm] = []
    seen_keys: set[str] = set()

    for form in forms:
        if len(selected) >= max_forms:
            break
        if not is_safe_stored_xss_form(form):
            continue
        form_key = f"{form.action_url}:{','.join(form.field_names)}"
        if form_key in seen_keys:
            continue
        seen_keys.add(form_key)
        selected.append(form)

    return selected


def build_stored_xss_submission(
    form: StoredXssForm,
    marker: str,
) -> dict[str, str] | None:
    payload = build_stored_xss_payload(marker)
    data: dict[str, str] = {}
    payload_field_added = False

    for input_record in form.inputs:
        name = input_record.name
        input_type = input_record.input_type.lower()
        if not name:
            if input_record.required:
                return None
            continue

        lowered_name = name.lower()
        if input_type == "hidden":
            if any(marker in lowered_name for marker in HIDDEN_PRESERVE_MARKERS):
                data[name] = input_record.value
            continue

        if input_type in {"submit", "button", "reset", "image"}:
            continue
        if input_type in {"checkbox", "radio", "password", "file"}:
            if input_record.required:
                return None
            continue
        if input_type not in SAFE_TEXT_INPUT_TYPES:
            if input_record.required:
                return None
            continue

        if "email" in lowered_name or input_type == "email":
            data[name] = "scanner@example.com"
        elif input_type == "url":
            data[name] = "https://example.com"
        elif input_type == "tel":
            data[name] = "5550100"
        elif input_type == "number":
            data[name] = "1"
        elif "name" in lowered_name:
            data[name] = "WebScanner"
        else:
            data[name] = payload
            payload_field_added = True

    return data if payload_field_added else None


def _encoded_variants(value: str) -> set[str]:
    escaped = html.escape(value, quote=True)
    return {
        escaped,
        "".join(f"&#{ord(character)};" for character in value),
        "".join(f"&#x{ord(character):x};" for character in value),
    }


def _short_snippet(body: str, evidence_marker: str, marker: str, payload: str) -> str:
    index = body.find(evidence_marker)
    if index < 0:
        return ""

    start = max(index - _SNIPPET_RADIUS, 0)
    end = min(index + len(evidence_marker) + _SNIPPET_RADIUS, len(body))
    snippet = body[start:end].replace("\n", " ").replace("\r", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    return snippet.replace(payload, "[payload]").replace(marker, "[marker]")


def _marker_is_in_script_block(marker: str, body: str) -> bool:
    return any(marker in match.group(0) for match in _SCRIPT_PATTERN.finditer(body))


def _marker_is_in_attribute(marker: str, body: str) -> bool:
    for match in _TAG_PATTERN.finditer(body):
        tag = match.group(0)
        if marker not in tag or tag.lower().startswith("</"):
            continue

        pattern = re.compile(
            _ATTRIBUTE_PATTERN.pattern.format(marker=re.escape(marker)),
            re.IGNORECASE,
        )
        if pattern.search(tag):
            return True
    return False


def _marker_is_inside_tag(marker: str, body: str) -> bool:
    return any(marker in match.group(0) for match in _TAG_PATTERN.finditer(body))


def classify_stored_xss_context(
    marker: str,
    payload: str,
    response_body: str | None,
    *,
    browser_verified: bool = False,
) -> StoredXssDetection | None:
    if browser_verified:
        return StoredXssDetection("browser_execution", True, marker, "high", "high")

    if not response_body:
        return None

    for encoded_payload in _encoded_variants(payload):
        if encoded_payload and encoded_payload in response_body:
            return StoredXssDetection("escaped", False, encoded_payload, "low", "low")

    if marker in response_body:
        context = classify_xss_context(response_body, marker)
        if not context["reflected"]:
            return None
        if context["executable_context"]:
            return StoredXssDetection(str(context["context"]), True, marker, "high", "high")
        return StoredXssDetection(str(context["context"]), True, marker, "medium", "medium")

    for encoded_value in _encoded_variants(marker):
        if encoded_value and encoded_value in response_body:
            return StoredXssDetection("escaped", False, encoded_value, "low", "low")

    if marker in html.unescape(response_body):
        return StoredXssDetection("escaped", False, "", "low", "low")

    return None


def check_stored_xss_response(
    *,
    form: StoredXssForm,
    marker: str,
    revisit_url: str,
    response_body: str | None,
    browser_verified: bool = False,
) -> list[StoredXssIssue]:
    payload = build_stored_xss_payload(marker)
    detection = classify_stored_xss_context(
        marker,
        payload,
        response_body,
        browser_verified=browser_verified,
    )
    if detection is None:
        return []

    snippet = ""
    if response_body and detection.evidence_marker:
        snippet = _short_snippet(response_body, detection.evidence_marker, marker, payload)

    field_names = ",".join(form.field_names)
    evidence = (
        f"form_url={form.page_url} action={form.action_url} fields={field_names} "
        f"revisit_url={revisit_url} context={detection.context} "
        f"browser_verified={str(browser_verified).lower()} snippet={snippet}"
    )[:500]
    context = classify_xss_context(response_body or "", marker)
    executable_context = browser_verified or bool(context["executable_context"])
    false_positive_notes = None
    if not executable_context:
        false_positive_notes = (
            "Reflected input was not observed in an executable context; "
            "manual verification is required."
        )
    metadata = finding_confidence_metadata(
        exploit_confirmed=browser_verified,
        context_validated=executable_context and not browser_verified,
        payload_reflected=detection.raw_reflection,
        weak_signal_count=0 if executable_context else 1,
        payload_used="[safe stored XSS marker payload]",
        affected_parameter=field_names or None,
        response_snippet=snippet[:240],
        request_url=form.action_url,
        http_method=form.method.upper(),
        tested_parameter=field_names or None,
        payload=payload,
        attack_response_size=len(response_body) if response_body is not None else None,
        response_diff_summary=(
            f"revisit_url={revisit_url}; context={detection.context}; "
            f"browser_verified={str(browser_verified).lower()}; "
            f"executable_context={str(executable_context).lower()}; summary={context['summary']}"
        ),
        verification_steps=[
            "Submit a safe marker payload to the selected public form.",
            "Revisit the page and confirm the marker is stored in the reported context.",
            "Use browser verification before treating this as confirmed execution.",
        ],
        false_positive_notes=false_positive_notes
        or "Stored reflections can be safe when output encoding prevents browser execution.",
    )

    return [
        StoredXssIssue(
            category="stored_xss",
            title="Possible stored XSS from public form",
            description=(
                "A controlled non-destructive marker submitted to a low-risk public "
                f"form was later observed in {detection.context} context."
            ),
            severity=detection.severity,
            remediation="Encode stored user-supplied content on output and sanitize rich text input server-side.",
            confidence=detection.confidence,
            evidence=evidence,
            dedupe_key=(
                f"{form.action_url}:{field_names}:{revisit_url}:"
                f"{detection.context}:stored-xss"
            ),
            **metadata,
        )
    ]


async def verify_stored_xss_execution(
    urls: list[str],
    marker: str,
    *,
    enabled: bool,
) -> set[str]:
    if not enabled:
        return set()

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return set()

    verified_urls: set[str] = set()
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                for url in urls:
                    await page.goto(url, wait_until="domcontentloaded", timeout=5000)
                    value = await page.evaluate("window.__WEBSCANNER_STORED_XSS__")
                    if value == marker:
                        verified_urls.add(url)
            finally:
                await browser.close()
    except Exception:
        return verified_urls

    return verified_urls
