from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.scanner.checks.csrf import TOKEN_NAME_MARKERS

RISKY_EXTENSIONS = {
    ".asp",
    ".aspx",
    ".exe",
    ".html",
    ".js",
    ".jsp",
    ".phar",
    ".php",
    ".phtml",
    ".sh",
    ".svg",
}
RISKY_MIME_TYPES = {"image/svg+xml"}
WILDCARD_ACCEPTS = {"*/*", "image/*", "application/*"}
GUIDANCE_MARKERS = {
    "max",
    "mb",
    "kb",
    "size",
    "jpg",
    "jpeg",
    "png",
    "pdf",
    "allowed",
    "only",
    "file type",
}


@dataclass(frozen=True)
class FileUploadAdvancedIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class AdvancedFileInput:
    name: str
    accept: str
    multiple: bool
    required: bool


@dataclass(frozen=True)
class AdvancedUploadForm:
    method: str
    action: str
    enctype: str
    input_names: tuple[str, ...]
    file_inputs: tuple[AdvancedFileInput, ...]
    nearby_text: str


class _AdvancedUploadParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[AdvancedUploadForm] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        tag_name = tag.lower()

        if tag_name == "form":
            self._current_form = {
                "method": (attributes.get("method") or "get").lower(),
                "action": attributes.get("action") or "",
                "enctype": (attributes.get("enctype") or "").lower(),
                "input_names": [],
                "file_inputs": [],
                "nearby_text": [],
            }
            return

        if self._current_form is None:
            return

        if tag_name in {"label", "small", "p", "span", "div"}:
            for marker_attr in ("aria-label", "title"):
                if attributes.get(marker_attr):
                    self._append_text(attributes[marker_attr])

        if tag_name != "input":
            return

        input_name = attributes.get("name") or ""
        input_type = (attributes.get("type") or "text").lower()
        if input_name:
            input_names = self._current_form["input_names"]
            assert isinstance(input_names, list)
            input_names.append(input_name)

        if input_type == "file":
            file_inputs = self._current_form["file_inputs"]
            assert isinstance(file_inputs, list)
            file_inputs.append(
                AdvancedFileInput(
                    name=input_name,
                    accept=attributes.get("accept") or "",
                    multiple="multiple" in attributes,
                    required="required" in attributes,
                )
            )

    def handle_data(self, data: str) -> None:
        if self._current_form is None:
            return
        self._append_text(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current_form is None:
            return

        input_names = self._current_form["input_names"]
        file_inputs = self._current_form["file_inputs"]
        nearby_text = self._current_form["nearby_text"]
        assert isinstance(input_names, list)
        assert isinstance(file_inputs, list)
        assert isinstance(nearby_text, list)

        self.forms.append(
            AdvancedUploadForm(
                method=str(self._current_form["method"]),
                action=str(self._current_form["action"]),
                enctype=str(self._current_form["enctype"]),
                input_names=tuple(input_names),
                file_inputs=tuple(file_inputs),
                nearby_text=" ".join(nearby_text),
            )
        )
        self._current_form = None

    def _append_text(self, text: str) -> None:
        stripped = " ".join(text.split())
        if not stripped:
            return
        assert self._current_form is not None
        nearby_text = self._current_form["nearby_text"]
        assert isinstance(nearby_text, list)
        nearby_text.append(stripped)


def _parse_upload_forms(html_content: str | None) -> list[AdvancedUploadForm]:
    if not html_content:
        return []
    parser = _AdvancedUploadParser()
    parser.feed(html_content)
    return [form for form in parser.forms if form.file_inputs]


def _has_csrf_token(input_names: tuple[str, ...]) -> bool:
    return any(
        marker in input_name.lower()
        for input_name in input_names
        for marker in TOKEN_NAME_MARKERS
    )


def _accept_tokens(form: AdvancedUploadForm) -> list[str]:
    tokens: list[str] = []
    for file_input in form.file_inputs:
        tokens.extend(
            token.strip().lower()
            for token in file_input.accept.split(",")
            if token.strip()
        )
    return tokens


def _risky_accept_tokens(tokens: list[str]) -> list[str]:
    return sorted(
        {
            token
            for token in tokens
            if token in RISKY_EXTENSIONS or token in RISKY_MIME_TYPES
        }
    )


def _wildcard_accept_tokens(tokens: list[str]) -> list[str]:
    return sorted({token for token in tokens if token in WILDCARD_ACCEPTS})


def _has_visible_guidance(form: AdvancedUploadForm) -> bool:
    text = form.nearby_text.lower()
    return any(marker in text for marker in GUIDANCE_MARKERS)


def _file_input_names(form: AdvancedUploadForm) -> str:
    return ",".join(
        sorted({file_input.name for file_input in form.file_inputs if file_input.name})
    ) or "-"


def _accept_values(form: AdvancedUploadForm) -> str:
    return ",".join(
        sorted({file_input.accept for file_input in form.file_inputs if file_input.accept})
    ) or "-"


def _evidence(
    page_url: str,
    form: AdvancedUploadForm,
    action_url: str,
    *,
    risky: list[str] | None = None,
    wildcard: list[str] | None = None,
) -> str:
    input_names = ",".join(sorted({name for name in form.input_names if name})) or "-"
    parts = [
        f"url={page_url}",
        f"action={action_url}",
        f"method={form.method.upper()}",
        f"enctype={form.enctype or '-'}",
        f"file_inputs={_file_input_names(form)}",
        f"accept={_accept_values(form)}",
        f"inputs={input_names}",
    ]
    if risky:
        parts.append(f"risky={','.join(risky)}")
    if wildcard:
        parts.append(f"wildcard={','.join(wildcard)}")
    return " ".join(parts)[:500]


def _issue(
    *,
    title: str,
    description: str,
    severity: str,
    remediation: str,
    evidence: str,
    dedupe_key: str,
) -> FileUploadAdvancedIssue:
    return FileUploadAdvancedIssue(
        category="file_upload",
        title=title,
        description=description,
        severity=severity,
        remediation=remediation,
        confidence="medium",
        evidence=evidence,
        dedupe_key=dedupe_key,
    )


def check_file_upload_advanced(
    page_url: str,
    html_content: str | None,
) -> list[FileUploadAdvancedIssue]:
    issues: list[FileUploadAdvancedIssue] = []
    seen_keys: set[str] = set()

    for form in _parse_upload_forms(html_content):
        action_url = urljoin(page_url, form.action)
        form_key = f"{page_url}:{action_url}"
        tokens = _accept_tokens(form)
        risky_tokens = _risky_accept_tokens(tokens)
        wildcard_tokens = _wildcard_accept_tokens(tokens)
        evidence = _evidence(
            page_url,
            form,
            action_url,
            risky=risky_tokens,
            wildcard=wildcard_tokens,
        )

        candidates = [
            _issue(
                title="File upload form allows risky file types",
                description="A file upload accept attribute includes executable or scriptable file types.",
                severity="high",
                remediation="Remove executable/scriptable file types and validate uploads server-side.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-risky-accept",
            )
            if risky_tokens
            else None,
            _issue(
                title="File upload form uses broad accept wildcard",
                description="A file upload accept attribute uses a broad wildcard.",
                severity="medium",
                remediation="Use narrow accept values and enforce file validation server-side.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-wildcard-accept",
            )
            if wildcard_tokens
            else None,
            _issue(
                title="File upload form missing CSRF token",
                description="A file upload form does not include an obvious CSRF or nonce field.",
                severity="medium",
                remediation="Add a server-validated CSRF token to upload forms.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-missing-csrf",
            )
            if not _has_csrf_token(form.input_names)
            else None,
            _issue(
                title="File upload form missing file type restrictions",
                description="A file upload input does not define accept restrictions.",
                severity="medium",
                remediation="Add accept restrictions and validate file type server-side.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-missing-accept",
            )
            if any(not file_input.accept for file_input in form.file_inputs)
            else None,
            _issue(
                title="File upload form uses GET",
                description="A file upload form uses GET instead of POST.",
                severity="medium",
                remediation="Use POST with multipart/form-data for upload forms.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-get-method",
            )
            if form.method.lower() == "get"
            else None,
            _issue(
                title="File upload form uses insecure action URL",
                description="An HTTPS page contains an upload form posting to HTTP.",
                severity="high",
                remediation="Use HTTPS for upload form actions.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-http-action",
            )
            if urlsplit(page_url).scheme == "https"
            and urlsplit(action_url).scheme == "http"
            else None,
            _issue(
                title="File upload form missing multipart enctype",
                description="A file upload form does not declare multipart/form-data.",
                severity="low",
                remediation="Set enctype=\"multipart/form-data\" on upload forms.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-missing-enctype",
            )
            if form.enctype != "multipart/form-data"
            else None,
            _issue(
                title="Multiple file upload enabled",
                description="A file upload input allows multiple files in one submission.",
                severity="medium",
                remediation="Allow multiple upload only when intended and enforce count and size limits server-side.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-multiple-upload",
            )
            if any(file_input.multiple for file_input in form.file_inputs)
            else None,
            _issue(
                title="File upload form lacks visible upload guidance",
                description="A file upload form does not show obvious type or size guidance near the control.",
                severity="low",
                remediation="Display allowed file types and size limits near upload controls.",
                evidence=evidence,
                dedupe_key=f"{form_key}:advanced-missing-guidance",
            )
            if not _has_visible_guidance(form)
            else None,
        ]

        for issue in candidates:
            if issue is None or issue.dedupe_key in seen_keys:
                continue
            seen_keys.add(issue.dedupe_key)
            issues.append(issue)

    return issues
