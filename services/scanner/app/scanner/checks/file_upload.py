from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin

from app.scanner.checks.csrf import TOKEN_NAME_MARKERS


@dataclass(frozen=True)
class FileUploadIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class FileInputRecord:
    name: str
    accept: str


@dataclass(frozen=True)
class UploadFormRecord:
    method: str
    action: str
    enctype: str
    input_names: tuple[str, ...]
    file_inputs: tuple[FileInputRecord, ...]


class _UploadFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[UploadFormRecord] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._current_form = {
                "method": (attributes.get("method") or "get").lower(),
                "action": attributes.get("action") or "",
                "enctype": (attributes.get("enctype") or "").lower(),
                "input_names": [],
                "file_inputs": [],
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

        if input_type == "file":
            file_inputs = self._current_form["file_inputs"]
            assert isinstance(file_inputs, list)
            file_inputs.append(
                FileInputRecord(
                    name=input_name,
                    accept=attributes.get("accept") or "",
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current_form is None:
            return

        input_names = self._current_form["input_names"]
        file_inputs = self._current_form["file_inputs"]
        assert isinstance(input_names, list)
        assert isinstance(file_inputs, list)

        self.forms.append(
            UploadFormRecord(
                method=str(self._current_form["method"]),
                action=str(self._current_form["action"]),
                enctype=str(self._current_form["enctype"]),
                input_names=tuple(input_names),
                file_inputs=tuple(file_inputs),
            )
        )
        self._current_form = None


def _parse_upload_forms(html_content: str) -> list[UploadFormRecord]:
    parser = _UploadFormParser()
    parser.feed(html_content)
    return [form for form in parser.forms if form.file_inputs]


def _has_csrf_token(input_names: tuple[str, ...]) -> bool:
    return any(
        marker in input_name.lower()
        for input_name in input_names
        for marker in TOKEN_NAME_MARKERS
    )


def _evidence(page_url: str, form: UploadFormRecord, action_url: str) -> str:
    file_names = ",".join(
        sorted({file_input.name for file_input in form.file_inputs if file_input.name})
    )
    accepts = ",".join(
        sorted({file_input.accept for file_input in form.file_inputs if file_input.accept})
    )
    return (
        f"url={page_url} action={action_url} method={form.method.upper()} "
        f"enctype={form.enctype or '-'} file_inputs={file_names or '-'} "
        f"accept={accepts or '-'}"
    )[:500]


def _issue(
    *,
    title: str,
    description: str,
    severity: str,
    remediation: str,
    evidence: str,
    dedupe_key: str,
) -> FileUploadIssue:
    return FileUploadIssue(
        category="file_upload",
        title=title,
        description=description,
        severity=severity,
        remediation=remediation,
        confidence="medium",
        evidence=evidence,
        dedupe_key=dedupe_key,
    )


def check_file_upload_forms(
    page_url: str,
    html_content: str | None,
) -> list[FileUploadIssue]:
    if not html_content:
        return []

    issues: list[FileUploadIssue] = []
    seen_keys: set[str] = set()

    for form in _parse_upload_forms(html_content):
        action_url = urljoin(page_url, form.action)
        evidence = _evidence(page_url, form, action_url)
        form_key = f"{page_url}:{action_url}"

        candidate_issues = [
            _issue(
                title="File upload form detected",
                description="A form contains a file input field.",
                severity="info",
                remediation="Ensure uploaded files are validated, stored safely, and never executed.",
                evidence=evidence,
                dedupe_key=f"{form_key}:file-upload-detected",
            ),
            _issue(
                title="File upload form missing CSRF token",
                description="A file upload form does not include an obvious CSRF token field.",
                severity="medium",
                remediation="Add a server-validated CSRF token to file upload forms.",
                evidence=evidence,
                dedupe_key=f"{form_key}:file-upload-missing-csrf",
            )
            if not _has_csrf_token(form.input_names)
            else None,
            _issue(
                title="File upload form missing file type restrictions",
                description="A file upload input does not expose accept restrictions.",
                severity="medium",
                remediation="Add accept restrictions and enforce file type validation server-side.",
                evidence=evidence,
                dedupe_key=f"{form_key}:file-upload-missing-accept",
            )
            if any(not file_input.accept for file_input in form.file_inputs)
            else None,
            _issue(
                title="File upload form missing multipart enctype",
                description="A file upload form does not declare multipart/form-data encoding.",
                severity="low",
                remediation="Set enctype=\"multipart/form-data\" on file upload forms.",
                evidence=evidence,
                dedupe_key=f"{form_key}:file-upload-missing-enctype",
            )
            if form.enctype != "multipart/form-data"
            else None,
        ]

        for issue in candidate_issues:
            if issue is None or issue.dedupe_key in seen_keys:
                continue
            seen_keys.add(issue.dedupe_key)
            issues.append(issue)

    return issues
