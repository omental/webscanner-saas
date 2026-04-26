from dataclasses import dataclass
from urllib.parse import urljoin


EXPOSURE_PATHS = (
    "/.git/HEAD",
    "/.env",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/wp-config.php.bak",
    "/wp-config.php~",
)
_SENSITIVE_PATHS = {"/.env", "/wp-config.php.bak", "/wp-config.php~"}


@dataclass(frozen=True)
class ExposurePathIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


def build_exposure_url(base_url: str, path: str) -> str:
    return urljoin(base_url, path)


def _snippet(path: str, body: str | None, content_type: str | None) -> str:
    if path in _SENSITIVE_PATHS:
        return f"content_type={content_type or '-'} snippet=[redacted sensitive file content]"

    if not body:
        return f"content_type={content_type or '-'}"

    snippet = " ".join(body[:160].replace("\r", " ").replace("\n", " ").split())
    return f"snippet={snippet}" if snippet else f"content_type={content_type or '-'}"


def _issue(
    *,
    path: str,
    url: str,
    status_code: int | None,
    title: str,
    description: str,
    severity: str,
    remediation: str,
    body: str | None,
    content_type: str | None,
) -> ExposurePathIssue:
    return ExposurePathIssue(
        category="sensitive_file_exposure",
        title=title,
        description=description,
        severity=severity,
        remediation=remediation,
        confidence="high",
        evidence=f"url={url} status={status_code} {_snippet(path, body, content_type)}"[:500],
        dedupe_key=f"exposure:{path}",
    )


def classify_exposure_path(
    path: str,
    url: str,
    status_code: int | None,
    body: str | None,
    content_type: str | None,
) -> list[ExposurePathIssue]:
    if status_code != 200:
        return []

    normalized_body = (body or "").strip()
    body_lower = normalized_body.lower()
    content_type_lower = (content_type or "").lower()

    if path == "/.git/HEAD" and normalized_body.startswith("ref:"):
        return [
            _issue(
                path=path,
                url=url,
                status_code=status_code,
                title="Exposed .git metadata",
                description="The /.git/HEAD file is publicly accessible and exposes repository metadata.",
                severity="high",
                remediation="Block public access to the .git directory.",
                body=body,
                content_type=content_type,
            )
        ]

    if path == "/.env":
        looks_like_env = (
            "database_url=" in body_lower
            or "app_key=" in body_lower
            or "secret_key=" in body_lower
            or "api_key=" in body_lower
            or ("\n" in normalized_body and "=" in normalized_body)
        )
        if looks_like_env and ("text" in content_type_lower or not content_type_lower):
            return [
                _issue(
                    path=path,
                    url=url,
                    status_code=status_code,
                    title="Exposed .env file",
                    description="The /.env file is publicly accessible and may expose sensitive configuration secrets.",
                    severity="critical",
                    remediation="Block access to .env files and rotate any exposed secrets.",
                    body=body,
                    content_type=content_type,
                )
            ]

    if path in {"/backup.sql", "/db.sql"}:
        looks_like_sql = any(
            marker in body_lower
            for marker in ("create table", "insert into", "dump", "mysql")
        )
        if looks_like_sql or "sql" in content_type_lower:
            return [
                _issue(
                    path=path,
                    url=url,
                    status_code=status_code,
                    title="Exposed SQL backup",
                    description="A SQL backup file appears to be publicly accessible.",
                    severity="critical",
                    remediation="Remove database backups from the web root and rotate exposed credentials.",
                    body=body,
                    content_type=content_type,
                )
            ]

    if path == "/backup.zip":
        if "zip" in content_type_lower or (body or "").startswith("PK"):
            return [
                _issue(
                    path=path,
                    url=url,
                    status_code=status_code,
                    title="Exposed backup archive",
                    description="A backup archive appears to be publicly accessible.",
                    severity="high",
                    remediation="Remove backup archives from the web root.",
                    body=body,
                    content_type=content_type,
                )
            ]

    if path in {"/phpinfo.php", "/info.php"}:
        if "phpinfo()" in body_lower or "php version" in body_lower:
            return [
                _issue(
                    path=path,
                    url=url,
                    status_code=status_code,
                    title="Exposed phpinfo page",
                    description="A phpinfo/debug page appears to be publicly accessible.",
                    severity="high",
                    remediation="Remove phpinfo/debug files from production.",
                    body=body,
                    content_type=content_type,
                )
            ]

    if path == "/server-status":
        if "server status" in body_lower or "apache server status" in body_lower:
            return [
                _issue(
                    path=path,
                    url=url,
                    status_code=status_code,
                    title="Exposed Apache server-status",
                    description="The Apache server-status page appears to be publicly accessible.",
                    severity="medium",
                    remediation="Restrict server-status to trusted administrators only.",
                    body=body,
                    content_type=content_type,
                )
            ]

    if path in {"/wp-config.php.bak", "/wp-config.php~"}:
        looks_like_wp_config = (
            "db_password" in body_lower
            or "db_name" in body_lower
            or "wp_debug" in body_lower
            or "authentication unique keys" in body_lower
        )
        if looks_like_wp_config:
            return [
                _issue(
                    path=path,
                    url=url,
                    status_code=status_code,
                    title="Exposed WordPress config backup",
                    description="A WordPress config backup appears to be publicly accessible.",
                    severity="critical",
                    remediation="Remove WordPress config backups from the web root and rotate exposed secrets.",
                    body=body,
                    content_type=content_type,
                )
            ]

    return []
