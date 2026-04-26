from dataclasses import dataclass
from typing import Mapping


TEST_ORIGINS = ("https://evil.example", "null")
_PERMISSIVE_METHODS = {"put", "patch", "delete"}


@dataclass(frozen=True)
class CorsIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key.lower(): value.strip() for key, value in headers.items()}


def _allowed_methods(headers: Mapping[str, str]) -> set[str]:
    value = headers.get("access-control-allow-methods")
    if not value:
        return set()
    return {method.strip().lower() for method in value.split(",") if method.strip()}


def check_cors_headers(
    url: str,
    request_origin: str,
    response_headers: Mapping[str, str],
) -> list[CorsIssue]:
    headers = _normalize_headers(response_headers)
    allowed_origin = headers.get("access-control-allow-origin")
    if not allowed_origin:
        return []

    allow_credentials = (
        headers.get("access-control-allow-credentials", "").lower() == "true"
    )
    issues: list[CorsIssue] = []

    if allowed_origin == "*":
        issues.append(
            CorsIssue(
                category="cors_misconfiguration",
                title="Wildcard CORS origin",
                description="The response allows cross-origin access from any origin.",
                severity="high" if allow_credentials else "medium",
                remediation="Restrict Access-Control-Allow-Origin to trusted origins.",
                confidence="high",
                evidence=(
                    f"url={url} origin={request_origin} "
                    f"acao=* credentials={str(allow_credentials).lower()}"
                ),
                dedupe_key=f"cors:wildcard:{allow_credentials}",
            )
        )

    if (
        allowed_origin.lower() == request_origin.lower()
        and request_origin in TEST_ORIGINS
    ):
        issues.append(
            CorsIssue(
                category="cors_misconfiguration",
                title="CORS reflects arbitrary Origin",
                description="The response reflects an untrusted Origin value in Access-Control-Allow-Origin.",
                severity="critical" if allow_credentials else "high",
                remediation="Validate Origin against a strict allowlist before reflecting it.",
                confidence="high",
                evidence=(
                    f"url={url} origin={request_origin} "
                    f"acao={allowed_origin} credentials={str(allow_credentials).lower()}"
                ),
                dedupe_key=f"cors:reflected:{allow_credentials}:{request_origin}",
            )
        )

    methods = _allowed_methods(headers)
    permissive_methods = sorted(methods & _PERMISSIVE_METHODS)
    if permissive_methods and allowed_origin in {"*", request_origin}:
        issues.append(
            CorsIssue(
                category="cors_misconfiguration",
                title="Overly permissive CORS methods",
                description="The response exposes state-changing methods to a broad or reflected CORS origin.",
                severity="medium",
                remediation="Expose only the cross-origin methods required by trusted clients.",
                confidence="medium",
                evidence=(
                    f"url={url} origin={request_origin} "
                    f"acao={allowed_origin} methods={','.join(permissive_methods)}"
                ),
                dedupe_key=f"cors:methods:{','.join(permissive_methods)}",
            )
        )

    return issues
