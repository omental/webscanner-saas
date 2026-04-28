import re
from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.services.confidence import score_finding_confidence

SITE_WIDE_FINDING_TITLES = {
    "Missing Content-Security-Policy",
    "Missing X-Frame-Options",
    "Missing X-Content-Type-Options",
    "Missing Referrer-Policy",
    "Missing Strict-Transport-Security",
    "Exposed server banner",
}
_PARAMETER_PATTERN = re.compile(r'\bparameter=([^\s]+)|via "([^"]+)" parameter')
_SNIPPET_PATTERN = re.compile(r"\bsnippet=([^=]+?)(?:\s+\w+=|$)")


def _normalized_key_part(value: object) -> str:
    text = str(value or "").strip().lower()
    return re.sub(r"\s+", " ", text) or "-"


def _normalized_url(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"

    parts = urlsplit(text)
    if not parts.scheme or not parts.netloc:
        return _normalized_key_part(text)

    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)), doseq=True)
    normalized = urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path or "/",
            query,
            "",
        )
    )
    return normalized.lower()


def build_finding_deduplication_key(
    *,
    scan_id: int,
    check_type: object,
    severity: object,
    title: object,
    request_url: object = None,
    affected_url: object = None,
    tested_parameter: object = None,
    affected_parameter: object = None,
    scan_page_id: int | None = None,
) -> str:
    location = request_url or affected_url
    if not location and scan_page_id is not None:
        location = f"scan_page:{scan_page_id}"
    if not location:
        location = "unknown_location"

    parameter = tested_parameter or affected_parameter or "-"
    canonical = "|".join(
        [
            str(scan_id),
            _normalized_key_part(check_type),
            _normalized_key_part(title),
            _normalized_key_part(severity),
            _normalized_url(location),
            _normalized_key_part(parameter),
        ]
    )
    return f"finding:v1:{sha256(canonical.encode('utf-8')).hexdigest()}"


def _effective_scan_page_id(issue: object, scan_page_id: int | None) -> int | None:
    if getattr(issue, "title", None) in SITE_WIDE_FINDING_TITLES:
        return None
    return scan_page_id


def _default_confidence_metadata(issue: object) -> dict[str, object]:
    category = str(getattr(issue, "category", "") or "").lower()
    severity = str(getattr(issue, "severity", "") or "").lower()
    confidence = str(getattr(issue, "confidence", "") or "").lower()

    if category in {"seo", "performance"} or "fingerprint" in category:
        result = score_finding_confidence(informational=True)
    elif category == "missing_security_header":
        result = score_finding_confidence(
            weak_signal_count=2 if severity in {"medium", "high", "critical"} else 1
        )
    elif confidence == "high":
        result = score_finding_confidence(weak_signal_count=2)
    elif confidence in {"medium", "low"}:
        result = score_finding_confidence(weak_signal_count=1)
    else:
        result = score_finding_confidence()

    return {
        "confidence_level": result.confidence_level,
        "confidence_score": result.confidence_score,
        "evidence_type": result.evidence_type,
        "verification_steps": result.verification_steps,
    }


def _confidence_metadata(issue: object) -> dict[str, object]:
    metadata = _default_confidence_metadata(issue)
    for field in (
        "confidence_level",
        "confidence_score",
        "evidence_type",
        "verification_steps",
        "payload_used",
        "affected_parameter",
        "response_snippet",
        "false_positive_notes",
        "request_url",
        "http_method",
        "tested_parameter",
        "payload",
        "baseline_status_code",
        "attack_status_code",
        "baseline_response_size",
        "attack_response_size",
        "baseline_response_time_ms",
        "attack_response_time_ms",
        "response_diff_summary",
        "deduplication_key",
    ):
        value = getattr(issue, field, None)
        if value is not None:
            metadata[field] = value

    evidence = str(getattr(issue, "evidence", "") or "")
    title = str(getattr(issue, "title", "") or "")

    if "affected_parameter" not in metadata:
        match = _PARAMETER_PATTERN.search(f"{evidence} {title}")
        if match:
            metadata["affected_parameter"] = match.group(1) or match.group(2)

    if "tested_parameter" not in metadata and "affected_parameter" in metadata:
        metadata["tested_parameter"] = metadata["affected_parameter"]

    if "request_url" not in metadata:
        url_match = re.search(r"\burl=([^\s]+)", evidence)
        if url_match:
            metadata["request_url"] = url_match.group(1)

    if "response_snippet" not in metadata:
        match = _SNIPPET_PATTERN.search(evidence)
        if match:
            metadata["response_snippet"] = match.group(1).strip()[:500]

    return metadata


def _deduplication_key(
    *,
    scan_id: int,
    scan_page_id: int | None,
    issue: object,
    metadata: dict[str, object],
) -> str:
    existing_key = metadata.get("deduplication_key")
    if existing_key:
        return str(existing_key)

    return build_finding_deduplication_key(
        scan_id=scan_id,
        check_type=getattr(issue, "category", issue.__class__.__name__),
        severity=getattr(issue, "severity", None),
        title=getattr(issue, "title", None),
        request_url=metadata.get("request_url"),
        affected_url=getattr(issue, "dedupe_key", None),
        tested_parameter=metadata.get("tested_parameter"),
        affected_parameter=metadata.get("affected_parameter"),
        scan_page_id=scan_page_id,
    )


async def get_or_create_finding(
    session: AsyncSession,
    *,
    scan_id: int,
    scan_page_id: int | None,
    issue: object,
) -> tuple[Finding, bool]:
    effective_scan_page_id = _effective_scan_page_id(issue, scan_page_id)
    metadata = _confidence_metadata(issue)
    deduplication_key = _deduplication_key(
        scan_id=scan_id,
        scan_page_id=effective_scan_page_id,
        issue=issue,
        metadata=metadata,
    )

    exact_duplicate_conditions = [
        Finding.scan_id == scan_id,
        Finding.scan_page_id == effective_scan_page_id,
        Finding.category == issue.category,
        Finding.title == issue.title,
        Finding.evidence == issue.evidence,
    ]
    duplicate_parameter = metadata.get("tested_parameter") or metadata.get(
        "affected_parameter"
    )
    if duplicate_parameter:
        exact_duplicate_conditions.append(
            or_(
                Finding.tested_parameter == duplicate_parameter,
                Finding.affected_parameter == duplicate_parameter,
            )
        )
    exact_duplicate = and_(*exact_duplicate_conditions)
    query: Select[tuple[Finding]] = select(Finding).where(
        Finding.scan_id == scan_id,
        or_(Finding.deduplication_key == deduplication_key, exact_duplicate),
    ).limit(1)
    existing = await session.execute(query)
    existing_finding = existing.scalar_one_or_none()
    if existing_finding is not None:
        return existing_finding, False

    finding = Finding(
        scan_id=scan_id,
        scan_page_id=effective_scan_page_id,
        category=issue.category,
        title=issue.title,
        description=issue.description,
        severity=issue.severity,
        confidence=issue.confidence,
        confidence_level=metadata["confidence_level"],
        confidence_score=metadata["confidence_score"],
        evidence_type=metadata["evidence_type"],
        verification_steps=metadata["verification_steps"],
        payload_used=metadata.get("payload_used"),
        affected_parameter=metadata.get("affected_parameter"),
        response_snippet=metadata.get("response_snippet"),
        false_positive_notes=metadata.get("false_positive_notes"),
        request_url=metadata.get("request_url"),
        http_method=metadata.get("http_method"),
        tested_parameter=metadata.get("tested_parameter"),
        payload=metadata.get("payload"),
        baseline_status_code=metadata.get("baseline_status_code"),
        attack_status_code=metadata.get("attack_status_code"),
        baseline_response_size=metadata.get("baseline_response_size"),
        attack_response_size=metadata.get("attack_response_size"),
        baseline_response_time_ms=metadata.get("baseline_response_time_ms"),
        attack_response_time_ms=metadata.get("attack_response_time_ms"),
        response_diff_summary=metadata.get("response_diff_summary"),
        deduplication_key=deduplication_key,
        evidence=issue.evidence,
        remediation=issue.remediation,
        is_confirmed=False,
    )
    session.add(finding)
    return finding, True


async def create_findings_if_missing(
    session: AsyncSession,
    *,
    scan_id: int,
    scan_page_id: int | None,
    issues: list[object],
) -> int:
    created_count = 0

    for issue in issues:
        _finding, created = await get_or_create_finding(
            session,
            scan_id=scan_id,
            scan_page_id=scan_page_id,
            issue=issue,
        )
        if created:
            created_count += 1

    if created_count:
        await session.commit()

    return created_count


async def count_findings_for_scan(session: AsyncSession, scan_id: int) -> int:
    result = await session.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    return len(list(result.scalars().all()))
