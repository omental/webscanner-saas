from urllib.parse import SplitResult, urlsplit, urlunsplit

SKIP_KEYWORDS = (
    "logout",
    "signout",
    "sign-out",
    "delete",
    "remove",
    "destroy",
    "unsubscribe",
)

STATIC_ASSET_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".css",
    ".js",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".mp4",
    ".webm",
    ".mp3",
    ".wav",
)


def strip_fragment(url: str) -> str:
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def normalize_url(url: str) -> str:
    stripped = strip_fragment(url)
    parts = urlsplit(stripped)

    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    port = parts.port

    if not hostname:
        return stripped

    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"

    path = parts.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    normalized = SplitResult(scheme, netloc, path, parts.query, "")
    return urlunsplit(normalized)


def get_domain(url: str) -> str:
    return urlsplit(normalize_url(url)).hostname or ""


def is_same_host(base_url: str, candidate_url: str) -> bool:
    return get_domain(base_url) == get_domain(candidate_url)


def should_skip_url(url: str) -> bool:
    candidate = url.strip().lower()

    if not candidate:
        return True

    if candidate.startswith(("javascript:", "mailto:", "tel:")):
        return True

    parts = urlsplit(candidate)
    if parts.scheme and parts.scheme not in {"http", "https"}:
        return True

    return any(keyword in candidate for keyword in SKIP_KEYWORDS)


def is_static_asset_url(url: str) -> bool:
    parts = urlsplit(url.strip().lower())
    return parts.path.endswith(STATIC_ASSET_EXTENSIONS)
