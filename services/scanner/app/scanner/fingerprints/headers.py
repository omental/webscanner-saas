import re
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class TechnologyMatch:
    product_name: str
    category: str
    version: str | None
    vendor: str | None
    confidence_score: float | None
    detection_method: str


def detect_from_headers(headers: Mapping[str, str]) -> list[TechnologyMatch]:
    normalized = {key.lower(): value for key, value in headers.items()}
    matches: list[TechnologyMatch] = []

    server = normalized.get("server", "")
    if server:
        matches.extend(_detect_server_banner(server))

    powered_by = normalized.get("x-powered-by", "")
    if powered_by:
        matches.extend(_detect_powered_by(powered_by))

    return matches


def _detect_server_banner(value: str) -> list[TechnologyMatch]:
    lower_value = value.lower()
    server_products = [
        ("nginx", "nginx", "F5"),
        ("apache", "Apache HTTP Server", "Apache Software Foundation"),
        ("litespeed", "LiteSpeed", "LiteSpeed Technologies"),
        ("caddy", "Caddy", "Caddy"),
    ]

    matches: list[TechnologyMatch] = []
    for needle, product_name, vendor in server_products:
        if needle in lower_value:
            version = None
            if needle == "apache":
                version = _extract_version(value, needle)
            elif needle in {"nginx", "litespeed", "caddy"}:
                version = _extract_version(value, needle)
            matches.append(
                TechnologyMatch(
                    product_name=product_name,
                    category="server",
                    version=version,
                    vendor=vendor,
                    confidence_score=0.9 if version else 0.7,
                    detection_method="response_header",
                )
            )
    return matches


def _detect_powered_by(value: str) -> list[TechnologyMatch]:
    lower_value = value.lower()
    products = [
        ("php", "PHP", "framework", "PHP Group"),
        ("express", "Express", "framework", "OpenJS Foundation"),
        ("asp.net", "ASP.NET", "framework", "Microsoft"),
    ]

    matches: list[TechnologyMatch] = []
    for needle, product_name, category, vendor in products:
        if needle in lower_value:
            version = None
            if needle == "php":
                version = _extract_version(value, needle)
            elif needle in {"express", "asp.net"}:
                version = _extract_version(value, needle)
            matches.append(
                TechnologyMatch(
                    product_name=product_name,
                    category=category,
                    version=version,
                    vendor=vendor,
                    confidence_score=0.85 if version else 0.65,
                    detection_method="response_header",
                )
            )
    return matches


def _extract_version(value: str, token: str) -> str | None:
    pattern = re.compile(rf"{re.escape(token)}[/ ]?([0-9]+(?:\.[0-9]+)+)", re.IGNORECASE)
    match = pattern.search(value)
    return match.group(1) if match else None
