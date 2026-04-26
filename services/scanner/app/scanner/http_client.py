import logging
from dataclasses import dataclass
from time import monotonic
from typing import Mapping

import httpx

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)
MAX_TEXT_BODY_CHARS = 10_000


def is_text_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False

    normalized = content_type.split(";", 1)[0].strip().lower()
    if normalized == "text/html":
        return True
    if normalized.startswith("text/"):
        return True
    if normalized in {"application/json", "application/javascript"}:
        return True
    return False


@dataclass
class FetchResult:
    url: str
    status_code: int | None
    content_type: str | None
    response_time_ms: int | None
    headers: dict[str, str]
    body: str | None
    error: str | None = None


class HttpClient:
    def __init__(self, timeout_seconds: int | None = None) -> None:
        self._client = httpx.AsyncClient(
            timeout=timeout_seconds or settings.scanner_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": settings.scanner_user_agent},
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(
        self,
        url: str,
        *,
        follow_redirects: bool | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> FetchResult:
        start = monotonic()
        try:
            response = await self._client.get(
                url,
                follow_redirects=follow_redirects,
                headers=headers,
            )
            elapsed_ms = int((monotonic() - start) * 1000)
            logger.info(
                "http fetch success url=%s status_code=%s elapsed_ms=%s",
                str(response.url),
                response.status_code,
                elapsed_ms,
            )
            content_type = response.headers.get("content-type")
            body = None
            if is_text_content_type(content_type):
                body = response.text
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
            set_cookie_headers = response.headers.get_list("set-cookie")
            if set_cookie_headers:
                response_headers["set-cookie"] = "\n".join(set_cookie_headers)
            return FetchResult(
                url=str(response.url),
                status_code=response.status_code,
                content_type=content_type,
                response_time_ms=elapsed_ms,
                headers=response_headers,
                body=body,
            )
        except httpx.HTTPError as exc:
            elapsed_ms = int((monotonic() - start) * 1000)
            logger.warning(
                "http fetch failed url=%s elapsed_ms=%s error=%s",
                url,
                elapsed_ms,
                exc,
            )
            return FetchResult(
                url=url,
                status_code=None,
                content_type=None,
                response_time_ms=elapsed_ms,
                headers={},
                body=None,
                error=str(exc),
            )

    async def post(
        self,
        url: str,
        *,
        data: Mapping[str, str] | None = None,
        follow_redirects: bool | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> FetchResult:
        start = monotonic()
        try:
            response = await self._client.post(
                url,
                data=data,
                follow_redirects=follow_redirects,
                headers=headers,
            )
            elapsed_ms = int((monotonic() - start) * 1000)
            logger.info(
                "http post success url=%s status_code=%s elapsed_ms=%s",
                str(response.url),
                response.status_code,
                elapsed_ms,
            )
            content_type = response.headers.get("content-type")
            body = None
            if is_text_content_type(content_type):
                body = response.text
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
            set_cookie_headers = response.headers.get_list("set-cookie")
            if set_cookie_headers:
                response_headers["set-cookie"] = "\n".join(set_cookie_headers)
            return FetchResult(
                url=str(response.url),
                status_code=response.status_code,
                content_type=content_type,
                response_time_ms=elapsed_ms,
                headers=response_headers,
                body=body,
            )
        except httpx.HTTPError as exc:
            elapsed_ms = int((monotonic() - start) * 1000)
            logger.warning(
                "http post failed url=%s elapsed_ms=%s error=%s",
                url,
                elapsed_ms,
                exc,
            )
            return FetchResult(
                url=url,
                status_code=None,
                content_type=None,
                response_time_ms=elapsed_ms,
                headers={},
                body=None,
                error=str(exc),
            )
