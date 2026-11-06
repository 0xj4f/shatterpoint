"""
Shared HTTP plumbing for every client that talks to the target.

Two jobs live here because every phase needs them the same way:

* **Rate-limit tolerance.** Targets behind nginx `limit_req`, Cloudflare or
  an API gateway answer a burst with `429 Too Many Requests`. Without a retry
  the 429 error page silently becomes "the landing HTML", "a crawled page" or
  "a probe result", and detection flips from run to run. `RetryTransport`
  retries 429 (and 503 when the server says when to come back), honouring
  `Retry-After`.
* **Set-Cookie parsing.** Auth detection and fingerprinting both need the
  per-cookie name / value / attributes, from either the raw per-header list
  or a collapsed `headers` dict.
"""

from __future__ import annotations

import asyncio
import time
from email.utils import parsedate_to_datetime

import httpx

_RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}


def retry_after_seconds(value: str | None) -> float | None:
    """Parse a Retry-After header (delta-seconds or HTTP-date) → seconds."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


class RetryTransport(httpx.AsyncBaseTransport):
    """Wraps a transport and retries rate-limited idempotent requests.

    * 429 → always retried; waits `Retry-After` if given, else backoff 1/2/4 s.
    * 503 → retried only when it carries `Retry-After` (a bare 503 may be
      the app's real state, e.g. a health endpoint, and is reported as is).
    Waits are capped at `max_wait` so one hostile header can't stall a scan.
    After `retries` attempts the last response is returned unchanged.
    """

    def __init__(
        self,
        transport: httpx.AsyncBaseTransport,
        retries: int = 3,
        backoff: float = 1.0,
        max_wait: float = 10.0,
    ):
        self._transport = transport
        self.retries = retries
        self.backoff = backoff
        self.max_wait = max_wait

    def _delay(self, response: httpx.Response, attempt: int) -> float | None:
        retry_after = retry_after_seconds(response.headers.get("retry-after"))
        if response.status_code == 429:
            wait = retry_after if retry_after is not None else self.backoff * (2 ** attempt)
        elif response.status_code == 503 and retry_after is not None:
            wait = retry_after
        else:
            return None
        return min(wait, self.max_wait)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        attempt = 0
        while True:
            response = await self._transport.handle_async_request(request)
            if request.method not in _RETRY_METHODS or attempt >= self.retries:
                return response
            wait = self._delay(response, attempt)
            if wait is None:
                return response
            await response.aclose()
            await asyncio.sleep(wait)
            attempt += 1

    async def aclose(self) -> None:
        await self._transport.aclose()


def build_client(
    proxy: str | None = None,
    limits: httpx.Limits | None = None,
    **client_kwargs,
) -> httpx.AsyncClient:
    """AsyncClient for target traffic: TLS verification off (lab certs),
    optional upstream proxy, and 429-tolerant via RetryTransport.

    The proxy goes on the inner transport: passing `proxy=` to the client
    as well would mount a second transport that bypasses the retry layer.
    """
    inner = httpx.AsyncHTTPTransport(
        verify=False,
        proxy=proxy,
        limits=limits or httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    return httpx.AsyncClient(transport=RetryTransport(inner), verify=False, **client_kwargs)


def parse_set_cookies(headers: dict | None, set_cookies: list[str] | None = None) -> list[dict]:
    """Return [{name, value, attrs}] for each Set-Cookie.

    `set_cookies` is the per-header list (preferred: `dict(httpx.Headers)`
    collapses duplicates). Falls back to `set-cookie` in `headers`.
    `attrs` maps lowercase attribute names (path, secure, httponly,
    samesite, …) to their value ("" for flags).
    """
    if set_cookies:
        raw = list(set_cookies)
    else:
        raw = [v for k, v in (headers or {}).items() if k.lower() == "set-cookie"]
    cookies: list[dict] = []
    for value in raw:
        parts = [p.strip() for p in value.split(";")]
        name, _, cookie_value = parts[0].partition("=")
        if not name.strip():
            continue
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            if not part:
                continue
            key, _, attr_value = part.partition("=")
            attrs[key.strip().lower()] = attr_value.strip()
        cookies.append({"name": name.strip(), "value": cookie_value.strip(), "attrs": attrs})
    return cookies
