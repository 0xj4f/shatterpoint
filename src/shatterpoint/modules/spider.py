"""
Spider Module - Async Web Crawler
Handles URL discovery, request management, and crawl orchestration.
Enforces single-domain scope with concurrency control.
"""

import asyncio
import time
from dataclasses import dataclass, field

import httpx

from shatterpoint.utils.auth import build_auth_headers, should_send_auth
from shatterpoint.utils.formatter import print_finding, print_status
from shatterpoint.utils.validator import URLValidator


@dataclass
class CrawlResult:
    """Result of crawling a single URL."""
    url: str
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    # Set-Cookie values preserved as a list. `dict(httpx.Headers)`
    # collapses duplicate headers into a comma-joined string, so a
    # plain `headers` dict can only show one cookie even when the
    # server sent two. We surface the raw list here for any caller
    # that needs per-cookie iteration (auth detection, fingerprinter).
    set_cookies: list = field(default_factory=list)
    body: str = ""
    content_type: str = ""
    redirect_chain: list = field(default_factory=list)
    response_time: float = 0.0
    error: str | None = None


class Spider:
    """
    Async spider that crawls a single domain.
    Manages the URL frontier, respects concurrency limits,
    and returns raw page data for downstream modules.
    """

    def __init__(self, config: dict, validator: URLValidator):
        crawler_cfg = config.get("crawler", {})
        self.validator = validator
        self.base_url = validator.base_url
        self.max_depth = crawler_cfg.get("max_depth", 10)
        self.max_pages = crawler_cfg.get("max_pages", 500)
        self.concurrency = crawler_cfg.get("concurrency", 15)
        self.timeout = crawler_cfg.get("timeout", 10)
        self.max_redirects = crawler_cfg.get("max_redirects", 3)
        self.delay = crawler_cfg.get("delay", 0.1)
        self.user_agent = crawler_cfg.get(
            "user_agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        )

        # Auth: bearer token + arbitrary -H headers are applied per-request
        # (not on the client) so the manual redirect loop in _fetch can
        # strip ALL of them when a hop leaves the original origin — a
        # custom X-API-Key or Cookie is just as sensitive as the bearer.
        auth_cfg = config.get("auth") or {}
        self.auth_token: str | None = auth_cfg.get("token")
        self.auth_headers: dict = auth_cfg.get("headers") or {}
        self.target_scheme = validator.scheme
        self.target_netloc = validator.target_domain

        # State
        self.visited: set[str] = set()
        self.queued: set[str] = set()
        self.results: dict[str, CrawlResult] = {}
        self.pages_crawled = 0

        # Semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(self.concurrency)

    def _auth_headers_for(self, url: str) -> dict:
        """Return the combined auth headers (bearer + custom -H) when they
        are safe to send to `url` (same origin as target), else empty."""
        if not self.auth_token and not self.auth_headers:
            return {}
        if should_send_auth(self.target_scheme, self.target_netloc, url):
            return build_auth_headers(self.auth_token, self.auth_headers)
        return {}

    async def crawl(self, seed_urls: list[str] | None = None) -> dict[str, CrawlResult]:
        """
        Main crawl loop. Starts from seed URLs and discovers pages.
        Returns dict of URL -> CrawlResult.
        """
        if seed_urls is None:
            seed_urls = [self.base_url]

        # Initialize the queue: (url, depth)
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        for url in seed_urls:
            normalized = self.validator.normalize(url)
            if normalized:
                queue.put_nowait((normalized, 0))
                self.queued.add(normalized)

        print_status(f"Starting crawl from {len(seed_urls)} seed URL(s)")
        print_status(f"Concurrency: {self.concurrency} | Max depth: {self.max_depth} | Max pages: {self.max_pages}")

        async with httpx.AsyncClient(
            follow_redirects=False,  # We handle redirects manually to track chains
            timeout=httpx.Timeout(self.timeout),
            verify=False,  # OSCP targets often have self-signed certs
            headers={"User-Agent": self.user_agent},
            limits=httpx.Limits(
                max_connections=self.concurrency + 5,
                max_keepalive_connections=self.concurrency,
            ),
        ) as client:
            workers = []
            for _ in range(self.concurrency):
                workers.append(asyncio.create_task(self._worker(client, queue)))

            # Wait for the queue to be fully processed
            await queue.join()

            # Cancel workers
            for w in workers:
                w.cancel()

        print_status(f"Crawl complete: {self.pages_crawled} pages crawled, {len(self.visited)} URLs visited")
        return self.results

    async def _worker(self, client: httpx.AsyncClient, queue: asyncio.Queue):
        """Worker coroutine that processes URLs from the queue."""
        while True:
            try:
                url, depth = await queue.get()
            except asyncio.CancelledError:
                return

            try:
                if url in self.visited:
                    continue
                if self.pages_crawled >= self.max_pages:
                    continue
                if depth > self.max_depth:
                    continue

                self.visited.add(url)

                async with self._semaphore:
                    result = await self._fetch(client, url)

                self.results[url] = result
                self.pages_crawled += 1

                if self.pages_crawled % 25 == 0:
                    print_status(f"Progress: {self.pages_crawled} pages crawled...")

                # Extract links and add to queue
                if result.body and result.status_code < 400:
                    from shatterpoint.modules.parser import HTMLParser
                    parser = HTMLParser()
                    links = parser.extract_links(result.body, url)

                    for link in links:
                        normalized = self.validator.normalize(link, url)
                        if (
                            normalized
                            and normalized not in self.visited
                            and normalized not in self.queued
                            and self.validator.is_in_scope(normalized)
                            and not self.validator.is_static_resource(normalized)
                        ):
                            self.queued.add(normalized)
                            queue.put_nowait((normalized, depth + 1))

                # Polite delay
                if self.delay > 0:
                    await asyncio.sleep(self.delay)

            except Exception as e:
                print_finding("Spider Error", f"{url}: {e}")
            finally:
                queue.task_done()

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> CrawlResult:
        """Fetch a URL, handling redirects manually to track the chain.

        Authorization is evaluated per-hop via should_send_auth so the
        bearer token is stripped when a redirect leaves the target origin.
        """
        redirect_chain = []
        current_url = url
        hops = 0

        while hops <= self.max_redirects:
            try:
                start = time.monotonic()
                response = await client.get(current_url, headers=self._auth_headers_for(current_url))
                elapsed = time.monotonic() - start

                if response.is_redirect and hops < self.max_redirects:
                    location = response.headers.get("location", "")
                    resolved = self.validator.normalize(location, current_url)
                    if resolved:
                        redirect_chain.append({
                            "from": current_url,
                            "to": resolved,
                            "status": response.status_code,
                        })
                        current_url = resolved
                        hops += 1
                        continue

                # Final response
                content_type = response.headers.get("content-type", "")
                body = ""
                if "text/" in content_type or "json" in content_type or "xml" in content_type:
                    body = response.text

                # Preserve all Set-Cookie values as a list. Casting to
                # dict() collapses duplicates into a comma-joined string,
                # which loses per-cookie evidence (laravel_session +
                # XSRF-TOKEN both fire on Laravel apps).
                set_cookies = response.headers.get_list("set-cookie") if hasattr(
                    response.headers, "get_list"
                ) else []

                return CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    set_cookies=set_cookies,
                    body=body,
                    content_type=content_type,
                    redirect_chain=redirect_chain,
                    response_time=elapsed,
                )

            except httpx.TimeoutException:
                return CrawlResult(url=url, error="timeout")
            except httpx.ConnectError:
                return CrawlResult(url=url, error="connection_error")
            except Exception as e:
                return CrawlResult(url=url, error=str(e))

        return CrawlResult(url=url, error="too_many_redirects", redirect_chain=redirect_chain)
