"""
Browser Crawler
Renders pages in headless Chromium (via Playwright) so the app's JavaScript
runs, like in a real user's browser. Captures what static fetching can't
see: the rendered DOM, client-side redirects, and the network calls the app
makes on its own (XHR / fetch / EventSource / WebSocket, third-party hosts).

Passive by design: it never clicks or types, and any non-GET request the
app fires is recorded and blocked, never sent.

Logged-in SPAs: `browser.local_storage` (--browser-storage KEY=VALUE) seeds
the app's localStorage on the target origin before its scripts run, e.g. the
JWT a React app keeps under "token".

Optional dependency:
    pip install 'shatterpoint[browser]'
    playwright install --only-shell chromium
"""

import json
from urllib.parse import urlparse

from shatterpoint.modules.spider import CrawlResult
from shatterpoint.utils.auth import build_auth_headers, should_send_auth
from shatterpoint.utils.formatter import print_finding, print_status
from shatterpoint.utils.validator import URLValidator

# Requests the browser may send. Anything else (POST, PUT, DELETE, ...)
# could change state on the target, so it is recorded and aborted.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Playwright resource types that mean "the app is talking to a backend".
API_TYPES = {"xhr", "fetch", "eventsource"}

# In-app navigation, as when a user follows a link: the URL changes without a
# reload, so session state the app restored in memory is kept.
SOFT_NAVIGATE = "url => { history.pushState(null, '', url); dispatchEvent(new PopStateEvent('popstate')) }"


class BrowserCrawler:
    """Visits seed URLs in headless Chromium and records what the app does."""

    def __init__(self, config: dict, validator: URLValidator):
        cfg = config.get("browser") or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.max_pages = int(cfg.get("max_pages", 30))
        self.wait_ms = int(cfg.get("wait_ms", 2000))
        self.user_agent = (config.get("crawler") or {}).get("user_agent") or None
        # Chromium knows socks5:// (and always resolves DNS through it), not socks5h://
        proxy_url = (config.get("proxy") or {}).get("url")
        self.proxy = {"server": proxy_url.replace("socks5h://", "socks5://")} if proxy_url else None
        auth = config.get("auth") or {}
        self.auth_headers = build_auth_headers(auth.get("token"), auth.get("headers"))
        self.local_storage = cfg.get("local_storage") or {}
        self.validator = validator
        self.report: dict = {"pages": [], "api_calls": [], "external_hosts": [], "blocked": []}

    async def crawl(self, seed_urls: list[str]) -> dict[str, CrawlResult]:
        """Render each seed, plus the in-scope links found on rendered pages.

        Returns {url: CrawlResult} with the rendered DOM as the body, keyed by
        where the app landed (routes that client-side redirect to /login all
        collapse into that one /login page). What the app did (backend calls,
        other hosts, blocked requests) lands in self.report.
        """
        from playwright.async_api import async_playwright  # optional dependency

        queue = list(dict.fromkeys(u for u in map(self.validator.normalize, seed_urls) if u))
        seen = set(queue)
        pages: dict[str, CrawlResult] = {}
        print_status(f"Rendering up to {self.max_pages} page(s) in headless Chromium ({len(queue)} seed(s))")

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(proxy=self.proxy)
            context = await browser.new_context(
                ignore_https_errors=True,  # same as the HTTP clients' verify=False
                service_workers="block",  # so every request passes through _route
                accept_downloads=False,  # a seed like /actuator/heapdump must not download
                user_agent=self.user_agent,
            )
            await context.route("**/*", self._route)
            context.on("request", self._on_request)
            if self.local_storage:
                # Log the app in: seed its storage on the target origin only,
                # before any page script runs. Values never reach the report.
                origin, items = json.dumps(self.validator.base_url), json.dumps(self.local_storage)
                await context.add_init_script(
                    f"if (location.origin === {origin}) "
                    f"for (const [k, v] of Object.entries({items})) localStorage.setItem(k, v)"
                )
                print_status(f"Seeding localStorage: {', '.join(self.local_storage)}")

            while queue and len(self.report["pages"]) < self.max_pages:
                url = queue.pop(0)
                page = await context.new_page()
                page.on("websocket", lambda ws: self._add_call("GET", ws.url, "websocket"))
                try:
                    response = await page.goto(url, wait_until="load")
                    await page.wait_for_timeout(self.wait_ms)  # let XHR / WebSocket traffic happen
                    redirected = self.validator.normalize(page.url) != url
                    if self.local_storage and redirected and self.validator.is_in_scope(page.url):
                        # With a seeded session, a redirect is often an auth guard
                        # that ran before the app restored it. Retry once in-app.
                        await page.evaluate(SOFT_NAVIGATE, url)
                        await page.wait_for_timeout(self.wait_ms)
                    html = await page.content()
                    title = await page.title()
                    links = await page.eval_on_selector_all("a[href]", "els => els.map(a => a.href)")
                    set_cookies = await response.header_values("set-cookie") if response else []
                except Exception as e:  # timeout, proxy failure, crashed tab, ...
                    print_finding("Browser", f"{url}: {str(e).splitlines()[0]}")
                    await page.close()
                    continue

                final_url = self.validator.normalize(page.url) or url  # differs on a client-side redirect
                status = response.status if response else 0
                self.report["pages"].append({"url": url, "final_url": final_url, "status": status, "title": title})
                if self.validator.is_in_scope(final_url):
                    headers = response.headers if response else {}
                    pages[final_url] = CrawlResult(
                        url=final_url,
                        status_code=status,
                        headers=headers,
                        set_cookies=set_cookies,
                        body=html,
                        content_type=headers.get("content-type", ""),
                    )
                for link in links:
                    link = self.validator.normalize(link)
                    if (
                        link
                        and link not in seen
                        and self.validator.is_in_scope(link)
                        and not self.validator.is_static_resource(link)
                    ):
                        seen.add(link)
                        queue.append(link)
                await page.close()

            await browser.close()

        print_finding("Browser", f"{len(self.report['pages'])} page(s) rendered, "
                                 f"{len(self.report['api_calls'])} backend call(s), "
                                 f"{len(self.report['external_hosts'])} external host(s), "
                                 f"{len(self.report['blocked'])} blocked request(s)")
        return pages

    async def _route(self, route) -> None:
        """Passive guard: block state-changing requests; send auth to the target origin only."""
        request = route.request
        if request.method not in SAFE_METHODS:
            # Query dropped: analytics beacons differ only by their parameters
            blocked = {"method": request.method, "url": request.url.split("?")[0]}
            if blocked not in self.report["blocked"]:
                self.report["blocked"].append(blocked)
            await route.abort()
        elif self.auth_headers and should_send_auth(self.validator.scheme, self.validator.target_domain, request.url):
            await route.continue_(headers={**request.headers, **self.auth_headers})
        else:
            await route.continue_()

    def _on_request(self, request) -> None:
        """Record every other host the page contacts, and its backend calls."""
        netloc = urlparse(request.url).netloc.lower()
        if netloc and netloc != self.validator.target_domain and netloc not in self.report["external_hosts"]:
            self.report["external_hosts"].append(netloc)
        if request.resource_type in API_TYPES:
            self._add_call(request.method, request.url, request.resource_type)

    def _add_call(self, method: str, url: str, kind: str) -> None:
        """Keep backend calls to the target's own site (sibling subdomains included,
        e.g. an API gateway); analytics and CDNs stay in external_hosts only."""
        host = urlparse(url).hostname or ""
        site = self.validator.registered_domain
        call = {"method": method, "url": url, "type": kind}
        if (host == site or host.endswith("." + site)) and call not in self.report["api_calls"]:
            self.report["api_calls"].append(call)
