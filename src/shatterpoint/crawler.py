"""
shatterpoint — Main Orchestrator
Ties together all modules into a single-pass reconnaissance workflow.

Usage:
    shatterpoint -u http://target.com
    shatterpoint -u http://target.com -o ./results -v
"""

import argparse
import asyncio
import importlib.util
import re
import sys
import time
import warnings
from pathlib import Path

import httpx
import yaml
from bs4 import XMLParsedAsHTMLWarning

from shatterpoint import __version__
from shatterpoint.modules.browser import BrowserCrawler
from shatterpoint.modules.extractor import Extractor
from shatterpoint.modules.fingerprint import (
    Fingerprinter,
    finalize_technologies,
)
from shatterpoint.modules.framework_recon import FrameworkRecon
from shatterpoint.modules.parser import HTMLParser
from shatterpoint.modules.recon import ReconModule, robots_seed_paths
from shatterpoint.modules.spa import SPAAnalyzer, extract_secrets, merge_secrets
from shatterpoint.modules.spider import (
    Spider,
    is_js_content_type,
    is_non_text_js_content_type,
)
from shatterpoint.utils.auth import (
    ENV_VAR,
    build_auth_headers,
    make_auth_strip_hook,
    redact_headers,
    redact_token,
    resolve_headers,
    resolve_token,
    warn_on_expiry,
)
from shatterpoint.utils.baseline import fetch_baseline
from shatterpoint.utils.formatter import (
    BANNER_TEXT,
    console,
    print_banner,
    print_finding,
    print_section,
    print_status,
    print_summary,
    save_report,
)
from shatterpoint.utils.http import build_client
from shatterpoint.utils.proxy import resolve_proxy
from shatterpoint.utils.stacktrace import merge_findings, mine_response
from shatterpoint.utils.validator import URLValidator

# Suppress SSL warnings (OSCP targets use self-signed certs)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
# XML docs (sitemaps, RSS feeds, oembed ?format=xml) are routed to the XML
# parser in parser.py; this filters any residual warning from a mislabeled body.
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


class _BannerArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that prepends the shatterpoint banner to --help output."""

    def format_help(self) -> str:
        return f"{BANNER_TEXT}\n\n" + super().format_help()


def load_config(config_path: str | None = None) -> dict:
    """Load configuration from YAML file.

    When `config_path` is None (user did not pass -c), we try the
    default ``config.yaml`` silently — running without a config is a
    valid mode.

    When `config_path` is explicit, the file MUST exist and parse
    cleanly; we exit non-zero on either failure rather than silently
    falling back to defaults. The pre-fix behaviour was to silently
    return `{}` on any failure, leaving operators unable to diagnose
    why their config wasn't being honoured.
    """
    explicit = config_path is not None
    path = config_path or "config.yaml"
    config_file = Path(path)

    if not config_file.exists():
        if explicit:
            console.print(f"[bold red]ERROR:[/bold red] config file not found: {path}")
            sys.exit(2)
        return {}

    try:
        with open(config_file, "r") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        console.print(f"[bold red]ERROR:[/bold red] config file '{path}' has YAML syntax errors:")
        console.print(f"  {e}")
        sys.exit(2)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = _BannerArgumentParser(
        prog="shatterpoint",
        description="shatterpoint — OSCP Recon Attack Surface Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic unauthenticated recon on an OSCP lab box
  shatterpoint -u http://10.10.10.1

  # Limit depth/pages for a fast first pass
  shatterpoint -u http://target.htb -d 5 -p 200

  # Authenticated crawl with a bearer token
  shatterpoint -u http://target.htb --token $JWT

  # Arbitrary auth headers (-H is repeatable; covers all auth types)
  shatterpoint -u http://target.htb -H "Authorization: Basic dXNlcjpwYXNz"
  shatterpoint -u http://target.htb -H "X-API-Key: $KEY" -H "X-Tenant: acme"
  shatterpoint -u http://target.htb -H "Cookie: session=$SID; role=admin"

  # SPA target (React/Vue/Angular/Next.js/Nuxt) — mines bundles & routes
  shatterpoint -u http://localhost:3001 --token $JWT --spa

  # SPA-only pass, skip noisy path probing on catch-all routers
  shatterpoint -u http://localhost:3001 --token $JWT --spa --no-recon

  # Render the app in headless Chromium too (needs shatterpoint[browser])
  shatterpoint -u http://localhost:3001 --spa --browser

  # Route ALL traffic through a proxy — inspect (Burp), rewrite (mitmproxy),
  # or scan from another IP (TOR). Bare host:port defaults to http://.
  shatterpoint -u http://target.htb --proxy http://127.0.0.1:8080
  shatterpoint -u http://target.htb --proxy socks5h://127.0.0.1:9050   # TOR

  # Save to a specific loot directory, verbose
  shatterpoint -u https://10.10.10.1:8443 -o ./loot -v

  # Config file instead of CLI flags
  shatterpoint -c custom_config.yaml

Environment:
  SHATTERPOINT_TOKEN    Bearer token fallback when --token is not passed.
        """,
    )
    parser.add_argument("-u", "--url", help="Target URL (overrides config)")
    parser.add_argument(
        "-c", "--config", default=None,
        help="Config file path (default: config.yaml if it exists; loud error if -c file is missing or malformed)",
    )
    parser.add_argument("-d", "--depth", type=int, help="Max crawl depth")
    parser.add_argument("-p", "--pages", type=int, help="Max pages to crawl")
    parser.add_argument("-t", "--threads", type=int, help="Concurrency level")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-fingerprint", action="store_true", help="Skip fingerprinting")
    parser.add_argument("--no-recon", action="store_true", help="Skip recon modules")
    parser.add_argument(
        "--spa",
        action="store_true",
        help=(
            "Enable SPA bundle mining (React/Vue/Angular/Next.js/Nuxt). "
            "Fetches same-origin JS bundles, probes source maps, extracts "
            "client-side routes, API endpoints, chunks, and baked secrets. "
            "SPA framework detection runs every scan regardless of this flag."
        ),
    )
    parser.add_argument(
        "--framework-recon",
        action="store_true",
        help=(
            "Enable framework-aware deep recon. When a supported framework "
            "is detected (v1: Laravel), probes framework-specific paths for "
            "common exposures (debug handlers, env file leaks, debug panels). "
            "Stack-trace mining of crawl responses runs every scan regardless."
        ),
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help=(
            "Also render pages in headless Chromium (Playwright) to capture the "
            "rendered DOM, client-side redirects and the XHR/fetch/WebSocket calls "
            "the app makes. Passive: never clicks; non-GET requests are blocked. "
            "Needs: pip install 'shatterpoint[browser]' && playwright install --only-shell chromium"
        ),
    )
    parser.add_argument(
        "--browser-storage",
        action="append",
        metavar="KEY=VALUE",
        help=(
            "Seed localStorage on the target origin before pages load (repeatable), so "
            "--browser crawls an SPA logged in, e.g. --browser-storage token=$JWT. "
            "Values never reach the report."
        ),
    )
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds")
    parser.add_argument(
        "--token",
        help=(
            "Bearer token for authenticated crawling (sent as Authorization: Bearer <token>). "
            f"Also reads ${ENV_VAR} env var or config 'auth.token'. "
            "CLI > env > config."
        ),
    )
    parser.add_argument(
        "-H", "--header",
        action="append",
        metavar='"Name: value"',
        dest="header",
        help=(
            "Add an arbitrary auth header (repeatable). Covers every auth type: "
            "Basic (-H 'Authorization: Basic <b64>'), API keys (-H 'X-API-Key: ...'), "
            "Cookie (-H 'Cookie: session=...'), NTLM/Negotiate, custom headers. "
            "Headers are origin-scoped: stripped on cross-origin redirects, like --token. "
            "An explicit -H 'Authorization: ...' overrides --token."
        ),
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help=(
            "Route ALL traffic through a proxy. Accepts http://host:port "
            "(Burp / mitmproxy; a bare host:port defaults to http://) or "
            "socks5h://host:port (TOR: socks5h://127.0.0.1:9050 — DNS via the "
            "proxy). Overrides config 'proxy.url'. A malformed value aborts "
            "the scan rather than connecting directly."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()


# Route segments that are placeholders, not pages: :id, [slug], *
_PARAM_ROUTE = re.compile(r"/:|\[|\*")


def _dedupe(items: list[dict], key) -> list[dict]:
    """Keep the first item per key(item), preserving order."""
    seen: set = set()
    unique: list[dict] = []
    for item in items:
        k = key(item)
        if k not in seen:
            seen.add(k)
            unique.append(item)
    return unique


class CrawlOrchestrator:
    """Sequences the ten-phase recon pipeline.

    State that flows between phases lives on the instance; each
    ``_phaseN_*`` method reads and mutates it. :meth:`run` opens the shared
    recon client and drives the phases in order. Behaviour is identical to
    the previous inline ``run_crawler`` — this is a mechanical extraction
    for readability, not a logic change.
    """

    def __init__(self, config: dict):
        self.config = config
        # Optional upstream proxy — applied to every httpx client this
        # orchestrator (and the spider) opens, so ALL traffic is routed.
        self.proxy_url = (config.get("proxy") or {}).get("url")
        self.target_url = config["target"]["url"]
        self.start_time = time.time()

        # Components
        self.validator = URLValidator(self.target_url)
        self.spider = Spider(config, self.validator)
        self.html_parser = HTMLParser()
        self.extractor = Extractor()
        self.fingerprinter = Fingerprinter(config)
        self.recon = ReconModule(config, self.validator.base_url)
        self.spa_analyzer = SPAAnalyzer(config, self.validator, self.extractor, self.html_parser)
        self.framework_recon = FrameworkRecon(config, self.validator)
        self.browser = BrowserCrawler(config, self.validator)

        # Results container
        self.results = {
            "target": {
                "url": self.target_url,
                "domain": self.validator.target_domain,
                "base_url": self.validator.base_url,
            },
            "scan_start": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "technologies": [],
            "forms": [],
            "api_endpoints": [],
            "file_uploads": [],
            "interesting_files": [],
            "comments": [],
            "emails": [],
            "parameters": [],
            "auth_mechanisms": [],
            "security_headers": [],
            "robots_txt": {},
            "sitemap": {},
            "security_txt": {},
            "common_paths": [],
            "all_urls": [],
            "attack_surface": {},
            "spa": {},
            "secrets": [],
            "framework_recon": {},
            "debug_exposure": {},
            "browser": {},
        }

        # Cross-phase state (populated as phases run)
        self.seed_urls: list[str] = [self.target_url]
        self.baseline = None
        self.landing_html: str = ""
        self.crawl_results: dict = {}
        self.browser_pages: dict = {}
        self.all_forms: list[dict] = []
        self.unique_apis: list[dict] = []
        self.all_urls: list[str] = []

    async def run(self) -> dict:
        """Open the shared recon client and drive all ten phases."""
        recon_headers = {"User-Agent": self.config.get("crawler", {}).get("user_agent", "")}
        auth_cfg = self.config.get("auth") or {}
        # Combined auth headers: bearer token (--token) + arbitrary -H headers,
        # applied to every recon/fingerprint/framework-recon/SPA request.
        auth_headers = build_auth_headers(auth_cfg.get("token"), auth_cfg.get("headers"))
        recon_headers.update(auth_headers)
        # Origin-scope them: strip on any cross-origin redirect the recon
        # client follows (covers custom headers httpx wouldn't strip itself).
        recon_hooks: dict = {}
        if auth_headers:
            recon_hooks = {"request": [make_auth_strip_hook(
                self.validator.scheme, self.validator.target_domain, set(auth_headers),
            )]}
        async with build_client(
            proxy=self.proxy_url,
            limits=httpx.Limits(max_connections=10),
            headers=recon_headers,
            event_hooks=recon_hooks,
        ) as recon_client:
            await self._phase1_recon(recon_client)
            await self._phase15_path_probe(recon_client)
            await self._phase16_body(recon_client)
            await self._phase17_framework(recon_client)
            await self._phase18_spa(recon_client)

        await self._phase19_browser()
        await self._phase2_crawl()
        self._phase3_extract()
        self._phase4_fingerprint()
        self._phase5_surface()

        # Timing
        self.results["scan_duration"] = round(time.time() - self.start_time, 2)
        self.results["pages_crawled"] = self.spider.pages_crawled
        return self.results

    async def _phase1_recon(self, recon_client) -> None:
        print_section("PHASE 1: Pre-Crawl Reconnaissance")

        # Fetch the catch-all baseline ONCE and share it across every
        # path-probing phase (recon, fingerprint, framework-recon) so the
        # same bogus-path round-trip isn't paid for three times per scan.
        self.baseline = await fetch_baseline(recon_client, self.validator.base_url)

        recon_results = await self.recon.run_all(recon_client, baseline=self.baseline)
        self.results.update(recon_results)

        # Add sitemap URLs to seed list
        sitemap_urls = self.results.get("sitemap", {}).get("urls", [])
        if sitemap_urls:
            for surl in sitemap_urls[:50]:
                if self.validator.is_in_scope(surl):
                    self.seed_urls.append(surl)
            print_status(f"Added {len(self.seed_urls) - 1} sitemap URLs as seeds")

        # Add robots.txt paths as seeds (Disallow rules are patterns; only
        # their literal prefix is a real path — see robots_seed_paths)
        robots_disallowed = self.results.get("robots_txt", {}).get("disallowed", [])
        for path in robots_seed_paths(robots_disallowed):
            full_url = f"{self.validator.base_url}{path}"
            if self.validator.is_in_scope(full_url):
                self.seed_urls.append(full_url)

    async def _phase15_path_probe(self, recon_client) -> None:
        # ─── Phase 1.5: Fingerprint via path probing ─────────────
        if self.config.get("_no_fingerprint"):
            return
        print_section("PHASE 1.5: Technology Path Probing")
        path_detections = await self.fingerprinter.probe_known_paths(
            recon_client, self.validator.base_url, baseline=self.baseline,
        )
        if path_detections:
            self.results["technologies"].extend(path_detections)
        # Dedup + resolve conflicts after Phase 1.5 so the Phase 4 merge
        # sees a clean per-id list (avoids 6× WordPress rows) and any
        # mutually-exclusive collision (e.g. Laravel vs Rails on a shared
        # <meta name="csrf-token">) is settled — strongest evidence wins.
        self.results["technologies"] = finalize_technologies(
            self.results["technologies"], self.fingerprinter.signatures
        )

    async def _phase16_body(self, recon_client) -> None:
        # ─── Phase 1.6: Landing-page body detection ──────────────
        # Fetch the landing HTML and run body/cookie/form-field
        # fingerprint checks. This MUST happen BEFORE framework deep
        # recon, otherwise targets that only reveal Laravel via cookies
        # (production deploys with Ignition disabled) never trigger the
        # deep-recon phase even when --framework-recon is set.
        print_section("PHASE 1.6: Landing-Page Body Detection")
        landing_resp = None
        landing_forms: list[dict] = []
        try:
            landing_resp = await recon_client.get(
                self.target_url,
                follow_redirects=True,
                timeout=httpx.Timeout(10),
            )
            if landing_resp.status_code == 429 or landing_resp.status_code >= 500:
                # Still rate-limited / erroring after the client's retries.
                # An error page is not the app: fingerprinting it or mining it
                # for SPA bundles gives wrong, run-to-run-different answers.
                print_finding(
                    "Landing",
                    f"[bold red]WARNING:[/bold red] landing page answered "
                    f"{landing_resp.status_code}; skipping body-based detection "
                    "(lower --threads / raise crawler.delay if the target rate-limits)",
                )
            else:
                self.landing_html = landing_resp.text or ""
        except Exception as e:
            print_finding("Landing", f"Could not fetch landing HTML: {e}")

        if self.landing_html and not self.config.get("_no_fingerprint"):
            # Pass forms parsed from the landing HTML so the form_fields:
            # signature channel can fire (Laravel _token, etc.).
            landing_forms = self.html_parser.extract_forms(self.landing_html, self.target_url)
            body_detections = self.fingerprinter.fingerprint_from_response(
                self.target_url,
                dict(landing_resp.headers) if landing_resp is not None else {},
                self.landing_html,
                forms=landing_forms,
            )
            existing_ids = {t["id"] for t in self.results["technologies"]}
            for det in body_detections:
                if det["id"] not in existing_ids:
                    self.results["technologies"].append(det)
                    existing_ids.add(det["id"])
            # Re-run dedup + conflict resolution after body merges so
            # the framework_recon decision sees a clean tech list.
            self.results["technologies"] = finalize_technologies(
                self.results["technologies"], self.fingerprinter.signatures,
            )

    async def _phase17_framework(self, recon_client) -> None:
        # ─── Phase 1.7: Framework deep recon ─────────────────────
        # Triggered when a supported framework appears in the detected
        # techs (v1: Laravel) AND framework_recon is enabled or
        # auto_when_detected is set. Mirrors the SPA gating pattern.
        print_section("PHASE 1.7: Framework Deep Recon")
        self.results["framework_recon"] = await self.framework_recon.analyze(
            recon_client, self.validator.base_url, self.results["technologies"],
            baseline=self.baseline,
        )
        if (
            self.results["framework_recon"].get("detected_frameworks")
            and not self.results["framework_recon"].get("ran")
        ):
            detected = self.results["framework_recon"]["detected_frameworks"]
            print_finding(
                "Framework Recon",
                f"{', '.join(d.title() for d in detected)} detected — "
                "rerun with --framework-recon to probe framework-specific paths",
            )

    async def _phase18_spa(self, recon_client) -> None:
        # ─── Phase 1.8: SPA Analysis ─────────────────────────────
        # Landing HTML was fetched in Phase 1.6; we reuse it here so
        # SPA mining doesn't need a second round-trip.
        print_section("PHASE 1.8: SPA Analysis")
        self.results["spa"] = await self.spa_analyzer.analyze(
            recon_client, self.landing_html, self.validator.base_url, self.results["technologies"]
        )

        # If SPA detected but mining didn't run, nudge the user.
        if (
            self.results["spa"].get("detected")
            and not self.results["spa"].get("mining_ran")
        ):
            print_finding(
                "SPA",
                f"{self.results['spa']['framework']} detected — "
                "rerun with --spa to mine bundles, routes, and secrets",
            )

        # Add SPA-discovered routes to the crawl seed list. Parameterised
        # routes (/users/:id, /posts/[slug], /docs/*) stay in the report but
        # aren't crawled: the literal ":id" URL is not a page.
        added = 0
        for route in self.results["spa"].get("routes", []):
            if _PARAM_ROUTE.search(route["path"]):
                continue
            route_url = f"{self.validator.base_url}{route['path']}"
            if self.validator.is_in_scope(route_url):
                self.seed_urls.append(route_url)
                added += 1
        if added:
            print_status(f"Added {added} SPA route(s) as crawl seeds")

    async def _phase19_browser(self) -> None:
        # ─── Phase 1.9: Browser crawl (--browser) ────────────────
        # Renders the seeds (SPA routes included) in headless Chromium.
        # URLs only the browser saw become HTTP-crawl seeds; the rendered
        # pages replace their empty-shell HTTP versions after Phase 2.
        if not self.browser.enabled:
            return
        print_section("PHASE 1.9: Browser Crawl")
        self.browser_pages = await self.browser.crawl(self.seed_urls)
        self.results["browser"] = self.browser.report
        self.seed_urls += list(self.browser_pages)
        self.seed_urls += [
            c["url"] for c in self.browser.report["api_calls"]
            if c["method"] == "GET" and self.validator.is_in_scope(c["url"])
        ]

    async def _phase2_crawl(self) -> None:
        # ─── Phase 2: Crawl ─────────────────────────────────────────
        print_section("PHASE 2: Crawling & Discovery")
        # Concrete API paths mined from the SPA bundles are fetched too (GET),
        # so their responses are seen, e.g. by mitmproxy when --proxy is set.
        # Added here rather than in 1.8 so the browser never renders JSON.
        for endpoint in self.results["spa"].get("api_endpoints_from_bundles", []):
            url = self.validator.normalize(endpoint["url"])
            if (
                url
                and "${" not in url
                and self.validator.is_in_scope(url)
                and self.extractor.API_INDICATORS.search(url)
            ):
                self.seed_urls.append(url)
        # Ordered dedupe: set() order changes per process (hash seed), which
        # made crawl order — and every "first wins" result — differ per run.
        self.seed_urls = list(dict.fromkeys(self.seed_urls))
        self.crawl_results = await self.spider.crawl(self.seed_urls)
        self.crawl_results.update(self.browser_pages)

    def _phase3_extract(self) -> None:
        # ─── Phase 3: Extract & Analyze ─────────────────────────────
        print_section("PHASE 3: Extraction & Analysis")

        self.all_urls = sorted(self.crawl_results)
        self.results["all_urls"] = list(self.all_urls)
        all_emails = set()
        self.all_forms = []
        all_api_endpoints = []
        all_comments = []
        all_auth = []
        all_security_headers = []
        all_js_endpoints = []
        # Stack-trace mining runs on every crawled page regardless of any
        # framework flag — it's the universal "did the server leak debug
        # info in an error response?" check.
        stacktrace_findings: list[tuple[str, dict]] = []
        crawl_secrets: list[dict] = []

        recon_cfg = self.config.get("recon", {})
        extract_cfg = self.config.get("extract", {})

        want_forms = extract_cfg.get("forms", True)
        want_comments = extract_cfg.get("comments", True)
        want_js_eps = extract_cfg.get("js_endpoints", True)
        want_secrets = extract_cfg.get("secrets", True)
        want_auth = recon_cfg.get("auth_detection", True)
        rate_limited = 0

        # Sorted so every "first wins" result (dedup winners, debug_exposure
        # scalars, comment order) is the same run to run; crawl_results is
        # in fetch-completion order.
        for url, crawl_result in sorted(self.crawl_results.items()):
            if crawl_result.error:
                continue
            if crawl_result.status_code == 429:
                # Still rate-limited after retries: the body is the limiter's
                # error page and its headers aren't the app's.
                rate_limited += 1
                continue

            body = crawl_result.body
            headers = crawl_result.headers
            content_type = crawl_result.content_type or headers.get("content-type", "")
            is_js = is_js_content_type(content_type) or url.split("?", 1)[0].endswith((".js", ".mjs"))

            # Header-level evidence needs no body: a binary /backup.sql or an
            # empty 401 + WWW-Authenticate still counts.
            if self.validator.is_interesting_file(url):
                self.results["interesting_files"].append({
                    "url": url,
                    "status_code": crawl_result.status_code,
                    "content_type": crawl_result.content_type,
                })

            page_forms: list[dict] = []

            # Baked secrets in JS the spider fetched (any page, no --spa).
            if body and want_secrets and is_js:
                crawl_secrets.extend(extract_secrets(body, url, source="js"))

            # application/javascript bodies are captured only for the secret
            # scan above; keep them out of the HTML-oriented extractors so
            # forms/comments/emails/stack-traces don't change.
            if body and not is_non_text_js_content_type(content_type):
                # Stack-trace miner — empty dict for clean pages, populated
                # dict for pages with debug/framework/ignition signals.
                st = mine_response(body)
                if st:
                    stacktrace_findings.append((url, st))

                # One DOM parse shared by every extractor below.
                doc = self.html_parser.parse(body)

                if want_forms or want_auth:
                    page_forms = self.html_parser.extract_forms(doc, url)
                    if want_forms:
                        self.all_forms.extend(page_forms)

                if want_comments:
                    all_comments.extend(self.html_parser.extract_comments(doc, url))

                if extract_cfg.get("emails", True):
                    all_emails.update(self.html_parser.extract_emails(body))

                # Extract API endpoints from URL/response
                if extract_cfg.get("api_endpoints", True):
                    all_api_endpoints.extend(self.extractor.extract_api_endpoints(url, headers, body))

                # Extract JS endpoints + inline-script secrets (covers
                # __NEXT_DATA__ / __NUXT__ and the --browser rendered DOM)
                want_inline_secrets = want_secrets and not is_js
                if want_js_eps or want_inline_secrets:
                    for inline_js in self.html_parser.extract_scripts(doc).get("inline", []):
                        if want_js_eps:
                            all_js_endpoints.extend(self.extractor.extract_js_endpoints(inline_js, url))
                        if want_inline_secrets:
                            crawl_secrets.extend(extract_secrets(inline_js, url, source="inline"))

            # Detect auth mechanisms + security headers (separate taxonomies)
            if want_auth:
                all_auth.extend(self.recon.detect_auth_mechanisms(
                    url, headers, body, page_forms,
                    set_cookies=getattr(crawl_result, "set_cookies", None),
                ))
                all_security_headers.extend(self.recon.detect_security_headers(url, headers))

        if rate_limited:
            print_finding(
                "Crawl",
                f"[bold red]WARNING:[/bold red] {rate_limited} page(s) still rate-limited (429) "
                "after retries and left out of the analysis — lower --threads or raise "
                "crawler.delay",
            )

        # Deduplicate API endpoints (includes SPA-mined and browser-seen endpoints)
        spa_endpoints = self.results.get("spa", {}).get("api_endpoints_from_bundles", [])
        browser_endpoints = [
            {"url": c["url"], "source": f"browser:{c['type']}"}
            for c in self.results["browser"].get("api_calls", [])
        ]
        self.unique_apis = _dedupe(
            all_api_endpoints + all_js_endpoints + spa_endpoints + browser_endpoints,
            key=lambda api: api.get("url", ""),
        )

        self.results["secrets"] = merge_secrets(
            self.results.get("spa", {}).get("secrets", []), crawl_secrets
        )

        self.results["forms"] = self.all_forms
        self.results["api_endpoints"] = self.unique_apis
        self.results["comments"] = all_comments
        self.results["emails"] = sorted(all_emails)
        self.results["parameters"] = self.extractor.extract_url_parameters(self.all_urls)

        # Merge stack-trace findings into the debug_exposure block. If the
        # stack-trace miner identified a framework that the fingerprinter
        # didn't, synthesise a tech entry so the operator sees it in the
        # summary tech table too.
        if stacktrace_findings:
            self.results["debug_exposure"] = merge_findings(stacktrace_findings)
            st_framework = self.results["debug_exposure"].get("framework")
            if st_framework:
                # Normalise to a fingerprint id: "Spring Boot" -> "springboot"
                # so the synthesised entry merges with the springboot signature.
                tech_id = st_framework.lower().replace(" ", "")
                existing_ids = {t.get("id") for t in self.results["technologies"]}
                if tech_id not in existing_ids:
                    self.results["technologies"].append({
                        "id": tech_id,
                        "name": st_framework,
                        "category": "Framework",
                        "version": self.results["debug_exposure"].get("framework_version"),
                        "matched_on": [{
                            "method": "stacktrace",
                            "detail": "Detected via leaked stack trace in error response",
                        }],
                        "confidence": "high",
                    })
                else:
                    # Add stack-trace evidence to the existing entry
                    for tech in self.results["technologies"]:
                        if tech.get("id") == tech_id:
                            tech.setdefault("matched_on", []).append({
                                "method": "stacktrace",
                                "detail": "Detected via leaked stack trace in error response",
                            })
                            if not tech.get("version") and self.results["debug_exposure"].get("framework_version"):
                                tech["version"] = self.results["debug_exposure"]["framework_version"]
                            break

        # Deduplicate auth mechanisms
        self.results["auth_mechanisms"] = _dedupe(
            all_auth, key=lambda a: (a["type"], a.get("url", ""), a.get("detail", "")[:50]),
        )

        # Deduplicate security headers — one entry per (header, value) gives
        # the operator one snapshot rather than a per-URL flood.
        self.results["security_headers"] = _dedupe(
            all_security_headers, key=lambda sh: (sh.get("header", ""), sh.get("value", "")),
        )

        # File uploads
        self.results["file_uploads"] = [f for f in self.all_forms if f.get("has_file_upload")]

    def _phase4_fingerprint(self) -> None:
        # ─── Phase 4: Fingerprinting ────────────────────────────────
        if self.config.get("_no_fingerprint"):
            return
        print_section("PHASE 4: Technology Fingerprinting")
        # Group forms by URL so the form_fields: signature channel can
        # fire on the aggregated pass (Laravel _token detection, etc).
        forms_by_url: dict[str, list[dict]] = {}
        for f in self.all_forms:
            forms_by_url.setdefault(f.get("found_on", ""), []).append(f)
        # Sorted for stable evidence order; 429 pages are the rate limiter's
        # error page, not the app, so they're not fingerprinted.
        pages = {
            url: result for url, result in sorted(self.crawl_results.items())
            if result.status_code != 429
        }
        crawl_detections = self.fingerprinter.fingerprint_aggregate(pages, forms_by_url=forms_by_url)

        # Append all crawl detections and run one unified dedup pass —
        # avoids the bug where Phase 4's inline merge silently dropped
        # extra evidence when entries had been duplicated by Phase 1.5.
        self.results["technologies"].extend(crawl_detections)
        # Final dedup + conflict-resolution pass after all evidence is in.
        self.results["technologies"] = finalize_technologies(
            self.results["technologies"], self.fingerprinter.signatures
        )

        for tech in self.results["technologies"]:
            print_finding(
                "Tech",
                f"{tech['name']} ({tech.get('category', '')}) "
                f"v{tech.get('version', '?')} [{tech.get('confidence', '?')}]",
            )

    def _phase5_surface(self) -> None:
        # ─── Phase 5: Attack Surface Summary ────────────────────────
        print_section("PHASE 5: Attack Surface Analysis")
        self.results["attack_surface"] = self.extractor.analyze_attack_surface(
            self.all_forms, self.all_urls, self.unique_apis
        )


async def run_crawler(config: dict) -> dict:
    """Main crawler orchestration logic.

    Thin wrapper over :class:`CrawlOrchestrator` — the module-level entry
    point that ``main()`` (and any external caller) invokes.
    """
    return await CrawlOrchestrator(config).run()


def main():
    """Entry point."""
    args = parse_args()
    config = load_config(args.config)

    # Apply CLI overrides
    if args.url:
        config.setdefault("target", {})["url"] = args.url
    if args.depth:
        config.setdefault("crawler", {})["max_depth"] = args.depth
    if args.pages:
        config.setdefault("crawler", {})["max_pages"] = args.pages
    if args.threads:
        config.setdefault("crawler", {})["concurrency"] = args.threads
    if args.timeout:
        config.setdefault("crawler", {})["timeout"] = args.timeout
    if args.verbose:
        config.setdefault("output", {})["verbose"] = True
    if args.no_fingerprint:
        config["_no_fingerprint"] = True
    if args.spa:
        config.setdefault("spa", {})["enabled"] = True
    if args.framework_recon:
        config.setdefault("framework_recon", {})["enabled"] = True
    if args.browser:
        if importlib.util.find_spec("playwright") is None:
            console.print(
                "[bold red]ERROR:[/bold red] --browser needs Playwright: "
                # \[ keeps Rich from eating [browser] as a markup tag
                "pip install 'shatterpoint\\[browser]' && playwright install --only-shell chromium"
            )
            sys.exit(2)
        config.setdefault("browser", {})["enabled"] = True
    for item in args.browser_storage or []:
        key, _, value = item.partition("=")
        config.setdefault("browser", {}).setdefault("local_storage", {})[key] = value
    if args.no_recon:
        config.setdefault("recon", {}).update({
            "robots_txt": False,
            "sitemap_xml": False,
            "security_txt": False,
            "common_paths": False,
        })

    # Resolve bearer token (CLI > env > config) and stash into config.
    # The raw token / header values only ever live under config['auth'] —
    # never placed into the results dict that gets serialized to disk.
    token = resolve_token(args.token, config)
    token_display = redact_token(token) if token else ""
    config.setdefault("auth", {})["token"] = token
    config["auth"]["token_display"] = token_display

    # Resolve arbitrary -H auth headers (CLI > config). Malformed -H
    # entries are warned about and skipped.
    custom_headers, header_errors = resolve_headers(args.header, config)
    config["auth"]["headers"] = custom_headers
    header_display = redact_headers(custom_headers)
    config["auth"]["headers_display"] = header_display

    # Resolve the proxy (CLI > config). A malformed value aborts the scan —
    # we must never silently connect direct when a proxy was requested, as
    # that would deanonymise a TOR user.
    proxy_url, proxy_err = resolve_proxy(args.proxy, config)
    if proxy_err:
        console.print(f"[bold red]ERROR:[/bold red] --proxy {proxy_err}")
        sys.exit(2)
    config.setdefault("proxy", {})["url"] = proxy_url

    print_banner(token_display=token_display, header_display=header_display)

    for bad in header_errors:
        print_finding(
            "Auth",
            f"[bold red]WARNING:[/bold red] ignoring malformed -H header "
            f"(expected 'Name: value'): {bad!r}",
        )

    # Validate target
    target_url = config.get("target", {}).get("url", "")
    if not target_url or target_url == "http://example.com":
        console.print("[bold red]ERROR:[/bold red] No target URL specified!")
        console.print("  Use: shatterpoint -u http://target.com")
        sys.exit(1)

    # Ensure scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
        config["target"]["url"] = target_url

    print_status(f"Target: {target_url}")
    print_status(f"Config: {args.config or 'config.yaml (default, optional)'}")
    if proxy_url:
        print_status(f"Proxy: {proxy_url} — all traffic routed through it")
    if token:
        warning = warn_on_expiry(token)
        if warning:
            print_finding("Auth", f"[bold red]WARNING:[/bold red] {warning}")
    console.print()

    # Run
    try:
        results = asyncio.run(run_crawler(config))
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user[/bold red]")
        sys.exit(1)

    # Output
    print_section("RESULTS")
    print_summary(results)

    # Save report
    output_dir = args.output or config.get("output", {}).get("directory", "./output")
    report_path = save_report(results, output_dir)
    console.print(f"[bold green]Report saved:[/bold green] {report_path}")
    console.print()


if __name__ == "__main__":
    main()
