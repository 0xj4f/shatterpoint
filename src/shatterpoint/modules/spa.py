"""
SPA Analyzer
Static analysis of Single Page Application bundles.

Pulls same-origin JS bundles referenced from the landing HTML, probes for
source maps, and extracts client-side routes, API endpoints, webpack
chunk maps, framework state dumps, and a curated set of baked-in
secrets. No browser, no JS execution — pure regex + JSON parsing.

The module is orchestration over existing helpers:
  - HTMLParser.extract_scripts for bundle enumeration
  - Extractor.extract_js_endpoints for API endpoint mining
  - Spider.probe_url for all HTTP fetches (inherits auth + timeout)
  - URLValidator.is_in_scope for scope discipline
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import httpx

from shatterpoint.utils.auth import redact_token
from shatterpoint.utils.formatter import print_finding, print_status

if TYPE_CHECKING:
    from shatterpoint.modules.extractor import Extractor
    from shatterpoint.modules.parser import HTMLParser
    from shatterpoint.utils.validator import URLValidator


# Frameworks recognised as SPA shells. Keys match the fingerprint IDs in
# src/shatterpoint/signatures/fingerprints.yaml.
_SPA_FRAMEWORK_IDS = {
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "nextjs": "Next.js",
    "nuxt": "Nuxt",
}


# Shell-confirming patterns. Presence in the raw landing HTML strongly
# suggests the whole page is an SPA shell rather than a static page with
# a widget.
_SHELL_PATTERNS = {
    "React": [
        re.compile(r'<div[^>]+id=["\']root["\'][^>]*>\s*</div>', re.IGNORECASE),
        re.compile(r'data-reactroot', re.IGNORECASE),
    ],
    "Vue.js": [
        re.compile(r'<div[^>]+id=["\']app["\'][^>]*>\s*</div>', re.IGNORECASE),
        re.compile(r'data-v-app', re.IGNORECASE),
    ],
    "Angular": [
        re.compile(r'<app-root[^>]*>\s*</app-root>', re.IGNORECASE),
        re.compile(r'ng-version=', re.IGNORECASE),
    ],
    "Next.js": [
        re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\']', re.IGNORECASE),
        re.compile(r'/_next/static/', re.IGNORECASE),
    ],
    "Nuxt": [
        re.compile(r'window\.__NUXT__', re.IGNORECASE),
        re.compile(r'id=["\']__nuxt["\']', re.IGNORECASE),
    ],
}


# Framework-specific route regexes. Minified bundles rename variables to
# single letters, so patterns anchor on the literal `path:` / `path=`
# tokens that survive minification.
_ROUTE_PATTERNS = {
    "React": [
        # createBrowserRouter / createRoutesFromElements: {path:"/foo",...}
        re.compile(r'\bpath\s*:\s*["\'](/[^"\']*)["\']'),
        # JSX in unminified / dev builds: <Route path="/foo" ...>
        re.compile(r'<Route\s+[^>]*path=["\'](/[^"\']*)["\']', re.IGNORECASE),
    ],
    "Vue.js": [
        re.compile(r'\bpath\s*:\s*["\'](/[^"\']*)["\']'),
    ],
    "Angular": [
        # RouterModule.forRoot([{path:'foo', ...}])  (Angular strips leading /)
        re.compile(r'\bpath\s*:\s*["\']([A-Za-z0-9_\-:/]+)["\']'),
    ],
    "Next.js": [
        # Pages manifest fragments: "/admin":{"page":"/admin",...}
        re.compile(r'["\'](/[A-Za-z0-9_\-/\[\]]*)["\']\s*:\s*\{[^}]*page\s*:'),
        re.compile(r'\bpath\s*:\s*["\'](/[^"\']*)["\']'),
    ],
    "Nuxt": [
        re.compile(r'\bpath\s*:\s*["\'](/[^"\']*)["\']'),
    ],
}


# Strings that routers store in `path:` but that aren't real routes.
_ROUTE_BLOCKLIST = {
    "/",
    "/*",
    "*",
    "/:path*",
}


# Curated secret patterns. Kept small — exam-grade usefulness over recall.
_SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY", re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
    ("AWS_SECRET_KEY", re.compile(r'\b([A-Za-z0-9/+=]{40})\b(?=[^A-Za-z0-9/+=])'), "aws_secret_filter"),
    ("GOOGLE_API_KEY", re.compile(r'\b(AIza[0-9A-Za-z_\-]{35})\b')),
    ("STRIPE_LIVE_SECRET", re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b')),
    ("STRIPE_LIVE_PUB", re.compile(r'\b(pk_live_[0-9a-zA-Z]{24,})\b')),
    ("SLACK_TOKEN", re.compile(r'\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b')),
    ("GITHUB_TOKEN", re.compile(r'\b(gh[pousr]_[0-9A-Za-z]{36,})\b')),
    ("FIREBASE_CONFIG_APIKEY", re.compile(r'apiKey\s*:\s*["\'](AIza[0-9A-Za-z_\-]{35})["\']')),
    ("GENERIC_API_KEY", re.compile(r'(?:API_KEY|api_key|apiKey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']')),
    ("GENERIC_SECRET", re.compile(r'(?:SECRET|secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']')),
    ("GENERIC_TOKEN_ASSIGN", re.compile(r'(?:TOKEN|token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']')),
]


# sourceMappingURL comment: //# sourceMappingURL=foo.js.map
_SOURCE_MAP_COMMENT = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')


# Webpack runtime chunk map. Shape:
#   (a[b.s]=function(e){return"static/js/"+({0:"abc",1:"def"}[e]||e)+".chunk.js"})
# Capture the {id:"name",...} object body.
_WEBPACK_CHUNK_MAP = re.compile(r'\{((?:\s*\d+\s*:\s*["\'][A-Za-z0-9_\-]+["\']\s*,?\s*){2,})\}')
_WEBPACK_CHUNK_ENTRY = re.compile(r'(\d+)\s*:\s*["\']([A-Za-z0-9_\-]+)["\']')


def detect_framework(detected_techs: list[dict], html: str) -> tuple[str | None, bool]:
    """Identify the SPA framework in use.

    Primary signal is the fingerprinter's existing tech detection. Secondary
    signal is a DOM-shell regex on the landing HTML. Both must fire for
    `shell_confirmed` to be True.

    Returns (framework_display_name or None, shell_confirmed).
    """
    framework: str | None = None
    for tech in detected_techs or []:
        tid = tech.get("id", "").lower()
        if tid in _SPA_FRAMEWORK_IDS:
            framework = _SPA_FRAMEWORK_IDS[tid]
            break

    # Fallback: if the fingerprinter didn't tag it, try shell patterns
    # directly. A positive shell hit is enough to declare the framework.
    if framework is None and html:
        for name, patterns in _SHELL_PATTERNS.items():
            if any(p.search(html) for p in patterns):
                return name, True

    shell_confirmed = False
    if framework and html:
        patterns = _SHELL_PATTERNS.get(framework, [])
        shell_confirmed = any(p.search(html) for p in patterns)

    return framework, shell_confirmed


def enumerate_bundles(html: str, base_url: str, validator: URLValidator, html_parser: HTMLParser) -> list[str]:
    """Return the list of same-origin <script src> URLs from the landing HTML.

    CDN-hosted bundles are rejected so we never fetch off-target assets.
    """
    scripts = html_parser.extract_scripts(html)
    bundles: list[str] = []
    seen: set[str] = set()
    for ext in scripts.get("external", []):
        src = ext.get("src", "")
        if not src:
            continue
        absolute = urljoin(base_url, src)
        # Normalize: drop fragments, keep query
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if not validator.is_in_scope(absolute):
            continue
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        if clean in seen:
            continue
        seen.add(clean)
        bundles.append(clean)
    return bundles


def extract_source_map_url(bundle_text: str, bundle_url: str) -> str | None:
    """Return the absolute URL of the source map, or None.

    Checks for a //# sourceMappingURL=... comment first; falls back to the
    conventional `<bundle>.map` sibling.
    """
    if not bundle_text:
        return None
    match = _SOURCE_MAP_COMMENT.search(bundle_text)
    if match:
        sm_ref = match.group(1).strip()
        if sm_ref.startswith("data:"):
            return None  # inline data URI — skip, not fetchable
        return urljoin(bundle_url, sm_ref)
    # Conventional sibling
    return bundle_url + ".map"


def parse_source_map(sm_text: str, preview_chars: int = 200) -> dict | None:
    """Parse a source-map JSON document.

    Returns {"sources": [...], "sources_count": N, "sources_preview": [{path, preview}]}
    where the preview is a truncated snippet of the original file. Returns
    None if the document isn't a parseable source map.
    """
    if not sm_text:
        return None
    try:
        doc = json.loads(sm_text)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    sources = doc.get("sources")
    if not isinstance(sources, list):
        return None
    sources_content = doc.get("sourcesContent") or []
    previews: list[dict] = []
    for idx, src_path in enumerate(sources):
        if not isinstance(src_path, str):
            continue
        content = ""
        if idx < len(sources_content) and isinstance(sources_content[idx], str):
            content = sources_content[idx][:preview_chars]
        previews.append({"path": src_path, "preview": content})
    return {
        "sources": [s for s in sources if isinstance(s, str)],
        "sources_count": len(previews),
        "sources_preview": previews,
    }


def extract_routes(text: str, framework: str) -> list[dict]:
    """Regex out client-side routes from a JS bundle or sourcesContent concat.

    Returns deduplicated [{path, source_pattern}].
    """
    if not text or framework not in _ROUTE_PATTERNS:
        return []
    seen: set[str] = set()
    routes: list[dict] = []
    for pat_idx, pattern in enumerate(_ROUTE_PATTERNS[framework]):
        for match in pattern.finditer(text):
            path = match.group(1)
            if path in _ROUTE_BLOCKLIST or path in seen:
                continue
            if len(path) > 200:
                continue
            # Angular paths lack leading slash; normalise for the crawler
            if framework == "Angular" and not path.startswith("/"):
                path = "/" + path
            seen.add(path)
            routes.append({"path": path, "source_pattern": f"{framework}#{pat_idx}"})
    return routes


def extract_chunks(bundle_text: str) -> list[str]:
    """Extract chunk names from a webpack runtime chunk map. Depth-1 only."""
    if not bundle_text:
        return []
    results: set[str] = set()
    for obj_match in _WEBPACK_CHUNK_MAP.finditer(bundle_text):
        body = obj_match.group(1)
        for entry in _WEBPACK_CHUNK_ENTRY.finditer(body):
            name = entry.group(2)
            if name:
                results.add(name)
    return sorted(results)


def extract_secrets(text: str, bundle_url: str) -> list[dict]:
    """Run curated secret patterns over bundle text.

    Returns [{type, value_redacted, bundle}]. Raw values never leave this
    function — only the first4…last4 form is surfaced.
    """
    if not text:
        return []
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    bundle_name = bundle_url.rsplit("/", 1)[-1]
    for entry in _SECRET_PATTERNS:
        # Support (name, pattern) and (name, pattern, filter) shapes
        if len(entry) == 2:
            name, pattern = entry
            extra_filter = None
        else:
            name, pattern, extra_filter = entry
        for match in pattern.finditer(text):
            value = match.group(1)
            if not value:
                continue
            # The AWS_SECRET_KEY pattern is intentionally broad (any 40-char
            # base64-ish string); require the surrounding context to hint
            # at an AWS secret to cut false positives.
            if extra_filter == "aws_secret_filter":
                ctx_start = max(0, match.start() - 60)
                ctx = text[ctx_start:match.start()].lower()
                if "aws" not in ctx and "secret" not in ctx:
                    continue
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "type": name,
                "value_redacted": redact_token(value),
                "bundle": bundle_name,
            })
    return findings


def extract_state_dumps(html: str, preview_chars: int = 500) -> dict:
    """Extract framework state dumps embedded in HTML.

    Captures __NEXT_DATA__, __NUXT__, and window.__INITIAL_STATE__ payloads,
    truncated for the report.
    """
    if not html:
        return {}
    dumps: dict = {}

    # __NEXT_DATA__ lives in a script tag
    next_data = re.search(
        r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        html,
        re.IGNORECASE | re.DOTALL,
    )
    if next_data:
        raw = next_data.group(1).strip()
        dumps["__NEXT_DATA__"] = {
            "truncated": len(raw) > preview_chars,
            "preview": raw[:preview_chars],
            "size_bytes": len(raw),
        }

    # window.__NUXT__ = {...}
    nuxt = re.search(r'window\.__NUXT__\s*=\s*(\{.*?\});', html, re.DOTALL)
    if nuxt:
        raw = nuxt.group(1).strip()
        dumps["__NUXT__"] = {
            "truncated": len(raw) > preview_chars,
            "preview": raw[:preview_chars],
            "size_bytes": len(raw),
        }

    # window.__INITIAL_STATE__ = {...}
    initial = re.search(r'window\.__INITIAL_STATE__\s*=\s*(\{.*?\});', html, re.DOTALL)
    if initial:
        raw = initial.group(1).strip()
        dumps["__INITIAL_STATE__"] = {
            "truncated": len(raw) > preview_chars,
            "preview": raw[:preview_chars],
            "size_bytes": len(raw),
        }

    return dumps


class SPAAnalyzer:
    """Orchestrates SPA bundle mining. Thin glue over pure helpers."""

    def __init__(
        self,
        config: dict,
        validator: URLValidator,
        extractor: Extractor,
        html_parser: HTMLParser,
    ):
        spa_cfg = config.get("spa") or {}
        self.enabled: bool = bool(spa_cfg.get("enabled", False))
        self.auto_when_detected: bool = bool(spa_cfg.get("auto_when_detected", False))
        self.source_maps: bool = bool(spa_cfg.get("source_maps", True))
        self.extract_secrets_enabled: bool = bool(spa_cfg.get("extract_secrets", True))
        self.max_bundles: int = int(spa_cfg.get("max_bundles", 20))
        self.max_bundle_size: int = int(spa_cfg.get("max_bundle_size_bytes", 5 * 1024 * 1024))
        self.fetch_timeout: int = int(spa_cfg.get("fetch_timeout", 15))
        self.validator = validator
        self.extractor = extractor
        self.html_parser = html_parser

    def should_run(self, framework_detected: str | None) -> bool:
        """Return True if the mining phase should execute this run."""
        if self.enabled:
            return True
        if self.auto_when_detected and framework_detected:
            return True
        return False

    async def _fetch_text(self, client: httpx.AsyncClient, url: str) -> tuple[str | None, str | None]:
        """Fetch a URL as text, regardless of content-type.

        Bypasses Spider.probe_url because its body filter drops
        `application/javascript` responses, which are exactly what we need.
        The caller's client carries the bearer-token Authorization header,
        and httpx strips it automatically on cross-origin redirects.
        """
        try:
            response = await client.get(
                url,
                follow_redirects=True,
                timeout=httpx.Timeout(self.fetch_timeout),
            )
        except httpx.TimeoutException:
            return None, "timeout"
        except httpx.ConnectError:
            return None, "connection_error"
        except Exception as e:
            return None, str(e)[:100]

        if response.status_code >= 400:
            return None, f"http_{response.status_code}"
        body = response.text or ""
        if len(body) > self.max_bundle_size:
            return None, "size_cap_exceeded"
        return body, None

    async def analyze(
        self,
        client: httpx.AsyncClient,
        landing_html: str,
        base_url: str,
        detected_techs: list[dict],
    ) -> dict:
        """Main entry point. Returns the full `spa` result block."""
        framework, shell_confirmed = detect_framework(detected_techs, landing_html)

        result: dict = {
            "detected": framework is not None,
            "framework": framework,
            "shell_confirmed": shell_confirmed,
            "bundles": [],
            "routes": [],
            "api_endpoints_from_bundles": [],
            "chunks": [],
            "secrets": [],
            "state_dumps": {},
            "mining_ran": False,
        }

        # Always extract state dumps — they're in the landing HTML,
        # essentially free.
        result["state_dumps"] = extract_state_dumps(landing_html)

        if not self.should_run(framework):
            return result

        result["mining_ran"] = True
        print_status(f"SPA mining enabled — framework={framework or 'unknown'}")

        bundle_urls = enumerate_bundles(landing_html, base_url, self.validator, self.html_parser)
        if not bundle_urls:
            print_finding("SPA", "No same-origin bundles found")
            return result

        # Hard cap to prevent downloading a monorepo build
        if len(bundle_urls) > self.max_bundles:
            print_finding("SPA", f"Capping bundles at {self.max_bundles} (found {len(bundle_urls)})")
            bundle_urls = bundle_urls[: self.max_bundles]

        combined_text_for_routes: list[str] = []
        seen_routes: set[str] = set()
        seen_endpoints: set[str] = set()
        seen_chunks: set[str] = set()

        for bundle_url in bundle_urls:
            bundle_text, err = await self._fetch_text(client, bundle_url)
            entry: dict = {
                "url": bundle_url,
                "size_bytes": len(bundle_text) if bundle_text else 0,
                "source_map_url": None,
                "source_map_found": False,
                "source_files_count": 0,
                "fetch_error": err,
            }
            if bundle_text is None:
                result["bundles"].append(entry)
                continue

            # API endpoints via existing extractor
            eps = self.extractor.extract_js_endpoints(bundle_text, bundle_url)
            for ep in eps:
                if ep["url"] in seen_endpoints:
                    continue
                seen_endpoints.add(ep["url"])
                result["api_endpoints_from_bundles"].append({
                    "url": ep["url"],
                    "source": bundle_url.rsplit("/", 1)[-1],
                    "method_hint": ep.get("source", "javascript"),
                })

            # Chunk map (webpack / Vite)
            for chunk in extract_chunks(bundle_text):
                if chunk in seen_chunks:
                    continue
                seen_chunks.add(chunk)
                result["chunks"].append({"name": chunk, "source": bundle_url.rsplit("/", 1)[-1]})

            # Secrets
            if self.extract_secrets_enabled:
                for secret in extract_secrets(bundle_text, bundle_url):
                    result["secrets"].append(secret)

            # Keep for route extraction (minified bundle text is noisy but
            # path:"..." literals survive).
            combined_text_for_routes.append(bundle_text)

            # Source map
            if self.source_maps:
                sm_url = extract_source_map_url(bundle_text, bundle_url)
                if sm_url:
                    entry["source_map_url"] = sm_url
                    sm_text, sm_err = await self._fetch_text(client, sm_url)
                    if sm_text:
                        parsed = parse_source_map(sm_text)
                        if parsed:
                            entry["source_map_found"] = True
                            entry["source_files_count"] = parsed["sources_count"]
                            # Mine routes + endpoints from original source too
                            full_source = "\n".join(
                                p.get("preview", "") for p in parsed["sources_preview"]
                            )
                            if full_source:
                                combined_text_for_routes.append(full_source)
                                for ep in self.extractor.extract_js_endpoints(full_source, sm_url):
                                    if ep["url"] in seen_endpoints:
                                        continue
                                    seen_endpoints.add(ep["url"])
                                    result["api_endpoints_from_bundles"].append({
                                        "url": ep["url"],
                                        "source": f"{bundle_url.rsplit('/', 1)[-1]}.map",
                                        "method_hint": "sourcemap",
                                    })
                            print_finding("SPA", f"source map: {sm_url} ({parsed['sources_count']} sources)")

            result["bundles"].append(entry)

        # Routes
        if framework:
            big_text = "\n".join(combined_text_for_routes)
            for route in extract_routes(big_text, framework):
                if route["path"] in seen_routes:
                    continue
                seen_routes.add(route["path"])
                result["routes"].append({
                    "path": route["path"],
                    "source_pattern": route["source_pattern"],
                })

        # Summary output
        print_finding("SPA", f"{len(result['bundles'])} bundle(s), "
                             f"{len(result['routes'])} route(s), "
                             f"{len(result['api_endpoints_from_bundles'])} endpoint(s), "
                             f"{len(result['secrets'])} secret(s), "
                             f"{len(result['chunks'])} chunk(s)")

        return result
