"""
Recon Module
Handles robots.txt, sitemap.xml, security.txt, common paths,
and authentication mechanism detection.
"""

import re
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

import httpx

from shatterpoint.utils.baseline import REDIRECT_CODES, Baseline, fetch_baseline
from shatterpoint.utils.formatter import print_finding, print_status
from shatterpoint.utils.http import parse_set_cookies

# Sitemap indexes can nest; real sites go 1–2 levels deep.
_SITEMAP_MAX_DEPTH = 3


def robots_seed_paths(disallowed: list[str]) -> list[str]:
    """Turn robots.txt Disallow rules into crawlable paths.

    Rules are patterns, not URLs: `/admin/*.php$` means "anything under
    /admin/ ending .php". The literal prefix before the first `*` / `$` is
    the part that exists, so that's what gets crawled. A missing leading
    slash is added; empty and duplicate results are dropped.
    """
    paths: list[str] = []
    for rule in disallowed:
        prefix = re.split(r"[*$]", rule, maxsplit=1)[0].strip()
        if not prefix:
            continue
        if not prefix.startswith("/"):
            prefix = "/" + prefix
        if prefix not in paths:
            paths.append(prefix)
    return paths


class ReconModule:
    """
    Performs passive reconnaissance tasks:
    - robots.txt parsing
    - sitemap.xml parsing
    - security.txt check
    - Common admin/sensitive path probing
    - Authentication mechanism detection
    """

    # Common paths to probe (high-value for OSCP)
    COMMON_PATHS = [
        # Admin panels
        "/admin", "/admin/", "/administrator/", "/admin/login",
        "/wp-admin/", "/wp-login.php", "/manager/html",
        "/phpmyadmin/", "/pma/", "/adminer.php",
        "/cpanel", "/webmail",
        # Login / Auth
        "/login", "/login.php", "/signin", "/auth", "/oauth",
        "/user/login", "/users/sign_in", "/account/login",
        # API docs
        "/swagger-ui.html", "/swagger-ui/", "/api-docs",
        "/swagger.json", "/openapi.json", "/graphql", "/graphiql",
        "/api/", "/api/v1/", "/api/v2/", "/rest/",
        # Info disclosure
        "/info.php", "/phpinfo.php", "/server-status", "/server-info",
        "/.env", "/.git/HEAD", "/.git/config",
        "/.svn/entries", "/.svn/wc.db",
        "/.htaccess", "/.htpasswd",
        "/web.config", "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/elmah.axd", "/trace.axd",
        # Backup / Config
        "/backup/", "/backups/", "/db/", "/database/",
        "/config/", "/conf/", "/configuration/",
        "/old/", "/temp/", "/tmp/", "/test/",
        "/debug/", "/debug/default/dashboard",
        # CMS specific
        "/xmlrpc.php", "/wp-json/wp/v2/users",
        "/feed/", "/sitemap_index.xml",
        "/CHANGELOG.txt", "/README.txt", "/LICENSE.txt",
        "/INSTALL.txt", "/UPGRADE.txt",
        # Dev tools
        "/console", "/_debug", "/_profiler",
        "/actuator", "/actuator/health", "/actuator/env",
        "/metrics", "/health", "/status",
    ]

    def __init__(self, config: dict, base_url: str):
        self.config = config.get("recon", {})
        self.base_url = base_url.rstrip("/")

    async def run_all(
        self, client: httpx.AsyncClient, baseline: Baseline | None = None
    ) -> dict:
        """Run all recon modules and return combined results.

        `baseline` is the shared catch-all snapshot fetched once by the
        orchestrator. When None (standalone use / unit tests) the common-
        path probe fetches its own.
        """
        results = {}

        if self.config.get("robots_txt", True):
            results["robots_txt"] = await self.parse_robots(client)

        if self.config.get("sitemap_xml", True):
            # Sitemaps named in robots.txt are tried before the defaults.
            listed = (results.get("robots_txt") or {}).get("sitemaps", [])
            results["sitemap"] = await self.parse_sitemap(client, extra_urls=listed)

        if self.config.get("security_txt", True):
            results["security_txt"] = await self.check_security_txt(client)

        if self.config.get("common_paths", True):
            results["common_paths"] = await self.probe_common_paths(client, baseline=baseline)

        if self.config.get("auth_detection", True):
            results["auth_mechanisms"] = []  # Populated during crawl analysis

        return results

    async def parse_robots(self, client: httpx.AsyncClient) -> dict:
        """Parse robots.txt for disallowed paths and sitemaps."""
        result = {
            "found": False,
            "url": f"{self.base_url}/robots.txt",
            "disallowed": [],
            "allowed": [],
            "sitemaps": [],
            "raw": "",
        }

        try:
            response = await client.get(
                f"{self.base_url}/robots.txt",
                follow_redirects=True,
                timeout=httpx.Timeout(10),
            )

            if response.status_code == 200 and "text" in response.headers.get("content-type", ""):
                result["found"] = True
                result["raw"] = response.text
                print_status("robots.txt found!")

                for line in response.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["disallowed"].append(path)
                            print_finding("robots.txt", f"Disallowed: {path}")
                    elif line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["allowed"].append(path)
                    elif line.lower().startswith("sitemap:"):
                        # Strip the "Sitemap:" prefix. Don't split on `:` —
                        # that mangles full URLs like
                        # "Sitemap: https://example.com/sitemap.xml" into
                        # "//example.com/sitemap.xml" (scheme dropped).
                        sitemap_url = line[len("sitemap:"):].strip()
                        if sitemap_url:
                            result["sitemaps"].append(sitemap_url)
                            print_finding("robots.txt", f"Sitemap: {sitemap_url}")
            else:
                print_status("robots.txt not found (or non-text response)")

        except Exception as e:
            print_finding("Recon Error", f"robots.txt: {e}")

        return result

    def _in_scope(self, url: str) -> bool:
        return urlparse(url).netloc.lower() == urlparse(self.base_url).netloc.lower()

    async def parse_sitemap(
        self,
        client: httpx.AsyncClient,
        sitemap_url: str | None = None,
        extra_urls: list[str] | None = None,
    ) -> dict:
        """Find the target's sitemap and extract all page URLs.

        Candidates, in order: `sitemap_url`, `extra_urls` (robots.txt
        `Sitemap:` lines, relative ones resolved), then the default
        locations. The first that parses as a sitemap wins; sitemap
        indexes are followed to their in-scope children.
        """
        result = {
            "found": False,
            "urls": [],
            "url_count": 0,
        }

        candidates = [sitemap_url] if sitemap_url else []
        candidates += [urljoin(self.base_url + "/", u) for u in (extra_urls or [])]
        candidates += [
            f"{self.base_url}/sitemap.xml",
            f"{self.base_url}/sitemap_index.xml",
            f"{self.base_url}/sitemap.xml.gz",
        ]

        visited: set[str] = set()
        for url in dict.fromkeys(candidates):
            urls = await self._fetch_sitemap(client, url, visited, depth=0)
            if urls is None:
                continue
            result["found"] = True
            result["urls"] = urls
            result["url_count"] = len(urls)
            print_status(f"Sitemap contains {result['url_count']} URLs")
            break

        return result

    async def _fetch_sitemap(
        self, client: httpx.AsyncClient, url: str, visited: set[str], depth: int,
    ) -> list[str] | None:
        """Fetch one sitemap (following index entries). Returns its URLs,
        or None when `url` isn't a reachable, in-scope sitemap.

        Each sitemap is fetched once (`visited`) and nesting stops at
        _SITEMAP_MAX_DEPTH, so an index that lists itself — or a child that
        fails — can't loop. Children never fall back to the default
        locations (that fallback used to re-enter the index forever).
        """
        if url in visited or depth > _SITEMAP_MAX_DEPTH or not self._in_scope(url):
            return None
        visited.add(url)
        try:
            response = await client.get(url, follow_redirects=True, timeout=httpx.Timeout(10))
        except Exception:
            return None

        content_type = response.headers.get("content-type", "")
        looks_like_xml = "xml" in content_type or response.text.strip().startswith("<?xml")
        if response.status_code != 200 or not looks_like_xml:
            return None
        print_status(f"Sitemap found: {url}")

        urls: list[str] = []
        try:
            root = ElementTree.fromstring(response.text)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

            # Sitemap index → follow each child sitemap
            for child in root.findall(".//sm:sitemap/sm:loc", ns):
                if child.text:
                    sub = await self._fetch_sitemap(client, child.text.strip(), visited, depth + 1)
                    urls.extend(sub or [])

            # Regular sitemap URLs
            for url_elem in root.findall(".//sm:url/sm:loc", ns):
                if url_elem.text:
                    urls.append(url_elem.text)

            # Try without namespace (some sitemaps don't use it)
            if not urls:
                for loc in root.iter("loc"):
                    if loc.text:
                        urls.append(loc.text)

        except ElementTree.ParseError:
            urls.extend(re.findall(r'<loc>(.*?)</loc>', response.text))

        return urls

    async def check_security_txt(self, client: httpx.AsyncClient) -> dict:
        """Check for .well-known/security.txt (RFC 9116)."""
        result = {"found": False, "content": ""}

        urls = [
            f"{self.base_url}/.well-known/security.txt",
            f"{self.base_url}/security.txt",
        ]

        for url in urls:
            try:
                response = await client.get(
                    url,
                    follow_redirects=True,
                    timeout=httpx.Timeout(10),
                )

                if response.status_code == 200 and "text" in response.headers.get("content-type", ""):
                    result["found"] = True
                    result["content"] = response.text[:2000]
                    result["url"] = url
                    print_status(f"security.txt found: {url}")
                    break

            except Exception:
                continue

        return result

    async def probe_common_paths(
        self, client: httpx.AsyncClient, baseline: Baseline | None = None
    ) -> list[dict]:
        """Probe common sensitive/interesting paths.

        Uses a 404-baseline; probes whose response matches the baseline
        (catch-all SPA routers, custom soft-404 pages) are dropped instead
        of being reported as 'found'. `baseline` is normally the shared
        snapshot threaded from run_all; when None we fetch our own.
        """
        found = []
        if baseline is None:
            baseline = await fetch_baseline(client, self.base_url)
        if baseline.available:
            print_status(
                f"404 baseline: status={baseline.status_code}, "
                f"len={baseline.body_length} (catch-all responses will be filtered)"
            )
        print_status(f"Probing {len(self.COMMON_PATHS)} common paths...")

        baseline_drops = 0
        for path in self.COMMON_PATHS:
            url = f"{self.base_url}{path}"
            try:
                response = await client.get(
                    url,
                    follow_redirects=False,  # Don't follow - we want to see redirects
                    timeout=httpx.Timeout(5),
                )

                body = response.text or ""
                location = response.headers.get("location", "")
                # Catch-all answers (soft-404 200s, everything → login
                # redirects, a 401/403 wall in front of every path) say
                # nothing about this path.
                if baseline.is_noise(response.status_code, body, location):
                    baseline_drops += 1
                    continue

                if response.status_code == 200:
                    content_length = len(body)
                    found.append({
                        "url": url,
                        "path": path,
                        "status_code": 200,
                        "content_length": content_length,
                        "content_type": response.headers.get("content-type", ""),
                    })
                    print_finding("Path Found", f"[200] {path} ({content_length} bytes)")

                elif response.status_code in REDIRECT_CODES:
                    found.append({
                        "url": url,
                        "path": path,
                        "status_code": response.status_code,
                        "redirect_to": location,
                    })
                    print_finding("Path Redirect", f"[{response.status_code}] {path} -> {location}")

                elif response.status_code in (401, 403):
                    found.append({
                        "url": url,
                        "path": path,
                        "status_code": response.status_code,
                        "note": "exists but protected",
                    })
                    print_finding("Path Protected", f"[{response.status_code}] {path}")

            except Exception:
                continue

        if baseline_drops:
            print_status(f"Dropped {baseline_drops} probe(s) matching the 404 baseline")
        print_status(f"Found {len(found)} accessible/interesting paths")
        return found

    # Security headers reported as defensive posture — NOT authentication.
    SECURITY_HEADERS = {
        "content-security-policy": "Content Security Policy",
        "strict-transport-security": "HSTS",
        "x-content-type-options": "X-Content-Type-Options",
        "x-xss-protection": "X-XSS-Protection",
        "permissions-policy": "Permissions Policy",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer Policy",
        "cross-origin-opener-policy": "COOP",
        "cross-origin-embedder-policy": "COEP",
        "cross-origin-resource-policy": "CORP",
    }

    def detect_auth_mechanisms(
        self,
        url: str,
        headers: dict,
        body: str,
        forms: list[dict],
        set_cookies: list[str] | None = None,
    ) -> list[dict]:
        """
        Detect authentication mechanisms from response data.
        NO attacks - just identification. Security headers are handled
        separately in `detect_security_headers` — they are defensive
        policy, not authentication.

        `set_cookies` is the per-cookie raw values list (one entry per
        Set-Cookie header). When provided, we iterate that list so
        targets sending multiple Set-Cookie headers (e.g. Laravel apps
        sending both XSRF-TOKEN and laravel_session) are fully detected.
        Falls back to `headers["set-cookie"]` for callers that don't
        thread the list through (backward compat).
        """
        auth = []

        # Check WWW-Authenticate header (Basic/Digest/NTLM auth)
        www_auth = headers.get("www-authenticate", "")
        if www_auth:
            if "basic" in www_auth.lower():
                realm = re.search(r'realm="?([^"]*)"?', www_auth, re.IGNORECASE)
                auth.append({
                    "type": "HTTP Basic Auth",
                    "url": url,
                    "detail": f"Realm: {realm.group(1) if realm else 'N/A'}",
                })
            if "digest" in www_auth.lower():
                auth.append({
                    "type": "HTTP Digest Auth",
                    "url": url,
                    "detail": www_auth[:200],
                })
            if "ntlm" in www_auth.lower():
                auth.append({
                    "type": "NTLM Auth",
                    "url": url,
                    "detail": "Windows NTLM authentication detected",
                })
            if "negotiate" in www_auth.lower():
                auth.append({
                    "type": "Kerberos/Negotiate Auth",
                    "url": url,
                    "detail": "Kerberos/SPNEGO authentication detected",
                })
            if "bearer" in www_auth.lower():
                auth.append({
                    "type": "Bearer Token Auth",
                    "url": url,
                    "detail": "OAuth2/JWT Bearer authentication",
                })

        # Check for login forms
        for form in forms:
            if form.get("has_password_field"):
                auth.append({
                    "type": "Login Form",
                    "url": form["found_on"],
                    "detail": f"Form action: {form['action']} | Method: {form['method']}",
                    "has_csrf": form.get("has_csrf_token", False),
                })

        # Check for session cookies (these ARE auth-relevant). The session
        # hint is judged on the cookie NAME and flags on its parsed
        # attributes — matching the whole Set-Cookie string made
        # `theme=dark; Path=/authors` a session cookie ("auth" in the path)
        # and gave a cookie named `insecure_pref` a Secure flag.
        session_indicators = ["session", "sess", "sid", "auth", "token", "jwt"]
        for cookie in parse_set_cookies(headers, set_cookies):
            name_lower = cookie["name"].lower()
            if not any(ind in name_lower for ind in session_indicators):
                continue
            flags = [
                label
                for attr, label in (("httponly", "HttpOnly"), ("secure", "Secure"), ("samesite", "SameSite"))
                if attr in cookie["attrs"]
            ]
            auth.append({
                "type": "Session Cookie",
                "url": url,
                "detail": f"Cookie: {cookie['name']} | Flags: {', '.join(flags) or 'NONE'}",
            })

        return auth

    def detect_security_headers(self, url: str, headers: dict) -> list[dict]:
        """Detect defensive HTTP security headers — separate from auth.

        These describe the server's defensive posture (CSP, HSTS, XFO,
        etc.) and don't tell you how users authenticate. Reporting them
        in their own list keeps the auth_mechanisms section actionable.
        """
        findings = []
        for header, name in self.SECURITY_HEADERS.items():
            value = headers.get(header)
            if value:
                findings.append({
                    "name": name,
                    "header": header,
                    "url": url,
                    "value": value[:200],
                })
        return findings
