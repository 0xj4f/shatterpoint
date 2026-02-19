"""
Recon Module
Handles robots.txt, sitemap.xml, security.txt, common paths,
and authentication mechanism detection.
"""

import re
from xml.etree import ElementTree

import httpx

from oxj4f_webcrawler.utils.formatter import print_status, print_finding


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

    async def run_all(self, client: httpx.AsyncClient) -> dict:
        """Run all recon modules and return combined results."""
        results = {}

        if self.config.get("robots_txt", True):
            results["robots_txt"] = await self.parse_robots(client)

        if self.config.get("sitemap_xml", True):
            results["sitemap"] = await self.parse_sitemap(client)

        if self.config.get("security_txt", True):
            results["security_txt"] = await self.check_security_txt(client)

        if self.config.get("common_paths", True):
            results["common_paths"] = await self.probe_common_paths(client)

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
                        sitemap_url = line.split(":", 1)[1].strip()
                        # Handle "Sitemap: http://..." where split on : breaks the URL
                        if not sitemap_url.startswith("http"):
                            sitemap_url = line.split(" ", 1)[1].strip() if " " in line else sitemap_url
                        result["sitemaps"].append(sitemap_url)
                        print_finding("robots.txt", f"Sitemap: {sitemap_url}")
            else:
                print_status("robots.txt not found (or non-text response)")

        except Exception as e:
            print_finding("Recon Error", f"robots.txt: {e}")

        return result

    async def parse_sitemap(self, client: httpx.AsyncClient, sitemap_url: str | None = None) -> dict:
        """Parse sitemap.xml and extract all URLs."""
        result = {
            "found": False,
            "urls": [],
            "url_count": 0,
        }

        urls_to_try = []
        if sitemap_url:
            urls_to_try.append(sitemap_url)
        urls_to_try.extend([
            f"{self.base_url}/sitemap.xml",
            f"{self.base_url}/sitemap_index.xml",
            f"{self.base_url}/sitemap.xml.gz",
        ])

        for url in urls_to_try:
            try:
                response = await client.get(
                    url,
                    follow_redirects=True,
                    timeout=httpx.Timeout(10),
                )

                if response.status_code == 200 and ("xml" in response.headers.get("content-type", "") or response.text.strip().startswith("<?xml")):
                    result["found"] = True
                    print_status(f"Sitemap found: {url}")

                    # Parse XML
                    try:
                        root = ElementTree.fromstring(response.text)
                        # Handle namespace
                        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

                        # Check for sitemap index
                        for sitemap in root.findall(".//sm:sitemap/sm:loc", ns):
                            if sitemap.text:
                                # Recursively parse sub-sitemaps
                                sub = await self.parse_sitemap(client, sitemap.text)
                                result["urls"].extend(sub.get("urls", []))

                        # Regular sitemap URLs
                        for url_elem in root.findall(".//sm:url/sm:loc", ns):
                            if url_elem.text:
                                result["urls"].append(url_elem.text)

                        # Try without namespace (some sitemaps don't use it)
                        if not result["urls"]:
                            for loc in root.iter("loc"):
                                if loc.text:
                                    result["urls"].append(loc.text)

                    except ElementTree.ParseError:
                        # Try regex fallback
                        locs = re.findall(r'<loc>(.*?)</loc>', response.text)
                        result["urls"].extend(locs)

                    result["url_count"] = len(result["urls"])
                    print_status(f"Sitemap contains {result['url_count']} URLs")
                    break

            except Exception as e:
                continue

        return result

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

    async def probe_common_paths(self, client: httpx.AsyncClient) -> list[dict]:
        """Probe common sensitive/interesting paths."""
        found = []
        print_status(f"Probing {len(self.COMMON_PATHS)} common paths...")

        for path in self.COMMON_PATHS:
            url = f"{self.base_url}{path}"
            try:
                response = await client.get(
                    url,
                    follow_redirects=False,  # Don't follow - we want to see redirects
                    timeout=httpx.Timeout(5),
                )

                if response.status_code == 200:
                    # Check it's not a generic 404 page
                    content_length = len(response.text)
                    found.append({
                        "url": url,
                        "path": path,
                        "status_code": 200,
                        "content_length": content_length,
                        "content_type": response.headers.get("content-type", ""),
                    })
                    print_finding("Path Found", f"[200] {path} ({content_length} bytes)")

                elif response.status_code in (301, 302, 307, 308):
                    location = response.headers.get("location", "")
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

        print_status(f"Found {len(found)} accessible/interesting paths")
        return found

    def detect_auth_mechanisms(self, url: str, headers: dict, body: str, forms: list[dict]) -> list[dict]:
        """
        Detect authentication mechanisms from response data.
        NO attacks - just identification.
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

        # Check for common auth-related headers
        if headers.get("x-frame-options"):
            auth.append({
                "type": "Clickjacking Protection",
                "url": url,
                "detail": f"X-Frame-Options: {headers['x-frame-options']}",
            })

        # Check for session cookies
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                cookie_lower = value.lower()
                flags = []
                if "httponly" in cookie_lower:
                    flags.append("HttpOnly")
                if "secure" in cookie_lower:
                    flags.append("Secure")
                if "samesite" in cookie_lower:
                    flags.append("SameSite")

                session_indicators = ["session", "sess", "sid", "auth", "token", "jwt"]
                if any(ind in cookie_lower for ind in session_indicators):
                    cookie_name = value.split("=")[0].strip()
                    auth.append({
                        "type": "Session Cookie",
                        "url": url,
                        "detail": f"Cookie: {cookie_name} | Flags: {', '.join(flags) or 'NONE'}",
                    })

        # Check security headers
        security_headers = {
            "content-security-policy": "Content Security Policy",
            "strict-transport-security": "HSTS",
            "x-content-type-options": "X-Content-Type-Options",
            "x-xss-protection": "X-XSS-Protection",
            "permissions-policy": "Permissions Policy",
        }

        for header, name in security_headers.items():
            value = headers.get(header)
            if value:
                auth.append({
                    "type": f"Security Header: {name}",
                    "url": url,
                    "detail": value[:200],
                })

        return auth
