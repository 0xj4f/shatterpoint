"""
Extractor Module
Extracts API endpoints, JavaScript-embedded URLs, and analyzes
attack surface from crawled content.
"""

import re


class Extractor:
    """Extracts API endpoints, JS URLs, and maps attack surface."""

    # Patterns for finding endpoints in JavaScript
    JS_URL_PATTERNS = [
        # Quoted strings that look like paths
        re.compile(
            r'''["']'''
            r'''(/(?:api|rest|graphql|v[0-9]+|ajax|ws|webhook|service|endpoint)[^\s"'<>]*?)'''
            r'''["']''',
            re.IGNORECASE,
        ),
        # fetch() calls
        re.compile(r'''fetch\s*\(\s*["']([^"']+?)["']''', re.IGNORECASE),
        # XMLHttpRequest.open
        re.compile(r'''\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+?)["']''', re.IGNORECASE),
        # axios calls
        re.compile(r'''axios\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+?)["']''', re.IGNORECASE),
        # jQuery AJAX
        re.compile(r'''(?:\$\.(?:ajax|get|post|getJSON)|\$\.fn\.load)\s*\(\s*["']([^"']+?)["']''', re.IGNORECASE),
        # url: "..." or endpoint: "..." patterns
        re.compile(r'''(?:url|endpoint|api_?url|base_?url|href)\s*[:=]\s*["']([^"']+?)["']''', re.IGNORECASE),
        # Relative paths starting with /
        re.compile(r'''["'](\/[a-zA-Z][a-zA-Z0-9_/\-]+?)["']'''),
    ]

    # Patterns indicating API endpoints in URLs
    API_INDICATORS = re.compile(
        r'(?:/api/|/rest/|/graphql|/v[0-9]+/|/ajax/|/json|/ws/|/webhook|\.json$|\.xml$)',
        re.IGNORECASE,
    )

    # Interesting path patterns
    INTERESTING_PATHS = re.compile(
        r'(?:/admin|/login|/register|/signup|/upload|/dashboard|/panel|/console|'
        r'/debug|/test|/backup|/config|/install|/setup|/phpinfo|/server-status|'
        r'/\.env|/\.git|/\.svn|/\.htaccess|/web\.config|/crossdomain\.xml|'
        r'/clientaccesspolicy\.xml|/swagger|/api-docs|/graphiql)',
        re.IGNORECASE,
    )

    def extract_js_endpoints(self, js_content: str, page_url: str) -> list[dict]:
        """Extract potential API endpoints from JavaScript code."""
        endpoints = set()

        for pattern in self.JS_URL_PATTERNS:
            for match in pattern.finditer(js_content):
                url = match.group(1).strip()
                # Filter out noise
                if self._is_valid_endpoint(url):
                    endpoints.add(url)

        return [
            {"url": ep, "source": "javascript", "found_on": page_url}
            for ep in sorted(endpoints)
        ]

    def extract_api_endpoints(self, url: str, headers: dict, body: str) -> list[dict]:
        """Identify API endpoints from URL patterns and response characteristics."""
        endpoints = []

        # Check URL pattern
        if self.API_INDICATORS.search(url):
            endpoints.append({
                "url": url,
                "source": "url_pattern",
                "content_type": headers.get("content-type", ""),
            })

        # Check if response is JSON/XML (API-like)
        content_type = headers.get("content-type", "").lower()
        if any(ct in content_type for ct in ["application/json", "application/xml", "text/xml"]):
            if not url.endswith((".js", ".css")):
                endpoints.append({
                    "url": url,
                    "source": "content_type",
                    "content_type": content_type,
                })

        return endpoints

    def find_interesting_paths(self, urls: list[str]) -> list[dict]:
        """Flag URLs that match interesting path patterns."""
        interesting = []
        for url in urls:
            if self.INTERESTING_PATHS.search(url):
                interesting.append({
                    "url": url,
                    "reason": "interesting_path",
                })
        return interesting

    def extract_url_parameters(self, urls: list[str]) -> list[dict]:
        """
        Extract and catalog all URL parameters.
        Parameters are key for finding injection points.
        """
        from urllib.parse import parse_qs, urlparse

        params_found = []
        seen = set()

        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                param_names = sorted(params.keys())
                key = f"{parsed.path}:{','.join(param_names)}"

                if key not in seen:
                    seen.add(key)
                    params_found.append({
                        "url": url,
                        "path": parsed.path,
                        "params": param_names,
                        "param_details": {
                            k: v[0] if len(v) == 1 else v
                            for k, v in params.items()
                        },
                    })

        return params_found

    def analyze_attack_surface(self, forms: list[dict], urls: list[str], api_endpoints: list[dict]) -> dict:
        """
        Produce an attack surface summary:
        - File upload points
        - Login forms
        - Search/input forms (potential SQLi/XSS)
        - API endpoints (potential IDOR, auth bypass)
        - Parameterized URLs
        """
        surface = {
            "file_uploads": [],
            "login_forms": [],
            "search_forms": [],
            "data_input_forms": [],
            "api_endpoints": len(api_endpoints),
            "parameterized_urls": 0,
            "total_forms": len(forms),
        }

        for form in forms:
            if form.get("has_file_upload"):
                surface["file_uploads"].append({
                    "url": form["found_on"],
                    "action": form["action"],
                    "method": form["method"],
                    "inputs": [
                        i for i in form["inputs"] if i["type"] == "file"
                    ],
                })

            if form.get("has_password_field"):
                surface["login_forms"].append({
                    "url": form["found_on"],
                    "action": form["action"],
                    "method": form["method"],
                })

            # Forms with text inputs (potential injection points)
            text_inputs = [
                i for i in form["inputs"]
                if i["type"] in ("text", "search", "url", "email", "number", "tel")
                and i.get("name")
            ]
            if text_inputs:
                if any(i["type"] == "search" or "search" in i.get("name", "").lower() for i in text_inputs):
                    surface["search_forms"].append({
                        "url": form["found_on"],
                        "action": form["action"],
                        "inputs": [i["name"] for i in text_inputs],
                    })
                else:
                    surface["data_input_forms"].append({
                        "url": form["found_on"],
                        "action": form["action"],
                        "method": form["method"],
                        "inputs": [i["name"] for i in text_inputs],
                    })

        from urllib.parse import urlparse
        surface["parameterized_urls"] = sum(
            1 for u in urls if urlparse(u).query
        )

        return surface

    def _is_valid_endpoint(self, url: str) -> bool:
        """Filter out obvious non-endpoints from JS extraction."""
        if not url or len(url) < 2 or len(url) > 500:
            return False

        # Skip obvious non-URLs
        skip_patterns = [
            r'^[./]?$',
            r'^#',
            r'^javascript:',
            r'^data:',
            r'^mailto:',
            r'^\w+$',  # Single word without slashes
            r'^\d+$',  # Just numbers
            r'^[{<\[]',  # Template literals
            r'\{\{',  # Template variables
            r'^\s*function',
            r'\.(?:png|jpg|gif|svg|css|ico|woff|ttf)$',
        ]

        for pattern in skip_patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return False

        return True
