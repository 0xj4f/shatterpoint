"""
Fingerprint Engine
Detects technologies, frameworks, CMS, and versions
by analyzing HTTP headers, cookies, HTML content, and known paths.
"""

import re
from pathlib import Path

import yaml
import httpx

from utils.formatter import print_finding


class Fingerprinter:
    """
    Technology fingerprinting engine.
    Loads signature definitions from YAML and matches against crawl data.
    """

    def __init__(self, config: dict, signatures_path: str | None = None):
        self.config = config.get("fingerprint", {})
        self.signatures = {}

        # Load signatures
        if signatures_path is None:
            signatures_path = str(
                Path(__file__).parent.parent / "signatures" / "fingerprints.yaml"
            )

        try:
            with open(signatures_path, "r") as f:
                self.signatures = yaml.safe_load(f) or {}
        except Exception as e:
            print_finding("Fingerprint", f"Failed to load signatures: {e}")

    def fingerprint_from_response(
        self, url: str, headers: dict, body: str, cookies: dict | None = None
    ) -> list[dict]:
        """
        Run all fingerprint checks against a single response.
        Returns list of detected technologies.
        """
        detections = []

        for tech_id, sig in self.signatures.items():
            result = self._check_signature(tech_id, sig, headers, body, cookies)
            if result:
                detections.append(result)

        return detections

    def fingerprint_aggregate(
        self, crawl_results: dict
    ) -> list[dict]:
        """
        Aggregate fingerprinting across all crawled pages.
        Merges detections and calculates confidence scores.
        """
        all_detections: dict[str, dict] = {}

        for url, result in crawl_results.items():
            if result.error or not result.headers:
                continue

            # Parse cookies from headers
            cookies = self._extract_cookies(result.headers)

            detections = self.fingerprint_from_response(
                url, result.headers, result.body, cookies
            )

            for det in detections:
                tech_id = det["id"]
                if tech_id in all_detections:
                    existing = all_detections[tech_id]
                    existing["match_count"] += 1
                    existing["matched_on"].extend(det.get("matched_on", []))
                    # Keep the most specific version
                    if det.get("version") and not existing.get("version"):
                        existing["version"] = det["version"]
                else:
                    det["match_count"] = 1
                    all_detections[tech_id] = det

        # Calculate confidence
        results = []
        for tech_id, det in all_detections.items():
            methods = set(m["method"] for m in det.get("matched_on", []))
            match_count = det["match_count"]

            # Confidence scoring
            if len(methods) >= 3 or match_count >= 5:
                confidence = "high"
            elif len(methods) >= 2 or match_count >= 2:
                confidence = "medium"
            else:
                confidence = "low"

            det["confidence"] = confidence
            # Deduplicate matched_on
            seen = set()
            unique_matches = []
            for m in det.get("matched_on", []):
                key = f"{m['method']}:{m.get('detail', '')}"
                if key not in seen:
                    seen.add(key)
                    unique_matches.append(m)
            det["matched_on"] = unique_matches[:10]  # Limit for readability

            results.append(det)

        # Sort by confidence
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        results.sort(key=lambda x: confidence_order.get(x.get("confidence", "low"), 3))

        return results

    async def probe_known_paths(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[dict]:
        """
        Probe known technology-specific paths to detect technologies.
        e.g., /wp-login.php for WordPress.
        """
        detections = []
        probed_paths = set()

        for tech_id, sig in self.signatures.items():
            paths = sig.get("paths", [])
            for path in paths:
                if path in probed_paths:
                    continue
                probed_paths.add(path)

                url = f"{base_url.rstrip('/')}{path}"
                try:
                    response = await client.get(
                        url,
                        follow_redirects=True,
                        timeout=httpx.Timeout(5),
                    )

                    if response.status_code == 200:
                        detections.append({
                            "id": tech_id,
                            "name": sig.get("name", tech_id),
                            "category": sig.get("category", "Unknown"),
                            "version": None,
                            "matched_on": [{
                                "method": "path_probe",
                                "detail": f"{path} returned 200",
                            }],
                        })
                        print_finding("Fingerprint", f"Found {sig.get('name', tech_id)} via {path}")

                    elif response.status_code in (401, 403):
                        # Protected but exists
                        detections.append({
                            "id": tech_id,
                            "name": sig.get("name", tech_id),
                            "category": sig.get("category", "Unknown"),
                            "version": None,
                            "matched_on": [{
                                "method": "path_probe",
                                "detail": f"{path} returned {response.status_code} (exists but protected)",
                            }],
                        })

                except Exception:
                    pass

        return detections

    def _check_signature(
        self, tech_id: str, sig: dict, headers: dict, body: str, cookies: dict | None
    ) -> dict | None:
        """Check a single technology signature against response data."""
        matched_on = []
        version = None

        # Check headers
        if self.config.get("check_headers", True):
            for header_check in sig.get("headers", []):
                header_name = header_check["header"].lower()
                header_value = headers.get(header_name, "")
                if header_value:
                    pattern = header_check.get("pattern", "")
                    match = re.search(pattern, header_value)
                    if match:
                        matched_on.append({
                            "method": "header",
                            "detail": f"{header_name}: {header_value[:100]}",
                        })
                        # Try to extract version
                        if match.groups():
                            ver = match.group(1)
                            if ver and not version:
                                version = ver

        # Check cookies
        if self.config.get("check_cookies", True) and cookies:
            for cookie_name in sig.get("cookies", []):
                if cookie_name.lower() in (c.lower() for c in cookies):
                    matched_on.append({
                        "method": "cookie",
                        "detail": f"Cookie: {cookie_name}",
                    })

        # Check meta tags (via body regex)
        if self.config.get("check_meta", True) and body:
            for meta_check in sig.get("meta", []):
                meta_name = meta_check.get("name", "")
                pattern = meta_check.get("pattern", "")
                # Look for <meta name="..." content="...">
                meta_regex = re.compile(
                    rf'<meta\s+[^>]*name=["\']?{re.escape(meta_name)}["\']?\s+[^>]*content=["\']?([^"\'>\s]+)',
                    re.IGNORECASE,
                )
                match = meta_regex.search(body)
                if match:
                    content = match.group(1)
                    if pattern:
                        ver_match = re.search(pattern, content)
                        if ver_match:
                            matched_on.append({
                                "method": "meta",
                                "detail": f"meta[{meta_name}]: {content[:100]}",
                            })
                            if ver_match.groups() and not version:
                                version = ver_match.group(1)
                    else:
                        matched_on.append({
                            "method": "meta",
                            "detail": f"meta[{meta_name}]: {content[:100]}",
                        })

        # Check body content
        if body:
            for body_pattern in sig.get("body", []):
                if body_pattern.lower() in body.lower():
                    matched_on.append({
                        "method": "body",
                        "detail": f"Body contains: {body_pattern}",
                    })
                    break  # One body match is enough

            # Check script patterns
            if self.config.get("check_scripts", True):
                for script_check in sig.get("scripts", []):
                    pattern = script_check.get("pattern", "")
                    if pattern:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            matched_on.append({
                                "method": "script",
                                "detail": f"Script pattern: {pattern}",
                            })
                            if match.groups() and not version:
                                version = match.group(1)

        if matched_on:
            return {
                "id": tech_id,
                "name": sig.get("name", tech_id),
                "category": sig.get("category", "Unknown"),
                "version": version,
                "matched_on": matched_on,
            }

        return None

    def _extract_cookies(self, headers: dict) -> dict:
        """Extract cookie names from Set-Cookie headers."""
        cookies = {}
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                # Parse cookie name
                parts = value.split(";")
                if parts:
                    name_val = parts[0].split("=", 1)
                    if name_val:
                        cookies[name_val[0].strip()] = name_val[1].strip() if len(name_val) > 1 else ""
        return cookies
