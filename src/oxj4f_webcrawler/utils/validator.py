"""
URL Validation & Scope Enforcement
Ensures we stay within the target domain boundary.
"""

import re
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

import tldextract


class URLValidator:
    """Validates and normalizes URLs, enforcing single-domain scope."""

    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.scheme = parsed.scheme
        self.target_domain = parsed.netloc.lower()
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        extracted = tldextract.extract(target_url)
        self.registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()

    def is_in_scope(self, url: str) -> bool:
        """Check if URL belongs to the target domain (strict)."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https", ""):
                return False
            return parsed.netloc.lower() == self.target_domain
        except Exception:
            return False

    def normalize(self, url: str, base_url: str | None = None) -> str | None:
        """Normalize a URL: resolve relative, strip fragments, lowercase domain."""
        try:
            # Remove fragments
            url, _ = urldefrag(url)
            url = url.strip()

            if not url or url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                return None

            # Resolve relative URLs
            if not url.startswith(("http://", "https://")):
                base = base_url or self.base_url
                url = urljoin(base, url)

            parsed = urlparse(url)

            # Enforce scheme
            if parsed.scheme not in ("http", "https"):
                return None

            # Normalize: lowercase domain, keep path as-is
            normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"

            return normalized
        except Exception:
            return None

    def extract_params(self, url: str) -> dict:
        """Extract query parameters from URL (interesting for parameter fuzzing)."""
        try:
            parsed = urlparse(url)
            return parse_qs(parsed.query)
        except Exception:
            return {}

    def get_path(self, url: str) -> str:
        """Extract the path component from URL."""
        try:
            return urlparse(url).path
        except Exception:
            return "/"

    def get_extension(self, url: str) -> str | None:
        """Get file extension from URL path."""
        path = self.get_path(url)
        match = re.search(r'\.(\w{1,10})$', path)
        return match.group(1).lower() if match else None

    def is_static_resource(self, url: str) -> bool:
        """Check if URL points to a static resource (image, css, font, etc.)."""
        static_extensions = {
            "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",
            "css", "woff", "woff2", "ttf", "eot", "otf",
            "mp3", "mp4", "avi", "mov", "wmv", "flv",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "zip", "tar", "gz", "rar", "7z",
        }
        ext = self.get_extension(url)
        return ext in static_extensions if ext else False

    def is_interesting_file(self, url: str) -> bool:
        """Check if URL points to a potentially interesting file for recon."""
        interesting_extensions = {
            "php", "asp", "aspx", "jsp", "cgi", "pl", "py",
            "txt", "xml", "json", "yaml", "yml", "conf", "config",
            "bak", "old", "orig", "save", "swp", "tmp",
            "sql", "db", "sqlite", "mdb",
            "log", "env", "ini", "htaccess", "htpasswd",
            "sh", "bat", "ps1",
        }
        ext = self.get_extension(url)
        return ext in interesting_extensions if ext else False
