"""
HTML Parser Module
Extracts links, forms, inputs, file uploads, comments, emails,
meta tags, and script sources from HTML content.
"""

import re

from bs4 import BeautifulSoup, Comment

# XML documents whose ROOT element identifies them, even without an
# ``<?xml?>`` declaration (some servers omit it).
_XML_ROOTS = {"rss", "feed", "urlset", "sitemapindex", "oembed", "sitemap"}


def _make_soup(markup: str) -> BeautifulSoup:
    """Parse ``markup`` with the right BeautifulSoup backend.

    XML documents — WordPress sitemaps, RSS/Atom feeds, and oembed
    ``?format=xml`` responses — must use the XML parser. Feeding them to the
    HTML parser (``"lxml"``) emits ``XMLParsedAsHTMLWarning`` and parses them
    unreliably.

    Routing is decided by the **root element**, not by whether ``<html>``
    appears anywhere: a WordPress oembed doc is ``<?xml?><oembed>`` but
    *contains* an ``<html>`` child (the escaped embed markup), so a naive
    "<html> present → HTML" check misroutes it. We read the first real tag
    (skipping the ``<?xml?>`` prolog, PIs, comments and ``<!DOCTYPE>``):
    an ``<html>`` root means (X)HTML and keeps the HTML parser (so forms and
    links are still extracted); an XML declaration or a known XML root means
    the XML parser.
    """
    # Find the first real element tag — re.search skips any leading BOM,
    # whitespace, <?xml?>/PI and <!DOCTYPE>/comment, so the root is detected
    # regardless of a byte-order mark.
    head = (markup or "")[:512].lstrip().lower()
    m = re.search(r"<([a-z][\w:-]*)", head)
    root = m.group(1) if m else ""
    looks_xml = (head.startswith("<?xml") or root in _XML_ROOTS) and root != "html"
    return BeautifulSoup(markup, "xml" if looks_xml else "lxml")


class HTMLParser:
    """Parses HTML content and extracts recon-relevant data."""

    # Regex patterns
    EMAIL_PATTERN = re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    )
    # Matches things that look like relative/absolute URLs in text
    URL_PATTERN = re.compile(
        r'''(?:href|src|action|data|poster|srcset)\s*=\s*["']([^"']+)["']''',
        re.IGNORECASE,
    )

    def extract_links(self, html: str, base_url: str = "") -> list[str]:
        """Extract all href and src links from HTML."""
        links = set()
        try:
            soup = _make_soup(html)

            # <a href="...">
            for tag in soup.find_all("a", href=True):
                links.add(tag["href"])

            # <link href="...">
            for tag in soup.find_all("link", href=True):
                links.add(tag["href"])

            # <script src="...">
            for tag in soup.find_all("script", src=True):
                links.add(tag["src"])

            # <img src="...">
            for tag in soup.find_all("img", src=True):
                links.add(tag["src"])

            # <iframe src="...">
            for tag in soup.find_all("iframe", src=True):
                links.add(tag["src"])

            # <form action="...">
            for tag in soup.find_all("form", action=True):
                links.add(tag["action"])

            # <area href="...">
            for tag in soup.find_all("area", href=True):
                links.add(tag["href"])

            # <base href="...">
            for tag in soup.find_all("base", href=True):
                links.add(tag["href"])

        except Exception:
            pass

        return list(links)

    def extract_forms(self, html: str, page_url: str) -> list[dict]:
        """
        Extract all forms with their inputs, methods, and actions.
        This is critical for OSCP - forms are primary attack vectors.
        """
        forms = []
        try:
            soup = _make_soup(html)

            for form in soup.find_all("form"):
                form_data = {
                    "found_on": page_url,
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "enctype": form.get("enctype", ""),
                    "id": form.get("id", ""),
                    "name": form.get("name", ""),
                    "inputs": [],
                    "has_file_upload": False,
                    "has_password_field": False,
                    "has_hidden_fields": False,
                    "has_csrf_token": False,
                }

                # Extract all input elements
                for inp in form.find_all(["input", "textarea", "select", "button"]):
                    input_data = {
                        "tag": inp.name,
                        "type": inp.get("type", "text"),
                        "name": inp.get("name", ""),
                        "id": inp.get("id", ""),
                        "value": inp.get("value", ""),
                        "placeholder": inp.get("placeholder", ""),
                        "required": inp.has_attr("required"),
                        "pattern": inp.get("pattern", ""),
                        "maxlength": inp.get("maxlength", ""),
                    }

                    # Track interesting input types
                    if input_data["type"] == "file":
                        form_data["has_file_upload"] = True
                        # Check for accept attribute (file type restrictions)
                        input_data["accept"] = inp.get("accept", "")

                    if input_data["type"] == "password":
                        form_data["has_password_field"] = True

                    if input_data["type"] == "hidden":
                        form_data["has_hidden_fields"] = True
                        # Check for CSRF tokens
                        name_lower = input_data["name"].lower()
                        if any(tok in name_lower for tok in ["csrf", "token", "_token", "nonce", "authenticity"]):
                            form_data["has_csrf_token"] = True

                    form_data["inputs"].append(input_data)

                forms.append(form_data)

        except Exception:
            pass

        return forms

    def extract_comments(self, html: str, page_url: str) -> list[dict]:
        """
        Extract HTML comments - often contain sensitive info:
        - TODO notes with credentials
        - Debug endpoints
        - Version info
        - Developer notes
        """
        comments = []
        try:
            soup = _make_soup(html)

            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                text = comment.strip()
                if len(text) > 3:  # Skip trivial comments
                    # Flag potentially interesting comments
                    interesting = False
                    keywords = [
                        "password", "user", "admin", "todo", "fixme", "hack",
                        "bug", "debug", "secret", "key", "token", "api",
                        "version", "v1", "v2", "deprecated", "backup",
                        "test", "temp", "remove", "credential", "login",
                        "database", "db", "sql", "config", "path",
                    ]
                    text_lower = text.lower()
                    matched_keywords = [kw for kw in keywords if kw in text_lower]

                    if matched_keywords or len(text) > 20:
                        interesting = True

                    if interesting:
                        comments.append({
                            "url": page_url,
                            "comment": text[:500],  # Truncate long comments
                            "keywords": matched_keywords,
                        })

        except Exception:
            pass

        return comments

    def extract_emails(self, html: str) -> list[str]:
        """Extract email addresses from HTML content."""
        return list(set(self.EMAIL_PATTERN.findall(html)))

    def extract_meta_tags(self, html: str) -> list[dict]:
        """Extract meta tags - useful for fingerprinting and info gathering."""
        meta_tags = []
        try:
            soup = _make_soup(html)
            for meta in soup.find_all("meta"):
                tag_data = {}
                for attr in ["name", "property", "http-equiv", "content", "charset"]:
                    val = meta.get(attr)
                    if val:
                        tag_data[attr] = val
                if tag_data:
                    meta_tags.append(tag_data)
        except Exception:
            pass
        return meta_tags

    def extract_scripts(self, html: str) -> dict:
        """
        Extract script information:
        - External script sources
        - Inline script content (for JS endpoint extraction)
        """
        scripts = {"external": [], "inline": []}
        try:
            soup = _make_soup(html)
            for script in soup.find_all("script"):
                if script.get("src"):
                    scripts["external"].append({
                        "src": script["src"],
                        "type": script.get("type", ""),
                        "integrity": script.get("integrity", ""),
                    })
                elif script.string:
                    # Only keep inline scripts that are substantial
                    content = script.string.strip()
                    if len(content) > 10:
                        scripts["inline"].append(content)
        except Exception:
            pass
        return scripts

    def extract_headers_from_html(self, html: str) -> list[dict]:
        """Extract page title and heading hierarchy (useful for mapping)."""
        headings = []
        try:
            soup = _make_soup(html)

            title = soup.find("title")
            if title and title.string:
                headings.append({"tag": "title", "text": title.string.strip()})

            for level in range(1, 7):
                for h in soup.find_all(f"h{level}"):
                    text = h.get_text(strip=True)
                    if text:
                        headings.append({"tag": f"h{level}", "text": text[:200]})
        except Exception:
            pass
        return headings
