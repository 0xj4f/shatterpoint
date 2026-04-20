"""Quick smoke test for all modules."""

from shatterpoint.modules.extractor import Extractor
from shatterpoint.modules.fingerprint import Fingerprinter
from shatterpoint.modules.parser import HTMLParser
from shatterpoint.modules.recon import ReconModule
from shatterpoint.modules.spider import Spider
from shatterpoint.utils.validator import URLValidator


def test_imports():
    """Verify all modules can be imported."""
    assert Spider is not None
    assert HTMLParser is not None
    assert Extractor is not None
    assert Fingerprinter is not None
    assert ReconModule is not None


def test_validator_scope():
    v = URLValidator("http://10.10.10.1")
    assert v.base_url == "http://10.10.10.1"
    assert v.is_in_scope("http://10.10.10.1/admin") is True
    assert v.is_in_scope("http://evil.com/test") is False


def test_validator_normalize():
    v = URLValidator("http://10.10.10.1")
    assert v.normalize("/page", "http://10.10.10.1/") == "http://10.10.10.1/page"
    assert v.normalize("javascript:void(0)") is None
    assert v.normalize("mailto:a@b.com") is None


def test_validator_file_detection():
    v = URLValidator("http://10.10.10.1")
    assert v.is_static_resource("http://10.10.10.1/img.png") is True
    assert v.is_static_resource("http://10.10.10.1/page.php") is False
    assert v.is_interesting_file("http://10.10.10.1/backup.sql") is True
    assert v.is_interesting_file("http://10.10.10.1/style.css") is False


def test_parser_forms():
    p = HTMLParser()
    html = """
    <html><body>
    <form action="/login" method="POST">
      <input type="text" name="user">
      <input type="password" name="pass">
      <input type="hidden" name="csrf_token" value="abc123">
      <input type="file" name="avatar">
    </form>
    </body></html>
    """
    forms = p.extract_forms(html, "http://test.com")
    assert len(forms) == 1
    assert forms[0]["has_file_upload"] is True
    assert forms[0]["has_password_field"] is True
    assert forms[0]["has_csrf_token"] is True
    assert forms[0]["method"] == "POST"


def test_parser_comments():
    p = HTMLParser()
    html = """
    <html><body>
    <!-- TODO: remove debug endpoint /api/debug -->
    <!-- password: admin123 -->
    </body></html>
    """
    comments = p.extract_comments(html, "http://test.com")
    assert len(comments) >= 1
    assert any("todo" in c.get("keywords", []) or "debug" in c.get("keywords", []) for c in comments)


def test_parser_links():
    p = HTMLParser()
    html = '<html><body><a href="/admin">Admin</a><a href="/api/users">API</a></body></html>'
    links = p.extract_links(html)
    assert "/admin" in links
    assert "/api/users" in links


def test_parser_emails():
    p = HTMLParser()
    emails = p.extract_emails("Contact us at admin@test.com or info@test.com")
    assert "admin@test.com" in emails
    assert "info@test.com" in emails


def test_extractor_js_endpoints():
    e = Extractor()
    js_code = """
    fetch('/api/v1/users');
    axios.get('/api/v2/data');
    var endpoint = '/rest/config';
    """
    eps = e.extract_js_endpoints(js_code, "http://test.com")
    found = [ep["url"] for ep in eps]
    assert "/api/v1/users" in found
    assert "/api/v2/data" in found


def test_extractor_parameters():
    e = Extractor()
    params = e.extract_url_parameters(["http://test.com/search?q=hello&page=1"])
    assert len(params) == 1
    assert "q" in params[0]["params"]
    assert "page" in params[0]["params"]


def test_fingerprinter():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True,
            "check_cookies": True,
            "check_meta": True,
            "check_scripts": True,
        }
    })
    assert len(fp.signatures) > 0
    detections = fp.fingerprint_from_response(
        "http://test.com",
        {"server": "Apache/2.4.41", "x-powered-by": "PHP/7.4.3"},
        "<html></html>",
    )
    names = [d["name"] for d in detections]
    assert "Apache HTTP Server" in names
    assert "PHP" in names


def test_fingerprinter_version_extraction():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True,
            "check_cookies": True,
            "check_meta": True,
            "check_scripts": True,
        }
    })
    detections = fp.fingerprint_from_response(
        "http://test.com",
        {"server": "Apache/2.4.41"},
        "<html></html>",
    )
    apache = [d for d in detections if d["name"] == "Apache HTTP Server"]
    assert len(apache) == 1
    assert apache[0]["version"] == "2.4.41"
