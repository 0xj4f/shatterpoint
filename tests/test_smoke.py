"""Quick smoke test for all modules."""

import base64
import json
import time

from shatterpoint.modules.extractor import Extractor
from shatterpoint.modules.fingerprint import Fingerprinter
from shatterpoint.modules.parser import HTMLParser
from shatterpoint.modules.recon import ReconModule
from shatterpoint.modules.spider import Spider
from shatterpoint.utils.auth import (
    decode_jwt_exp,
    redact_token,
    resolve_token,
    should_send_auth,
    warn_on_expiry,
)
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


def _make_jwt(payload: dict) -> str:
    """Build a JWT-shaped string with the given payload. Signature is fake."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.signature"


def test_redact_token_typical():
    token = "eyJhbGci" + "X" * 40 + "6Dc1"
    redacted = redact_token(token)
    assert redacted.startswith("eyJh")
    assert redacted.endswith("6Dc1")
    assert "…" in redacted
    assert "X" * 40 not in redacted


def test_redact_token_short():
    # Tokens shorter than 8 chars are fully redacted
    assert redact_token("abc") == "…"
    assert redact_token("1234567") == "…"
    assert redact_token("") == ""
    assert redact_token(None) == ""


def test_redact_token_boundary():
    # Exactly 8 chars is the smallest length where first4/last4 is shown
    assert redact_token("12345678") == "1234…5678"


def test_resolve_token_cli_wins(monkeypatch):
    monkeypatch.setenv("SHATTERPOINT_TOKEN", "env-tok")
    assert resolve_token("cli-tok", {"auth": {"token": "cfg-tok"}}) == "cli-tok"


def test_resolve_token_env_over_config(monkeypatch):
    monkeypatch.setenv("SHATTERPOINT_TOKEN", "env-tok")
    assert resolve_token(None, {"auth": {"token": "cfg-tok"}}) == "env-tok"


def test_resolve_token_config_fallback(monkeypatch):
    monkeypatch.delenv("SHATTERPOINT_TOKEN", raising=False)
    assert resolve_token(None, {"auth": {"token": "cfg-tok"}}) == "cfg-tok"


def test_resolve_token_none(monkeypatch):
    monkeypatch.delenv("SHATTERPOINT_TOKEN", raising=False)
    assert resolve_token(None, {}) is None
    assert resolve_token("", {}) is None
    assert resolve_token(None, {"auth": {"token": ""}}) is None


def test_jwt_exp_parse_valid():
    token = _make_jwt({"sub": "u", "exp": 1776412517})
    assert decode_jwt_exp(token) == 1776412517


def test_jwt_exp_parse_opaque():
    assert decode_jwt_exp("opaque-random-string") is None
    assert decode_jwt_exp("") is None
    assert decode_jwt_exp(None) is None


def test_jwt_exp_parse_malformed():
    assert decode_jwt_exp("not.enough") is None
    bad_b64 = "!!!notbase64!!!"
    assert decode_jwt_exp(f"hdr.{bad_b64}.sig") is None
    not_json = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
    assert decode_jwt_exp(f"hdr.{not_json}.sig") is None


def test_jwt_exp_missing_claim():
    token = _make_jwt({"sub": "u"})
    assert decode_jwt_exp(token) is None


def test_warn_on_expiry_past():
    token = _make_jwt({"exp": int(time.time()) - 100})
    msg = warn_on_expiry(token)
    assert msg is not None
    assert "expired" in msg.lower()


def test_warn_on_expiry_soon():
    token = _make_jwt({"exp": int(time.time()) + 60})
    msg = warn_on_expiry(token, warn_window_seconds=600)
    assert msg is not None
    assert "expires in" in msg.lower()


def test_warn_on_expiry_fresh():
    token = _make_jwt({"exp": int(time.time()) + 86400})
    assert warn_on_expiry(token, warn_window_seconds=600) is None


def test_warn_on_expiry_opaque():
    assert warn_on_expiry("opaque-token") is None
    assert warn_on_expiry(None) is None


def test_should_send_auth_same_origin():
    assert should_send_auth("http", "localhost:3001", "http://localhost:3001/api/x")


def test_should_send_auth_different_host():
    assert not should_send_auth("http", "localhost:3001", "http://evil.com/x")


def test_should_send_auth_different_port():
    assert not should_send_auth("http", "localhost:3001", "http://localhost:3002/x")


def test_should_send_auth_different_scheme():
    assert not should_send_auth("http", "localhost:3001", "https://localhost:3001/x")


def test_should_send_auth_default_ports():
    # http://example.com == http://example.com:80
    assert should_send_auth("http", "example.com", "http://example.com:80/x")
    assert should_send_auth("http", "example.com:80", "http://example.com/x")
    # https://example.com == https://example.com:443
    assert should_send_auth("https", "example.com", "https://example.com:443/x")


def test_should_send_auth_subdomain():
    assert not should_send_auth("http", "example.com", "http://api.example.com/x")


def test_should_send_auth_empty_and_garbage():
    assert not should_send_auth("http", "example.com", "")
    assert not should_send_auth("http", "example.com", "not-a-url")


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
