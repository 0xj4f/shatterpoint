"""Quick smoke test for all modules."""
import sys
sys.path.insert(0, ".")

from modules.spider import Spider
from modules.parser import HTMLParser
from modules.extractor import Extractor
from modules.fingerprint import Fingerprinter
from modules.recon import ReconModule
from utils.validator import URLValidator
from utils.formatter import print_banner, print_summary, save_report

print("All imports successful!")

# Validator tests
v = URLValidator("http://10.10.10.1")
assert v.base_url == "http://10.10.10.1"
assert v.is_in_scope("http://10.10.10.1/admin") is True
assert v.is_in_scope("http://evil.com/test") is False
assert v.is_static_resource("http://10.10.10.1/img.png") is True
assert v.is_interesting_file("http://10.10.10.1/backup.sql") is True
assert v.normalize("/page", "http://10.10.10.1/") == "http://10.10.10.1/page"
print("Validator: PASS")

# Parser tests
p = HTMLParser()
test_html = """
<html><body>
<form action="/login" method="POST">
  <input type="text" name="user">
  <input type="password" name="pass">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="file" name="avatar">
</form>
<a href="/admin">Admin</a>
<a href="/api/users">API</a>
<!-- TODO: remove debug endpoint /api/debug -->
<!-- password: admin123 -->
</body></html>
"""

forms = p.extract_forms(test_html, "http://test.com")
assert len(forms) == 1
assert forms[0]["has_file_upload"] is True
assert forms[0]["has_password_field"] is True
assert forms[0]["has_csrf_token"] is True
assert forms[0]["method"] == "POST"
print("Parser (forms): PASS")

comments = p.extract_comments(test_html, "http://test.com")
assert len(comments) >= 1
assert any("todo" in c.get("keywords", []) or "debug" in c.get("keywords", []) for c in comments)
print("Parser (comments): PASS")

links = p.extract_links(test_html)
assert "/admin" in links
assert "/api/users" in links
print("Parser (links): PASS")

emails = p.extract_emails("Contact us at admin@test.com or info@test.com")
assert "admin@test.com" in emails
print("Parser (emails): PASS")

# Extractor tests
e = Extractor()
js_code = """
fetch('/api/v1/users');
axios.get('/api/v2/data');
var endpoint = '/rest/config';
"""
js_eps = e.extract_js_endpoints(js_code, "http://test.com")
found_urls = [ep["url"] for ep in js_eps]
assert "/api/v1/users" in found_urls
assert "/api/v2/data" in found_urls
print("Extractor (JS endpoints): PASS")

params = e.extract_url_parameters(["http://test.com/search?q=hello&page=1"])
assert len(params) == 1
assert "q" in params[0]["params"]
print("Extractor (parameters): PASS")

# Fingerprinter tests
fp = Fingerprinter({"fingerprint": {"check_headers": True, "check_cookies": True, "check_meta": True, "check_scripts": True}})
assert len(fp.signatures) > 0
detections = fp.fingerprint_from_response(
    "http://test.com",
    {"server": "Apache/2.4.41", "x-powered-by": "PHP/7.4.3"},
    "<html></html>",
)
tech_names = [d["name"] for d in detections]
assert "Apache HTTP Server" in tech_names
assert "PHP" in tech_names
print("Fingerprinter: PASS")

print("\n=== ALL TESTS PASSED ===")
