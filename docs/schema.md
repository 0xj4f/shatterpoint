# JSON Report Schema

The output report is a single JSON object saved to `./output/recon_{domain}_{timestamp}.json`.

---

## Top-Level Structure

```json
{
  "target": { ... },
  "scan_start": "2026-02-19 12:00:00 UTC",
  "scan_duration": 42.5,
  "pages_crawled": 127,
  "technologies": [ ... ],
  "forms": [ ... ],
  "api_endpoints": [ ... ],
  "file_uploads": [ ... ],
  "interesting_files": [ ... ],
  "comments": [ ... ],
  "emails": [ ... ],
  "parameters": [ ... ],
  "auth_mechanisms": [ ... ],
  "robots_txt": { ... },
  "sitemap": { ... },
  "security_txt": { ... },
  "common_paths": [ ... ],
  "all_urls": [ ... ],
  "attack_surface": { ... }
}
```

---

## Field Reference

### `target`
```json
{
  "url": "http://10.10.10.1",
  "domain": "10.10.10.1",
  "base_url": "http://10.10.10.1"
}
```

### `technologies[]`
```json
{
  "id": "wordpress",
  "name": "WordPress",
  "category": "CMS",
  "version": "6.4.2",
  "confidence": "high",
  "match_count": 12,
  "matched_on": [
    { "method": "header", "detail": "x-powered-by: PHP/8.1" },
    { "method": "path_probe", "detail": "/wp-login.php returned 200" },
    { "method": "body", "detail": "Body contains: wp-content/themes/" }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Internal signature ID |
| `name` | string | Human-readable technology name |
| `category` | string | CMS, Web Server, Framework, Language, etc. |
| `version` | string \| null | Detected version (if extractable) |
| `confidence` | string | `high`, `medium`, or `low` |
| `matched_on` | array | Detection evidence |

### `forms[]`
```json
{
  "found_on": "http://10.10.10.1/login",
  "action": "/auth",
  "method": "POST",
  "enctype": "multipart/form-data",
  "id": "login-form",
  "name": "",
  "inputs": [
    {
      "tag": "input",
      "type": "text",
      "name": "username",
      "id": "user",
      "value": "",
      "placeholder": "Username",
      "required": true,
      "pattern": "",
      "maxlength": "50"
    }
  ],
  "has_file_upload": false,
  "has_password_field": true,
  "has_hidden_fields": true,
  "has_csrf_token": true
}
```

### `api_endpoints[]`
```json
{
  "url": "/api/v1/users",
  "source": "javascript",
  "found_on": "http://10.10.10.1/app.js",
  "content_type": "application/json"
}
```

| `source` values | Meaning |
|-----------------|---------|
| `url_pattern` | URL matched API indicator regex |
| `content_type` | Response was JSON/XML |
| `javascript` | Extracted from inline/external JS |

### `parameters[]`
```json
{
  "url": "http://10.10.10.1/search?q=test&page=1",
  "path": "/search",
  "params": ["page", "q"],
  "param_details": {
    "q": "test",
    "page": "1"
  }
}
```

### `auth_mechanisms[]`
```json
{
  "type": "HTTP Basic Auth",
  "url": "http://10.10.10.1/admin",
  "detail": "Realm: Admin Panel"
}
```

| `type` values |
|---------------|
| `HTTP Basic Auth` |
| `HTTP Digest Auth` |
| `NTLM Auth` |
| `Kerberos/Negotiate Auth` |
| `Bearer Token Auth` |
| `Login Form` |
| `Session Cookie` |
| `Clickjacking Protection` |
| `Security Header: *` |

### `robots_txt`
```json
{
  "found": true,
  "url": "http://10.10.10.1/robots.txt",
  "disallowed": ["/admin/", "/backup/"],
  "allowed": ["/public/"],
  "sitemaps": ["http://10.10.10.1/sitemap.xml"],
  "raw": "User-agent: *\nDisallow: /admin/\n..."
}
```

### `sitemap`
```json
{
  "found": true,
  "urls": ["http://10.10.10.1/page1", "http://10.10.10.1/page2"],
  "url_count": 2
}
```

### `security_txt`
```json
{
  "found": true,
  "url": "http://10.10.10.1/.well-known/security.txt",
  "content": "Contact: security@example.com\n..."
}
```

### `common_paths[]`
```json
{
  "url": "http://10.10.10.1/admin",
  "path": "/admin",
  "status_code": 200,
  "content_length": 4521,
  "content_type": "text/html"
}
```

For redirects:
```json
{
  "url": "http://10.10.10.1/admin",
  "path": "/admin",
  "status_code": 302,
  "redirect_to": "/login"
}
```

For protected paths:
```json
{
  "url": "http://10.10.10.1/.htpasswd",
  "path": "/.htpasswd",
  "status_code": 403,
  "note": "exists but protected"
}
```

### `interesting_files[]`
```json
{
  "url": "http://10.10.10.1/config.php",
  "status_code": 200,
  "content_type": "text/html"
}
```

### `comments[]`
```json
{
  "url": "http://10.10.10.1/index.html",
  "comment": "TODO: remove debug endpoint /api/debug",
  "keywords": ["todo", "debug", "api"]
}
```

### `attack_surface`
```json
{
  "file_uploads": [
    {
      "url": "http://10.10.10.1/upload",
      "action": "/api/upload",
      "method": "POST",
      "inputs": [{ "tag": "input", "type": "file", "name": "file", "accept": ".jpg,.png" }]
    }
  ],
  "login_forms": [
    { "url": "http://10.10.10.1/login", "action": "/auth", "method": "POST" }
  ],
  "search_forms": [
    { "url": "http://10.10.10.1/", "action": "/search", "inputs": ["q"] }
  ],
  "data_input_forms": [
    { "url": "http://10.10.10.1/contact", "action": "/submit", "method": "POST", "inputs": ["name", "email", "message"] }
  ],
  "api_endpoints": 12,
  "parameterized_urls": 34,
  "total_forms": 8
}
```

### `all_urls[]`
Flat sorted array of every URL discovered during the crawl.

```json
[
  "http://10.10.10.1/",
  "http://10.10.10.1/about",
  "http://10.10.10.1/admin",
  "http://10.10.10.1/api/v1/users"
]
```
