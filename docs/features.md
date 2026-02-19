# Features

Complete feature reference for **0xj4f-webcrawler**.

---

## Crawling Engine

| Feature | Description |
|---------|-------------|
| **Async I/O** | Built on `httpx` + `asyncio` for non-blocking concurrent requests |
| **Concurrency control** | Configurable semaphore (default: 15 concurrent requests) |
| **Scope enforcement** | Strict single-domain — never leaves the target `netloc` |
| **Redirect tracking** | Manual redirect handling up to N hops (default: 3), logs the full chain |
| **Depth limiting** | Configurable max crawl depth from seed URL |
| **Page cap** | Safety limit on total pages crawled (default: 500) |
| **Polite delay** | Configurable inter-request delay (default: 0.1s) |
| **Self-signed certs** | TLS verification disabled — works with OSCP lab targets |
| **Custom User-Agent** | Defaults to Firefox on Linux, fully configurable |

---

## Extraction

### Forms & Inputs
- Extracts every `<form>` with action, method, enctype
- Catalogs all `<input>`, `<textarea>`, `<select>`, `<button>` elements
- Flags **file upload** inputs (`type="file"`) with `accept` attribute
- Flags **password fields** (login form detection)
- Detects **hidden fields** and **CSRF tokens** by name pattern
- Records input attributes: name, id, type, value, placeholder, required, pattern, maxlength

### API Endpoints
- URL pattern matching (`/api/`, `/rest/`, `/graphql`, `/v1/`, etc.)
- Content-type detection (JSON/XML responses flagged as API)
- JavaScript extraction via regex:
  - `fetch()` calls
  - `axios.get/post/put/delete/patch()`
  - `XMLHttpRequest.open()`
  - jQuery AJAX (`$.ajax`, `$.get`, `$.post`, `$.getJSON`)
  - Variable assignments (`url = "..."`, `endpoint = "..."`)
  - Inline relative paths (`"/some/path"`)

### Comments
- Extracts all HTML comments (`<!-- ... -->`)
- Keyword flagging: password, admin, todo, debug, secret, token, api, sql, config, backup, etc.
- Truncates to 500 chars per comment

### Emails
- Regex extraction from full page body
- Deduplicated across all pages

### URL Parameters
- Catalogs every unique path + parameter combination
- Records parameter names and sample values
- Key for identifying injection points (SQLi, XSS, IDOR)

### Scripts
- External script sources with integrity hashes
- Inline script content (fed to JS endpoint extractor)

### Meta Tags
- All `<meta>` attributes (name, property, http-equiv, content, charset)
- Used by fingerprinting engine

---

## Technology Fingerprinting

Multi-method detection engine with confidence scoring.

### Detection Methods
| Method | How it works |
|--------|-------------|
| **HTTP Headers** | Regex match on `Server`, `X-Powered-By`, `X-Generator`, etc. |
| **Cookies** | Cookie name matching (`PHPSESSID`, `laravel_session`, etc.) |
| **Meta tags** | `<meta name="generator">` content matching |
| **Body content** | String presence in HTML body |
| **Script patterns** | Regex on `<script src="...">` for versioned libraries |
| **Known paths** | Probes tech-specific URLs (`/wp-login.php`, `/manager/html`, etc.) |

### Confidence Scoring
- **High**: 3+ detection methods match, or 5+ page matches
- **Medium**: 2+ methods or 2+ page matches
- **Low**: Single match

### Supported Technologies (25+)
**CMS**: WordPress, Drupal, Joomla  
**Web Servers**: Apache, Nginx, IIS, Tomcat  
**Languages**: PHP, ASP.NET  
**Frameworks**: Flask, Django, Express.js, Rails, Laravel, Angular, React, Vue.js  
**Libraries**: jQuery, Bootstrap  
**Tools**: phpMyAdmin, Webmin, Grafana, Jenkins, GitLab  
**CDN/WAF**: Cloudflare  

Custom signatures can be added to `signatures/fingerprints.yaml`.

---

## Reconnaissance Modules

### robots.txt
- Fetches and parses `robots.txt`
- Extracts `Disallow`, `Allow`, and `Sitemap` directives
- Disallowed paths added as crawl seeds

### sitemap.xml
- Parses `sitemap.xml`, `sitemap_index.xml`, `.gz` variants
- Handles XML namespaces and sitemap indexes (recursive)
- Regex fallback for malformed XML
- Discovered URLs added as crawl seeds

### security.txt
- Checks `/.well-known/security.txt` and `/security.txt` (RFC 9116)

### Common Path Probing
70+ high-value paths probed:
- **Admin panels**: `/admin`, `/wp-admin/`, `/manager/html`, `/phpmyadmin/`
- **Login pages**: `/login`, `/signin`, `/auth`, `/user/login`
- **API docs**: `/swagger-ui.html`, `/api-docs`, `/graphql`, `/graphiql`
- **Info disclosure**: `/.env`, `/.git/HEAD`, `/phpinfo.php`, `/server-status`
- **Backups**: `/backup/`, `/db/`, `/config/`, `/old/`, `/tmp/`
- **CMS files**: `/xmlrpc.php`, `/CHANGELOG.txt`, `/README.txt`
- **Dev tools**: `/actuator`, `/console`, `/_debug`, `/_profiler`

Responses categorized as: **200 OK**, **Redirect** (with location), **Protected** (401/403).

### Authentication Detection
Passive identification only — no attacks:
- **HTTP Auth**: Basic, Digest, NTLM, Kerberos/Negotiate, Bearer
- **Login forms**: Password field detection with CSRF token check
- **Session cookies**: Name pattern matching with flag analysis (HttpOnly, Secure, SameSite)
- **Security headers**: CSP, HSTS, X-Content-Type-Options, X-XSS-Protection, Permissions-Policy
- **Clickjacking protection**: X-Frame-Options

---

## Attack Surface Analysis

Automated summary generated from all extracted data:

| Category | What's reported |
|----------|----------------|
| **File uploads** | Forms with `type="file"` inputs, including accepted types |
| **Login forms** | Forms with password fields, action URLs, methods |
| **Search forms** | Text inputs likely used for search (XSS/SQLi targets) |
| **Data input forms** | All other forms with text inputs (injection candidates) |
| **API endpoint count** | Total unique API endpoints discovered |
| **Parameterized URLs** | Count of URLs with query parameters |
| **Total forms** | Overall form count |

---

## Output

### CLI Output
Rich-formatted terminal output using the `rich` library:
- Color-coded tables for technologies, forms, APIs, parameters
- Tree views for robots.txt and auth mechanisms
- Progress indicators during crawl
- Phase-by-phase status updates

### JSON Report
Complete structured output saved to `./output/recon_{domain}_{timestamp}.json`.  
See [schema.md](schema.md) for the full report schema.
