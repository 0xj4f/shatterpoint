# Using shatterpoint

shatterpoint maps a website: its pages, technologies, forms, API endpoints and weak spots.
It only sends GET requests and never attacks anything. **Scan only targets you own or are allowed to test.**

```bash
export RHOST=https://app.example.com      # the target, used in every example below
```

---

## Use cases

### 1. First look at a site

```bash
shatterpoint -u $RHOST
```
**You get:** pages, technologies (with versions), forms, API endpoints, emails, comments and security headers.

### 2. Quick scan

```bash
shatterpoint -u $RHOST -d 3 -p 100
```
**You get:** the same, limited to 3 links deep and 100 pages.

### 3. Logged-in scan

```bash
shatterpoint -u $RHOST --token "$SHATTERPOINT_TOKEN"
shatterpoint -u $RHOST -H "Cookie: session=abc123"
```
**You get:** the pages and APIs behind login. The token is only sent to `$RHOST`, and never written to the report.

### 4. React / Vue / Angular app (SPA)

```bash
shatterpoint -u $RHOST --spa
```
**You get:** what's hidden in the JavaScript files:
- client routes (`/admin`, `/settings`);
- API paths, which are also requested, so you see their status;
- RPC methods;
- leaked keys;
- source maps.

### 5. See the app like a real browser

```bash
shatterpoint -u $RHOST --spa --browser
```
**You get:**
- pages after JavaScript runs;
- where each page really lands (`/admin → /login` means "needs login");
- the API calls the app makes by itself (XHR, fetch, WebSocket).

The browser never clicks, and it blocks anything that isn't a GET.

### 6. Logged-in SPA in the browser

SPAs keep their login token in the browser's localStorage, so a header alone doesn't log them in.

```bash
shatterpoint -u $RHOST --spa --browser \
  --token "$SHATTERPOINT_TOKEN" \
  --browser-storage token="$SHATTERPOINT_TOKEN" --browser-storage 'user={}'
```
**You get:** the protected pages rendered, and the API calls they make.
The key names (`token`, `user`) belong to the app: log in once in your browser, then look in DevTools → Application → Local Storage.

### 7. Check for known framework weaknesses

```bash
shatterpoint -u $RHOST --framework-recon
```
**You get:** framework exposures (Laravel, Django, Spring Boot, …), such as debug pages and exposed admin or actuator endpoints, with CVE pointers to verify by hand.

### 8. Go through a proxy

```bash
shatterpoint -u $RHOST --proxy http://127.0.0.1:8080        # Burp / mitmproxy
shatterpoint -u $RHOST --proxy socks5h://127.0.0.1:9050     # TOR
```
**You get:** the same scan, with every request (browser included) sent through the proxy.

### 9. Crawl → API spec (OpenAPI)

Turn a crawl into an OpenAPI (Swagger) file: every API endpoint seen, with its responses.
You also need [mitmproxy](https://mitmproxy.org) and [mitmproxy2swagger](https://github.com/0xj4f/mitmproxy2swagger).

Run these in **one terminal**, in this order:

```bash
# 1. Start recording $RHOST/api in the background
mitmdump -q -p 8899 -w flows.mitm "~u ^$RHOST/api & !(~c 404 | ~c 405)" &

# 2. Crawl through it (drop the last three flags if no login is needed)
shatterpoint -u $RHOST --spa --browser --no-recon --proxy http://127.0.0.1:8899 \
  --token "$SHATTERPOINT_TOKEN" \
  --browser-storage token="$SHATTERPOINT_TOKEN" --browser-storage 'user={}'

# 3. Stop recording (the file is only complete after this)
kill %1

# 4. Convert: list paths, keep them all, build the spec
docker run --rm -v "$PWD":/app mitmproxy2swagger -f flow -i flows.mitm -o openapi.yaml -p $RHOST/api
sed -i.bak 's/^- ignore:/- /' openapi.yaml
docker run --rm -v "$PWD":/app mitmproxy2swagger -f flow -i flows.mitm -o openapi.yaml -p $RHOST/api

# 5. View the APIs
grep -E '^  /' openapi.yaml
docker run --rm -p 8088:8080 -e SWAGGER_JSON=/spec/openapi.yaml -v "$PWD":/spec swaggerapi/swagger-ui
```
**You get:** `openapi.yaml` with the GET endpoints, their responses and parameters. Browse it at http://localhost:8088.

**Not included:** POST/PUT/DELETE (shatterpoint never submits anything) and WebSocket APIs.
They still appear in shatterpoint's own report.

| Problem | Fix |
|---|---|
| `openapi.yaml` has no APIs | `$RHOST` isn't set in the terminal running `mitmdump`: export it there |
| Only `- ignore:` lines | You skipped the `sed` or the second `docker run` |
| Browser pages all end on `/login` | Add `--browser-storage` |
| Address already in use | Another port: `-p 8898` in step 1 and step 2 |

`flows.mitm` holds your token and full responses: keep it private, and delete it when done.

---

## Flags

| Flag | What it does |
|---|---|
| `-u URL` | Target |
| `-d N` | How deep to follow links (default 10) |
| `-p N` | Max pages (default 500) |
| `-t N` | Requests at once (default 15) |
| `-o DIR` | Where to save the report (default `./output`) |
| `-c FILE` | Config file (default `config.yaml`, if present) |
| `--timeout N` | Seconds per request (default 10) |
| `--no-recon` | Skip robots.txt, sitemap and common-path checks |
| `--no-fingerprint` | Skip technology detection |
| `--spa` | Mine the JavaScript of React/Vue/Angular/Next/Nuxt apps |
| `--browser` | Also open pages in headless Chrome (needs the browser install, below) |
| `--browser-storage KEY=VALUE` | Put a value in the browser's localStorage before pages load (repeatable) |
| `--framework-recon` | Check framework-specific weaknesses |
| `--token TOKEN` | Send `Authorization: Bearer TOKEN` (or set `$SHATTERPOINT_TOKEN`) |
| `-H "Name: value"` | Send any header, e.g. a cookie or API key (repeatable) |
| `--proxy URL` | Send all traffic through a proxy (`http://`, `socks5h://`) |
| `-v` | Verbose |

**Browser install (once):**
```bash
pipx inject --include-apps shatterpoint playwright
playwright install --only-shell chromium
```

---

## Output

**On screen:** the scan runs in phases (recon → SPA → browser → crawl → analysis), then prints the results as tables:

| Table | Meaning |
|---|---|
| Technologies | What the site runs, with version and confidence |
| API Endpoints | Every API URL found, and where it came from (`url_pattern`, a JS file, `browser:xhr`, …) |
| Forms | Forms and their inputs (login, upload, search) |
| Framework Findings | Exposures with severity, plus CVEs to verify by hand |
| SPA Routes / RPC Methods | Client routes and backend methods found in the JavaScript |
| Browser Pages | Each page, and where it really landed |
| Debug Exposure | Leaked paths, versions and DB URLs from error pages |

**On disk:** a JSON report, `./output/recon_<domain>_<time>.json`. It has the same data, ready for scripts:
```bash
jq '.api_endpoints[].url' output/recon_*.json
```
