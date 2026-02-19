# 0xj4f-webcrawler

OSCP-focused web reconnaissance crawler — maps attack surfaces, fingerprints technologies, and catalogs every form, endpoint, and parameter on a target domain.

```bash
╰─$ 0xj4f-webcrawler --help

╔═══════════════════════════════════════════════════════╗
║       0xj4f-webcrawler v1.0                           ║
║       Attack Surface Mapper & Fingerprinter           ║
╚═══════════════════════════════════════════════════════╝

usage: 0xj4f-webcrawler [-h] [-u URL] [-c CONFIG] [-d DEPTH] [-p PAGES] [-t THREADS] [-o OUTPUT] [-v] [--no-fingerprint] [--no-recon] [--timeout TIMEOUT]
                        [--version]

0xj4f-webcrawler — OSCP Recon Attack Surface Mapper

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target URL (overrides config)
  -c, --config CONFIG   Config file path
  -d, --depth DEPTH     Max crawl depth
  -p, --pages PAGES     Max pages to crawl
  -t, --threads THREADS
                        Concurrency level
  -o, --output OUTPUT   Output directory
  -v, --verbose         Verbose output
  --no-fingerprint      Skip fingerprinting
  --no-recon            Skip recon modules
  --timeout TIMEOUT     Request timeout in seconds
  --version             show program's version number and exit

Examples:
  0xj4f-webcrawler -u http://10.10.10.1
  0xj4f-webcrawler -u http://target.htb -d 5 -p 200
  0xj4f-webcrawler -u https://10.10.10.1:8443 -o ./loot -v
  0xj4f-webcrawler -c custom_config.yaml

```

## What It Does

Single-pass recon against **one target domain**. No attacks — just mapping.

- 🕷️ **Crawls** every in-scope page (async, 15 concurrent requests)
- 📝 **Extracts** forms, file uploads, API endpoints, URL parameters, emails, HTML comments
- 🔍 **Fingerprints** 25+ technologies with version detection and confidence scoring
- 🗺️ **Probes** 70+ common paths (admin panels, backups, .git, .env, etc.)
- 🤖 **Parses** robots.txt, sitemap.xml, security.txt
- 🔐 **Detects** auth mechanisms (Basic, NTLM, Bearer, login forms, session cookies)
- 📊 **Reports** structured JSON + rich CLI output

---

## Installation

### pipx (recommended)

```bash
pipx install git+https://github.com/0xj4f/0xj4f-webcrawler.git
pipx install -e . --force --python "$(which python3)"

```

### pip

```bash
pip install git+https://github.com/0xj4f/0xj4f-webcrawler.git
```

### From source (dev)

```bash
git clone https://github.com/0xj4f/0xj4f-webcrawler.git
cd 0xj4f-webcrawler
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Basic scan
0xj4f-webcrawler -u http://10.10.10.1

# OSCP box with limits
0xj4f-webcrawler -u http://target.htb -d 5 -p 200

# Save to specific directory
0xj4f-webcrawler -u http://10.10.10.1 -o ./loot/box1

# Fast scan — skip path probing
0xj4f-webcrawler -u http://10.10.10.1 --no-recon

# Use a config file
0xj4f-webcrawler -c config.yaml
```

---

## CLI Reference

```
usage: 0xj4f-webcrawler [-h] [-u URL] [-c CONFIG] [-d DEPTH] [-p PAGES]
                        [-t THREADS] [-o OUTPUT] [-v]
                        [--no-fingerprint] [--no-recon] [--timeout TIMEOUT]
                        [--version]

options:
  -u, --url URL          Target URL
  -c, --config CONFIG    Config file path (default: config.yaml)
  -d, --depth DEPTH      Max crawl depth (default: 10)
  -p, --pages PAGES      Max pages to crawl (default: 500)
  -t, --threads THREADS  Concurrency level (default: 15)
  -o, --output OUTPUT    Output directory (default: ./output)
  -v, --verbose          Verbose output
  --no-fingerprint       Skip technology fingerprinting
  --no-recon             Skip recon modules (robots, sitemap, path probing)
  --timeout TIMEOUT      Request timeout in seconds (default: 10)
  --version              Show version
```

---

## Configuration

Drop a `config.yaml` in your working directory to customize defaults:

```yaml
target:
  url: "http://10.10.10.1"

crawler:
  max_depth: 10
  max_pages: 500
  concurrency: 15
  timeout: 10
  max_redirects: 3
  delay: 0.1

extract:
  forms: true
  api_endpoints: true
  file_uploads: true
  comments: true
  emails: true
  js_endpoints: true

fingerprint:
  enabled: true
  check_headers: true
  check_cookies: true
  check_paths: true
  check_meta: true

recon:
  robots_txt: true
  sitemap_xml: true
  security_txt: true
  common_paths: true
  auth_detection: true

output:
  directory: "./output"
```

CLI flags override config file values.

---

## Output

Reports are saved as JSON to `./output/recon_{domain}_{timestamp}.json`.

See [docs/schema.md](docs/schema.md) for the full report schema and [docs/features.md](docs/features.md) for detailed feature documentation.

---

## Project Structure

```
0xj4f-webcrawler/
├── pyproject.toml
├── config.yaml
├── src/oxj4f_webcrawler/
│   ├── __init__.py
│   ├── crawler.py              # Main orchestrator & CLI entry point
│   ├── modules/
│   │   ├── spider.py           # Async crawler engine
│   │   ├── parser.py           # HTML extraction (forms, links, comments)
│   │   ├── extractor.py        # API/JS endpoint & attack surface analysis
│   │   ├── fingerprint.py      # Technology detection engine
│   │   └── recon.py            # robots.txt, sitemap, common paths, auth
│   ├── utils/
│   │   ├── validator.py        # URL validation & scope enforcement
│   │   └── formatter.py        # Rich CLI output & JSON reporting
│   └── signatures/
│       └── fingerprints.yaml   # 25+ technology signatures
├── tests/
│   └── test_smoke.py
└── docs/
    ├── features.md
    └── schema.md
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Native Python** (not Scrapy) | Surgical precision for OSCP recon, not general scraping |
| **15 concurrent requests** | Fast enough under time pressure, won't DoS the lab |
| **Single domain scope** | One target per run — compose with a wrapper later |
| **Manual redirect tracking** | Logs full redirect chains (useful for auth bypass recon) |
| **Self-signed cert support** | `verify=False` — OSCP targets always have bad certs |
| **No attacks** | Map only — exploitation is your job |

---

## Adding Custom Fingerprints

Edit `src/oxj4f_webcrawler/signatures/fingerprints.yaml`:

```yaml
my_custom_app:
  name: "My Custom App"
  category: "Custom"
  headers:
    - header: "x-custom-header"
      pattern: "(?i)myapp/?([\\d.]+)?"
  paths:
    - "/custom/login"
    - "/custom/api/"
  body:
    - "MyCustomApp"
  cookies:
    - "myapp_session"
```

---

## License

MIT

---

**Author**: [0xj4f](https://github.com/0xj4f)