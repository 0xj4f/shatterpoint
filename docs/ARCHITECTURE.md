# shatterpoint architecture

How a scan flows end-to-end, what each phase produces, and the precision guards that keep findings honest. shatterpoint is **signal-only** — it maps and detects, it never exploits.

---

## The pipeline

A single scan runs nine ordered phases inside one async run. Earlier phases feed later ones (`seed_urls`, `landing_html`, `detected_techs`, `crawl_results`).

```mermaid
flowchart TD
    CLI["main(): parse args · load config · resolve --token/-H"] --> RC["run_crawler()"]
    RC --> P1

    subgraph recon_client["recon httpx client (auth headers + origin-strip hook)"]
        P1["Phase 1 · Pre-crawl recon<br/>robots.txt · sitemap · security.txt · common paths"]
        P15["Phase 1.5 · Tech path probing<br/>fingerprint known paths"]
        P16["Phase 1.6 · Landing-page body detection<br/>body/cookie/form fingerprints"]
        P17["Phase 1.7 · Framework deep recon<br/>(--framework-recon) CVE signal probes"]
        P18["Phase 1.8 · SPA analysis<br/>(--spa) bundles · source maps · routes · secrets"]
    end

    P1 -->|"+ sitemap/robots → seed_urls"| P15
    P15 -->|technologies| P16
    P16 -->|"detected_techs · landing_html"| P17
    P17 --> P18
    P18 -->|"+ SPA routes → seed_urls"| P2

    P2["Phase 2 · Crawl<br/>async spider, domain-scoped"]
    P2 -->|crawl_results| P3
    P3["Phase 3 · Extract & analyze<br/>forms · emails · comments · APIs · auth · security headers · stack-trace mining"]
    P3 --> P4
    P4["Phase 4 · Fingerprint aggregate<br/>confidence scoring across all pages"]
    P4 --> P5
    P5["Phase 5 · Attack-surface summary"]
    P5 --> OUT["print_summary() · save_report() → output/recon_&lt;domain&gt;_&lt;ts&gt;.json"]
```

### Phase responsibilities

| Phase | Calls | Populates `results[...]` | Carries forward |
|---|---|---|---|
| **1 — Pre-crawl recon** | `ReconModule.run_all` | `robots_txt`, `sitemap`, `security_txt`, `common_paths` | sitemap + robots-disallowed → `seed_urls` |
| **1.5 — Tech path probing** | `Fingerprinter.probe_known_paths` → `finalize_technologies` | `technologies` | `detected_techs` |
| **1.6 — Landing body detection** | `recon_client.get(target)` · `HTMLParser.extract_forms` · `Fingerprinter.fingerprint_from_response` → `finalize_technologies` | `technologies` (merged) | `detected_techs`, `landing_html` |
| **1.7 — Framework deep recon** | `FrameworkRecon.analyze` | `framework_recon` | — (CVE signals + manual pointers) |
| **1.8 — SPA analysis** | `SPAAnalyzer.analyze` | `spa` | SPA routes → `seed_urls`; SPA endpoints → Phase 3 |
| **2 — Crawl** | `Spider.crawl(seed_urls)` | `all_urls` | `crawl_results` |
| **3 — Extract & analyze** | `HTMLParser`, `Extractor`, `ReconModule.detect_*`, `mine_response` | `forms`, `api_endpoints`, `comments`, `emails`, `parameters`, `auth_mechanisms`, `security_headers`, `interesting_files`, `debug_exposure`, (+`technologies` if a stack trace reveals a framework) | `forms_by_url` |
| **4 — Fingerprint aggregate** | `Fingerprinter.fingerprint_aggregate` → `finalize_technologies` | `technologies` (final) | — |
| **5 — Attack surface** | `Extractor.analyze_attack_surface` | `attack_surface`, `scan_duration`, `pages_crawled` | — |

---

## Module call-graph

```mermaid
flowchart LR
    crawler["crawler.py<br/>(orchestrator)"]

    crawler --> spider["modules/spider.py<br/>async crawl"]
    crawler --> recon["modules/recon.py<br/>robots/sitemap/paths/auth"]
    crawler --> fingerprint["modules/fingerprint.py<br/>tech detection + confidence"]
    crawler --> framework["modules/framework_recon.py<br/>CVE signal probes"]
    crawler --> spa["modules/spa.py<br/>SPA bundle mining"]
    crawler --> parser["modules/parser.py<br/>HTML extraction"]
    crawler --> extractor["modules/extractor.py<br/>API/attack-surface"]

    crawler --> auth["utils/auth.py<br/>token/-H resolve · redact · origin-scope"]
    crawler --> formatter["utils/formatter.py<br/>Rich output · save_report"]
    crawler --> stacktrace["utils/stacktrace.py<br/>debug-page + leak mining"]

    spider --> auth
    spider --> validator["utils/validator.py<br/>scope/normalize"]
    spider --> parser
    recon --> baseline["utils/baseline.py<br/>404 + redirect baseline"]
    fingerprint --> baseline
    framework --> baseline
    spa --> extractor
    spa --> parser
    crawler --> validator
```

---

## Authentication & origin scoping

Credentials (`--token` bearer, or any `-H "Name: value"`) are sent **same-origin only** and stripped on cross-origin redirects, so a token / API key / cookie never leaks to a third party. Values are redacted in the banner and never written to the report.

```mermaid
flowchart TD
    A["--token / $SHATTERPOINT_TOKEN / config.auth.token"] --> R1["resolve_token()"]
    B["-H 'Name: value' (repeatable) / config.auth.headers"] --> R2["resolve_headers()"]
    R1 --> M["build_auth_headers()<br/>(-H Authorization overrides --token)"]
    R2 --> M
    M --> RH["recon client headers"]
    M --> SH["spider per-hop headers"]
    RH --> HOOK["make_auth_strip_hook()<br/>strips ALL auth headers when<br/>should_send_auth() == False"]
    SH --> SCOPE["_auth_headers_for(url)<br/>same-origin → send, else drop"]
    HOOK --> NET["requests (recon/fingerprint/framework/SPA)"]
    SCOPE --> NET2["requests (crawl spider)"]
```

---

## Results schema

Every top-level key in the saved JSON, and the phase that fills it:

| Key | Phase |
|---|---|
| `target`, `scan_start` | init |
| `technologies` | 1.5, 1.6, 3 (stack-trace), 4 |
| `robots_txt`, `sitemap`, `security_txt`, `common_paths` | 1 |
| `framework_recon` | 1.7 |
| `spa` | 1.8 |
| `all_urls` | 2 |
| `forms`, `file_uploads`, `api_endpoints`, `comments`, `emails`, `parameters`, `interesting_files`, `auth_mechanisms`, `security_headers`, `debug_exposure` | 3 |
| `attack_surface`, `scan_duration`, `pages_crawled` | 5 |

---

## Precision guards (why findings are trustworthy)

| Guard | What it prevents | Where |
|---|---|---|
| **404 content baseline** | catch-all routers (SPA dev servers) that 200 every path → phantom path hits | `utils/baseline.py` |
| **Redirect baseline** | apps that 302 every path to a login (GitLab) → flood of false probe "findings" | `Baseline.is_catchall_redirect` |
| **Content-confirm gate** | a bare 200 at `/console` / `/admin/` masquerading as the real product | `framework_recon` `confirm_any` |
| **Conflict resolution** | two incompatible techs both firing (Laravel vs Rails on shared `<meta csrf-token>`) | `fingerprint.resolve_conflicts` |
| **Product-specific signatures** | generic paths/headers (`/admin/`, `x-powered-by: PHP`) cross-tagging frameworks | `signatures/fingerprints.yaml` |
| **Signal-only, no exploit** | the tool never sends a payload; CVEs are mapped as "verify manually" | `framework_recon` (GET-only, CI passivity test) |

---

*Keep this in sync with `crawler.py:run_crawler` when phases change.*
