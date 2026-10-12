
- framework recon and common cves/exploits to test per framework(remember we don't exploit we just check signals)
  - laravel
  - django
  - flask
  - springboot
  - react js

- Add Headers
  - feature to add header via -H "Authorization: Bearer REDACTED"
  - I want to cover all types of authentication
 
- Add Proxy
  - ability to add Proxy for Tor or for MITM
- UTILITY - MITMPROXY script for shatterpoint 
  - is there a need to develop mitmproxy for examining all request?
  - and maybe building a sitemap like burp is doing? 
  - let's explore this idea if this is worth it

- precision: Django/Jenkins false-positives on non-Django/Jenkins apps
  - a Next.js app that protects `/admin` in middleware 307/308-redirects `/admin/` → the
    Django `/admin/` probe (non-200 bypasses the content gate) fires "Django admin exposed",
    and a 200 `/login` page gets claimed by the Jenkins path signature.
  - seen live against the VSN `03-nextjs-middleware-bypass` lab (worked around there by
    guarding `/portal` + `/signin`). Consider: require the Django *fingerprint* before the
    Django framework-recon profile runs, and tighten the Jenkins signature beyond `/login`.
  - also seen on the VSN `05-jenkins-cli-fileread` lab (real Jenkins 2.441): a **Django**
    fingerprint FP (Jenkins is not Django — likely a body marker collision; its headers are
    `X-Frame-Options: sameorigin`, `/admin/` → 404) AND a **Spring Boot** stack-trace-miner
    FP attributed to `/manage/about`. The true signal (Jenkins high-confidence + CVE-2024-23897
    pointer) is correct; the Django/Spring noise should be tightened.
  - and on the VSN `06-gitlab-exiftool` lab (real GitLab CE 13.10): a **Laravel** FP because
    GitLab's Rails forms carry a `_method` hidden field that matches the Laravel `form_fields`
    signature, plus the usual Django `/admin/` redirect FP. Consider requiring ≥2 distinct
    Laravel evidence types (cookie/body/path), not a lone `_method` form field.
  