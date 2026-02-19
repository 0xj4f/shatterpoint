# WEB CRAWLER

```bash
╰─$ python3 crawler.py --help

╔═══════════════════════════════════════════════════════╗
║          WEB RECON CRAWLER v1.0 (by 0xj4f)            ║
║          Attack Surface Mapper & Fingerprinter        ║
╚═══════════════════════════════════════════════════════╝

usage: crawler.py [-h] [-u URL] [-c CONFIG] [-d DEPTH] [-p PAGES] [-t THREADS] [-o OUTPUT] [-v] [--no-fingerprint] [--no-recon] [--timeout TIMEOUT]

Web Recon Crawler - Attack Surface Mapper

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

Examples:
  python crawler.py -u http://10.10.10.1
  python crawler.py -u http://target.htb -d 5 -p 200
  python crawler.py -u https://10.10.10.1:8443 -o ./loot -v
  python crawler.py -c custom_config.yaml
```