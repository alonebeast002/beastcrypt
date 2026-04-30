# beastcrypt

```
  ██████╗ ███████╗ █████╗ ███████╗████████╗
  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝
  ██████╔╝█████╗  ███████║███████╗   ██║   
  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   
  ██████╔╝███████╗██║  ██║███████║   ██║   
  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
  ⬡  Wayback Hunter · JS Secret Scanner · v1.2 · by ALONE BEAST  ⬡
```

**beastcrypt** is a terminal-based OSINT and secret scanning toolkit for bug bounty hunters and security researchers.

---

## Features

- **Wayback File Hunter** — Pull any file type (JS, JSON, config, SQL, PDF, ZIP, etc.) from the Wayback Machine CDX API
- **JS Secret Scanner** — Crawl live + archived JavaScript files and detect 25+ secret patterns (API keys, tokens, JWTs, DB URLs, and more)
- **Full Beast Mode** — Combined Wayback secret-file hunt + JS scanner in one run
- **Katana integration** — Auto-crawls live JS via [Katana](https://github.com/projectdiscovery/katana) when available
- **Structured map download** — JS and `.map` files saved into clean `downloads/<domain>/js/` and `downloads/<domain>/maps/` trees
- **False positive filtering** — Built-in blacklist + regex guards
- **Cross-file dedup** — Same secret found in 10 files → reported once
- **ANSI terminal UI** — Colored boxes, spinners, progress with percentage

---

## Installation

```bash
pip install beastcrypt
```

> **Requires:** Python 3.8+, `curl` on PATH.  
> Optional: [Katana](https://github.com/projectdiscovery/katana) at `~/go/bin/katana` for live JS crawl.

---

## Usage

### Interactive menu
```bash
beastcrypt
```

### CLI flags
```bash
# Mode 1 — Wayback file hunter
beastcrypt -d example.com -m 1 -t js,json,config

# Mode 2 — JS secret scanner
beastcrypt -d example.com -m 2 -o my_output

# Mode 3 — Full Beast Mode
beastcrypt -d example.com -m 3

# Mode 1 JSON report only (no download)
beastcrypt -d example.com -m 1 --json-only
```

### Modes

| Mode | Name | What it does |
|------|------|-------------|
| 1 | Wayback File Hunter | Download archived files by type |
| 2 | JS Secret Scanner | Scan JS for secrets + endpoints |
| 3 | Full Beast Mode | Both combined |

### File types (Mode 1 `-t` flag)
`js` `json` `pdf` `zip` `xml` `csv` `sql` `config` `html` `img` `map` `txt` `wasm` `all`

---

## Output structure

```
beast_output/
├── wayback_example_com_<ts>/
│   ├── *.js / *.json / ...       # downloaded files
│   └── wayback_report_*.json     # full report
├── jsreaper_example_com_<ts>/
│   ├── *.js                      # flat JS dump
│   ├── js_urls.txt
│   ├── map_urls.txt
│   └── secrets_*.json            # findings
└── downloads/
    └── example/
        ├── js/                   # structured JS files
        └── maps/                 # structured .map files
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KATANA_TIMEOUT` | `300` | Katana crawl timeout (seconds) |
| `CDX_LIMIT_JS` | `10000` | Max JS URLs from Wayback CDX |
| `CDX_LIMIT_ALL` | `5000` | Max URLs from Wayback CDX (Mode 1) |

```bash
KATANA_TIMEOUT=600 CDX_LIMIT_JS=20000 beastcrypt -d bigsite.com -m 2
```

---

## Secret patterns detected

Google API Key · AWS Access/Secret Key · GitHub Token · Slack Token · Stripe Key · Twilio SID · SendGrid Key · JWT · Private Key · Bearer Token · Basic Auth · Passwords in JS · Database URLs · S3 Buckets · Cloudinary · Mapbox · NPM Token · Azure Key · Heroku API Key · Telegram Bot Token · API Endpoints · GraphQL Endpoints · Firebase URL · Mailgun Key · Azure Connection String

---

## Disclaimer

This tool is intended for **authorized security testing and bug bounty research only**. Use responsibly and only against targets you have permission to test. The author is not responsible for any misuse.

---

## Author

**ALONE BEAST** — Bug bounty hunter & security researcher  
HackerOne · Google VRP

---

## License

MIT
