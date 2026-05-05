```markdown
# BeastCrypt

> v2.0 · JS & Source Map Secret Scanner · by alone_beast_02

Terminal-based recon toolkit — hunt exposed secrets, API keys, and sensitive endpoints from live JavaScript files and source maps.

---

## Install

```bash
pip install beastcrypt
```

Requires Python 3.8+. No external dependencies needed.

---

## Usage

```bash
beastcrypt    # interactive menu (recommended)
```

| Mode | Description |
|------|-------------|
| 1 | Single Target URL — deep crawl + source map extraction |
| 2 | Subdomain List — scan multiple targets from a `.txt` file |
| 3 | JS / .map URL List — direct secrets scan on provided URLs |

---

## What It Detects

| Category | Examples |
|----------|---------|
| Cloud Keys | AWS Access/Secret Key, Azure Storage Key, Azure SAS Token |
| Auth Tokens | JWT, Bearer Token, GitHub Token (`ghp_`, `github_pat_`) |
| API Keys | Google API Key, Firebase Key, Generic API Key |
| Payment | Stripe Live/Test Keys |
| Messaging | Slack Token, SendGrid Key |
| Generic | Passwords, Session Tokens, Access Tokens, Private Keys |
| Infrastructure | Firebase URLs, Cloudinary URLs |
| Internal Paths | Webpack paths, API routes, admin/internal endpoints |

---

## Output Files

| File | Contents |
|------|----------|
| `all_js_urls.txt` | All discovered JS asset URLs |
| `results.json` | Secrets with type, value, source, and timestamp |
| `internal_paths.txt` | Extracted internal API paths and routes |

---

## How It Works

1. Fetches target URL and crawls for linked `.js` files
2. For each `.js` file, attempts to fetch its `.map` source map
3. Scans all content with 20+ secret patterns using regex
4. Extracts internal paths matching sensitive route patterns
5. Saves everything to local output files in real time

Supports 15 concurrent threads. SSL verification skipped for self-signed certs. Press `Ctrl+C` anytime to stop — results are saved on exit.

---

## Disclaimer

For authorized security testing and bug bounty research only. Always obtain permission before scanning any target.

---

**alone_beast_02** · [MIT](LICENSE)
```
