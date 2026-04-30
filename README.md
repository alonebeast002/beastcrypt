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

Terminal-based recon toolkit — hunt exposed secrets, API keys, and sensitive endpoints from archived and live JavaScript files.

---

## Install

```bash
pip install beastcrypt
```

Requires Python 3.8+ and `curl`. Optional: [Katana](https://github.com/projectdiscovery/katana) at `~/go/bin/katana`.

---

## Usage

```bash
beastcrypt                                     # interactive menu (recommended)

```

| Mode | Description |
|------|-------------|
| 1 | Wayback File Hunter — pull archived files by type |
| 2 | JS Secret Scanner — scan live + archived JS for secrets |
| 3 | Full Beast Mode — both combined |

File types (`-t`): `js` `json` `pdf` `zip` `xml` `csv` `sql` `config` `html` `img` `map` `txt` `wasm` `all`

---

## Detects

AWS · Google API · GitHub · Slack · Stripe · Twilio · SendGrid · JWT · Private Keys · Bearer Tokens · DB URLs · S3 · Azure · Heroku · Telegram · Mapbox · NPM · GraphQL · Firebase · and more

---

## Disclaimer

For authorized security testing and bug bounty research only.

---

**ALONE BEAST** · HackerOne · Google VRP · [MIT](LICENSE)
