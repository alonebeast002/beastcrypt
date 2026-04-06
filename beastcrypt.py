#!/usr/bin/env python3
# ============================================================
#   BEAST TOOL  v1.1  —  by ALONE BEAST
#   [1] Wayback File Hunter  — download any file type
#   [2] JS Secret Scanner    — scan JS for secrets
#   [3] Full Beast Mode      — Mode 1 (secret files) + Mode 2
# ============================================================

import subprocess, sys, os, re, json, time, argparse, signal
import urllib.parse
from datetime import datetime
from collections import defaultdict


R   = "\033[91m"; G   = "\033[92m"; Y   = "\033[93m"
B   = "\033[94m"; M   = "\033[95m"; C   = "\033[96m"
W   = "\033[97m"; DIM = "\033[2m";  BLD = "\033[1m"
RST = "\033[0m";  HIDE= "\033[?25l"; SHOW= "\033[?25h"


def _sigint(sig, frame):
    print(f"\n\n  {Y}[!]{RST} Stopped by user.\n")
    sys.exit(0)

signal.signal(signal.SIGINT, _sigint)


FP_BLACKLIST = {
    "password","passwd","pwd","secret","token","bearer token","bearer",
    "auth_token","access_token","api_key","apikey","your_password",
    "your_secret","your_token","example","placeholder","changeme",
    "xxxxxxxx","testtoken","none","null","undefined","insert_key_here",
    "enter_key","12345678","00000000","password123","test","demo","sample",
}

SECRET_PATTERNS = {
    "Google API Key":   (r'AIza[0-9A-Za-z\-_]{35}',                                                        None),
    "Firebase URL":     (r'https://[a-z0-9-]+\.firebaseio\.com',                                           None),
    "AWS Access Key":   (r'AKIA[0-9A-Z]{16}',                                                              None),
    "AWS Secret Key":   (r'(?i)aws[_\-\s]{0,5}secret[_\-\s]{0,10}[\'"]([0-9a-zA-Z/+]{40})[\'"]',         1),
    "GitHub Token":     (r'(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})',                            1),
    "Slack Token":      (r'(xox[baprs]-[0-9A-Za-z\-]{10,80})',                                            1),
    "Stripe Live Key":  (r'(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})',                            1),
    "Twilio SID":       (r'(AC[a-f0-9]{32})',                                                              1),
    "Mailgun Key":      (r'(key-[0-9a-zA-Z]{32})',                                                         1),
    "SendGrid Key":     (r'(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})',                                 1),
    "JWT Token":        (r'(eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_.+/=]{10,})',         1),
    "Private Key":      (r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',                            None),
    "Bearer Token":     (r'(?i)bearer\s+([a-zA-Z0-9\-._~+/]{20,})',                                       1),
    "Basic Auth":       (r'(?i)basic\s+([a-zA-Z0-9+/=]{20,})',                                            1),
    "Password in JS":   (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"]([^\'"]{8,})[\'"]',                  1),
    "Secret Key in JS": (r'(?i)(?:secret_key|api_secret|client_secret)\s*[:=]\s*[\'"]([^\'"]{10,})[\'"]', 1),
    "Auth Token in JS": (r'(?i)(?:auth_token|authtoken|access_token)\s*[:=]\s*[\'"]([^\'"]{10,})[\'"]',   1),
    "Database URL":     (r'((?:mysql|postgres|mongodb|redis)://[^\s\'"<>{},]{10,})',                       1),
    "S3 Bucket":        (r'([a-z0-9.\-]+\.s3\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.\-]+)',            1),
    "Cloudinary URL":   (r'(cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z]+)',                                 1),
    "Mapbox Token":     (r'(pk\.eyJ1[0-9A-Za-z._\-]+)',                                                   1),
    "NPM Token":        (r'(npm_[A-Za-z0-9]{36})',                                                         1),
    "Heroku API Key":   (r'(?i)heroku.{0,30}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 1),
    "Telegram Bot":     (r'([0-9]{8,10}:[A-Za-z0-9_\-]{35})',                                             1),
    "API Endpoint":     (r'(https?://[^\s\'"<>{}]{5,}/api/v[0-9]+/[^\s\'"<>{}]{3,})',                     1),
    "GraphQL Endpoint": (r'(https?://[^\s\'"<>{}]{5,}/graphql[^\s\'"<>{}]*)',                             1),
}


FILE_GROUPS = {
    "js":     {"exts": [".js", ".mjs", ".cjs"],                                                "label": "JavaScript",  "color": Y},
    "json":   {"exts": [".json", ".jsonld"],                                                   "label": "JSON",        "color": G},
    "pdf":    {"exts": [".pdf"],                                                               "label": "PDF",         "color": R},
    "zip":    {"exts": [".zip", ".gz", ".tar", ".rar", ".7z", ".bz2"],                        "label": "Archives",    "color": M},
    "xml":    {"exts": [".xml", ".rss", ".atom"],                                              "label": "XML/RSS",     "color": C},
    "csv":    {"exts": [".csv", ".tsv"],                                                       "label": "CSV/TSV",     "color": B},
    "sql":    {"exts": [".sql", ".db", ".sqlite"],                                             "label": "Database",    "color": R},
    "config": {"exts": [".env", ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml"],"label": "Config",      "color": Y},
    "html":   {"exts": [".html", ".htm"],                                                      "label": "HTML",        "color": C},
    "img":    {"exts": [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp"],             "label": "Images",      "color": M},
    "map":    {"exts": [".map"],                                                               "label": "Source Maps", "color": M},
    "txt":    {"exts": [".txt", ".md", ".log"],                                                "label": "Text/Docs",   "color": W},
    "wasm":   {"exts": [".wasm"],                                                              "label": "WebAssembly", "color": R},
}


MODE3_EXTS = {
    ".js", ".mjs", ".cjs", ".map",
    ".json", ".jsonld",
    ".env", ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
    ".sql", ".db", ".sqlite",
    ".txt", ".log", ".xml",
}

SPIN = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]


def tw():
    try:    return os.get_terminal_size().columns
    except: return 110

def info(m): print(f"  {C}[*]{RST} {m}")
def ok(m):   print(f"  {G}[✔]{RST} {m}")
def warn(m): print(f"  {Y}[!]{RST} {m}")
def err(m):  print(f"  {R}[✘]{RST} {m}")

def box(title, color=R):
    w = tw(); inner = w - 4
    print(f"\n{color}┌{'─'*(w-2)}┐{RST}")
    print(f"{color}│ {BLD}{title[:inner]:<{inner}}{RST}{color}│{RST}")
    print(f"{color}└{'─'*(w-2)}┘{RST}")

def decode_url(url):
    url = url.strip()
    try:
        prev = None
        while prev != url:
            prev = url; url = urllib.parse.unquote(url)
    except: pass
    return url.strip()

def normalize_domain(domain):
    domain = domain.strip().rstrip("/")
    if not domain.startswith("http"):
        domain = "https://" + domain
    return domain

def safe_filename(url, max_len=180):
    parsed    = urllib.parse.urlparse(url)
    path_part = parsed.netloc + parsed.path
    safe      = re.sub(r'[^\w.\-]', '_', path_part)
    return safe[:max_len] if safe else "unknown"

def _strip_wayback(content):
    for pat in [
        r'/\* FILE ARCHIVED ON .*?END WAYBACK MACHINE \*/',
        r'^\s*/\*\s*FILE ARCHIVED.*?\*/\s*',
        r'<!--\s*FILE ARCHIVED ON.*?-->\s*',
        r'<script[^>]*>[\s\S]{0,500}?__wm\.rw\([\s\S]*?</script>\s*',
    ]:
        content = re.sub(pat, '', content, flags=re.DOTALL)
    return content

def _save_json(data, folder, filename):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    ok(f"JSON saved → {G}{path}{RST}")


def curl_get(url, timeout=25, retries=3, raw_url=None):
    referer_base = raw_url or url
    try:
        parts   = referer_base.split('/')
        referer = parts[0] + '//' + parts[2] + '/'
    except: referer = referer_base

    cmd = [
        "curl", "-s", "-L",
        "--max-time", str(timeout), "--compressed", "--retry", "0",
        "-w", "\n__HTTPCODE__%{http_code}",
        "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "-H", "Accept: */*",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Accept-Encoding: gzip, deflate",
        "-H", f"Referer: {referer}",
        "-H", "Connection: keep-alive",
        url,
    ]
    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout+10)
            try:    out = result.stdout.decode("utf-8",    errors="replace")
            except: out = result.stdout.decode("latin-1", errors="replace")
            if "__HTTPCODE__" in out:
                body, code_str = out.rsplit("__HTTPCODE__", 1)
                code = int(code_str.strip()) if code_str.strip().isdigit() else 0
                if code in (429, 502, 503) and attempt < retries:
                    time.sleep(2**attempt); continue
                return code, body
            return 0, ""
        except subprocess.TimeoutExpired:
            if attempt < retries: time.sleep(2)
        except: return 0, ""
    return 0, ""


def curl_download_file(url, dest_path, timeout=60, raw_url=None):
    """Download file directly to disk. Returns HTTP status code."""
    referer_base = raw_url or url
    try:
        parts   = referer_base.split('/')
        referer = parts[0] + '//' + parts[2] + '/'
    except: referer = referer_base

    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    
    code_file = dest_path + ".httpcode"
    cmd = [
        "curl", "-s", "-L",
        "--max-time", str(timeout), "--compressed", "--retry", "0",
        "-o", dest_path,
        "-w", "%{http_code}",
        "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "-H", "Accept: */*",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Accept-Encoding: gzip, deflate",
        "-H", f"Referer: {referer}",
        "-H", "Connection: keep-alive",
        url,
    ]
    try:
        result   = subprocess.run(cmd, capture_output=True, timeout=timeout+15)
        code_str = result.stdout.decode("ascii", errors="ignore").strip()
        
        match = re.search(r'(\d{3})$', code_str)
        code = int(match.group(1)) if match else 0
        return code
    except: return 0
    finally:
        
        if os.path.exists(code_file):
            try: os.remove(code_file)
            except: pass


def banner():
    ART = [
        r"  ██████╗ ███████╗ █████╗ ███████╗████████╗",
        r"  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝",
        r"  ██████╔╝█████╗  ███████║███████╗   ██║   ",
        r"  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   ",
        r"  ██████╔╝███████╗██║  ██║███████║   ██║   ",
        r"  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ",
    ]
    SUB      = "  ⬡  Wayback Hunter  ·  JS Secret Scanner  ·  v1.1  ·  by ALONE BEAST  ⬡"
    FALLBACK = "  ▓▓  BEAST v1.1  ·  by ALONE BEAST  ▓▓"
    w        = tw(); art_w = max(len(l) for l in ART)

    print(); sys.stdout.write(HIDE)
    if w >= art_w:
        pad = max(0, (w - art_w) // 2)
        for line in ART:
            sys.stdout.write(f"{R}{BLD}{' '*pad}{line}{RST}\n")
    else:
        pad = max(0, (w - len(FALLBACK)) // 2)
        sys.stdout.write(f"{R}{BLD}{' '*pad}{FALLBACK}{RST}\n")
    sys.stdout.write(SHOW)

    print()
    sub_clean = re.sub(r'\033\[[0-9;]*m', '', SUB)
    pad2      = max(0, (w - len(sub_clean)) // 2)
    print(f"{R}{BLD}{' '*pad2}{SUB}{RST}")
    print(f"{R}{BLD}{chr(9473)*w}{RST}\n")



def main_menu():
    w = tw()
    print(f"\n{R}{BLD}{'SELECT MODE':^{w}}{RST}\n")
    modes = [
        ("1", "Wayback File Hunter", "Download any file type from Wayback Machine"),
        ("2", "JS Secret Scanner",   "Scan live + Wayback JS for secrets & endpoints"),
        ("3", "Full Beast Mode",     "Wayback secret-relevant files + JS Scanner"),
        ("0", "Exit",                ""),
    ]
    for num, title, desc in modes:
        col      = R if num != "0" else DIM
        desc_str = f"  {DIM}{desc}{RST}" if desc else ""
        print(f"  {col}{BLD}[{num}]{RST}  {W}{BLD}{title}{RST}{desc_str}")
    print()
    print(f"  {R}❯{RST} ", end="", flush=True)
    return input().strip()


def filetype_menu():
    """Mode 1 only. Returns set of extensions or None (=all)."""
    box("SELECT FILE TYPES TO DOWNLOAD", R)
    print(f"  {DIM}Space-separated numbers  |  0 = ALL FILES{RST}\n")

    items = list(FILE_GROUPS.keys())
    for i, key in enumerate(items, 1):
        g   = FILE_GROUPS[key]
        ext = "  ".join(g["exts"])
        print(f"  {g['color']}{BLD}[{i:>2}]{RST}  {W}{g['label']:<18}{RST}  {DIM}{ext}{RST}")
    print(f"\n  {R}{BLD}[ 0]{RST}  {W}{BLD}ALL FILES{RST}  {DIM}(everything archived){RST}")
    print()
    print(f"  {R}❯{RST} ", end="", flush=True)
    raw = input().strip()

    if "0" in raw.split():
        return None 

    selected = set()
    for tok in raw.split():
        if tok.isdigit():
            idx = int(tok) - 1
            if 0 <= idx < len(items):
                selected.update(FILE_GROUPS[items[idx]]["exts"])
    return selected if selected else None


def get_domain_input(prompt="Target domain (e.g. example.com)"):
    print(f"\n  {R}{BLD}{prompt}{RST}: ", end="", flush=True)
    return input().strip()

def get_output_dir(default="beast_output"):
    print(f"  {R}{BLD}Output directory{RST} {DIM}(Enter = {default}){RST}: ", end="", flush=True)
    val = input().strip()
    return val if val else default

def ask_output_format():
    print(f"\n  {R}{BLD}Output format:{RST}")
    print(f"  {G}[1]{RST}  Save files to disk  {DIM}(default){RST}")
    print(f"  {Y}[2]{RST}  JSON report only    {DIM}(URLs + metadata, no download){RST}")
    print(f"  {M}[3]{RST}  Both")
    print(f"\n  {R}❯{RST} ", end="", flush=True)
    return input().strip()



def cdx_fetch_urls(domain, exts_filter=None, limit=5000):
    """
    Query Wayback CDX for archived URLs.
    exts_filter : set of extensions → one strict CDX query per ext + client-side check
                  None              → fetch everything (no filter)
    Returns list of dicts {orig, snap, ts, ext}
    """
    clean  = domain.split("://")[-1].rstrip("/")
    url_ts = {}
    spin_i = 0

    if exts_filter:
        queries = []
        for ext in sorted(exts_filter):
            queries.append((
                f"http://web.archive.org/cdx/search/cdx"
                f"?url={clean}/*{ext}&output=text&matchType=domain"
                f"&fl=timestamp,original&collapse=urlkey&limit={limit}"
                f"&filter=statuscode:200",
                ext
            ))
    else:
        queries = [(
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={clean}/*&output=text&matchType=domain"
            f"&fl=timestamp,original&collapse=urlkey&limit={limit}"
            f"&filter=statuscode:200",
            "all files"
        )]

    for api, label in queries:
        frame = SPIN[spin_i % len(SPIN)]; spin_i += 1
        sys.stdout.write(f"\r  {Y}{frame}{RST} CDX querying {BLD}{label}{RST}   ")
        sys.stdout.flush()

        status, body = curl_get(api, timeout=60, retries=2)

        if status != 200 or not body.strip():
            sys.stdout.write(f"\r  {R}✘{RST} CDX {BLD}{label}{RST}  HTTP {status} / empty{' '*20}\n")
            sys.stdout.flush(); continue

        before = len(url_ts)
        for line in body.splitlines():
            line = line.strip()
            if not line: continue
            parts = line.split(" ", 1)
            if len(parts) != 2: continue
            ts, raw = parts
            url = decode_url(raw.strip())
            if not url.startswith("http"): continue
            url = url.split("#")[0]

            
            if exts_filter:
                url_ext = os.path.splitext(urllib.parse.urlparse(url).path)[1].lower()
                if url_ext not in exts_filter:
                    continue

            ext = os.path.splitext(urllib.parse.urlparse(url).path)[1].lower()
            if url not in url_ts or ts > url_ts[url][0]:
                url_ts[url] = (ts, ext)

        gained = len(url_ts) - before
        sys.stdout.write(f"\r  {G}✔{RST} CDX {BLD}{label}{RST}  {G}+{gained}{RST} URLs{' '*20}\n")
        sys.stdout.flush()

    ok(f"Total unique URLs found: {G}{BLD}{len(url_ts)}{RST}")

    result = []
    for orig, (ts, ext) in url_ts.items():
        encoded = urllib.parse.quote(orig, safe=':/?=&%+@#')
        snap    = f"http://web.archive.org/web/{ts}if_/{encoded}"
        result.append({"orig": orig, "snap": snap, "ts": ts, "ext": ext})
    return result



def wayback_hunter(domain, exts_filter, output_dir, save_files=True, json_only=False):
    domain    = normalize_domain(domain)
    clean_dom = re.sub(r'[^\w]', '_', domain.split("://")[-1].rstrip("/"))
    ts_sfx    = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder    = os.path.join(output_dir, f"wayback_{clean_dom}_{ts_sfx}")

    info(f"Target     : {BLD}{domain}{RST}")
    info(f"Output dir : {BLD}{folder}/{RST}")

    box(f"WAYBACK CDX — {domain}", R)
    urls = cdx_fetch_urls(domain, exts_filter)

    if not urls:
        err("No URLs found in Wayback for this domain."); return []

    
    by_ext = defaultdict(list)
    for u in urls:
        by_ext[u["ext"] or "no-ext"].append(u)
    print(f"\n  {BLD}File type breakdown:{RST}")
    for ext, lst in sorted(by_ext.items(), key=lambda x: -len(x[1])):
        print(f"    {Y}{ext:<14}{RST}  {G}{len(lst)}{RST}")
    print()

    os.makedirs(folder, exist_ok=True)
    report     = {"domain": domain, "timestamp": ts_sfx, "files": []}
    downloaded = 0; failed = 0; total = len(urls)

    if json_only:
        for u in urls:
            report["files"].append({"url": u["orig"], "snap": u["snap"],
                                    "ts": u["ts"], "ext": u["ext"]})
        _save_json(report, folder, f"wayback_urls_{clean_dom}_{ts_sfx}.json")
        ok("JSON report saved (no files downloaded).")
        return report["files"]

    box(f"DOWNLOADING {total} FILES", R)

    for i, u in enumerate(urls, 1):
        orig  = u["orig"]; snap = u["snap"]; ext = u["ext"] or ""
        fname = safe_filename(orig)
        if ext and not fname.endswith(ext): fname += ext
        dest  = os.path.join(folder, fname)

        sys.stdout.write(f"\r  {DIM}[{i:>{len(str(total))}}/{total}]{RST} {DIM}↓{RST} {orig[:tw()-20]}")
        sys.stdout.flush()

        
        code = curl_download_file(snap, dest, timeout=40, raw_url=orig)
        src  = "WB"
        if code != 200 or not os.path.exists(dest) or os.path.getsize(dest) < 10:
            if os.path.exists(dest): os.remove(dest)
            code = curl_download_file(orig, dest, timeout=25)
            src  = "LV"

        if code == 200 and os.path.exists(dest) and os.path.getsize(dest) > 5:
            col = M if src == "WB" else G
            downloaded += 1
            size_kb = os.path.getsize(dest) / 1024
            sys.stdout.write(
                f"\r  {G}[✔]{RST}({col}{src}{RST})"
                f" {G}[{downloaded}↑ {failed}✘]{RST}"
                f" {DIM}{size_kb:.1f}KB{RST} {orig[:tw()-35]}\n"
            )
            sys.stdout.flush()
            report["files"].append({
                "url": orig, "snap": snap, "ts": u["ts"], "ext": ext,
                "local": dest, "source": src, "size_bytes": os.path.getsize(dest),
            })
        else:
            if os.path.exists(dest): os.remove(dest)
            failed += 1
            sys.stdout.write(
                f"\r  {R}[✘]{RST}(HTTP {code})"
                f" {G}[{downloaded}↑ {failed}✘]{RST}"
                f" {DIM}{orig[:tw()-35]}{RST}\n"
            )
            sys.stdout.flush()
            report["files"].append({"url": orig, "snap": snap, "ts": u["ts"],
                                    "ext": ext, "local": None, "source": None})

    print()
    ok(f"Downloaded : {G}{BLD}{downloaded}{RST}  /  {total} total")
    if failed:
        warn(f"Failed     : {Y}{failed}{RST}")
    else:
        ok(f"Failed     : {G}0{RST}")
    _save_json(report, folder, f"wayback_report_{clean_dom}_{ts_sfx}.json")
    return report["files"]



def extract_js_url(raw):
    url = decode_url(raw.strip()).split('#')[0]
    if not url.startswith('http'): return None
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path
    if path.endswith('.js'): return url
    if '.js' in path:
        idx = path.rfind('.js')
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path[:idx+3], '', '', ''))
    return None

def is_false_positive(label, value):
    v = value.strip().lower()
    if len(v) < 8: return True
    if v in FP_BLACKLIST: return True
    if label in ("Password in JS", "Secret Key in JS", "Auth Token in JS"):
        if re.match(r'^[a-z_\-]+$', v): return True
    if label in ("Bearer Token", "Basic Auth Header"):
        if v.split()[-1] in FP_BLACKLIST: return True
    return False

def fetch_wayback_js(domain):
    box(f"WAYBACK JS — {domain}", R)
    clean  = domain.split("://")[-1].rstrip("/")
    url_ts = {}; spin_i = 0
    queries = [
        (f"http://web.archive.org/cdx/search/cdx?url={clean}/*.js&output=text&matchType=prefix"
         f"&fl=timestamp,original&collapse=urlkey&limit=3000&filter=statuscode:200"
         f"&filter=mimetype:application/javascript", "pass 1 (mime)"),
        (f"http://web.archive.org/cdx/search/cdx?url={clean}/*.js&output=text&matchType=domain"
         f"&fl=timestamp,original&collapse=urlkey&limit=3000&filter=statuscode:200",
         "pass 2 (domain)"),
    ]
    for api, label in queries:
        frame = SPIN[spin_i % len(SPIN)]; spin_i += 1
        sys.stdout.write(f"\r  {Y}{frame}{RST} CDX {BLD}[{label}]{RST}   ")
        sys.stdout.flush()
        status, body = curl_get(api, timeout=45)
        if status != 200 or not body.strip():
            sys.stdout.write(f"\r  {R}✘{RST} CDX [{label}]  HTTP {status}{' '*20}\n")
            sys.stdout.flush(); continue
        before = len(url_ts)
        for line in body.splitlines():
            line = line.strip()
            if not line: continue
            parts = line.split(" ", 1)
            if len(parts) != 2: continue
            ts, raw = parts
            orig = extract_js_url(raw)
            if not orig: continue
            if orig not in url_ts or ts > url_ts[orig]: url_ts[orig] = ts
        gained = len(url_ts) - before
        sys.stdout.write(f"\r  {G}✔{RST} CDX [{label}]  {G}+{gained}{RST} URLs{' '*20}\n")
        sys.stdout.flush()

    if not url_ts:
        warn("Wayback returned no JS for this domain."); return []
    ok(f"Found {G}{BLD}{len(url_ts)}{RST} unique JS URLs from Wayback")
    result = []
    for orig, ts in url_ts.items():
        encoded = urllib.parse.quote(orig, safe=':/?=&%+@#')
        snap    = f"http://web.archive.org/web/{ts}if_/{encoded}"
        result.append((orig, snap))
    return result

def fetch_katana_js(domain):
    box(f"KATANA — {domain}", R)
    katana_path = os.path.expanduser("~/go/bin/katana")
    if not os.path.isfile(katana_path):
        warn("Katana not found at ~/go/bin/katana — skipping"); return []
    info("Running Katana (depth 3, JS crawl mode)...")
    try:
        result = subprocess.run(
            [katana_path, "-u", domain, "-jc", "-d", "3", "-silent", "-nc"],
            capture_output=True, text=True, timeout=180, errors="ignore"
        )
        seen, pairs = set(), []
        for line in result.stdout.splitlines():
            u = extract_js_url(line.strip())
            if u and u not in seen:
                seen.add(u); pairs.append((u, None))
        ok(f"Katana found {G}{BLD}{len(pairs)}{RST} JS URLs")
        if not pairs:
            warn("No JS from Katana — sample:")
            for l in result.stdout.splitlines()[:8]: print(f"    {DIM}{l}{RST}")
        return pairs
    except FileNotFoundError:         warn("Katana not executable — skipping"); return []
    except subprocess.TimeoutExpired: warn("Katana timed out"); return []

def validate_and_download_js(url_pairs, output_dir):
    box("DOWNLOADING JS + .map probe", R)
    os.makedirs(output_dir, exist_ok=True)
    live_js, live_maps = [], []
    seen, deduped = set(), []
    for pair in url_pairs:
        if pair[0] not in seen:
            seen.add(pair[0]); deduped.append(pair)

    total = len(deduped)
    for i, (orig_url, snap_url) in enumerate(deduped, 1):
        sys.stdout.write(f"\r  {DIM}[{i:>{len(str(total))}}/{total}]{RST} {orig_url}")
        sys.stdout.flush()

        status, body, used_snap = 0, "", False

        if snap_url:
            status, body = curl_get(snap_url, timeout=35, raw_url=orig_url)
            if status == 200 and len(body.strip()) > 50:
                used_snap = True; body = _strip_wayback(body)
            else: status, body = 0, ""

        if not used_snap:
            status, body = curl_get(orig_url, timeout=25)
            if status == 200 and len(body.strip()) > 50: body = _strip_wayback(body)
            else: status, body = 0, ""

        if not used_snap and not body and snap_url:
            sys.stdout.write(f"\r  {Y}[retry→WB]{RST} {orig_url}")
            sys.stdout.flush()
            status, body = curl_get(snap_url, timeout=45, raw_url=orig_url)
            if status == 200 and len(body.strip()) > 50:
                used_snap = True; body = _strip_wayback(body)
            else: status, body = 0, ""

        if body and len(body.strip()) > 50:
            fname = safe_filename(orig_url)
            if not fname.endswith(".js"): fname += ".js"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "w", encoding="utf-8", errors="ignore") as f: f.write(body)
            src = f"{M}(WB){RST}" if used_snap else f"{G}(LV){RST}"
            sys.stdout.write(f"\r  {G}[✔ JS]{RST}{src} {orig_url}\n")
            sys.stdout.flush()
            live_js.append((orig_url, fpath, body))

            # probe .map
            p       = urllib.parse.urlparse(orig_url)
            map_url = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, '', '', '')) + ".map"
            ms, mb  = curl_get(map_url, timeout=20)
            if (ms != 200 or len(mb.strip()) < 10) and snap_url:
                try:
                    enc_map  = urllib.parse.quote(map_url, safe=':/?=&%+@#')
                    m        = re.search(r'/web/(\d+)if_/', snap_url)
                    snap_map = (f"http://web.archive.org/web/{m.group(1)}if_/{enc_map}"
                                if m else snap_url.split("if_/")[0] + "if_/" + enc_map)
                    ms, mb   = curl_get(snap_map, timeout=25, raw_url=map_url)
                except: ms, mb = 0, ""
            if ms == 200 and len(mb.strip()) > 10:
                mb    = _strip_wayback(mb)
                mpath = os.path.join(output_dir, fname + ".map")
                with open(mpath, "w", encoding="utf-8", errors="ignore") as f: f.write(mb)
                map_src = f"{M}(WB){RST}" if snap_url else f"{G}(LV){RST}"
                sys.stdout.write(f"  {M}[★ MAP]{RST}{map_src} {map_url}\n")
                sys.stdout.flush()
                live_maps.append((map_url, mpath, mb))

        elif status in (301, 302, 403, 429):
            sys.stdout.write(f"\r  {Y}[{status}]{RST} {orig_url}\n"); sys.stdout.flush()
        else:
            sys.stdout.write(f"\r  {DIM}[---] {orig_url}{RST}\n"); sys.stdout.flush()

    print()
    ok(f"JS  files : {G}{BLD}{len(live_js)}{RST}")
    ok(f".map files: {M}{BLD}{len(live_maps)}{RST}")
    return live_js, live_maps

def scan_secrets(live_js, live_maps, output_dir, domain):
    box("SECRET SCANNER", R)
    all_findings = []

    for url, fpath, content in (live_js + live_maps):
        file_findings, seen = [], set()
        tag = f"{M}MAP{RST}" if url.endswith(".map") else f"{C} JS{RST}"
        for label, (pattern, group) in SECRET_PATTERNS.items():
            try:    matches = re.findall(pattern, content)
            except: continue
            for match in matches:
                if group is None:
                    val = match if isinstance(match, str) else match[0]
                else:
                    val = match[group-1] if isinstance(match, tuple) else match
                val = val.strip()
                if not val or len(val) < 8: continue
                if is_false_positive(label, val): continue
                key = (label, val[:60])
                if key in seen: continue
                seen.add(key)
                file_findings.append((label, val))
                all_findings.append({"url": url, "type": label, "value": val})

        if file_findings:
            w = tw()
            print(f"\n  {Y}┌─[{tag}{Y}] {BLD}{url}{RST}")
            for label, val in file_findings:
                print(f"  {Y}│{RST}  {M}{BLD}{label:<25}{RST} {W}{val[:w-35]}{RST}")
            print(f"  {Y}└{'─'*min(65, w-4)}{RST}")

    if all_findings and output_dir:
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        clean = re.sub(r'[^\w.]', '_', domain.split("://")[-1].rstrip("/"))
        _save_json({"domain": domain, "timestamp": ts, "findings": all_findings},
                   output_dir, f"secrets_{clean}_{ts}.json")
    elif not all_findings:
        warn("No secrets found.")
    return all_findings

def save_url_lists(live_js, live_maps, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    js_path  = os.path.join(output_dir, "js_urls.txt")
    map_path = os.path.join(output_dir, "map_urls.txt")
    with open(js_path,  "w") as f:
        for url, _, _ in live_js:   f.write(url + "\n")
    with open(map_path, "w") as f:
        for url, _, _ in live_maps: f.write(url + "\n")
    ok(f"JS  URLs → {G}{js_path}{RST}")
    ok(f"Map URLs → {M}{map_path}{RST}")

def js_scanner_run(domain, output_dir):
    domain    = normalize_domain(domain)
    clean_dom = re.sub(r'[^\w]', '_', domain.split("://")[-1].rstrip("/"))
    ts_sfx    = datetime.now().strftime("%H%M%S")
    folder    = os.path.join(output_dir, f"jsreaper_{clean_dom}_{ts_sfx}")

    info(f"Target     : {BLD}{domain}{RST}")
    info(f"Output dir : {BLD}{folder}/{RST}")

    wb_pairs     = fetch_wayback_js(domain)
    katana_pairs = fetch_katana_js(domain)

    merged = {}
    for o, s in katana_pairs: merged[o] = s
    for o, s in wb_pairs:     merged[o] = s
    all_pairs = list(merged.items())

    if not all_pairs:
        err(f"No JS URLs found for {domain}"); return

    box(f"TOTAL UNIQUE JS URLs: {len(all_pairs)}", R)
    live_js, live_maps = validate_and_download_js(all_pairs, folder)

    if not live_js and not live_maps:
        warn("No files downloaded."); return

    box("SAVING URL LISTS", R)
    save_url_lists(live_js, live_maps, folder)
    findings = scan_secrets(live_js, live_maps, folder, domain)

    box("JS SCAN COMPLETE — ALONE BEAST", R)
    w = tw()
    def _row(label, color, value):
        val_str = str(value)
        dots    = f"{DIM}{'·'*max(1, w-24-len(val_str)-8)}{RST}"
        print(f"  {color}{label:<22}{RST} {dots} {BLD}{color}{val_str}{RST}")
    print()
    _row("JS Files Downloaded",  G, len(live_js))
    _row(".map Files Found",     M, len(live_maps))
    _row("Secrets / Endpoints",  R, len(findings))
    _row("Output Folder",        B, folder + "/")
    print(f"\n  {R}{'━'*(w-4)}{RST}\n")



def full_beast_mode(domain, output_dir):
    box("FULL BEAST MODE — Wayback Secret Files + JS Scanner", R)
    exts_str = "  ".join(sorted(MODE3_EXTS))
    info(f"Auto file types: {DIM}{exts_str}{RST}")
    wayback_hunter(domain, MODE3_EXTS, output_dir, save_files=True, json_only=False)
    js_scanner_run(domain, output_dir)


def parse_cli():
    p = argparse.ArgumentParser(
        description="BEAST v1.1 — Wayback Hunter + JS Secret Scanner  (by ALONE BEAST)",
        add_help=True
    )
    p.add_argument("-d",  "--domain",   metavar="DOMAIN", help="Target domain")
    p.add_argument("-o",  "--output",   metavar="DIR",    default="beast_output", help="Output directory")
    p.add_argument("-m",  "--mode",     metavar="N",      help="1=Wayback  2=JS Scanner  3=Full Beast")
    p.add_argument("-t",  "--types",    metavar="TYPES",
                   help="Comma-separated types (Mode 1 only): js,json,pdf,zip,xml,csv,sql,config,html,img,map,txt,wasm,all")
    p.add_argument("--json-only",       action="store_true",
                   help="Mode 1: save JSON report only, skip file download")
    return p.parse_args()


def main():
    banner()
    args = parse_cli()

    
  if args.domain and args.mode:
        domain = args.domain
        mode   = args.mode.strip()
        out    = args.output

        exts_filter = None
        if args.types and args.types.lower() != "all":
            exts_filter = set()
            for t in args.types.split(","):
                t = t.strip().lower()
                if t in FILE_GROUPS:
                    exts_filter.update(FILE_GROUPS[t]["exts"])

        if   mode == "1": wayback_hunter(domain, exts_filter, out,
                                         save_files=not args.json_only,
                                         json_only=args.json_only)
        elif mode == "2": js_scanner_run(domain, out)
        elif mode == "3": full_beast_mode(domain, out)
        else:             err(f"Unknown mode: {mode}")
        return

    # ── Interactive menu ─────────────────────────────────────
    while True:
        choice = main_menu()

        if choice == "0":
            print(f"\n  {Y}[!]{RST} Bye!\n"); sys.exit(0)

        elif choice == "1":
            domain     = get_domain_input()
            exts       = filetype_menu()
            out_fmt    = ask_output_format()
            output_dir = get_output_dir()
            save_files = out_fmt in ("1", "3", "")
            json_only  = out_fmt == "2"
            wayback_hunter(domain, exts, output_dir,
                           save_files=save_files, json_only=json_only)

        elif choice == "2":
            domain     = get_domain_input()
            output_dir = get_output_dir()
            js_scanner_run(domain, output_dir)

        elif choice == "3":
            domain     = get_domain_input()
            output_dir = get_output_dir()
            full_beast_mode(domain, output_dir)

        else:
            warn("Invalid choice — try again."); continue

        print(f"\n{R}{'═'*tw()}{RST}")
        print(f"{R}{BLD}{'DONE — ALONE BEAST'.center(tw())}{RST}")
        print(f"{R}{'═'*tw()}{RST}\n")
        print(f"  {DIM}Press Enter to return to menu...{RST}")
        input()


if __name__ == "__main__":
    main()
