#!/usr/bin/env python3

import subprocess
import sys
import os
import re
import json
import time
import random
import signal
import urllib.parse
from datetime import datetime
from collections import defaultdict

# ── COLORS ─────────────────────────────────────────────────────────────────────
R   = "\033[91m"; G   = "\033[92m"; Y   = "\033[93m"
B   = "\033[94m"; M   = "\033[95m"; C   = "\033[96m"
W   = "\033[97m"; DIM = "\033[2m";  BLD = "\033[1m"
RST = "\033[0m"

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
]

KATANA_TIMEOUT = int(os.environ.get("KATANA_TIMEOUT", "300"))
CDX_LIMIT_JS   = int(os.environ.get("CDX_LIMIT_JS",  "10000"))
CDX_LIMIT_ALL  = int(os.environ.get("CDX_LIMIT_ALL", "5000"))

def _sigint(sig, frame):
    print(f"\n\n  {Y}[-]{RST} Interrupted by user.\n")
    sys.exit(0)

signal.signal(signal.SIGINT, _sigint)

# ── BLACKLISTS / PATTERNS ──────────────────────────────────────────────────────
FP_BLACKLIST = {
    "password","passwd","pwd","secret","token","bearer token","bearer",
    "auth_token","access_token","api_key","apikey","your_password",
    "your_secret","your_token","example","placeholder","changeme",
    "xxxxxxxx","testtoken","none","null","undefined","insert_key_here",
    "enter_key","12345678","00000000","password123","test","demo","sample",
}

SECRET_PATTERNS = {
    "Google API Key":    (r'AIza[0-9A-Za-z\-_]{35}',                                                        None),
    "Firebase URL":      (r'https://[a-z0-9-]+\.firebaseio\.com',                                           None),
    "AWS Access Key":    (r'AKIA[0-9A-Z]{16}',                                                              None),
    "AWS Secret Key":    (r'(?i)aws[_\-\s]{0,5}secret[_\-\s]{0,10}[\'"]([0-9a-zA-Z/+]{40})[\'"]',         1),
    "GitHub Token":      (r'(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})',                            1),
    "Slack Token":       (r'(xox[baprs]-[0-9A-Za-z\-]{10,80})',                                            1),
    "Stripe Live Key":   (r'(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})',                            1),
    "Twilio SID":        (r'(AC[a-f0-9]{32})',                                                              1),
    "Mailgun Key":       (r'(key-[0-9a-zA-Z]{32})',                                                         1),
    "SendGrid Key":      (r'(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})',                                 1),
    "JWT Token":         (r'(eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_.+/=]{10,})',         1),
    "Private Key":       (r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',                            None),
    "Bearer Token":      (r'(?i)bearer\s+([a-zA-Z0-9\-._~+/]{20,})',                                       1),
    "Basic Auth":        (r'(?i)basic\s+([a-zA-Z0-9+/=]{20,})',                                            1),
    "Password in JS":    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"]([^\'"]{8,})[\'"]',                  1),
    "Secret Key in JS":  (r'(?i)(?:secret_key|api_secret|client_secret)\s*[:=]\s*[\'"]([^\'"]{10,})[\'"]', 1),
    "Auth Token in JS":  (r'(?i)(?:auth_token|authtoken|access_token)\s*[:=]\s*[\'"]([^\'"]{10,})[\'"]',   1),
    "Database URL":      (r'((?:mysql|postgres|mongodb|redis)://[^\s\'"<>{},]{10,})',                       1),
    "S3 Bucket":         (r'([a-z0-9.\-]+\.s3\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.\-]+)',            1),
    "Cloudinary URL":    (r'(cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z]+)',                                 1),
    "Mapbox Token":      (r'(pk\.eyJ1[0-9A-Za-z._\-]+)',                                                   1),
    "NPM Token":         (r'(npm_[A-Za-z0-9]{36})',                                                         1),
    "Azure Key":         (r'(?i)(?:azure|DefaultEndpointsProtocol).{0,50}AccountKey=([A-Za-z0-9+/=]{60,})',1),
    "Azure Conn String": (r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+', None),
    "Heroku API Key":    (r'(?i)heroku[_\-\s]{0,10}(?:api[_\-]?key|token)[_\-\s]{0,5}[=:\'"\\s]{1,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 1),
    "Telegram Bot":      (r'([0-9]{8,10}:[A-Za-z0-9_\-]{35})',                                             1),
    "API Endpoint":      (r'(https?://[^\s\'"<>{}]{5,}/api/v[0-9]+/[^\s\'"<>{}]{3,})',                     1),
    "GraphQL Endpoint":  (r'(https?://[^\s\'"<>{}]{5,}/graphql[^\s\'"<>{}]*)',                             1),
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

# ── TERMINAL UTILS ─────────────────────────────────────────────────────────────

SPIN_FRAMES = ["|", "/", "-", "\\"]
_spin_idx   = 0
_prog_lines = 0

def tw():
    try:
        return max(50, min(os.get_terminal_size().columns, 120))
    except:
        return 80

def _clear_prev(n):
    if n > 0:
        sys.stdout.write(f"\033[{n}A\r")

def _erase_line():
    sys.stdout.write("\033[2K\r")

def _reset_progress():
    global _prog_lines
    _prog_lines = 0

def _print_progress_block(lines):
    global _prog_lines
    _clear_prev(_prog_lines)
    for line in lines:
        _erase_line()
        print(line)
    _prog_lines = len(lines)
    sys.stdout.flush()

# ── PRINT HELPERS ──────────────────────────────────────────────────────────────

def info(m): print(f"  {C}  *  {RST}{m}")
def ok(m):   print(f"  {G}  +  {RST}{m}")
def warn(m): print(f"  {Y}  !  {RST}{m}")
def err(m):  print(f"  {R}  x  {RST}{m}")

def _sep(color=R, char="-"):
    w = tw()
    print(f"{color}{char * w}{RST}")

def _section_header(title, color=R):
    w = tw()
    print()
    _sep(color)
    print(f"{color}{BLD}  {title}{RST}")
    _sep(color)
    print()

def _progress_bar(current, total, width=30):
    pct    = int(current / max(1, total) * 100)
    filled = int(width * pct / 100)
    bar    = f"{G}{'#' * filled}{DIM}{'.' * (width - filled)}{RST}"
    return bar, f"{pct:>3}%"

# ── PROGRESS DISPLAYS ──────────────────────────────────────────────────────────
# Every function prints exactly 10 lines so _prog_lines stays consistent.

def show_cdx_progress(target, ext_label, ext_idx, total_exts, found, offset, status):
    global _spin_idx
    _spin_idx = (_spin_idx + 1) % len(SPIN_FRAMES)
    spin     = SPIN_FRAMES[_spin_idx]
    bar, pct = _progress_bar(ext_idx, total_exts, 30)
    w        = tw()
    tgt      = target[:w - 20]
    lbl      = ext_label[:16]
    stat     = status[:max(10, w - 20)]

    lines = [
        f"",
        f"  {R}{BLD}  WAYBACK CDX  {RST}{DIM}  [{spin}]{RST}",
        f"",
        f"  {DIM}  Target    {RST}  {W}{BLD}{tgt}{RST}",
        f"  {DIM}  Type      {RST}  {Y}{BLD}{lbl}{RST}",
        f"  {DIM}  Progress  {RST}  [{bar}{RST}]  {Y}{BLD}{pct}{RST}  {DIM}({ext_idx}/{total_exts}){RST}",
        f"  {DIM}  Found     {RST}  {G}{BLD}{found}{RST}  {DIM}urls   offset={offset}{RST}",
        f"  {DIM}  Status    {RST}  {DIM}{stat}{RST}",
        f"",
        f"",
    ]
    _print_progress_block(lines)


def show_hunt_progress(target, current, total, ok_count, f403, f404, url):
    global _spin_idx
    _spin_idx = (_spin_idx + 1) % len(SPIN_FRAMES)
    spin     = SPIN_FRAMES[_spin_idx]
    bar, pct = _progress_bar(current, total, 30)
    w        = tw()
    tgt      = target[:w - 20]
    u        = url if len(url) <= w - 16 else url[:w - 19] + "..."

    lines = [
        f"",
        f"  {R}{BLD}  DOWNLOADING  {RST}{DIM}  [{spin}]{RST}",
        f"",
        f"  {DIM}  Target    {RST}  {W}{BLD}{tgt}{RST}",
        f"  {DIM}  Progress  {RST}  [{bar}{RST}]  {Y}{BLD}{pct}{RST}  {DIM}({current}/{total}){RST}",
        f"",
        f"  {G}  200 OK    {RST}  {BLD}{ok_count:<6}{RST}  {Y}  403  {RST}{BLD}{f403:<6}{RST}  {R}  404  {RST}{BLD}{f404}{RST}",
        f"",
        f"  {DIM}  URL       {RST}  {DIM}{u}{RST}",
        f"",
    ]
    _print_progress_block(lines)


def show_js_download_progress(target, current, total, ok_count, fail_count, url):
    global _spin_idx
    _spin_idx = (_spin_idx + 1) % len(SPIN_FRAMES)
    spin     = SPIN_FRAMES[_spin_idx]
    bar, pct = _progress_bar(current, total, 30)
    w        = tw()
    tgt      = target[:w - 20]
    u        = url if len(url) <= w - 16 else url[:w - 19] + "..."

    lines = [
        f"",
        f"  {C}{BLD}  JS SCANNER  {RST}{DIM}  [{spin}]{RST}",
        f"",
        f"  {DIM}  Target    {RST}  {W}{BLD}{tgt}{RST}",
        f"  {DIM}  Progress  {RST}  [{bar}{RST}]  {Y}{BLD}{pct}{RST}  {DIM}({current}/{total}){RST}",
        f"",
        f"  {G}  Saved     {RST}  {BLD}{ok_count:<6}{RST}  {R}  Failed  {RST}{BLD}{fail_count}{RST}",
        f"",
        f"  {DIM}  File      {RST}  {DIM}{u}{RST}",
        f"",
    ]
    _print_progress_block(lines)


def show_secret_progress(target, current, total, secrets_found, fname):
    global _spin_idx
    _spin_idx = (_spin_idx + 1) % len(SPIN_FRAMES)
    spin     = SPIN_FRAMES[_spin_idx]
    bar, pct = _progress_bar(current, total, 30)
    tgt      = target[:60]
    fn       = fname[:60]

    lines = [
        f"",
        f"  {M}{BLD}  SECRET SCAN  {RST}{DIM}  [{spin}]{RST}",
        f"",
        f"  {DIM}  Target    {RST}  {W}{BLD}{tgt}{RST}",
        f"  {DIM}  Progress  {RST}  [{bar}{RST}]  {Y}{BLD}{pct}{RST}  {DIM}({current}/{total}){RST}",
        f"",
        f"  {R}  Secrets   {RST}  {BLD}{secrets_found}{RST}  {DIM}found so far{RST}",
        f"",
        f"  {DIM}  File      {RST}  {DIM}{fn}{RST}",
        f"",
    ]
    _print_progress_block(lines)

# ── PAGE SIZE ──────────────────────────────────────────────────────────────────

PAGE_SIZE = 500

# ── URL / STRING UTILS ─────────────────────────────────────────────────────────

def decode_url(url):
    url = url.strip()
    try:
        prev = None
        while prev != url:
            prev = url; url = urllib.parse.unquote(url)
    except:
        pass
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

def _strip_domain_tld(domain):
    clean = domain.split("://")[-1].rstrip("/").lower()
    clean = re.sub(r'^www\.', '', clean)
    clean = re.sub(r'\.(com|net|org|io|co|uk|in|de|fr|jp|au|us|gov|edu|info|biz|me|app|dev|ai)(\.[a-z]{2})?$', '', clean)
    clean = re.sub(r'[^\w]', '_', clean)
    return clean.strip('_') or "target"

def _url_to_filename(url, ext_override=None):
    parsed   = urllib.parse.urlparse(url)
    path     = parsed.path.strip('/')
    path     = urllib.parse.unquote(path)
    basename = os.path.basename(path) if path else "index"
    basename = re.sub(r'[^\w.\-]', '_', basename)
    if not basename:
        basename = "unknown"
    if ext_override and not basename.endswith(ext_override):
        basename += ext_override
    return basename[:180]

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
    ok(f"Saved  {G}{path}{RST}")

# ── NETWORK ────────────────────────────────────────────────────────────────────

def curl_get(url, timeout=25, retries=3, raw_url=None):
    referer_base = raw_url or url
    try:
        parts   = referer_base.split('/')
        referer = parts[0] + '//' + parts[2] + '/'
    except:
        referer = referer_base

    cmd = [
        "curl", "-s", "-L",
        "--max-time", str(timeout),
        "--max-redirs", "5",
        "--compressed", "--retry", "0",
        "-w", "\n__HTTPCODE__%{http_code}",
        "-A", random.choice(USER_AGENTS),
        "-H", "Accept: */*",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Accept-Encoding: gzip, deflate",
        "-H", f"Referer: {referer}",
        "-H", "Connection: keep-alive",
        url,
    ]
    for attempt in range(1, retries + 1):
        try:
            result     = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
            stderr_out = result.stderr.decode("utf-8", errors="replace").lower()
            if "permission denied" in stderr_out:
                return 0, ""
            try:    out = result.stdout.decode("utf-8",    errors="replace")
            except: out = result.stdout.decode("latin-1", errors="replace")
            if "__HTTPCODE__" in out:
                body, code_str = out.rsplit("__HTTPCODE__", 1)
                code = int(code_str.strip()) if code_str.strip().isdigit() else 0
                if code in (429, 502, 503) and attempt < retries:
                    time.sleep(2 ** attempt); continue
                return code, body
            return 0, ""
        except subprocess.TimeoutExpired:
            if attempt < retries: time.sleep(2)
        except:
            return 0, ""
    return 0, ""

def curl_download_file(url, dest_path, timeout=60, raw_url=None):
    referer_base = raw_url or url
    try:
        parts   = referer_base.split('/')
        referer = parts[0] + '//' + parts[2] + '/'
    except:
        referer = referer_base

    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    cmd = [
        "curl", "-s", "-L",
        "--max-time", str(timeout),
        "--max-redirs", "5",
        "--compressed", "--retry", "0",
        "-o", dest_path,
        "-w", "%{http_code}",
        "-A", random.choice(USER_AGENTS),
        "-H", "Accept: */*",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Accept-Encoding: gzip, deflate",
        "-H", f"Referer: {referer}",
        "-H", "Connection: keep-alive",
        url,
    ]
    try:
        result   = subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
        code_str = result.stdout.decode("ascii", errors="ignore").strip()
        match    = re.search(r'(\d{3})$', code_str)
        return int(match.group(1)) if match else 0
    except:
        return 0

# ── BANNER ─────────────────────────────────────────────────────────────────────

def banner():
    ART = [
        r"  ██████╗ ███████╗ █████╗ ███████╗████████╗",
        r"  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝",
        r"  ██████╔╝█████╗  ███████║███████╗   ██║   ",
        r"  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   ",
        r"  ██████╔╝███████╗██║  ██║███████║   ██║   ",
        r"  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝  ",
    ]
    FALLBACK = "  BEAST v1.2.1"
    w        = tw()
    art_w    = max(len(l) for l in ART)

    print()
    if w >= art_w:
        for line in ART:
            print(f"{R}{BLD}{line}{RST}")
    else:
        print(f"{R}{BLD}{FALLBACK}{RST}")

    print()
    print(f"  {DIM}Wayback Hunter   JS Secret Scanner   v1.2   by ALONE BEAST{RST}")
    print(f"{R}{'-' * min(w, 64)}{RST}")
    print()

# ── MENUS ──────────────────────────────────────────────────────────────────────

def show_help():
    _section_header("BEASTCRYPT  v1.2  --  USAGE", R)
    print(f"  {W}{BLD}COMMANDS{RST}\n")
    cmds = [
        ("beastcrypt",                               "Interactive menu"),
        ("beastcrypt -d <domain> -m <mode>",         "Direct run"),
        ("beastcrypt -d <domain> -m 1 -t <types>",  "Wayback with file type filter"),
        ("beastcrypt -d <domain> -m 1 --json-only", "URL report only, no download"),
    ]
    for cmd, desc in cmds:
        print(f"    {G}{cmd:<46}{RST}  {DIM}{desc}{RST}")

    print(f"\n  {W}{BLD}MODES{RST}\n")
    modes = [
        ("1", "Wayback File Hunter",  "Download archived files by type"),
        ("2", "JS Secret Scanner",    "Scan live + Wayback JS for secrets"),
        ("3", "Full Beast Mode",      "Both modes combined"),
    ]
    for n, title, desc in modes:
        print(f"    {R}{BLD}  {n}  {RST}  {W}{BLD}{title:<22}{RST}  {DIM}{desc}{RST}")

    print(f"\n  {W}{BLD}FILE TYPES{RST}  {DIM}(for -t flag, Mode 1 only){RST}\n")
    types = ["js", "json", "pdf", "zip", "xml", "csv", "sql", "config", "html", "img", "map", "txt", "wasm", "all"]
    row = "    "
    for i, t in enumerate(types):
        row += f"{Y}{t}{RST}  "
        if (i + 1) % 7 == 0:
            print(row); row = "    "
    if row.strip(): print(row)
    print()
    _sep(R)
    print()

def main_menu():
    print(f"\n{R}{BLD}  SELECT MODE{RST}\n")
    modes = [
        ("1", R,   "Wayback File Hunter",  "Retrieve archived files from Wayback Machine"),
        ("2", C,   "JS Secret Scanner",    "Scan JS files for secrets and endpoints"),
        ("3", M,   "Full Beast Mode",      "Wayback hunter + JS scanner combined"),
        ("0", DIM, "Exit",                 ""),
    ]
    for num, col, title, desc in modes:
        desc_str = f"  {DIM}{desc}{RST}" if desc else ""
        print(f"  {col}{BLD}  {num}  {RST}  {W}{BLD}{title}{RST}{desc_str}")
    print()
    print(f"  {R}>{RST} ", end="", flush=True)
    return input().strip()

def filetype_menu():
    _section_header("SELECT FILE TYPES TO DOWNLOAD", R)
    print(f"  {DIM}Enter space-separated numbers.  0 = all files.{RST}\n")
    items = list(FILE_GROUPS.keys())
    for i, key in enumerate(items, 1):
        g   = FILE_GROUPS[key]
        ext = "  ".join(g["exts"])
        print(f"  {g['color']}{BLD}  {i:>2}  {RST}  {W}{g['label']:<18}{RST}  {DIM}{ext}{RST}")
    print(f"\n  {R}{BLD}   0  {RST}  {W}{BLD}All Files{RST}  {DIM}(everything archived){RST}\n")
    print(f"  {R}>{RST} ", end="", flush=True)
    raw = input().strip()
    if "0" in raw.split(): return None
    selected = set()
    for tok in raw.split():
        if tok.isdigit():
            idx = int(tok) - 1
            if 0 <= idx < len(items):
                selected.update(FILE_GROUPS[items[idx]]["exts"])
    return selected if selected else None

def get_domain_input(prompt="Target domain  (e.g. example.com)"):
    print(f"\n  {R}{BLD}{prompt}{RST}")
    print(f"  {R}>{RST} ", end="", flush=True)
    return input().strip()

def get_output_dir(default="beast_output"):
    print(f"\n  {DIM}Output directory  (press Enter for: {default}){RST}")
    print(f"  {R}>{RST} ", end="", flush=True)
    val = input().strip()
    return val if val else default

def ask_output_format():
    print(f"\n  {R}{BLD}Output format{RST}\n")
    print(f"  {G}  1  {RST}  Save files to disk  {DIM}(default){RST}")
    print(f"  {Y}  2  {RST}  JSON report only    {DIM}(no download){RST}")
    print(f"  {M}  3  {RST}  Both\n")
    print(f"  {R}>{RST} ", end="", flush=True)
    return input().strip()

# ── CDX FETCHER ────────────────────────────────────────────────────────────────

def _cdx_fetch_one_query(api_base, label, url_ts, timeout=60, max_retries=4, on_update=None):
    offset = 0; gained = 0
    while True:
        paged_url = f"{api_base}&limit={PAGE_SIZE}&offset={offset}"
        retry = 0; status = 0; body = ""
        while retry <= max_retries:
            if on_update: on_update(offset, len(url_ts), f"offset={offset}  retry={retry}")
            status, body = curl_get(paged_url, timeout=timeout)
            if status == 200 and body.strip(): break
            elif status == 429:
                wait = 8 * (2 ** retry)
                if on_update: on_update(offset, len(url_ts), f"rate limited  waiting {wait}s")
                time.sleep(wait); retry += 1
            elif status == 0:
                wait = 5 * (2 ** retry)
                if on_update: on_update(offset, len(url_ts), f"timeout  retry in {wait}s")
                time.sleep(wait); retry += 1
            else:
                if on_update: on_update(offset, len(url_ts), f"HTTP {status}  skipping")
                return gained

        if status != 200 or not body.strip():
            if on_update: on_update(offset, len(url_ts), f"failed after {max_retries} retries")
            return gained

        raw_lines = [l.strip() for l in body.splitlines() if l.strip()]
        raw_count = len(raw_lines); page_got = 0
        for line in raw_lines:
            parts = line.split(" ", 1)
            if len(parts) != 2: continue
            ts, raw = parts
            url = decode_url(raw.strip()).split("#")[0]
            if not url.startswith("http"): continue
            ext = os.path.splitext(urllib.parse.urlparse(url).path)[1].lower()
            if url not in url_ts or ts > url_ts[url][0]:
                url_ts[url] = (ts, ext); page_got += 1; gained += 1

        if on_update: on_update(offset, len(url_ts), f"page done  +{page_got} new")
        if raw_count < PAGE_SIZE or page_got == 0: break
        offset += PAGE_SIZE; time.sleep(1.2)
    return gained

def cdx_fetch_urls(domain, exts_filter=None, limit=None):
    clean  = domain.split("://")[-1].rstrip("/")
    url_ts = {}

    if exts_filter:
        queries = [(
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={clean}/*{ext}&output=text&matchType=domain"
            f"&fl=timestamp,original&collapse=urlkey&filter=statuscode:200",
            ext
        ) for ext in sorted(exts_filter)]
    else:
        queries = [(
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={clean}/*&output=text&matchType=domain"
            f"&fl=timestamp,original&collapse=urlkey&filter=statuscode:200",
            "all"
        )]

    total_q = len(queries)
    _reset_progress()

    for qi, (api_base, ext_label) in enumerate(queries, 1):
        show_cdx_progress(clean, ext_label, qi, total_q, len(url_ts), 0, f"starting  {ext_label}")

        def make_cb(lbl, idx):
            def cb(offset, found, status_str):
                show_cdx_progress(clean, lbl, idx, total_q, found, offset, status_str)
            return cb

        _cdx_fetch_one_query(api_base, ext_label, url_ts,
                             timeout=60, max_retries=4,
                             on_update=make_cb(ext_label, qi))
        show_cdx_progress(clean, ext_label, qi, total_q, len(url_ts), 0, f"complete  total={len(url_ts)}")
        time.sleep(1.5)

    _reset_progress()
    print()
    ok(f"Total unique URLs found  {G}{BLD}{len(url_ts)}{RST}")
    print()

    result = []
    for orig, (ts, ext) in url_ts.items():
        encoded = urllib.parse.quote(orig, safe=':/?=&%+@#')
        snap    = f"http://web.archive.org/web/{ts}if_/{encoded}"
        result.append({"orig": orig, "snap": snap, "ts": ts, "ext": ext})
    return result

# ── WAYBACK HUNTER ─────────────────────────────────────────────────────────────

def wayback_hunter(domain, exts_filter, output_dir, save_files=True, json_only=False):
    domain    = normalize_domain(domain)
    clean_dom = _strip_domain_tld(domain)
    folder    = os.path.join(output_dir, f"wayback_{clean_dom}")

    print()
    info(f"Target      {W}{BLD}{domain}{RST}")
    info(f"Output      {W}{BLD}{folder}/{RST}")

    _section_header(f"WAYBACK CDX  --  {domain}", R)
    urls = cdx_fetch_urls(domain, exts_filter)

    if not urls:
        err("No archived URLs found for this domain."); return []

    by_ext = defaultdict(list)
    for u in urls: by_ext[u["ext"] or "no-ext"].append(u)

    print(f"  {W}{BLD}File type breakdown{RST}\n")
    for ext, lst in sorted(by_ext.items(), key=lambda x: -len(x[1])):
        bar_len = min(20, max(1, len(lst) * 20 // max(1, len(urls))))
        bar     = f"{G}{'|' * bar_len}{DIM}{'.' * (20 - bar_len)}{RST}"
        print(f"  {Y}  {ext:<14}{RST}  {bar}  {DIM}{len(lst)}{RST}")
    print()

    os.makedirs(folder, exist_ok=True)
    ts_now     = datetime.now().strftime("%Y%m%d_%H%M%S")
    report     = {"domain": domain, "timestamp": ts_now, "files": []}
    downloaded = 0; failed = 0; f403 = 0; f404 = 0; total = len(urls)

    if json_only:
        for u in urls:
            report["files"].append({"url": u["orig"], "snap": u["snap"],
                                    "ts": u["ts"], "ext": u["ext"]})
        _save_json(report, folder, "wayback_urls.json")
        ok("JSON report saved.")
        return report["files"]

    _sep(R)
    print(f"\n  {W}{BLD}Download {total} archived files?{RST}")
    print(f"  {DIM}yes  =  download all     no  =  save URL list only{RST}\n")
    print(f"  {R}>{RST} ", end="", flush=True)
    dl_ans = input().strip().lower()
    print()

    if dl_ans not in ("yes", "y"):
        info("Saving URL list only.")
        for u in urls:
            report["files"].append({"url": u["orig"], "snap": u["snap"],
                                    "ts": u["ts"], "ext": u["ext"]})
        urls_path = os.path.join(folder, "wayback_urls.txt")
        with open(urls_path, "w", encoding="utf-8") as f:
            for u in urls: f.write(u["orig"] + "\n")
        ok(f"Saved  {G}{urls_path}{RST}")
        return report["files"]

    target_lbl = domain.split("://")[-1].rstrip("/")
    _reset_progress()

    for i, u in enumerate(urls, 1):
        orig  = u["orig"]; snap = u["snap"]; ext = u["ext"] or ""
        fname = safe_filename(orig)
        if ext and not fname.endswith(ext): fname += ext
        dest  = os.path.join(folder, fname)

        show_hunt_progress(target_lbl, i, total, downloaded, f403, f404, orig)

        code = curl_download_file(snap, dest, timeout=40, raw_url=orig)
        src  = "WB"
        if code != 200 or not os.path.exists(dest) or os.path.getsize(dest) < 10:
            if os.path.exists(dest): os.remove(dest)
            code = curl_download_file(orig, dest, timeout=25); src = "LV"

        if code == 200 and os.path.exists(dest) and os.path.getsize(dest) > 5:
            downloaded += 1
            report["files"].append({
                "url": orig, "snap": snap, "ts": u["ts"], "ext": ext,
                "local": dest, "source": src, "size_bytes": os.path.getsize(dest),
            })
        else:
            if os.path.exists(dest): os.remove(dest)
            if code == 403:   f403 += 1
            elif code == 404: f404 += 1
            else:             failed += 1
            report["files"].append({"url": orig, "snap": snap, "ts": u["ts"],
                                    "ext": ext, "local": None, "source": None})

    _reset_progress()
    print()
    _sep(R)
    print()
    ok(f"Downloaded    {G}{BLD}{downloaded}{RST}  /  {total}")
    total_fail = failed + f403 + f404
    if total_fail:
        warn(f"Failed        {Y}{total_fail}{RST}  (403: {f403}   404: {f404}   other: {failed})")
    else:
        ok(f"Failed        {G}0{RST}")
    print()
    _save_json(report, folder, "wayback_report.json")
    return report["files"]

# ── JS SCANNER ─────────────────────────────────────────────────────────────────

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
    clean  = domain.split("://")[-1].rstrip("/")
    url_ts = {}

    queries = [
        (f"http://web.archive.org/cdx/search/cdx?url={clean}/*.js&output=text&matchType=prefix"
         f"&fl=timestamp,original&collapse=urlkey"
         f"&filter=statuscode:200&filter=mimetype:application/javascript",
         "mime-filter"),
        (f"http://web.archive.org/cdx/search/cdx?url={clean}/*.js&output=text&matchType=domain"
         f"&fl=timestamp,original&collapse=urlkey&filter=statuscode:200",
         "domain-wide"),
    ]

    total_q = len(queries)
    _reset_progress()

    for qi, (api_base, ext_label) in enumerate(queries, 1):
        show_cdx_progress(clean, ext_label, qi, total_q, len(url_ts), 0, f"starting  {ext_label}")

        def make_cb(lbl, idx):
            def cb(offset, found, status_str):
                show_cdx_progress(clean, lbl, idx, total_q, found, offset, status_str)
            return cb

        _cdx_fetch_one_query(api_base, ext_label, url_ts,
                             timeout=60, max_retries=4,
                             on_update=make_cb(ext_label, qi))
        show_cdx_progress(clean, ext_label, qi, total_q, len(url_ts), 0, f"complete  total={len(url_ts)}")
        time.sleep(1.5)

    _reset_progress()
    print()

    if not url_ts:
        warn("No JS files found in Wayback for this domain."); return []

    result = []
    for orig, (ts, ext) in url_ts.items():
        encoded = urllib.parse.quote(orig, safe=':/?=&%+@#')
        snap    = f"http://web.archive.org/web/{ts}if_/{encoded}"
        result.append((orig, snap))
    return result

def fetch_katana_js(domain):
    _section_header(f"KATANA  --  {domain}", R)
    katana_path = os.path.expanduser("~/go/bin/katana")
    if not os.path.isfile(katana_path):
        warn("Katana not found at ~/go/bin/katana  --  skipping"); return []
    info(f"Running Katana  depth=3  timeout={KATANA_TIMEOUT}s")
    print()
    try:
        result = subprocess.run(
            [katana_path, "-u", domain, "-jc", "-d", "3", "-silent", "-nc"],
            capture_output=True, text=True, timeout=KATANA_TIMEOUT, errors="ignore"
        )
        seen, pairs = set(), []
        for line in result.stdout.splitlines():
            u = extract_js_url(line.strip())
            if u and u not in seen: seen.add(u); pairs.append((u, None))
        ok(f"Katana found  {G}{BLD}{len(pairs)}{RST}  JS URLs")
        print()
        return pairs
    except FileNotFoundError:
        warn("Katana not executable  --  skipping"); return []
    except subprocess.TimeoutExpired:
        warn(f"Katana timed out after {KATANA_TIMEOUT}s"); return []

def _download_js_core(url_pairs, js_dir, map_dir, label):
    total = len(url_pairs); ok_c = 0; fail_c = 0
    js_records = []; map_records = []
    _reset_progress()

    for i, (orig_url, snap_url) in enumerate(url_pairs, 1):
        show_js_download_progress(os.path.basename(js_dir), i, total, ok_c, fail_c, orig_url)
        js_fname = _url_to_filename(orig_url, ".js")
        js_path  = os.path.join(js_dir, js_fname)
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
            status, body = curl_get(snap_url, timeout=45, raw_url=orig_url)
            if status == 200 and len(body.strip()) > 50:
                used_snap = True; body = _strip_wayback(body)
            else: status, body = 0, ""

        if body and len(body.strip()) > 50:
            with open(js_path, "w", encoding="utf-8", errors="ignore") as f: f.write(body)
            js_src = "WB" if used_snap else "LV"
            ok_c  += 1
            js_records.append({"orig_url": orig_url, "snap_url": snap_url,
                                "local_path": js_path, "source": js_src})

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
                mb        = _strip_wayback(mb)
                map_fname = js_fname + ".map"
                map_path  = os.path.join(map_dir, map_fname)
                with open(map_path, "w", encoding="utf-8", errors="ignore") as f: f.write(mb)
                map_records.append({"orig_url": map_url, "snap_url": snap_url,
                                    "local_path": map_path, "source": js_src})
        else:
            fail_c += 1
            js_records.append({"orig_url": orig_url, "snap_url": snap_url,
                                "local_path": None, "source": "FAIL"})

    _reset_progress()
    print()
    ok(f"JS files saved      {G}{BLD}{ok_c}{RST}")
    ok(f"Map files saved     {M}{BLD}{len(map_records)}{RST}")
    print()
    return js_records, map_records

def download_js_and_maps_structured(domain, url_pairs, output_dir):
    dom_label = _strip_domain_tld(domain)
    js_dir    = os.path.join(output_dir, "downloads", dom_label, "js")
    map_dir   = os.path.join(output_dir, "downloads", dom_label, "maps")
    os.makedirs(js_dir, exist_ok=True); os.makedirs(map_dir, exist_ok=True)
    return _download_js_core(url_pairs, js_dir, map_dir, "structured")

def validate_and_download_js(url_pairs, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    seen, deduped = set(), []
    for pair in url_pairs:
        if pair[0] not in seen: seen.add(pair[0]); deduped.append(pair)

    js_records, map_records = _download_js_core(deduped, output_dir, output_dir, "download")

    def _read(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f: return f.read()
        except: return ""

    live_js   = [(r["orig_url"], r["local_path"], _read(r["local_path"]))
                  for r in js_records if r["local_path"] and os.path.exists(r["local_path"])]
    live_maps = [(r["orig_url"], r["local_path"], _read(r["local_path"]))
                  for r in map_records if r["local_path"] and os.path.exists(r["local_path"])]
    return live_js, live_maps

def scan_secrets(live_js, live_maps, output_dir, domain):
    all_items     = live_js + live_maps
    total         = len(all_items)
    all_findings  = []
    global_seen   = set()
    secrets_found = 0
    tgt_lbl       = domain.split("://")[-1].rstrip("/")
    _reset_progress()

    for idx, (url, fpath, content) in enumerate(all_items, 1):
        fname = url.split("/")[-1][:60]
        show_secret_progress(tgt_lbl, idx, total, secrets_found, fname)

        file_seen = set()
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
                if key in file_seen: continue
                file_seen.add(key)
                if key in global_seen: continue
                global_seen.add(key)
                all_findings.append({"url": url, "type": label, "value": val})
                secrets_found += 1

    _reset_progress()
    print()

    if all_findings:
        w = tw()
        _section_header(f"SECRETS FOUND  --  {secrets_found} total", R)
        for url, fpath, _ in all_items:
            found = [f for f in all_findings if f["url"] == url]
            if not found: continue
            tag = "MAP" if url.endswith(".map") else " JS"
            print(f"  {Y}  [{tag}]  {RST}{W}{BLD}{url}{RST}")
            for f in found:
                val_display = f["value"][:w - 40]
                print(f"  {DIM}         {RST}  {M}{BLD}{f['type']:<26}{RST}  {W}{val_display}{RST}")
            print()

    if all_findings and output_dir:
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        clean = re.sub(r'[^\w.]', '_', domain.split("://")[-1].rstrip("/"))
        _save_json({"domain": domain, "timestamp": ts, "findings": all_findings},
                   output_dir, f"secrets_{clean}.json")
    elif not all_findings:
        warn("No secrets found.")
        print()

    return all_findings

def save_url_lists(live_js, live_maps, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    js_path  = os.path.join(output_dir, "js_urls.txt")
    map_path = os.path.join(output_dir, "map_urls.txt")
    with open(js_path,  "w") as f:
        for url, _, _ in live_js:   f.write(url + "\n")
    with open(map_path, "w") as f:
        for url, _, _ in live_maps: f.write(url + "\n")
    ok(f"JS URLs    {G}{js_path}{RST}")
    ok(f"Map URLs   {M}{map_path}{RST}")
    print()

def js_scanner_run(domain, output_dir):
    domain    = normalize_domain(domain)
    clean_dom = _strip_domain_tld(domain)
    folder    = os.path.join(output_dir, f"jsreaper_{clean_dom}")

    print()
    info(f"Target     {W}{BLD}{domain}{RST}")
    info(f"Output     {W}{BLD}{folder}/{RST}")
    print()

    _section_header(f"WAYBACK JS FETCH  --  {domain}", R)
    wb_pairs = fetch_wayback_js(domain)

    _section_header(f"KATANA CRAWL  --  {domain}", R)
    katana_pairs = fetch_katana_js(domain)

    merged = {}
    for o, s in katana_pairs: merged[o] = s
    for o, s in wb_pairs:     merged[o] = s
    all_pairs = list(merged.items())

    if not all_pairs:
        err(f"No JS URLs found for {domain}"); return

    _section_header(f"JS DOWNLOAD  --  {len(all_pairs)} unique files", R)
    live_js, live_maps = validate_and_download_js(all_pairs, folder)
    download_js_and_maps_structured(domain, all_pairs, output_dir)

    if not live_js and not live_maps:
        warn("No files downloaded."); return

    save_url_lists(live_js, live_maps, folder)

    _section_header("SECRET SCAN", R)
    findings = scan_secrets(live_js, live_maps, folder, domain)

    _section_header("SCAN COMPLETE  --  ALONE BEAST", R)
    w    = tw()
    rows = [
        ("JS Files Downloaded",   G, str(len(live_js))),
        ("Map Files Found",       M, str(len(live_maps))),
        ("Secrets / Endpoints",   R, str(len(findings))),
        ("Output Folder",         B, folder + "/"),
    ]
    for label, color, value in rows:
        pad = "." * max(2, w - 30 - len(value))
        print(f"  {color}{BLD}{label:<24}{RST}  {DIM}{pad}{RST}  {BLD}{color}{value}{RST}")
    print()
    _sep(R)
    print()

def full_beast_mode(domain, output_dir):
    _section_header("FULL BEAST MODE  --  Wayback + JS Scanner", R)
    exts_str = "  ".join(sorted(MODE3_EXTS))
    info(f"File types  {DIM}{exts_str}{RST}")
    print()
    wayback_hunter(domain, MODE3_EXTS, output_dir, save_files=True, json_only=False)
    js_scanner_run(domain, output_dir)

# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_cli():
    import argparse
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-d",  "--domain",  metavar="DOMAIN")
    p.add_argument("-o",  "--output",  metavar="DIR",  default="beast_output")
    p.add_argument("-m",  "--mode",    metavar="N")
    p.add_argument("-t",  "--types",   metavar="TYPES")
    p.add_argument("--json-only",      action="store_true")
    p.add_argument("-h",  "--help",    action="store_true")
    return p.parse_args()

def _usage_error():
    print()
    _sep(R)
    print(f"  {R}{BLD}  Usage error  --  run:  beastcrypt{RST}")
    _sep(R)
    print()
    sys.exit(0)

def main():
    allowed_flags = {"-d","--domain","-o","--output","-m","--mode","-t","--types","--json-only"}
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            if a.startswith("-") and a not in allowed_flags:
                os.system("clear"); banner(); _usage_error()

    banner()
    args = parse_cli()

    if len(sys.argv) > 1 and not (args.domain and args.mode):
        _usage_error()

    if args.domain and args.mode:
        domain = args.domain; mode = args.mode.strip(); out = args.output
        exts_filter = None
        if args.types and args.types.lower() != "all":
            exts_filter = set()
            for t in args.types.split(","):
                t = t.strip().lower()
                if t in FILE_GROUPS: exts_filter.update(FILE_GROUPS[t]["exts"])

        if   mode == "1": wayback_hunter(domain, exts_filter, out,
                                         save_files=not args.json_only,
                                         json_only=args.json_only)
        elif mode == "2": js_scanner_run(domain, out)
        elif mode == "3": full_beast_mode(domain, out)
        else:             err(f"Unknown mode '{mode}'  --  valid: 1 / 2 / 3")
        return

    while True:
        choice = main_menu()

        if choice == "0":
            print(f"\n  {DIM}Exiting.{RST}\n"); sys.exit(0)

        elif choice == "1":
            domain     = get_domain_input()
            exts       = filetype_menu()
            out_fmt    = ask_output_format()
            output_dir = get_output_dir()
            os.system("clear"); banner()
            wayback_hunter(domain, exts, output_dir,
                           save_files=out_fmt in ("1", "3", ""),
                           json_only=out_fmt == "2")

        elif choice == "2":
            domain     = get_domain_input()
            output_dir = get_output_dir()
            os.system("clear"); banner()
            js_scanner_run(domain, output_dir)

        elif choice == "3":
            domain     = get_domain_input()
            output_dir = get_output_dir()
            os.system("clear"); banner()
            full_beast_mode(domain, output_dir)

        else:
            warn("Invalid choice."); continue

        print()
        _sep(R)
        print(f"{R}{BLD}{'  DONE  --  ALONE BEAST'.center(tw())}{RST}")
        _sep(R)
        print(f"\n  {DIM}Press Enter to return to menu ...{RST}")
        input()
        os.system("clear"); banner()

if __name__ == "__main__":
    main()
