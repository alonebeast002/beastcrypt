#!/usr/bin/env python3

import sys
import os
import re
import time
import json
import signal
import threading
import ssl
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

W, G, R, Y, C, M, RST, BLD, DIM = "\033[97m", "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[95m", "\033[0m", "\033[1m", "\033[2m"

SECRET_PATTERNS = {
    "AWS Access Key": (r'AKIA[0-9A-Z]{16}', False),
    "AWS Secret Key": (r'(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key[\s]*[=:]+[\s]*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?', True),
    "Google API Key": (r'AIza[0-9A-Za-z\-_]{35}', False),
    "GitHub Token": (r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}', False),
    "Slack Token": (r'xox[baprs]-[0-9A-Za-z]{10,48}', False),
    "Stripe Key": (r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}', False),
    "Firebase URL": (r'https://[a-z0-9\-]+\.firebaseio\.com', False),
    "Firebase Key": (r'(?i)firebase[_\-\.]?(?:api[_\-\.]?)?key[\s]*[=:]+[\s]*[\'"]?([A-Za-z0-9\-_]{30,45})[\'"]?', True),
    "JWT Token": (r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', False),
    "Bearer Token": (r'(?i)bearer\s+([A-Za-z0-9\-_\.]{30,})', True),
    "Generic API Key": (r'(?i)(?:api[_\-\.]?key|apikey|api[_\-\.]?secret|app[_\-\.]?key)[\'"]?\s*[:=]\s*[\'"]([A-Za-z0-9\-_\.]{20,50})[\'"]', True),
    "Generic Token": (r'(?i)(?:access[_\-\.]?token|auth[_\-\.]?token|session[_\-\.]?token)[\'"]?\s*[:=]\s*[\'"]([A-Za-z0-9\-_\.]{20,100})[\'"]', True),
    "Generic Password": (r'(?i)(?:password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"]([^\'"]{8,40})[\'"]', True),
    "Private Key": (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', False),
    "Cloudinary URL": (r'cloudinary://[0-9]{10,}:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+', False),
    "Sendgrid Key": (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', False),
    "Azure Storage Key": (r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,}', False),
    "Azure SAS Token": (r'sv=\d{4}-\d{2}-\d{2}&s[a-z]=&se=[^&]+&sk=[^&]+&sig=[^&\s"\']+', False),
}

INTERNAL_PATH_PATTERNS = [
    r'(?<!["\'/])(\.\./(?:\.\./)*)(?:node_modules|src|lib|dist|build|app|server|config|backend|internal|private|admin|api)[/\w\-\.]+',
    r'(?:webpack|ng|vue)://[^\s\'"<>?#]{5,100}',
    r'(?<!["\'])(/(?:api|v\d+|internal|admin|private|backend|config|auth|user|users|account|accounts|token|tokens|secret|secrets|debug|staging|prod|production|service|services|graphql|rest|endpoint|endpoints|upload|uploads|download|downloads|file|files|data|db|database|manage|management|dashboard|panel|console|system|core|module|modules|handler|handlers|middleware|util|utils|helper|helpers|route|routes|controller|controllers|model|models|schema|schemas)[/\w\-\.]{2,80})',
]

IGNORE_PATH_PATTERNS = [
    r'^/{3,}', r'^/{1,2}[*#!@]', r'(?://){2,}', r'[^\x20-\x7E]',
    r'^https?://', r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|html|htm|map|json)$',
    r'^/(?:static|assets|images|fonts|css|scss|media|vendor)[/\w]',
    r'node_modules/.+/node_modules',
]

SKIP_SECRET_VALS = [
    'undefined', 'null', 'true', 'false', 'example', 'placeholder',
    'your_key', 'YOUR_KEY', 'xxxx', 'XXXX', '****', 'test', 'demo',
    'sample', 'changeme', 'insert', 'replace', 'here', 'value', 'string', 'key', 'secret'
]

_interrupted = False
found_urls_count = 0
found_secrets_count = 0
found_paths_count = 0
_spinner_line = ""
_spinner_lock = threading.Lock()


def _sigint(sig, frame):
    global _interrupted
    _interrupted = True
    sys.stdout.write("\n")
    sys.stdout.flush()
    os._exit(0)

signal.signal(signal.SIGINT, _sigint)


def strip_ansi(text):
    return re.sub(r'\033\[[0-9;]*m', '', text)

def get_cols():
    try:
        return os.get_terminal_size().columns
    except:
        return 80

def cprint(line):
    cols = get_cols()
    clean = strip_ansi(line)
    pad = " " * max(0, (cols - len(clean)) // 2)
    print(f"{pad}{line}")

def print_block(lines):
    cols = get_cols()
    max_clean = max(len(strip_ansi(l)) for l in lines)
    pad = " " * max(0, (cols - max_clean) // 2)
    for line in lines:
        print(f"{pad}{line}")

def print_sep(char="─", width=50):
    cols = get_cols()
    pad = " " * max(0, (cols - width) // 2)
    print(f"{pad}{BLD}{W}{char * width}{RST}")

BANNER_BEAST = [
    f"{BLD}{G}██████╗ ███████╗ █████╗ ███████╗████████╗{RST}",
    f"{BLD}{G}██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝{RST}",
    f"{BLD}{G}██████╔╝█████╗  ███████║███████╗   ██║   {RST}",
    f"{BLD}{G}██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   {RST}",
    f"{BLD}{G}██████╔╝███████╗██║  ██║███████║   ██║   {RST}",
    f"{BLD}{G}╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝  {RST}",
]

BANNER_CRYPT = [
    f"{BLD}{G} ██████╗██████╗ ██╗   ██╗██████╗ ████████╗{RST}",
    f"{BLD}{G}██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝{RST}",
    f"{BLD}{G}██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   {RST}",
    f"{BLD}{G}██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   {RST}",
    f"{BLD}{G}╚██████╗██║  ██║   ██║   ██║        ██║   {RST}",
    f"{BLD}{G} ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝  {RST}",
]

def print_banner(animate=False):
    all_lines = BANNER_BEAST + [""] + BANNER_CRYPT
    cols = get_cols()
    max_len = max(len(strip_ansi(l)) for l in all_lines if l != "")
    pad = " " * max(0, (cols - max_len) // 2)
    print()
    for line in all_lines:
        if line == "":
            print()
        else:
            print(f"{pad}{line}")
            if animate:
                time.sleep(0.03)

def print_header():
    line1 = "v2.0  ·  JS & Source Map Secret Scanner  ·  alone_beast_02"
    line2 = "Secrets · Internal Paths · Source Maps · JS Hunter"
    w = max(len(line1), len(line2))
    cols = get_cols()
    pad = " " * max(0, (cols - w) // 2)
    sep = "─" * w
    print()
    print(f"{pad}{W}{sep}{RST}")
    print(f"{pad}{C}{line1}{RST}")
    print(f"{pad}{DIM}{line2}{RST}")
    print(f"{pad}{W}{sep}{RST}")
    print()


class LoadingSpinner:
    def __init__(self):
        self.chars = ["⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷"]
        self.running = False
        self.idx = 0
        self.msg_idx = 0
        self.messages = [
            "Grab a coffee... tool is working",
            "Scanning JS files...",
            "Hunting for secrets...",
            "Please wait...",
            "Checking source maps...",
            "Maybe AWS keys ahead... 🤞",
            "Extracting internal paths...",
            "Go make another coffee...",
            "Almost there...",
            "Token hunt in progress...",
            "Stay focused, scan running...",
            "Looking for GitHub tokens...",
            "Bearer tokens are interesting...",
            "Crawling webpack paths...",
        ]

    def _render(self):
        msg = self.messages[self.msg_idx % len(self.messages)]
        spinner_char = self.chars[self.idx % 8]
        # Plain text line — no padding issues
        line = (
            f"\r\033[2K"
            f"{G}{spinner_char}{RST} "
            f"{Y}{msg}{RST} "
            f"| {W}Assets:{G}{found_urls_count}{RST}"
            f" | {R}Secrets:{found_secrets_count}{RST}"
            f" | {C}Paths:{found_paths_count}{RST}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    def spin(self):
        while self.running:
            self._render()
            self.idx += 1
            if self.idx % 30 == 0:
                self.msg_idx += 1
            time.sleep(0.1)

    def start(self):
        self.running = True
        # Print empty line so spinner has a line to overwrite
        sys.stdout.write("\n")
        sys.stdout.flush()
        threading.Thread(target=self.spin, daemon=True).start()

    def stop(self):
        self.running = False
        time.sleep(0.2)
        sys.stdout.write("\r\033[2K")
        sys.stdout.flush()
        print()


def save_secret(secret_data):
    with open("results.json", "a") as f:
        f.write(json.dumps(secret_data, indent=2) + "\n")

def save_url(url):
    with open("all_js_urls.txt", "a") as f:
        f.write(url + "\n")

def save_path(path_data):
    with open("internal_paths.txt", "a") as f:
        f.write(json.dumps(path_data, indent=2) + "\n")

def should_ignore_path(path):
    for pat in IGNORE_PATH_PATTERNS:
        if re.search(pat, path, re.IGNORECASE):
            return True
    if len(path) > 150 or path.count('/') > 8 or path.count('.') > 6:
        return True
    return False

def extract_internal_paths(content, source_url):
    global found_paths_count
    found = set()
    for pat in INTERNAL_PATH_PATTERNS:
        for m in re.finditer(pat, content):
            path = m.group(0).strip().strip('"\'`')
            if not should_ignore_path(path) and len(path) > 4:
                found.add(path)
    for path in found:
        found_paths_count += 1
        save_path({"path": path, "source": source_url, "time": time.ctime()})

def scan_secrets(content, source_url):
    global found_secrets_count
    for name, (pattern, has_group) in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, content):
            try:
                val = m.group(1) if has_group and m.lastindex else m.group(0)
            except IndexError:
                val = m.group(0)
            val = val.strip()
            if len(val) < 8:
                continue
            if any(s.lower() in val.lower() for s in SKIP_SECRET_VALS):
                continue
            found_secrets_count += 1
            save_secret({"type": name, "value": val, "source": source_url, "time": time.ctime()})

def fetch_content(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=7, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except:
        return 0, ""

def process_content(url, content):
    global found_urls_count
    found_urls_count += 1
    save_url(url)
    scan_secrets(content, url)
    extract_internal_paths(content, url)

def extract_js_links(text, base_url):
    found = set()
    patterns = [
        r'src\s*=\s*[\'"]([^\'"]+\.js)[\'"]',
        r'href\s*=\s*[\'"]([^\'"]+\.js)[\'"]',
        r'[\'"`](/[^\'"`\s]+\.js)[\'"`]'
    ]
    for p in patterns:
        for m in re.finditer(p, text):
            full_url = urllib.parse.urljoin(base_url, m.group(1)).split('?')[0]
            if full_url.endswith(".js"):
                found.add(full_url)
    return found

def process_target(target):
    if not target.startswith("http"):
        target = "https://" + target
    scanned, queue = set(), {target}
    for _ in range(2):
        if not queue or _interrupted:
            break
        batch = list(queue - scanned)
        scanned.update(batch)
        queue = set()
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(fetch_content, url): url for url in batch}
            for fut in as_completed(futures):
                url = futures[fut]
                status, content = fut.result()
                if status == 200:
                    process_content(url, content)
                    if not url.endswith(".js"):
                        for f in extract_js_links(content, url):
                            if f not in scanned:
                                queue.add(f)
                    if url.endswith(".js"):
                        m_url = url + ".map"
                        m_status, m_content = fetch_content(m_url)
                        if m_status == 200:
                            process_content(m_url, m_content)

def process_file_list(filepath):
    if not os.path.exists(filepath):
        cprint(f"\n{R}[✗] File not found: {filepath}{RST}\n")
        return
    with open(filepath, "r") as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    cprint(f"\n{G}[✓]{RST} {W}{len(urls)} JS/.map URLs loaded — starting scan...{RST}\n")
    time.sleep(0.3)
    show_coffee_animation()
    spinner = LoadingSpinner()
    spinner.start()
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(fetch_content, url): url for url in urls}
        for fut in as_completed(futures):
            if _interrupted:
                break
            url = futures[fut]
            status, content = fut.result()
            if status == 200:
                process_content(url, content)
    spinner.stop()

def show_coffee_animation():
    os.system("clear")
    print_banner()
    print_header()
    art = [
        f"{Y}   ( (   {RST}  {W}☕  Grab a coffee and wait...{RST}",
        f"{Y}    ) )  {RST}  {G}    Loading secret patterns...{RST}",
        f"{Y}  ......{RST}   {C}    Warming up engines...{RST}",
        f"{C}  |    | {RST}  {Y}    Ready for hunt! 😈{RST}",
        f"{C}   \\  / {RST}",
        f"{G}    `--'{RST}",
    ]
    cols = get_cols()
    max_len = max(len(strip_ansi(l)) for l in art)
    art_pad = " " * max(0, (cols - max_len) // 2)
    for line in art:
        print(f"{art_pad}{line}")
        time.sleep(0.15)
    time.sleep(0.8)
    print()
    cprint(f"{G}[✓]{RST} {W}BeastCrypt Engines Fired! Scan Starting...{RST}")
    print()
    time.sleep(0.4)

def show_intro():
    os.system("clear")
    print_banner(animate=True)
    print_header()
    cols = get_cols()
    box_w = 38
    top = f"┌{'─' * box_w}┐"
    mid = f"├{'─' * box_w}┤"
    bot = f"└{'─' * box_w}┘"
    title = "=[ OPTIONS ]="
    t_pad = (box_w - len(title)) // 2

    def bline(content):
        clean_len = len(strip_ansi(content))
        right = box_w - 2 - clean_len
        return f"│ {content}{' ' * max(0, right)} │"

    title_line = f"│{' ' * t_pad}{Y}{BLD}{title}{RST}{' ' * (box_w - t_pad - len(title))}│"
    box = [
        f"{W}{top}{RST}",
        title_line,
        f"{W}{mid}{RST}",
        bline(f"  {G}{BLD}1.{RST}  Single Target   {DIM}(deep crawl){RST}"),
        bline(f"  {C}{BLD}2.{RST}  Subdomain list  {DIM}(.txt scan){RST}"),
        bline(f"  {M}{BLD}3.{RST}  JS / .map URL list scan{RST}"),
        f"{W}{bot}{RST}",
    ]
    pad = " " * max(0, (cols - box_w - 2) // 2)
    for bl in box:
        print(f"{pad}{bl}")
    print()

def show_results():
    os.system("clear")
    print_banner()
    print()
    print_sep("═", 52)
    print()
    cprint(f"{BLD}{M}BEASTCRYPT — HUNT COMPLETE 😈{RST}")
    print()
    stats = [
        f"{G}[✓]{RST}  JS Assets Found  :  {BLD}{G}{found_urls_count}{RST}",
        f"{R}[!]{RST}  Secrets Found    :  {BLD}{R}{found_secrets_count}{RST}",
        f"{C}[~]{RST}  Internal Paths   :  {BLD}{C}{found_paths_count}{RST}",
    ]
    print_block(stats)
    print()
    print_sep("─", 52)
    print()
    files = [
        f"{Y}[📁]{RST}  JS URLs    →  {BLD}all_js_urls.txt{RST}",
        f"{R}[📁]{RST}  Secrets    →  {BLD}results.json{RST}",
        f"{C}[📁]{RST}  Int Paths  →  {BLD}internal_paths.txt{RST}",
    ]
    print_block(files)
    print()
    print_sep("─", 52)
    print()
    if found_secrets_count > 0:
        cprint(f"{R}{BLD}⚠  SECRETS FOUND! — PLEASE DO RESPONSIBLE DISCLOSURE!{RST}")
    else:
        cprint(f"{G}✓  No secrets found — target looks clean!{RST}")
    print()

def main():
    show_intro()
    cols = get_cols()
    prompt_text = "> Selection [1/2/3]: "
    pad = " " * max(0, (cols - len(prompt_text)) // 2)
    choice = input(f"{pad}{G}>{RST} {BLD}{G}Selection [{W}1/2/3{G}]{RST}{G}: {RST}").strip()

    if choice == "1":
        url_prompt = "Enter URL: "
        upad = " " * max(0, (cols - len(url_prompt)) // 2)
        target = input(f"{upad}{W}Enter URL: {RST}").strip()
        print()
        cprint(f"{G}[✓]{RST} {W}Target loaded — starting scan...{RST}")
        time.sleep(0.3)
        show_coffee_animation()
        spinner = LoadingSpinner()
        spinner.start()
        process_target(target)
        spinner.stop()

    elif choice == "2":
        fp_prompt = "Enter subdomain list path: "
        fpad = " " * max(0, (cols - len(fp_prompt)) // 2)
        path = input(f"{fpad}{W}Enter subdomain list path: {RST}").strip()
        if not os.path.exists(path):
            cprint(f"\n{R}[✗] File not found!{RST}\n")
            return
        with open(path) as f:
            targets = [l.strip() for l in f if l.strip()]
        print()
        cprint(f"{G}[✓]{RST} {W}{len(targets)} targets loaded — starting scan...{RST}")
        time.sleep(0.3)
        show_coffee_animation()
        spinner = LoadingSpinner()
        spinner.start()
        for t in targets:
            if _interrupted:
                break
            process_target(t)
        spinner.stop()

    elif choice == "3":
        jp_prompt = "Enter JS/.map URL list path: "
        jpad = " " * max(0, (cols - len(jp_prompt)) // 2)
        path = input(f"{jpad}{W}Enter JS/.map URL list path: {RST}").strip()
        process_file_list(path)

    else:
        cprint(f"\n{R}[✗] Invalid choice — enter 1, 2, or 3!{RST}\n")
        return

    show_results()

if __name__ == "__main__":
    main()
