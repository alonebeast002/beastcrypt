#!/usr/bin/env bash
# ============================================================
#   beastcrypt — Setup Script
#   by ALONE BEAST
# ============================================================

set -e

R="\033[91m"; G="\033[92m"; Y="\033[93m"
W="\033[97m"; BLD="\033[1m"; RST="\033[0m"

info()  { echo -e "  ${W}[*]${RST} $1"; }
ok()    { echo -e "  ${G}[✔]${RST} $1"; }
warn()  { echo -e "  ${Y}[!]${RST} $1"; }
err()   { echo -e "  ${R}[✘]${RST} $1"; exit 1; }

echo -e "\n${R}${BLD}  ██████╗ ███████╗ █████╗ ███████╗████████╗"
echo -e "  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝"
echo -e "  ██████╔╝█████╗  ███████║███████╗   ██║   "
echo -e "  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   "
echo -e "  ██████╔╝███████╗██║  ██║███████║   ██║   "
echo -e "  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝  ${RST}"
echo -e "  ${R}${BLD}  beastcrypt — Setup  ·  by ALONE BEAST${RST}\n"

# ── Check Python ─────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    err "Python3 not found. Install it first: https://python.org"
fi
ok "Python3 found: $(python3 --version)"

# ── Check curl ───────────────────────────────────────────────
if ! command -v curl &>/dev/null; then
    err "curl not found. Install it: sudo apt install curl  OR  brew install curl"
fi
ok "curl found"

# ── Download tool ────────────────────────────────────────────
INSTALL_DIR="$HOME/.beastcrypt"
mkdir -p "$INSTALL_DIR"

info "Downloading beastcrypt..."
curl -fsSL "https://raw.githubusercontent.com/alonebeast002/beastcrypt/main/beast_tool.py" \
    -o "$INSTALL_DIR/beast_tool.py" || err "Download failed. Check your internet connection."
chmod +x "$INSTALL_DIR/beast_tool.py"
ok "Downloaded to $INSTALL_DIR/beast_tool.py"

# ── Install global command ────────────────────────────────────
BIN_PATH=""

if [ -d "$HOME/.local/bin" ]; then
    BIN_PATH="$HOME/.local/bin/beastcrypt"
elif [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    BIN_PATH="/usr/local/bin/beastcrypt"
else
    mkdir -p "$HOME/.local/bin"
    BIN_PATH="$HOME/.local/bin/beastcrypt"
fi

cat > "$BIN_PATH" <<EOF
#!/usr/bin/env bash
python3 "$INSTALL_DIR/beast_tool.py" "\$@"
EOF
chmod +x "$BIN_PATH"
ok "Command installed → $BIN_PATH"

# ── PATH check ───────────────────────────────────────────────
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    warn "Add this to your ~/.bashrc or ~/.zshrc:"
    echo -e "\n    export PATH=\"\$HOME/.local/bin:\$PATH\"\n"
    warn "Then run: source ~/.bashrc"
fi

# ── Katana (optional) ────────────────────────────────────────
echo ""
info "Checking for Katana (optional — for live JS crawl)..."
if command -v katana &>/dev/null || [ -f "$HOME/go/bin/katana" ]; then
    ok "Katana found — live JS crawl enabled"
else
    warn "Katana not found. Install it for live crawling:"
    echo -e "    go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
fi

# ── Done ─────────────────────────────────────────────────────
echo -e "\n${R}${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "  ${G}${BLD}Setup complete!${RST}"
echo -e "  Run: ${R}${BLD}beastcrypt${RST}"
echo -e "${R}${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"
