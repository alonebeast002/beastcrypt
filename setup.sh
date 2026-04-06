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
    err "Python3 not found. Install it: https://python.org"
fi
ok "Python3 found: $(python3 --version)"

# ── Check curl ───────────────────────────────────────────────
if ! command -v curl &>/dev/null; then
    err "curl not found. Install: sudo apt install curl"
fi
ok "curl found"

# ── Check git ────────────────────────────────────────────────
if ! command -v git &>/dev/null; then
    err "git not found. Install: sudo apt install git"
fi
ok "git found"

# ── Clone repo ───────────────────────────────────────────────
INSTALL_DIR="$HOME/.beastcrypt"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Updating existing install..."
    git -C "$INSTALL_DIR" pull --quiet
else
    info "Cloning beastcrypt..."
    rm -rf "$INSTALL_DIR"
    git clone --quiet https://github.com/alonebeast002/beastcrypt.git "$INSTALL_DIR"
fi
ok "Downloaded to $INSTALL_DIR"

# ── Verify main file exists ──────────────────────────────────
if [ ! -f "$INSTALL_DIR/beastcrypt.py" ]; then
    err "beastcrypt.py not found in repo. Check the repository."
fi
chmod +x "$INSTALL_DIR/beastcrypt.py"

# ── Install global command ────────────────────────────────────
mkdir -p "$HOME/.local/bin"
BIN_PATH="$HOME/.local/bin/beastcrypt"

cat > "$BIN_PATH" << EOF
#!/usr/bin/env bash
python3 "$INSTALL_DIR/beastcrypt.py" "\$@"
EOF
chmod +x "$BIN_PATH"
ok "Command installed → $BIN_PATH"

# ── PATH check ───────────────────────────────────────────────
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    warn "Run this to activate the command:"
    echo ""
    echo -e "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
    echo ""
fi

# ── Katana (optional) ────────────────────────────────────────
if command -v katana &>/dev/null || [ -f "$HOME/go/bin/katana" ]; then
    ok "Katana found — live JS crawl enabled"
else
    warn "Katana not found (optional). Install for live crawling:"
    echo -e "    go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
fi

# ── Done ─────────────────────────────────────────────────────
echo -e "\n${R}${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "  ${G}${BLD}Setup complete!${RST}"
echo -e "  Run: ${R}${BLD}beastcrypt${RST}"
echo -e "${R}${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"
