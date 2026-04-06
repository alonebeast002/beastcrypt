#!/usr/bin/env bash

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

if ! command -v python3 &>/dev/null; then
    err "Python3 not found. Install it: https://python.org"
fi
ok "Python3 found: $(python3 --version)"

if ! command -v curl &>/dev/null; then
    err "curl not found. Install: sudo apt install curl"
fi
ok "curl found"

if ! command -v git &>/dev/null; then
    err "git not found. Install: sudo apt install git"
fi
ok "git found"

INSTALL_DIR="$HOME/.beastcrypt"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Updating existing install..."
    git -C "$INSTALL_DIR" reset --hard HEAD --quiet
    git -C "$INSTALL_DIR" pull --quiet
else
    info "Cloning beastcrypt..."
    rm -rf "$INSTALL_DIR"
    git clone --quiet https://github.com/alonebeast002/beastcrypt.git "$INSTALL_DIR"
fi
ok "Downloaded to $INSTALL_DIR"

if [ ! -f "$INSTALL_DIR/beastcrypt.py" ]; then
    err "beastcrypt.py not found in repo. Check the repository."
fi
chmod +x "$INSTALL_DIR/beastcrypt.py"

mkdir -p "$HOME/.local/bin"
BIN_PATH="$HOME/.local/bin/beastcrypt"

cat > "$BIN_PATH" << EOF
#!/usr/bin/env bash
python3 "$INSTALL_DIR/beastcrypt.py" "\$@"
EOF
chmod +x "$BIN_PATH"
ok "Command installed → $BIN_PATH"

PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
for RC in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc"; do
    if [ -f "$RC" ] && ! grep -q '.local/bin' "$RC"; then
        echo "$PATH_LINE" >> "$RC"
        ok "PATH added to $RC"
    fi
done
if [ ! -f "$HOME/.bashrc" ] && [ ! -f "$HOME/.bash_profile" ]; then
    echo "$PATH_LINE" >> "$HOME/.bashrc"
    ok "PATH added to ~/.bashrc"
fi
export PATH="$HOME/.local/bin:$PATH"
ok "PATH activated for current session"

if command -v katana &>/dev/null || [ -f "$HOME/go/bin/katana" ]; then
    ok "Katana found — live JS crawl enabled"
else
    warn "Katana not found (optional). Install for live crawling:"
    echo -e "    go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
fi

echo -e "\n${R}${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "  ${G}${BLD}Setup complete!${RST}"
echo -e "  Run: ${R}${BLD}beastcrypt${RST}"
echo -e "${R}${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"
