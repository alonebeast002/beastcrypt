#!/usr/bin/env bash

R="\033[91m"; G="\033[92m"; Y="\033[93m"
W="\033[97m"; BLD="\033[1m"; RST="\033[0m"

ok()   { echo -e "  ${G}[✔]${RST} $1"; }
warn() { echo -e "  ${Y}[!]${RST} $1"; }
err()  { echo -e "  ${R}[✘]${RST} $1\n"; exit 1; }
info() { echo -e "  ${W}[*]${RST} $1"; }

echo -e "\n${R}${BLD}  ██████╗ ███████╗ █████╗ ███████╗████████╗"
echo -e "  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝"
echo -e "  ██████╔╝█████╗  ███████║███████╗   ██║   "
echo -e "  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   "
echo -e "  ██████╔╝███████╗██║  ██║███████║   ██║   "
echo -e "  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝  ${RST}"
echo -e "  ${R}${BLD}  BeastCrypt — Setup  ·  by ALONE BEAST${RST}\n"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_FILE="$SCRIPT_DIR/beastcrypt.py"

if [ ! -f "$PY_FILE" ]; then
    err "beastcrypt.py not found in: $SCRIPT_DIR"
fi

if ! command -v python3 &>/dev/null; then
    err "python3 not found. Install it first:
       Debian/Ubuntu/Parrot/Kali : sudo apt install python3
       BlackArch                 : sudo pacman -S python
       Termux                    : pkg install python"
fi

PY_VER=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$PY_VER" -lt 8 ]; then
    err "Python 3.8+ required. Found: $(python3 --version)"
fi
ok "Python $(python3 --version | cut -d' ' -f2) detected"

if ! command -v curl &>/dev/null; then
    warn "curl not found — trying to install..."
    if command -v apt &>/dev/null;    then sudo apt install -y curl
    elif command -v pacman &>/dev/null; then sudo pacman -S --noconfirm curl
    elif command -v pkg &>/dev/null;    then pkg install -y curl
    else err "curl not found. Install manually: curl"; fi
fi
ok "curl ready"

if [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
    ENV="termux"
    BIN_DIR="$HOME/.local/bin"
    SHELL_RCS=("$HOME/.bashrc" "$HOME/.zshrc" "$PREFIX/etc/bash.bashrc")
else
    ENV="linux"
    BIN_DIR="$HOME/.local/bin"
    SHELL_RCS=("$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc" "$HOME/.profile")
fi
info "Environment: $ENV"

mkdir -p "$BIN_DIR"

WRAPPER="$BIN_DIR/beastcrypt"
cat > "$WRAPPER" << EOF
#!/usr/bin/env bash
exec python3 "$PY_FILE" "\$@"
EOF
chmod +x "$WRAPPER"
ok "Wrapper installed → $WRAPPER"

PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
ADDED=0
for RC in "${SHELL_RCS[@]}"; do
    if [ -f "$RC" ] && ! grep -q '\.local/bin' "$RC" 2>/dev/null; then
        echo "" >> "$RC"
        echo "$PATH_LINE" >> "$RC"
        ok "PATH added → $RC"
        ADDED=1
    fi
done
[ "$ADDED" -eq 0 ] && ok "PATH already configured in shell rc"

export PATH="$HOME/.local/bin:$PATH"
ok "PATH activated for this session"

if [ "$ENV" = "linux" ]; then
    SYSBIN="/usr/local/bin/beastcrypt"
    if command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
        sudo bash -c "cat > '$SYSBIN' << 'SEOF'
#!/usr/bin/env bash
exec python3 \"$PY_FILE\" \"\$@\"
SEOF
chmod +x '$SYSBIN'"
        ok "System-wide command installed → $SYSBIN"
    else
        warn "No sudo access — skipping system-wide install (user install still works)"
    fi
fi

echo ""
if command -v beastcrypt &>/dev/null; then
    ok "Verified: 'beastcrypt' command is working"
else
    warn "Command not found in current shell yet — run: source ~/.bashrc"
fi

W_LEN=46
echo -e "\n${R}${BLD}$(printf '━%.0s' $(seq 1 $W_LEN))${RST}"
echo -e "  ${G}${BLD}Setup complete!${RST}"
echo -e "  ${W}Run the tool anytime with:${RST}  ${R}${BLD}beastcrypt${RST}"
if [ "$ENV" = "termux" ]; then
    echo -e "  ${Y}Termux tip:${RST} restart your session if command not found"
fi
echo -e "${R}${BLD}$(printf '━%.0s' $(seq 1 $W_LEN))${RST}\n"
