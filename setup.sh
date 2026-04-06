#!/usr/bin/env bash

R="\033[91m"; G="\033[92m"; Y="\033[93m"
W="\033[97m"; BLD="\033[1m"; RST="\033[0m"

ok()   { echo -e "  ${G}[✔]${RST} $1"; }
warn() { echo -e "  ${Y}[!]${RST} $1"; }
err()  { echo -e "  ${R}[✘]${RST} $1"; exit 1; }

echo -e "\n${R}${BLD}  ██████╗ ███████╗ █████╗ ███████╗████████╗"
echo -e "  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝"
echo -e "  ██████╔╝█████╗  ███████║███████╗   ██║   "
echo -e "  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   "
echo -e "  ██████╔╝███████╗██║  ██║███████║   ██║   "
echo -e "  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝  ${RST}"
echo -e "  ${R}${BLD}  beastcrypt — Setup  ·  by ALONE BEAST${RST}\n"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_FILE="$SCRIPT_DIR/beastcrypt.py"

if [ ! -f "$PY_FILE" ]; then
    err "beastcrypt.py not found. Make sure setup.sh is in the same folder."
fi

mkdir -p "$HOME/.local/bin"

cat > "$HOME/.local/bin/beastcrypt" << EOF
#!/usr/bin/env bash
python3 "$PY_FILE" "\$@"
EOF
chmod +x "$HOME/.local/bin/beastcrypt"
ok "Command installed"

PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
for RC in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc"; do
    if [ -f "$RC" ] && ! grep -q '.local/bin' "$RC"; then
        echo "$PATH_LINE" >> "$RC"
        ok "PATH added to $RC"
    fi
done
export PATH="$HOME/.local/bin:$PATH"
ok "PATH activated"

echo -e "\n${R}${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "  ${G}${BLD}Done! Now run: beastcrypt${RST}"
echo -e "${R}${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"
