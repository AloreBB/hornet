#!/bin/bash
# ============================================================
# 🕸️ HORNET — Installer
# ============================================================

set -eo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
err()  { echo -e "${RED}✖ $*${RESET}" >&2; exit 1; }
ok()   { echo -e "${GREEN}✔ $*${RESET}"; }
info() { echo -e "${CYAN}→ $*${RESET}"; }
step() { echo -e "\n${BOLD}$*${RESET}"; }

INSTALL_DIR="${HORNET_DIR:-$HOME/.hornet}"
BIN_DIR="${HORNET_BIN:-$HOME/.local/bin}"

echo -e "
${BOLD}🕸️  HORNET — Server Security Monitor${RESET}
Installer v1.0
"

# ── 1. Check OS ───────────────────────────────────────────
step "Checking system..."
OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "$OS" != "Linux" ]]; then
    err "Hornet currently supports Linux only."
fi

# ── 2. Install dependencies ───────────────────────────────
step "Installing dependencies..."

install_gum_debian() {
    info "Adding Charm repository..."
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://repo.charm.sh/apt/gpg.key \
        | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
    echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" \
        | sudo tee /etc/apt/sources.list.d/charm.list > /dev/null
    sudo apt-get update -q
    sudo apt-get install -y gum
}

install_gum_binary() {
    info "Downloading gum binary..."
    local gum_version
    gum_version=$(curl -fsSL https://api.github.com/repos/charmbracelet/gum/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | ltrimstr "v" 2>/dev/null || echo "0.14.5")
    local arch_label="x86_64"
    [[ "$ARCH" == "aarch64" ]] && arch_label="arm64"
    curl -fsSL "https://github.com/charmbracelet/gum/releases/latest/download/gum_Linux_${arch_label}.tar.gz" \
        -o /tmp/gum.tar.gz
    tar xz -C /tmp -f /tmp/gum.tar.gz gum
    sudo mv /tmp/gum /usr/local/bin/gum
    rm -f /tmp/gum.tar.gz
}

# jq
if ! command -v jq &>/dev/null; then
    info "Installing jq..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y jq
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y jq
    elif command -v yum &>/dev/null; then
        sudo yum install -y jq
    else
        err "Cannot install jq automatically. Please install it manually: https://jqlang.github.io/jq/"
    fi
fi
ok "jq $(jq --version)"

# gum
if ! command -v gum &>/dev/null; then
    info "Installing gum..."
    if command -v apt-get &>/dev/null; then
        install_gum_debian || install_gum_binary
    else
        install_gum_binary
    fi
fi
ok "gum $(gum --version)"

# ── 3. Install Hornet ─────────────────────────────────────
step "Installing Hornet..."

mkdir -p "$INSTALL_DIR" "$BIN_DIR"

# Copy files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/hornet.sh"  "$INSTALL_DIR/hornet.sh"
cp "$SCRIPT_DIR/hornet"     "$INSTALL_DIR/hornet"
chmod +x "$INSTALL_DIR/hornet.sh" "$INSTALL_DIR/hornet"

# Copy config if it doesn't exist yet
if [[ ! -f "$INSTALL_DIR/hornet.json" ]]; then
    if [[ -f "$SCRIPT_DIR/hornet.json" ]]; then
        cp "$SCRIPT_DIR/hornet.json" "$INSTALL_DIR/hornet.json"
    else
        # Create fresh config
        cat > "$INSTALL_DIR/hornet.json" <<'EOF'
{
  "notifications": {
    "url": "",
    "topic": "",
    "icon": ""
  },
  "baseline": {
    "users": [],
    "ssh_keys": [],
    "crontabs": []
  },
  "whitelist": {
    "ports": [22, 80, 443],
    "processes": [],
    "containers": [],
    "extensions": ["so", "py", "sh"]
  }
}
EOF
    fi
fi

# .hornet.env (secrets) — only create if missing
if [[ ! -f "$INSTALL_DIR/.hornet.env" ]]; then
    printf '# Hornet secrets — never commit this file\nNTFY_TOKEN=\n' \
        > "$INSTALL_DIR/.hornet.env"
    chmod 600 "$INSTALL_DIR/.hornet.env"
fi

# Symlink CLI to bin
ln -sf "$INSTALL_DIR/hornet" "$BIN_DIR/hornet"

ok "Hornet installed to $INSTALL_DIR"
ok "CLI available at $BIN_DIR/hornet"

# ── 4. PATH check ─────────────────────────────────────────
if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    echo
    echo -e "${CYAN}Add this to your ~/.bashrc or ~/.zshrc:${RESET}"
    echo -e "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo
fi

# ── 5. First-run setup ────────────────────────────────────
echo
if gum confirm "  Run initial setup now? (configure ntfy + whitelists)"; then
    "$INSTALL_DIR/hornet" setup
fi

echo -e "
${BOLD}🕸️  Hornet is ready.${RESET}

  ${CYAN}hornet run${RESET}       — Run a scan now
  ${CYAN}hornet setup${RESET}     — Configure notifications & whitelists
  ${CYAN}hornet status${RESET}    — View recent scan history

Hornet vigila. Hallownest no caerá.
"
