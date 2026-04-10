#!/bin/bash
# ============================================================
# 🕸️ HORNET — Installer
# ============================================================

set -eo pipefail

REPO="AloreBB/hornet"
BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

INSTALL_DIR="${HORNET_DIR:-$HOME/.hornet}"
BIN_DIR="${HORNET_BIN:-$HOME/.local/bin}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

err()  { echo -e "${RED}✖ $*${RESET}" >&2; exit 1; }
ok()   { echo -e "${GREEN}✔ $*${RESET}"; }
info() { echo -e "${CYAN}→ $*${RESET}"; }
step() { echo -e "\n${BOLD}$*${RESET}"; }

# Suppress apt noise and needrestart prompts
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

echo -e "
${BOLD}🕸️  HORNET — Server Security Monitor${RESET}
Installer v1.0
"

# ── 1. Check OS ───────────────────────────────────────────
step "Checking system..."
OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "$OS" != "Linux" ]]; then
    echo -e "${RED}✖ Hornet only runs on Linux servers.${RESET}"
    echo
    echo "  Hornet monitors server-specific tools (Docker, fail2ban, ss, /proc)"
    echo "  that are not available on macOS or Windows."
    echo
    echo "  Deploy it on your Linux VPS and connect from your Mac via SSH."
    exit 1
fi
ok "Linux $(uname -r | cut -d- -f1) — $ARCH"

# ── 2. Install dependencies ───────────────────────────────
step "Installing dependencies..."

_apt_install() {
    sudo apt-get install -y -qq "$@" 2>&1 | grep -v "^$" | grep -E "^(Err|W:|E:)" || true
}

install_gum_debian() {
    info "Deploying silk threads for gum..."
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://repo.charm.sh/apt/gpg.key \
        | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg 2>/dev/null
    echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" \
        | sudo tee /etc/apt/sources.list.d/charm.list > /dev/null
    sudo apt-get update -qq 2>/dev/null
    _apt_install gum
}

install_gum_binary() {
    info "Weaving gum from source..."
    local arch_label="x86_64"
    [[ "$ARCH" == "aarch64" ]] && arch_label="arm64"
    curl -fsSL "https://github.com/charmbracelet/gum/releases/latest/download/gum_Linux_${arch_label}.tar.gz" \
        -o /tmp/gum.tar.gz 2>/dev/null
    tar xz -C /tmp -f /tmp/gum.tar.gz gum
    sudo mv /tmp/gum /usr/local/bin/gum
    rm -f /tmp/gum.tar.gz
}

# jq
if ! command -v jq &>/dev/null; then
    info "Spinning jq..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq 2>/dev/null
        _apt_install jq
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y -q jq 2>/dev/null
    elif command -v yum &>/dev/null; then
        sudo yum install -y -q jq 2>/dev/null
    else
        err "Cannot install jq automatically. Install it manually: https://jqlang.github.io/jq/"
    fi
fi
ok "jq ready"

# gum
if ! command -v gum &>/dev/null; then
    info "Spinning gum..."
    if command -v apt-get &>/dev/null; then
        install_gum_debian 2>/dev/null || install_gum_binary
    else
        install_gum_binary
    fi
fi
ok "gum ready"

# ── 3. Download and install Hornet ────────────────────────
step "Installing Hornet..."

mkdir -p "$INSTALL_DIR" "$BIN_DIR"

info "Downloading Hornet files..."
curl -fsSL "$BASE_URL/hornet.sh" -o "$INSTALL_DIR/hornet.sh"
curl -fsSL "$BASE_URL/hornet"    -o "$INSTALL_DIR/hornet"
chmod +x "$INSTALL_DIR/hornet.sh" "$INSTALL_DIR/hornet"

# Download config template only if no config exists yet
if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
    curl -fsSL "$BASE_URL/config.json" -o "$INSTALL_DIR/config.json"
fi

# Create credentials file if missing
CREDENTIALS_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/hornet/credentials"
if [[ ! -f "$CREDENTIALS_FILE" ]]; then
    mkdir -p "$(dirname "$CREDENTIALS_FILE")"
    printf 'NTFY_TOKEN=\n' > "$CREDENTIALS_FILE"
    chmod 600 "$CREDENTIALS_FILE"
fi

# Symlink CLI
ln -sf "$INSTALL_DIR/hornet" "$BIN_DIR/hornet"

ok "Hornet installed to $INSTALL_DIR"

# ── 4. PATH check ─────────────────────────────────────────
if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    echo
    info "Add this to your ~/.bashrc or ~/.zshrc to use 'hornet' directly:"
    echo -e "  ${CYAN}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
    echo
fi

# ── 5. Set up cron ────────────────────────────────────────
if ! crontab -l 2>/dev/null | grep -q "hornet.sh"; then
    (crontab -l 2>/dev/null; echo "*/15 * * * * $INSTALL_DIR/hornet.sh >> $INSTALL_DIR/hornet.log 2>&1") | crontab -
    ok "Cron job set up (runs every 15 min)"
fi

# ── 6. First-run setup ────────────────────────────────────
echo
if gum confirm "  Run initial setup now? (configure ntfy + whitelists)"; then
    "$INSTALL_DIR/hornet" setup
fi

echo -e "
${BOLD}🕸️  Hornet is ready.${RESET}

  ${CYAN}hornet run${RESET}     — Run a scan now
  ${CYAN}hornet setup${RESET}   — Configure notifications & whitelists
  ${CYAN}hornet status${RESET}  — View recent scan history

Hornet vigila. Hallownest no caerá.
"
