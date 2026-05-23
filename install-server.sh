#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/Maximus002/tundra.git"
INSTALL_DIR="/opt/tundra"
CONFIG_FILE="/etc/tundra/tundra-server.toml"
SERVICE_FILE="/etc/systemd/system/tundra-server.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Run as root: sudo $0"
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS. Only Ubuntu/Debian supported."
    fi
    source /etc/os-release
    case "$ID" in
        ubuntu|debian) info "Detected: $PRETTY_NAME" ;;
        *) warn "Untested OS: $PRETTY_NAME. Proceeding anyway..." ;;
    esac
}

install_deps() {
    info "Installing dependencies..."
    apt-get update -qq
    apt-get install -y -qq build-essential pkg-config libssl-dev git curl ufw > /dev/null
}

install_rust() {
    if command -v cargo &> /dev/null; then
        info "Rust already installed: $(rustc --version)"
        return
    fi
    info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    info "Rust installed: $(rustc --version)"
}

clone_repo() {
    if [[ -d "$INSTALL_DIR" && -d "$INSTALL_DIR/.git" ]]; then
        info "Updating existing repo at $INSTALL_DIR..."
        git -C "$INSTALL_DIR" pull --ff-only || error "Git pull failed. Resolve conflicts or remove $INSTALL_DIR"
    else
        info "Cloning $REPO..."
        git clone "$REPO" "$INSTALL_DIR"
    fi
}

build_server() {
    info "Building tundra-server (release)..."
    source "$HOME/.cargo/env"
    cd "$INSTALL_DIR"
    cargo build --release --bin tundra-server
    info "Binary: $INSTALL_DIR/target/release/tundra-server"
    info "Size: $(du -h target/release/tundra-server | cut -f1)"
}

generate_psk() {
    openssl rand -hex 32
}

create_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        warn "Config already exists at $CONFIG_FILE"
        read -p "Overwrite? [y/N] " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && return
    fi

    mkdir -p "$(dirname "$CONFIG_FILE")"

    read -p "Listen port [8443]: " LISTEN_PORT
    LISTEN_PORT="${LISTEN_PORT:-8443}"

    read -p "Target domain for camouflage [www.microsoft.com]: " TARGET_DOMAIN
    TARGET_DOMAIN="${TARGET_DOMAIN:-www.microsoft.com}"

    read -p "Enter PSK (64 hex chars) or press Enter to generate: " PSK
    if [[ -z "$PSK" ]]; then
        PSK=$(generate_psk)
        info "Generated PSK: $PSK"
    fi

    read -p "Max connections [100]: " MAX_CONN
    MAX_CONN="${MAX_CONN:-100}"

    read -p "Max connections per IP [10]: " MAX_PER_IP
    MAX_PER_IP="${MAX_PER_IP:-10}"

    cat > "$CONFIG_FILE" << EOF
listen = "0.0.0.0:${LISTEN_PORT}"
psk = "${PSK}"
target_domain = "${TARGET_DOMAIN}"
max_connections = ${MAX_CONN}
max_per_ip = ${MAX_PER_IP}
EOF

    chmod 600 "$CONFIG_FILE"
    info "Config written to $CONFIG_FILE"
    info ""
    info "PSK: $PSK"
    info "Save this PSK for your client configuration!"
}

install_service() {
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Tundra DPI-resistant Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/target/release/tundra-server --config $CONFIG_FILE
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

WorkingDirectory=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable tundra-server
    info "systemd service installed"
}

configure_firewall() {
    if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
        source /etc/os-release
        read -p "Open port ${LISTEN_PORT:-8443}/tcp in UFW? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            ufw allow "${LISTEN_PORT:-8443}"/tcp
            info "Port ${LISTEN_PORT:-8443} opened in UFW"
        fi
    else
        info "UFW not active, skipping firewall config"
    fi
}

start_service() {
    info "Starting tundra-server..."
    systemctl start tundra-server
    sleep 2
    if systemctl is-active --quiet tundra-server; then
        info "tundra-server is running!"
        systemctl status tundra-server --no-pager
    else
        error "tundra-server failed to start. Check: journalctl -u tundra-server -n 50"
    fi
}

show_status() {
    echo ""
    echo "============================================"
    echo "  Tundra Server Installation Complete"
    echo "============================================"
    echo ""
    echo "  Config:  $CONFIG_FILE"
    echo "  Binary:  $INSTALL_DIR/target/release/tundra-server"
    echo "  Service: systemctl {start|stop|restart|status} tundra-server"
    echo "  Logs:    journalctl -u tundra-server -f"
    echo ""
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "  PSK: $(grep '^psk' "$CONFIG_FILE" | cut -d'"' -f2)"
        echo "  Port: $(grep '^listen' "$CONFIG_FILE" | grep -oP ':\K[0-9]+')"
    fi
    echo ""
    echo "============================================"
}

main() {
    check_root
    check_os
    install_deps
    install_rust
    clone_repo
    build_server
    create_config
    install_service
    configure_firewall
    start_service
    show_status
}

main "$@"
