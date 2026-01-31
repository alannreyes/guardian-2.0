#!/bin/bash
# =============================================================================
# Luxia Guardian 2.0 - Installation Script
# =============================================================================
# Usage: curl -sSL https://guardian.luxia.us/install.sh | bash
# Or:    ./install.sh [--server-name NAME] [--telegram-token TOKEN] [--telegram-chat CHAT_ID]
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GUARDIAN_DIR="/opt/luxia/guardian"
GUARDIAN_USER="guardian"
GUARDIAN_GROUP="guardian"
PYTHON_MIN_VERSION="3.10"
REPO_URL="https://github.com/luxia-us/guardian.git"  # TODO: Update when repo exists

# Parse arguments
SERVER_NAME=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
ANTHROPIC_KEY=""
SENDGRID_KEY=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --server-name)
            SERVER_NAME="$2"
            shift 2
            ;;
        --telegram-token)
            TELEGRAM_TOKEN="$2"
            shift 2
            ;;
        --telegram-chat)
            TELEGRAM_CHAT="$2"
            shift 2
            ;;
        --anthropic-key)
            ANTHROPIC_KEY="$2"
            shift 2
            ;;
        --sendgrid-key)
            SENDGRID_KEY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS. This script supports Ubuntu/Debian."
        exit 1
    fi

    . /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        log_warning "Untested OS: $ID. Continuing anyway..."
    fi

    log_success "OS: $PRETTY_NAME"
}

check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)"; then
            log_success "Python $PYTHON_VERSION"
            return 0
        fi
    fi

    log_info "Installing Python 3.10+..."
    apt-get update -qq
    apt-get install -y python3 python3-pip python3-venv
    log_success "Python installed"
}

install_dependencies() {
    log_info "Installing system dependencies..."
    apt-get update -qq
    apt-get install -y \
        git \
        curl \
        jq \
        sqlite3 \
        libffi-dev \
        libssl-dev \
        > /dev/null 2>&1

    log_success "System dependencies installed"
}

create_user() {
    if id "$GUARDIAN_USER" &>/dev/null; then
        log_success "User $GUARDIAN_USER already exists"
    else
        log_info "Creating guardian user..."
        useradd -r -s /usr/sbin/nologin -d "$GUARDIAN_DIR" "$GUARDIAN_USER"
        log_success "User $GUARDIAN_USER created"
    fi
}

create_directories() {
    log_info "Creating directory structure..."

    mkdir -p "$GUARDIAN_DIR"/{core,modules,data,logs,output,quarantine,secrets,templates}

    chown -R root:"$GUARDIAN_GROUP" "$GUARDIAN_DIR"
    chmod 750 "$GUARDIAN_DIR"
    chmod 700 "$GUARDIAN_DIR/secrets"

    log_success "Directories created"
}

setup_venv() {
    log_info "Setting up Python virtual environment..."

    python3 -m venv "$GUARDIAN_DIR/venv"
    source "$GUARDIAN_DIR/venv/bin/activate"

    pip install --upgrade pip > /dev/null

    pip install \
        anthropic \
        requests \
        pyyaml \
        jinja2 \
        pytz \
        sendgrid \
        > /dev/null 2>&1

    log_success "Virtual environment ready"
}

install_guardian() {
    log_info "Installing Guardian 2.0..."

    # For now, copy files from current directory or download
    # In production, this would clone from git

    # Check if we're running from the guardian directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SOURCE_DIR="$(dirname "$SCRIPT_DIR")"

    if [ -f "$SOURCE_DIR/guardian.py" ]; then
        log_info "Installing from local source..."
        cp "$SOURCE_DIR/guardian.py" "$GUARDIAN_DIR/"
        cp -r "$SOURCE_DIR/core" "$GUARDIAN_DIR/"
        cp -r "$SOURCE_DIR/modules" "$GUARDIAN_DIR/"
        cp "$SOURCE_DIR/config.example.yaml" "$GUARDIAN_DIR/"
    else
        log_warning "Source files not found. Please copy manually."
    fi

    chmod +x "$GUARDIAN_DIR/guardian.py"
    chown -R root:"$GUARDIAN_GROUP" "$GUARDIAN_DIR"

    log_success "Guardian installed to $GUARDIAN_DIR"
}

configure_guardian() {
    log_info "Configuring Guardian..."

    # Get server name if not provided
    if [ -z "$SERVER_NAME" ]; then
        SERVER_NAME=$(hostname)
    fi

    # Create config from example
    if [ ! -f "$GUARDIAN_DIR/config.yaml" ]; then
        if [ -f "$GUARDIAN_DIR/config.example.yaml" ]; then
            cp "$GUARDIAN_DIR/config.example.yaml" "$GUARDIAN_DIR/config.yaml"
        fi
    fi

    # Update config with provided values
    if [ -f "$GUARDIAN_DIR/config.yaml" ]; then
        # Using sed for basic replacements
        sed -i "s/name: \"vmi2959779\"/name: \"$SERVER_NAME\"/" "$GUARDIAN_DIR/config.yaml"

        if [ -n "$TELEGRAM_TOKEN" ]; then
            sed -i "s/bot_token: \"\"/bot_token: \"$TELEGRAM_TOKEN\"/" "$GUARDIAN_DIR/config.yaml"
        fi

        if [ -n "$TELEGRAM_CHAT" ]; then
            sed -i "s/chat_id: \"\"/chat_id: \"$TELEGRAM_CHAT\"/" "$GUARDIAN_DIR/config.yaml"
        fi
    fi

    # Create secrets file
    if [ -n "$ANTHROPIC_KEY" ] || [ -n "$SENDGRID_KEY" ] || [ -n "$TELEGRAM_TOKEN" ]; then
        cat > "$GUARDIAN_DIR/secrets/keys.yaml" << EOF
# Guardian Secrets - KEEP THIS FILE SECURE
# Permissions should be 600

anthropic_api_key: "${ANTHROPIC_KEY:-}"
sendgrid_api_key: "${SENDGRID_KEY:-}"
telegram_bot_token: "${TELEGRAM_TOKEN:-}"
EOF
        chmod 600 "$GUARDIAN_DIR/secrets/keys.yaml"
    fi

    chmod 640 "$GUARDIAN_DIR/config.yaml"
    log_success "Configuration created"
}

setup_systemd_service() {
    log_info "Setting up systemd service..."

    cat > /etc/systemd/system/guardian-sentinel.service << EOF
[Unit]
Description=Luxia Guardian 2.0 Sentinel
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=root
Group=$GUARDIAN_GROUP
WorkingDirectory=$GUARDIAN_DIR
ExecStart=$GUARDIAN_DIR/venv/bin/python $GUARDIAN_DIR/guardian.py sentinel
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=guardian

# Security
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=read-only

# Environment
Environment=GUARDIAN_CONFIG=$GUARDIAN_DIR/config.yaml

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

setup_cron() {
    log_info "Setting up cron jobs..."

    cat > /etc/cron.d/guardian << EOF
# Luxia Guardian 2.0 Cron Jobs
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily report at 4:30 AM
30 4 * * * root $GUARDIAN_DIR/venv/bin/python $GUARDIAN_DIR/guardian.py run >> $GUARDIAN_DIR/logs/daily.log 2>&1

# Update IOCs at 2:00 AM
0 2 * * * root $GUARDIAN_DIR/venv/bin/python $GUARDIAN_DIR/guardian.py update-iocs >> $GUARDIAN_DIR/logs/ioc-update.log 2>&1
EOF

    chmod 644 /etc/cron.d/guardian
    log_success "Cron jobs configured"
}

create_cli_symlink() {
    log_info "Creating CLI symlink..."

    cat > /usr/local/bin/guardian << EOF
#!/bin/bash
$GUARDIAN_DIR/venv/bin/python $GUARDIAN_DIR/guardian.py "\$@"
EOF

    chmod +x /usr/local/bin/guardian
    log_success "CLI available as 'guardian' command"
}

print_summary() {
    echo ""
    echo "============================================================"
    echo -e "${GREEN}Guardian 2.0 Installation Complete!${NC}"
    echo "============================================================"
    echo ""
    echo "Directory:    $GUARDIAN_DIR"
    echo "Config:       $GUARDIAN_DIR/config.yaml"
    echo "Secrets:      $GUARDIAN_DIR/secrets/keys.yaml"
    echo ""
    echo "Commands:"
    echo "  guardian check         - Run security check"
    echo "  guardian sentinel      - Start monitoring daemon"
    echo "  guardian update-iocs   - Update threat feeds"
    echo "  guardian status        - Show status"
    echo "  guardian test-notify   - Test notifications"
    echo ""
    echo "Service:"
    echo "  systemctl start guardian-sentinel    - Start daemon"
    echo "  systemctl enable guardian-sentinel   - Enable on boot"
    echo "  systemctl status guardian-sentinel   - Check status"
    echo ""
    echo "Next steps:"
    echo "  1. Edit $GUARDIAN_DIR/config.yaml"
    echo "  2. Add API keys to $GUARDIAN_DIR/secrets/keys.yaml"
    echo "  3. Run: guardian update-iocs"
    echo "  4. Run: guardian test-notify"
    echo "  5. Start: systemctl start guardian-sentinel"
    echo ""
    echo "============================================================"
}

# Main installation
main() {
    echo "============================================================"
    echo "     Luxia Guardian 2.0 - Installation"
    echo "============================================================"
    echo ""

    check_root
    check_os
    check_python
    install_dependencies
    create_user
    create_directories
    setup_venv
    install_guardian
    configure_guardian
    setup_systemd_service
    setup_cron
    create_cli_symlink
    print_summary
}

# Run main
main "$@"
