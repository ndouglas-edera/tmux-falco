#!/usr/bin/env bash
#
# install-falco-edera.sh
#
# Install/configure Falco with the Edera Falco plugin.
#
# Usage:
#   sudo ./install-falco-edera.sh
#   sudo ./install-falco-edera.sh --check
#   sudo ./install-falco-edera.sh --status
#   sudo ./install-falco-edera.sh --logs
#   sudo ./install-falco-edera.sh --follow
#   sudo ./install-falco-edera.sh --cleanup
#
# Environment:
#   FALCO_SERVICE=falco-modern-bpf.service
#

set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

FALCO_SERVICE="${FALCO_SERVICE:-falco-modern-bpf.service}"
FALCO_ALIAS="falco.service"

FALCO_CONFIG_DIR="/etc/falco"
FALCO_CONFIG_DROPIN_DIR="/etc/falco/config.d"
FALCO_RULES_DIR="/etc/falco/rules.d"

EDERA_PLUGIN="/var/lib/edera/protect/falco/libedera_falco_plugin.so"
EDERA_SOCKET="/var/lib/edera/protect/daemon.socket"

EDERA_CONFIG="${FALCO_CONFIG_DROPIN_DIR}/falco-edera-config.yaml"
EDERA_RULES="${FALCO_RULES_DIR}/falco-edera-rules.yaml"

LOG_LINES="${LOG_LINES:-100}"

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    RESET=''
fi

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

info() {
    echo -e "${BLUE}[INFO]${RESET} $*"
}

ok() {
    echo -e "${GREEN}[ OK ]${RESET} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${RESET} $*"
}

error() {
    echo -e "${RED}[ERROR]${RESET} $*" >&2
}

debug() {
    echo -e "${CYAN}[DEBUG]${RESET} $*"
}

section() {
    echo
    echo "============================================================"
    echo -e "${BOLD}$*${RESET}"
    echo "============================================================"
    echo
}

die() {
    error "$*"
    exit 1
}

# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

on_error() {
    local exit_code=$?
    local line_no="${BASH_LINENO[0]:-unknown}"

    echo
    echo "============================================================"
    error "Script failed at line ${line_no}"
    error "Exit code: ${exit_code}"
    echo "============================================================"
    echo

    warn "The installation may be partially complete."
    warn "Run:"
    echo
    echo "  sudo $0 --check"
    echo "  sudo $0 --status"
    echo "  sudo $0 --logs"
    echo

    exit "$exit_code"
}

trap on_error ERR

# ---------------------------------------------------------------------------
# Privilege checks
# ---------------------------------------------------------------------------

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This command must be run as root. Try: sudo $0 $*"
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

# ---------------------------------------------------------------------------
# Generic service helpers
# ---------------------------------------------------------------------------

service_exists() {
    systemctl cat "$FALCO_SERVICE" >/dev/null 2>&1
}

service_active() {
    systemctl is-active --quiet "$FALCO_SERVICE"
}

service_enabled() {
    systemctl is-enabled --quiet "$FALCO_SERVICE"
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

show_status() {
    require_root
    require_command systemctl

    section "Falco / Edera Status"

    echo -e "${BOLD}Service:${RESET}"
    echo "  ${FALCO_SERVICE}"
    echo

    if service_exists; then
        ok "Service unit exists"

        echo
        systemctl is-enabled "$FALCO_SERVICE" 2>&1 || true
        systemctl is-active "$FALCO_SERVICE" 2>&1 || true

        echo
        systemctl status "$FALCO_SERVICE" --no-pager -l || true
    else
        error "Service unit does not exist: ${FALCO_SERVICE}"
    fi

    echo
    echo -e "${BOLD}Alias:${RESET}"

    if [[ -L "/etc/systemd/system/${FALCO_ALIAS}" ]]; then
        ls -l "/etc/systemd/system/${FALCO_ALIAS}"
    elif [[ -e "/etc/systemd/system/${FALCO_ALIAS}" ]]; then
        ls -l "/etc/systemd/system/${FALCO_ALIAS}"
    else
        warn "No ${FALCO_ALIAS} alias found"
    fi

    echo
    echo -e "${BOLD}Falco binary:${RESET}"

    if command -v falco >/dev/null 2>&1; then
        falco --version || true
    else
        error "Falco binary not found"
    fi

    echo
    echo -e "${BOLD}Edera plugin:${RESET}"

    if [[ -f "$EDERA_PLUGIN" ]]; then
        ok "Plugin exists"
        ls -lh "$EDERA_PLUGIN"
    else
        error "Plugin missing: $EDERA_PLUGIN"
    fi

    echo
    echo -e "${BOLD}Edera daemon socket:${RESET}"

    if [[ -S "$EDERA_SOCKET" ]]; then
        ok "Socket exists"
        ls -l "$EDERA_SOCKET"
    else
        warn "Socket missing: $EDERA_SOCKET"
    fi

    echo
    echo -e "${BOLD}Edera Falco configuration:${RESET}"

    if [[ -f "$EDERA_CONFIG" ]]; then
        ok "$EDERA_CONFIG"
    else
        error "Missing: $EDERA_CONFIG"
    fi

    echo
    echo -e "${BOLD}Edera Falco rules:${RESET}"

    if [[ -f "$EDERA_RULES" ]]; then
        ok "$EDERA_RULES"
    else
        error "Missing: $EDERA_RULES"
    fi
}

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

show_logs() {
    require_root
    require_command journalctl

    section "Recent Falco Logs"

    info "Service: ${FALCO_SERVICE}"
    info "Showing last ${LOG_LINES} lines"
    echo

    journalctl \
        -u "$FALCO_SERVICE" \
        -n "$LOG_LINES" \
        --no-pager \
        -o short-precise || true
}

follow_logs() {
    require_root
    require_command journalctl

    section "Following Falco Logs"

    info "Service: ${FALCO_SERVICE}"
    info "Press Ctrl+C to stop"
    echo

    journalctl \
        -u "$FALCO_SERVICE" \
        -f \
        -o short-precise
}

# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

check_service() {
    local failures=0

    echo -e "${BOLD}1. Service unit${RESET}"

    if service_exists; then
        ok "Unit exists: ${FALCO_SERVICE}"
    else
        error "Unit missing: ${FALCO_SERVICE}"
        failures=$((failures + 1))
    fi

    echo
    echo -e "${BOLD}2. Service enabled${RESET}"

    if service_enabled; then
        ok "${FALCO_SERVICE} is enabled"
    else
        error "${FALCO_SERVICE} is NOT enabled"
        failures=$((failures + 1))
    fi

    echo
    echo -e "${BOLD}3. Service active${RESET}"

    if service_active; then
        ok "${FALCO_SERVICE} is active/running"
    else
        error "${FALCO_SERVICE} is NOT active"

        echo
        warn "Current service status:"
        systemctl status "$FALCO_SERVICE" --no-pager -l || true

        failures=$((failures + 1))
    fi

    return "$failures"
}

check_files() {
    local failures=0

    echo
    echo -e "${BOLD}4. Falco configuration${RESET}"

    if [[ -f "${FALCO_CONFIG_DIR}/falco.yaml" ]]; then
        ok "Default Falco configuration exists"
    else
        error "Missing ${FALCO_CONFIG_DIR}/falco.yaml"
        failures=$((failures + 1))
    fi

    if [[ -f "$EDERA_CONFIG" ]]; then
        ok "Edera configuration exists"
    else
        error "Missing $EDERA_CONFIG"
        failures=$((failures + 1))
    fi

    if [[ -f "$EDERA_RULES" ]]; then
        ok "Edera rules exist"
    else
        error "Missing $EDERA_RULES"
        failures=$((failures + 1))
    fi

    echo
    echo -e "${BOLD}5. Edera plugin${RESET}"

    if [[ -f "$EDERA_PLUGIN" && -x "$EDERA_PLUGIN" ]]; then
        ok "Edera plugin exists and is executable"
        ls -lh "$EDERA_PLUGIN"
    else
        error "Edera plugin missing or not executable"
        failures=$((failures + 1))
    fi

    echo
    echo -e "${BOLD}6. Edera daemon socket${RESET}"

    if [[ -S "$EDERA_SOCKET" ]]; then
        ok "Edera daemon socket exists"
        ls -l "$EDERA_SOCKET"
    else
        warn "Edera daemon socket does not exist"
        warn "This may mean the Edera daemon is not running."
        failures=$((failures + 1))
    fi

    return "$failures"
}

check_falco_config() {
    local failures=0

    echo
    echo -e "${BOLD}7. Falco configuration validation${RESET}"

    if ! command -v falco >/dev/null 2>&1; then
        error "Falco binary not found"
        return 1
    fi

    # Validate the configuration without starting another Falco daemon.
    #
    # Falco's exact CLI validation options can vary between versions, so
    # first use the installed binary's help output to determine whether
    # --dry-run is supported.
    if falco --help 2>&1 | grep -q -- '--dry-run'; then
        if falco --dry-run >/tmp/falco-edera-config-check.log 2>&1; then
            ok "Falco configuration validation passed"
        else
            error "Falco configuration validation failed"
            cat /tmp/falco-edera-config-check.log
            failures=$((failures + 1))
        fi
    else
        warn "This Falco build does not expose --dry-run"
        warn "Relying on the running service and journal configuration checks"
    fi

    return "$failures"
}

check_logs() {
    local failures=0
    local logs

    echo
    echo -e "${BOLD}8. Recent Falco log state${RESET}"

    logs="$(journalctl -u "$FALCO_SERVICE" -n 100 --no-pager 2>/dev/null || true)"

    if [[ -z "$logs" ]]; then
        warn "No journal entries found"
        return 0
    fi

    if grep -q "Main process exited" <<<"$logs"; then
        error "Falco has recently exited"
        failures=$((failures + 1))
    fi

    if grep -q "Failed with result" <<<"$logs"; then
        error "systemd reports a recent Falco failure"
        failures=$((failures + 1))
    fi

    if grep -q "Loaded plugin 'edera@" <<<"$logs"; then
        ok "Edera plugin was loaded by Falco"
    else
        error "No evidence of the Edera plugin being loaded"
        failures=$((failures + 1))
    fi

    if grep -q "edera_zone" <<<"$logs"; then
        ok "Edera event source is present in Falco logs"
    else
        error "No evidence of edera_zone event source"
        failures=$((failures + 1))
    fi

    if grep -q "Enabled event sources:.*edera_zone" <<<"$logs"; then
        ok "edera_zone event source is enabled"
    else
        warn "edera_zone is not shown as enabled in recent logs"
    fi

    if grep -q "waiting for zones" <<<"$logs"; then
        ok "Edera plugin is waiting for zones"
        info "This is expected when no Edera zone is currently available."
    fi

    echo
    echo -e "${BOLD}Relevant recent messages:${RESET}"

    grep -Ei \
        "edera|error|failed|warning|loaded event sources|enabled event sources|waiting for zones|SIGHUP" \
        <<<"$logs" \
        | tail -50 || true

    return "$failures"
}

run_check() {
    require_root

    section "Falco + Edera Health Check"

    local failures=0

    check_service || failures=$((failures + 1))
    check_files || failures=$((failures + 1))
    check_falco_config || failures=$((failures + 1))
    check_logs || failures=$((failures + 1))

    echo
    echo "============================================================"

    if [[ "$failures" -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}[ PASS ] Falco + Edera health check passed${RESET}"
        echo "============================================================"
        echo
        info "Falco is running and the Edera integration is loaded."
        info "If the plugin says 'waiting for zones', create/use an Edera zone"
        info "and then run:"
        echo
        echo "  sudo $0 --follow"
        echo
        return 0
    fi

    echo -e "${RED}${BOLD}[ FAIL ] ${failures} health-check area(s) need attention${RESET}"
    echo "============================================================"
    echo

    warn "Run the following for more information:"
    echo
    echo "  sudo $0 --status"
    echo "  sudo $0 --logs"
    echo

    return 1
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    require_root
    require_command systemctl

    section "Falco + Edera Cleanup"

    warn "This removes the Edera-specific Falco configuration and rules."
    warn "It does NOT uninstall Falco itself."
    echo

    read -r -p "Continue? [y/N] " answer

    case "$answer" in
        y|Y|yes|YES)
            ;;
        *)
            info "Cleanup cancelled."
            return 0
            ;;
    esac

    echo

    info "Stopping ${FALCO_SERVICE}..."

    if service_exists; then
        systemctl stop "$FALCO_SERVICE" || true
    fi

    info "Removing Edera Falco configuration..."

    rm -f "$EDERA_CONFIG"
    rm -f "$EDERA_RULES"

    ok "Removed Edera Falco configuration files"

    info "Reloading systemd..."

    systemctl daemon-reload

    info "Starting ${FALCO_SERVICE} again..."

    if service_exists; then
        systemctl start "$FALCO_SERVICE" || true
    fi

    echo
    ok "Cleanup complete."
    echo

    info "Falco itself was NOT uninstalled."
    info "The Edera plugin binary was NOT removed."
    info "The Edera daemon was NOT removed."
}

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

install_falco() {
    section "Installing Falco + Edera Integration"

    info "Falco service: ${FALCO_SERVICE}"
    info "Edera plugin:  ${EDERA_PLUGIN}"
    info "Edera socket:  ${EDERA_SOCKET}"

    # -----------------------------------------------------------------------
    # Step 1
    # -----------------------------------------------------------------------

    section "Step 1: Checking prerequisites"

    require_command systemctl
    require_command curl
    require_command apt-get

    ok "Required commands are available"

    # -----------------------------------------------------------------------
    # Step 2
    # -----------------------------------------------------------------------

    section "Step 2: Checking Edera"

    if [[ -S "$EDERA_SOCKET" ]]; then
        ok "Edera daemon socket exists"
    else
        warn "Edera daemon socket not found:"
        warn "  ${EDERA_SOCKET}"
        warn "The Falco plugin may remain in 'waiting for zones' state."
    fi

    # -----------------------------------------------------------------------
    # Step 3
    # -----------------------------------------------------------------------

    section "Step 3: Installing Falco"

    # Keep the existing Falco installation mechanism here.
    #
    # Example:
    #
    # curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
    #   | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    #
    # ... repository setup ...
    #
    # apt-get update
    # apt-get install -y falco

    if command -v falco >/dev/null 2>&1; then
        ok "Falco is already installed"
        falco --version || true
    else
        die "Falco is not installed. Insert/use the existing Falco installation block here."
    fi

    # -----------------------------------------------------------------------
    # Step 4
    # -----------------------------------------------------------------------

    section "Step 4: Checking Falco service"

    if service_exists; then
        ok "Found ${FALCO_SERVICE}"
    else
        die "Expected Falco service not found: ${FALCO_SERVICE}"
    fi

    # -----------------------------------------------------------------------
    # Step 5
    # -----------------------------------------------------------------------

    section "Step 5: Checking Edera plugin"

    if [[ ! -f "$EDERA_PLUGIN" ]]; then
        die "Edera Falco plugin not found: ${EDERA_PLUGIN}"
    fi

    if [[ ! -x "$EDERA_PLUGIN" ]]; then
        chmod +x "$EDERA_PLUGIN"
    fi

    ok "Edera plugin exists:"
    ls -lh "$EDERA_PLUGIN"

    # -----------------------------------------------------------------------
    # Step 6
    # -----------------------------------------------------------------------

    section "Step 6: Enabling Falco"

    systemctl daemon-reload

    # IMPORTANT:
    # Do NOT run:
    #
    #   systemctl enable falco.service
    #
    # because falco.service may be an alias/symlink to the real unit.
    #
    systemctl enable "$FALCO_SERVICE"

    ok "Enabled ${FALCO_SERVICE}"

    # -----------------------------------------------------------------------
    # Step 7
    # -----------------------------------------------------------------------

    section "Step 7: Writing Edera plugin configuration"

    mkdir -p "$FALCO_CONFIG_DROPIN_DIR"

    cat > "$EDERA_CONFIG" <<'EOF'
plugins:
  - name: edera
    library_path: /var/lib/edera/protect/falco/libedera_falco_plugin.so
    init_config: {}

load_plugins:
  - edera

source_plugin:
  name: edera_zone
  library_path: /var/lib/edera/protect/falco/libedera_falco_plugin.so
EOF

    ok "Created:"
    echo "  ${EDERA_CONFIG}"

    # -----------------------------------------------------------------------
    # Step 8
    # -----------------------------------------------------------------------

    section "Step 8: Writing Edera detection rules"

    mkdir -p "$FALCO_RULES_DIR"

    cat > "$EDERA_RULES" <<'EOF'
# Edera Falco detection rules.
#
# Add Edera-specific detection rules here.
#
# The Edera event source is:
#
#   edera_zone
#
EOF

    ok "Created:"
    echo "  ${EDERA_RULES}"

    # -----------------------------------------------------------------------
    # Step 9
    # -----------------------------------------------------------------------

    section "Step 9: Restarting Falco"

    systemctl daemon-reload

    info "Restarting ${FALCO_SERVICE}..."

    systemctl restart "$FALCO_SERVICE"

    ok "Falco restart command completed"

    # -----------------------------------------------------------------------
    # Step 10
    # -----------------------------------------------------------------------

    section "Step 10: Waiting for Falco"

    local attempts=0

    while [[ "$attempts" -lt 10 ]]; do
        if service_active; then
            ok "Falco is active"
            break
        fi

        attempts=$((attempts + 1))
        sleep 1
    done

    if ! service_active; then
        error "Falco did not become active"

        systemctl status "$FALCO_SERVICE" --no-pager -l || true

        echo
        warn "Recent logs:"
        journalctl -u "$FALCO_SERVICE" -n 100 --no-pager || true

        die "Falco startup failed"
    fi

    # -----------------------------------------------------------------------
    # Step 11
    # -----------------------------------------------------------------------

    section "Step 11: Verifying Edera integration"

    sleep 2

    systemctl status "$FALCO_SERVICE" --no-pager -l || true

    echo
    info "Checking recent Edera messages..."

    journalctl \
        -u "$FALCO_SERVICE" \
        -n 100 \
        --no-pager \
        | grep -Ei \
            "edera|loaded event sources|enabled event sources|waiting for zones" \
        | tail -50 \
        || true

    # -----------------------------------------------------------------------
    # Step 12
    # -----------------------------------------------------------------------

    section "Step 12: Installation Summary"

    if service_active; then
        ok "Falco service: ACTIVE"
    else
        error "Falco service: INACTIVE"
    fi

    if [[ -f "$EDERA_PLUGIN" ]]; then
        ok "Edera plugin: PRESENT"
    else
        error "Edera plugin: MISSING"
    fi

    if [[ -f "$EDERA_CONFIG" ]]; then
        ok "Edera config: PRESENT"
    else
        error "Edera config: MISSING"
    fi

    if [[ -f "$EDERA_RULES" ]]; then
        ok "Edera rules: PRESENT"
    else
        error "Edera rules: MISSING"
    fi

    if [[ -S "$EDERA_SOCKET" ]]; then
        ok "Edera socket: PRESENT"
    else
        warn "Edera socket: NOT PRESENT"
    fi

    echo
    echo "Useful commands:"
    echo
    echo "  sudo $0 --check"
    echo "  sudo $0 --status"
    echo "  sudo $0 --logs"
    echo "  sudo $0 --follow"
    echo "  sudo systemctl status ${FALCO_SERVICE} --no-pager -l"
    echo
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF

Falco + Edera installer / diagnostics

Usage:

  sudo $0                  Install/configure Falco + Edera
  sudo $0 --check          Run health checks
  sudo $0 --status         Show service/files/plugin status
  sudo $0 --logs           Show recent Falco logs
  sudo $0 --follow         Follow Falco logs live
  sudo $0 --cleanup        Remove Edera Falco configuration
  sudo $0 --help           Show this help

Environment:

  LOG_LINES=200 sudo $0 --logs

Service:

  ${FALCO_SERVICE}

EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local command="${1:-install}"

    case "$command" in
        install)
            require_root
            install_falco
            ;;

        --check|check)
            run_check
            ;;

        --status|status)
            show_status
            ;;

        --logs|logs)
            show_logs
            ;;

        --follow|follow)
            follow_logs
            ;;

        --cleanup|cleanup)
            cleanup
            ;;

        --help|-h|help)
            usage
            ;;

        *)
            error "Unknown option: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
