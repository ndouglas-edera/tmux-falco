#!/usr/bin/env bash

# ============================================================================
# Edera + Falco installer / configurator
#
# Designed for:
#   - Falco 0.44.x
#   - Edera Protect installation already present on the host
#   - modern eBPF Falco engine
#
# This script does NOT install Edera itself.
# It configures the Edera Falco plugin supplied by the Edera installation.
#
# Usage:
#   sudo ./install-falco-edera-v2.sh
#   sudo ./install-falco-edera-v2.sh --check
#   sudo ./install-falco-edera-v2.sh --status
#   sudo ./install-falco-edera-v2.sh --logs
#   sudo ./install-falco-edera-v2.sh --cleanup
# ============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

readonly EDERA_ROOT="/var/lib/edera/protect"
readonly EDERA_SOCKET="${EDERA_ROOT}/daemon.socket"
readonly EDERA_PLUGIN="${EDERA_ROOT}/falco/libedera_falco_plugin.so"

readonly FALCO_CONFIG="/etc/falco/falco.yaml"
readonly FALCO_CONFIG_DROPIN_DIR="/etc/falco/config.d"
readonly FALCO_RULES_DIR="/etc/falco/rules.d"

readonly EDERA_CONFIG="${FALCO_CONFIG_DROPIN_DIR}/falco-edera-config.yaml"
readonly EDERA_CONFIG_BACKUP="${EDERA_CONFIG}.bak"
readonly EDERA_RULES="${FALCO_RULES_DIR}/falco-edera-rules.yaml"

readonly EDERA_SERVICE="protect-daemon.service"

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    readonly RED=$'\033[0;31m'
    readonly GREEN=$'\033[0;32m'
    readonly YELLOW=$'\033[1;33m'
    readonly BLUE=$'\033[0;34m'
    readonly CYAN=$'\033[0;36m'
    readonly BOLD=$'\033[1m'
    readonly RESET=$'\033[0m'
else
    readonly RED=""
    readonly GREEN=""
    readonly YELLOW=""
    readonly BLUE=""
    readonly CYAN=""
    readonly BOLD=""
    readonly RESET=""
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

info() {
    printf '%s[%s INFO]%s %s\n' "$BLUE" "$(timestamp)" "$RESET" "$*"
}

ok() {
    printf '%s[ OK ]%s %s\n' "$GREEN" "$RESET" "$*"
}

warn() {
    printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*"
}

error() {
    printf '%s[ERROR]%s %s\n' "$RED" "$RESET" "$*" >&2
}

section() {
    echo
    printf '%s============================================================%s\n' \
        "$BOLD" "$RESET"
    printf '%s%s%s\n' "$BOLD" "$*" "$RESET"
    printf '%s============================================================%s\n' \
        "$BOLD" "$RESET"
    echo
}

# Print commands before executing them.
run() {
    printf '%s$%s' "$CYAN" "$RESET"

    printf ' %q' "$@"
    echo

    "$@"
}

# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

on_error() {
    local rc=$?
    error "Command failed with exit code ${rc}."
    error "Line: ${BASH_LINENO[0]:-unknown}"
    exit "$rc"
}

trap on_error ERR

# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "Run this script as root:"
        echo
        echo "  sudo $0"
        exit 1
    fi
}

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        error "Required command not found: $command_name"
        return 1
    fi
}

check_commands() {
    section "Checking required commands"

    local commands=(
        bash
        find
        grep
        sed
        awk
        systemctl
        journalctl
        ss
        install
    )

    local failed=0

    for cmd in "${commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            ok "$cmd"
        else
            error "Missing command: $cmd"
            failed=1
        fi
    done

    if [[ "$failed" -ne 0 ]]; then
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Falco service detection
# ---------------------------------------------------------------------------

FALCO_SERVICE=""

detect_falco_service() {
    section "Detecting Falco service"

    local candidates=(
        "falco.service"
        "falco-modern-bpf.service"
        "falco-custom.service"
    )

    local service

    for service in "${candidates[@]}"; do
        if systemctl list-unit-files "$service" \
            --no-legend 2>/dev/null | grep -q "^${service}"; then

            FALCO_SERVICE="$service"
            ok "Detected Falco service: $FALCO_SERVICE"
            return 0
        fi
    done

    # Generic fallback.
    while IFS= read -r service; do
        service="${service%% *}"

        if [[ "$service" == falco*.service ]]; then
            FALCO_SERVICE="$service"
            ok "Detected Falco service: $FALCO_SERVICE"
            return 0
        fi
    done < <(
        systemctl list-unit-files \
            --type=service \
            --no-legend 2>/dev/null || true
    )

    error "Could not find a Falco systemd service."
    return 1
}

service_exists() {
    [[ -n "$FALCO_SERVICE" ]] &&
        systemctl cat "$FALCO_SERVICE" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Edera checks
# ---------------------------------------------------------------------------

check_edera_installation() {
    section "Checking Edera installation"

    if [[ -d "$EDERA_ROOT" ]]; then
        ok "Edera directory exists: $EDERA_ROOT"
    else
        error "Missing Edera directory: $EDERA_ROOT"
        return 1
    fi

    if [[ -f "$EDERA_PLUGIN" ]]; then
        ok "Edera Falco plugin exists:"
        echo "    $EDERA_PLUGIN"
    else
        error "Missing Edera Falco plugin:"
        echo "    $EDERA_PLUGIN"
        return 1
    fi

    if [[ -x /usr/sbin/protect-daemon ]]; then
        ok "protect-daemon exists: /usr/sbin/protect-daemon"
    else
        warn "protect-daemon binary was not found at /usr/sbin/protect-daemon"
    fi
}

check_edera_service() {
    section "Checking Edera Protect Daemon"

    if systemctl cat "$EDERA_SERVICE" >/dev/null 2>&1; then
        ok "Systemd unit exists: $EDERA_SERVICE"
    else
        error "Systemd unit not found: $EDERA_SERVICE"
        return 1
    fi

    if systemctl is-active --quiet "$EDERA_SERVICE"; then
        ok "Edera Protect Daemon is active"
    else
        error "Edera Protect Daemon is not active"
        systemctl status "$EDERA_SERVICE" --no-pager || true
        return 1
    fi
}

check_edera_socket() {
    section "Checking Edera daemon socket"

    if [[ ! -S "$EDERA_SOCKET" ]]; then
        error "Edera daemon socket does not exist:"
        echo "    $EDERA_SOCKET"
        return 1
    fi

    ok "Edera daemon socket exists:"
    echo "    $EDERA_SOCKET"

    if ss -lxnp 2>/dev/null |
        grep -Fq "$EDERA_SOCKET"; then
        ok "Edera daemon socket is listening"
    else
        warn "Socket exists but could not be confirmed in ss output"
    fi

    if command -v lsof >/dev/null 2>&1; then
        local owner

        owner="$(
            lsof -U 2>/dev/null |
                grep -F "$EDERA_SOCKET" |
                head -n 1 || true
        )"

        if [[ -n "$owner" ]]; then
            ok "Socket owner:"
            echo "    $owner"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Stale configuration handling
# ---------------------------------------------------------------------------

find_stale_backups() {
    find "$FALCO_CONFIG_DROPIN_DIR" \
        -maxdepth 1 \
        -type f \
        \( \
            -name 'falco-edera-config.yaml.bak' \
            -o -name 'falco-edera-config.yml.bak' \
            -o -name 'falco-edera-*.bak' \
        \) \
        -print0 2>/dev/null
}

remove_stale_backups() {
    local removed=0
    local file

    while IFS= read -r -d '' file; do
        info "Removing stale Edera backup: $file"
        rm -f -- "$file"
        removed=$((removed + 1))
    done < <(find_stale_backups)

    if [[ "$removed" -eq 0 ]]; then
        ok "No stale Edera configuration backups found"
    else
        ok "Removed $removed stale Edera backup(s)"
    fi
}

check_stale_backups() {
    section "Checking stale Edera configuration backups"

    local found=0
    local file

    while IFS= read -r -d '' file; do
        warn "Stale Edera configuration found:"
        echo "    $file"
        found=1
    done < <(find_stale_backups)

    if [[ "$found" -eq 0 ]]; then
        ok "No stale Edera configuration backups found"
        return 0
    fi

    return 1
}

# ---------------------------------------------------------------------------
# Falco configuration
# ---------------------------------------------------------------------------

write_edera_config() {
    section "Writing Edera Falco plugin configuration"

    install -d -m 0755 "$FALCO_CONFIG_DROPIN_DIR"

    # Remove the exact backup first.
    rm -f -- "$EDERA_CONFIG_BACKUP"

    # Remove any other Edera backups.
    remove_stale_backups

    cat > "$EDERA_CONFIG" <<EOF
plugins:
  - name: edera
    library_path: ${EDERA_PLUGIN}
    init_config: ""

load_plugins:
  - edera
EOF

    chmod 0644 "$EDERA_CONFIG"

    ok "Wrote:"
    echo "    $EDERA_CONFIG"

    echo
    cat "$EDERA_CONFIG"
}

write_edera_rules() {
    section "Writing Edera Falco rules"

    install -d -m 0755 "$FALCO_RULES_DIR"

    cat > "$EDERA_RULES" <<'EOF'
# Edera Falco detection rules.
#
# The Edera event source is:
#
#   edera_zone
#
# Add Edera-specific detection rules here.
#
# This file intentionally contains no rules by default.
EOF

    chmod 0644 "$EDERA_RULES"

    ok "Wrote:"
    echo "    $EDERA_RULES"
}

# ---------------------------------------------------------------------------
# Falco configuration validation
# ---------------------------------------------------------------------------

validate_falco_configuration() {
    section "Validating Falco configuration"

    if [[ ! -f "$FALCO_CONFIG" ]]; then
        error "Falco configuration not found:"
        echo "    $FALCO_CONFIG"
        return 1
    fi

    if [[ ! -f "$EDERA_CONFIG" ]]; then
        error "Edera Falco configuration not found:"
        echo "    $EDERA_CONFIG"
        return 1
    fi

    if ! command -v falco >/dev/null 2>&1; then
        error "falco executable not found"
        return 1
    fi

    info "Running Falco configuration validation..."

    local output
    local rc=0

    output="$(
        timeout 15 \
            falco \
            -c "$FALCO_CONFIG" \
            -M 1 \
            2>&1
    )" || rc=$?

    printf '%s\n' "$output" | sed -n '1,120p'

    # timeout(124) is acceptable here if Falco successfully initializes
    # and then gets terminated by timeout.
    if printf '%s\n' "$output" |
        grep -qE \
        'schema validation: (ok|none)|Loaded plugin .edera.|Loaded event sources:.*edera_zone'; then

        ok "Falco accepted the Edera configuration"
    else
        error "Could not confirm successful Falco initialization"
        return 1
    fi

    if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        warn "Falco returned exit code $rc during the short validation run"
    fi
}

# ---------------------------------------------------------------------------
# Plugin inspection
# ---------------------------------------------------------------------------

check_edera_plugin() {
    section "Checking Edera plugin"

    if ! command -v falco >/dev/null 2>&1; then
        error "falco command not found"
        return 1
    fi

    local output

    output="$(
        falco --list-plugins 2>&1 || true
    )"

    if printf '%s\n' "$output" | grep -qiE '^Name: edera$'; then
        ok "Edera plugin is loaded by Falco"

        printf '%s\n' "$output" |
            grep -i -A8 -B1 '^Name: edera$' ||
            true
    else
        error "Falco did not report the Edera plugin"
        printf '%s\n' "$output"
        return 1
    fi
}

check_edera_source() {
    section "Checking Edera event source"

    local output

    output="$(
        timeout 15 \
            falco \
            -c "$FALCO_CONFIG" \
            -M 1 \
            -v 2>&1 || true
    )"

    if printf '%s\n' "$output" |
        grep -q 'edera_zone'; then

        ok "Edera event source edera_zone is available"
    else
        error "Edera event source edera_zone was not detected"
        return 1
    fi

    if printf '%s\n' "$output" |
        grep -q 'Loaded plugin .edera@'; then

        ok "Falco loaded the Edera plugin"
    else
        warn "Could not confirm plugin load from verbose output"
    fi
}

# ---------------------------------------------------------------------------
# Falco service operations
# ---------------------------------------------------------------------------

restart_falco() {
    section "Restarting Falco"

    if ! service_exists; then
        error "Falco service is not available"
        return 1
    fi

    run systemctl daemon-reload
    run systemctl restart "$FALCO_SERVICE"

    sleep 2

    if systemctl is-active --quiet "$FALCO_SERVICE"; then
        ok "Falco is active: $FALCO_SERVICE"
    else
        error "Falco failed to become active"
        systemctl status "$FALCO_SERVICE" --no-pager || true
        return 1
    fi
}

enable_falco() {
    section "Enabling Falco"

    if ! service_exists; then
        return 1
    fi

    run systemctl enable "$FALCO_SERVICE"

    ok "Enabled $FALCO_SERVICE"
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

show_status() {
    section "Edera + Falco status"

    if [[ -z "$FALCO_SERVICE" ]]; then
        detect_falco_service || true
    fi

    echo "Falco service:"
    echo "  ${FALCO_SERVICE:-not detected}"
    echo

    if [[ -n "$FALCO_SERVICE" ]]; then
        systemctl status "$FALCO_SERVICE" --no-pager || true
    fi

    echo
    echo "Edera service:"
    systemctl status "$EDERA_SERVICE" --no-pager || true

    echo
    echo "Edera socket:"
    ls -l "$EDERA_SOCKET" 2>/dev/null || true

    echo
    echo "Edera plugin:"
    ls -l "$EDERA_PLUGIN" 2>/dev/null || true

    echo
    echo "Edera configuration:"
    ls -l "$EDERA_CONFIG" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

show_logs() {
    section "Recent Edera + Falco logs"

    echo "--- Edera Protect Daemon ---"
    journalctl \
        -u "$EDERA_SERVICE" \
        --since "30 minutes ago" \
        --no-pager || true

    echo
    echo "--- Falco ---"

    if [[ -n "$FALCO_SERVICE" ]]; then
        journalctl \
            -u "$FALCO_SERVICE" \
            --since "30 minutes ago" \
            --no-pager || true
    fi
}

# ---------------------------------------------------------------------------
# Full health check
# ---------------------------------------------------------------------------

health_check() {
    local failures=0

    section "Edera + Falco health check"

    detect_falco_service || failures=$((failures + 1))
    check_edera_installation || failures=$((failures + 1))
    check_edera_service || failures=$((failures + 1))
    check_edera_socket || failures=$((failures + 1))

    if [[ -n "$FALCO_SERVICE" ]]; then
        if systemctl is-active --quiet "$FALCO_SERVICE"; then
            ok "Falco service is active"
        else
            error "Falco service is not active"
            failures=$((failures + 1))
        fi
    fi

    [[ -f "$EDERA_CONFIG" ]] || {
        error "Missing Edera Falco configuration"
        failures=$((failures + 1))
    }

    check_stale_backups || failures=$((failures + 1))
    check_edera_plugin || failures=$((failures + 1))
    check_edera_source || failures=$((failures + 1))

    echo

    if [[ "$failures" -eq 0 ]]; then
        ok "HEALTH CHECK PASSED"
        return 0
    fi

    error "HEALTH CHECK FAILED: $failures check(s)"
    return 1
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    section "Removing Edera Falco configuration"

    if [[ -n "$FALCO_SERVICE" ]] &&
        systemctl is-active --quiet "$FALCO_SERVICE"; then

        info "Stopping $FALCO_SERVICE..."
        systemctl stop "$FALCO_SERVICE" || true
    fi

    rm -f -- "$EDERA_CONFIG"
    rm -f -- "$EDERA_CONFIG_BACKUP"
    rm -f -- "$EDERA_RULES"

    # IMPORTANT:
    # Single backslashes only.
    #
    # This was the bug in the previous script.
    find "$FALCO_CONFIG_DROPIN_DIR" \
        -maxdepth 1 \
        -type f \
        \( \
            -name 'falco-edera-config.yaml.bak' \
            -o -name 'falco-edera-config.yml.bak' \
            -o -name 'falco-edera-*.bak' \
        \) \
        -delete 2>/dev/null || true

    ok "Removed Edera Falco configuration"

    if [[ -n "$FALCO_SERVICE" ]] &&
        service_exists; then

        systemctl daemon-reload
        systemctl start "$FALCO_SERVICE" || true
    fi

    ok "Cleanup complete"
}

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

install_integration() {
    section "Step 1: Preconditions"

    check_commands

    section "Step 2: Detect Falco"

    detect_falco_service

    section "Step 3: Check Edera"

    check_edera_installation
    check_edera_service
    check_edera_socket

    section "Step 4: Prepare Falco directories"

    run install -d -m 0755 "$FALCO_CONFIG_DROPIN_DIR"
    run install -d -m 0755 "$FALCO_RULES_DIR"

    ok "Falco configuration directories ready"

    section "Step 5: Remove stale Edera configuration backups"

    remove_stale_backups

    section "Step 6: Write Edera plugin configuration"

    write_edera_config

    section "Step 7: Write Edera rules file"

    write_edera_rules

    section "Step 8: Validate configuration before restart"

    validate_falco_configuration

    section "Step 9: Restart Falco"

    restart_falco

    section "Step 10: Enable Falco"

    enable_falco

    section "Step 11: Verify Edera plugin"

    check_edera_plugin
    check_edera_source

    section "Step 12: Final health check"

    health_check

    section "Installation complete"

    ok "Falco + Edera integration is configured"

    echo
    echo "Falco service:"
    echo "  $FALCO_SERVICE"

    echo
    echo "Edera daemon:"
    echo "  $EDERA_SERVICE"

    echo
    echo "Edera socket:"
    echo "  $EDERA_SOCKET"

    echo
    echo "Edera plugin:"
    echo "  $EDERA_PLUGIN"

    echo
    echo "Edera event source:"
    echo "  edera_zone"
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage:
  sudo $0                  Install/configure Edera + Falco
  sudo $0 --check          Run health checks
  sudo $0 --status         Show service status
  sudo $0 --logs           Show recent logs
  sudo $0 --cleanup        Remove Edera Falco configuration
  sudo $0 --help           Show this help

This script configures the Edera Falco plugin already installed under:

  $EDERA_ROOT
EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    require_root

    local action="${1:-install}"

    case "$action" in

        install)
            install_integration
            ;;

        --check|check)
            check_commands
            detect_falco_service
            health_check
            ;;

        --status|status)
            detect_falco_service || true
            show_status
            ;;

        --logs|logs)
            detect_falco_service || true
            show_logs
            ;;

        --cleanup|cleanup)
            detect_falco_service || true
            cleanup
            ;;

        --help|-h|help)
            usage
            ;;

        *)
            error "Unknown option: $action"
            echo
            usage
            exit 2
            ;;
    esac
}

main "$@"
