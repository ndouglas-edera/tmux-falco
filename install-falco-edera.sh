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
#   LOG_LINES=100
#
# The script intentionally prints the commands it executes.
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

FALCO_MAIN_CONFIG="${FALCO_CONFIG_DIR}/falco.yaml"

EDERA_PLUGIN="/var/lib/edera/protect/falco/libedera_falco_plugin.so"
EDERA_SOCKET="/var/lib/edera/protect/daemon.socket"

EDERA_CONFIG="${FALCO_CONFIG_DROPIN_DIR}/falco-edera-config.yaml"
EDERA_RULES="${FALCO_RULES_DIR}/falco-edera-rules.yaml"

BACKUP_DIR="/var/backups/falco-edera"

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
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    MAGENTA=''
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

command_log() {
    echo -e "${MAGENTA}[CMD ]${RESET} $*"
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
# Command execution helpers
#
# Every command executed through these helpers is displayed first.
# ---------------------------------------------------------------------------

print_cmd() {
    local arg
    printf '%s' "${MAGENTA}[CMD ]${RESET} "

    for arg in "$@"; do
        printf '%q ' "$arg"
    done

    printf '\n'
}

run_cmd() {
    print_cmd "$@"
    "$@"
}

run_cmd_quiet() {
    print_cmd "$@"
    "$@" >/dev/null
}

run_cmd_capture() {
    print_cmd "$@"
    "$@"
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
    echo
    echo "Recommended diagnostics:"
    echo
    echo "  sudo $0 --check"
    echo "  sudo $0 --status"
    echo "  sudo $0 --logs"
    echo

    exit "$exit_code"
}

trap on_error ERR

# ---------------------------------------------------------------------------
# Privilege / command checks
# ---------------------------------------------------------------------------

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This command must be run as root. Try: sudo $0 $*"
    fi
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die "Required command not found: $1"
    fi
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
# Utility: timestamp
# ---------------------------------------------------------------------------

timestamp() {
    date '+%Y%m%d-%H%M%S'
}

# ---------------------------------------------------------------------------
# Utility: backup a file if it exists
# ---------------------------------------------------------------------------

backup_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        return 0
    fi

    mkdir -p "$BACKUP_DIR"

    local base
    local backup

    base="$(basename "$file")"
    backup="${BACKUP_DIR}/${base}.$(timestamp).bak"

    print_cmd cp -a "$file" "$backup"
    cp -a "$file" "$backup"

    ok "Backed up ${file}"
    echo "     -> ${backup}"
}

# ---------------------------------------------------------------------------
# Utility: show a file
# ---------------------------------------------------------------------------

show_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        warn "File does not exist: $file"
        return 0
    fi

    echo
    echo "----- ${file} -----"

    print_cmd sed -n '1,240p' "$file"
    sed -n '1,240p' "$file"

    echo "----- end ${file} -----"
    echo
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
        print_cmd systemctl is-enabled "$FALCO_SERVICE"
        systemctl is-enabled "$FALCO_SERVICE" 2>&1 || true

        print_cmd systemctl is-active "$FALCO_SERVICE"
        systemctl is-active "$FALCO_SERVICE" 2>&1 || true

        echo
        print_cmd systemctl status "$FALCO_SERVICE" --no-pager -l
        systemctl status "$FALCO_SERVICE" --no-pager -l || true
    else
        error "Service unit does not exist: ${FALCO_SERVICE}"
    fi

    echo
    echo -e "${BOLD}Alias:${RESET}"

    if [[ -L "/etc/systemd/system/${FALCO_ALIAS}" ]]; then
        print_cmd ls -l "/etc/systemd/system/${FALCO_ALIAS}"
        ls -l "/etc/systemd/system/${FALCO_ALIAS}"
    elif [[ -e "/etc/systemd/system/${FALCO_ALIAS}" ]]; then
        print_cmd ls -l "/etc/systemd/system/${FALCO_ALIAS}"
        ls -l "/etc/systemd/system/${FALCO_ALIAS}"
    else
        warn "No ${FALCO_ALIAS} alias found"
    fi

    echo
    echo -e "${BOLD}Falco binary:${RESET}"

    if command -v falco >/dev/null 2>&1; then
        print_cmd falco --version
        falco --version || true
    else
        error "Falco binary not found"
    fi

    echo
    echo -e "${BOLD}Falco main configuration:${RESET}"

    if [[ -f "$FALCO_MAIN_CONFIG" ]]; then
        ok "$FALCO_MAIN_CONFIG exists"
    else
        error "Missing $FALCO_MAIN_CONFIG"
    fi

    echo
    echo -e "${BOLD}Edera plugin:${RESET}"

    if [[ -f "$EDERA_PLUGIN" ]]; then
        ok "Plugin exists"

        print_cmd ls -lh "$EDERA_PLUGIN"
        ls -lh "$EDERA_PLUGIN"
    else
        error "Plugin missing: $EDERA_PLUGIN"
    fi

    echo
    echo -e "${BOLD}Edera daemon socket:${RESET}"

    if [[ -S "$EDERA_SOCKET" ]]; then
        ok "Socket exists"

        print_cmd ls -l "$EDERA_SOCKET"
        ls -l "$EDERA_SOCKET"
    else
        warn "Socket missing: $EDERA_SOCKET"
    fi

    echo
    echo -e "${BOLD}Edera Falco configuration:${RESET}"

    if [[ -f "$EDERA_CONFIG" ]]; then
        ok "$EDERA_CONFIG"

        show_file "$EDERA_CONFIG"
    else
        error "Missing: $EDERA_CONFIG"
    fi

    echo
    echo -e "${BOLD}Edera Falco rules:${RESET}"

    if [[ -f "$EDERA_RULES" ]]; then
        ok "$EDERA_RULES"

        show_file "$EDERA_RULES"
    else
        error "Missing: $EDERA_RULES"
    fi

    echo
    echo -e "${BOLD}Edera configuration backups:${RESET}"

    if [[ -d "$BACKUP_DIR" ]]; then
        local backups=()

        while IFS= read -r -d '' file; do
            backups+=("$file")
        done < <(
            print_cmd find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.bak' -print0 >&2
            find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.bak' -print0
        )

        if [[ "${#backups[@]}" -eq 0 ]]; then
            ok "No configuration backups found"
        else
            info "Configuration backups:"
            printf '  %s\n' "${backups[@]}"
        fi
    else
        ok "No backup directory exists"
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

    print_cmd journalctl -u "$FALCO_SERVICE" -n "$LOG_LINES" --no-pager -o short-precise

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

    print_cmd journalctl -u "$FALCO_SERVICE" -f -o short-precise

    journalctl \
        -u "$FALCO_SERVICE" \
        -f \
        -o short-precise
}

# ---------------------------------------------------------------------------
# Falco configuration validation
# ---------------------------------------------------------------------------

validate_falco_config() {
    local failures=0

    section "Falco Configuration Validation"

    if ! command -v falco >/dev/null 2>&1; then
        error "Falco binary not found"
        return 1
    fi

    if falco --help 2>&1 | grep -q -- '--dry-run'; then
        local tmp_log="/tmp/falco-edera-config-check.log"

        info "Falco supports --dry-run."
        info "Validating configuration without starting a second Falco daemon."

        print_cmd falco --dry-run

        if falco --dry-run >"$tmp_log" 2>&1; then
            ok "Falco configuration validation passed"
        else
            error "Falco configuration validation failed"
            echo
            print_cmd cat "$tmp_log"
            cat "$tmp_log"

            failures=1
        fi

        rm -f "$tmp_log"
    else
        warn "This Falco build does not expose --dry-run."
        warn "Configuration will be validated through service startup."
    fi

    return "$failures"
}

# ---------------------------------------------------------------------------
# Edera plugin registration / event source checks
# ---------------------------------------------------------------------------

check_plugin_registration() {
    local failures=0

    echo
    echo -e "${BOLD}9. Edera plugin registration${RESET}"

    if [[ ! -f "$EDERA_PLUGIN" ]]; then
        error "Edera plugin library does not exist"
        return 1
    fi

    # Falco 0.44 exposes plugin information through `falco --list-plugins`.
    if falco --help 2>&1 | grep -q -- '--list-plugins'; then
        local plugin_output

        print_cmd falco --list-plugins

        plugin_output="$(falco --list-plugins 2>&1 || true)"

        if grep -qE '(^|[[:space:]])edera([@[:space:]]|$)' <<<"$plugin_output"; then
            ok "Edera plugin is registered with Falco"
        else
            error "Edera plugin was not found in Falco's plugin list"
            failures=$((failures + 1))
        fi

        if grep -q "edera_zone" <<<"$plugin_output"; then
            ok "Edera plugin exposes event source: edera_zone"
        else
            warn "Could not confirm edera_zone through falco --list-plugins"
        fi
    else
        warn "Falco does not expose --list-plugins."
        warn "Using current service logs instead."
    fi

    return "$failures"
}

# ---------------------------------------------------------------------------
# Current-boot log checks
# ---------------------------------------------------------------------------

get_current_boot_logs() {
    journalctl \
        -b \
        -u "$FALCO_SERVICE" \
        --no-pager \
        2>/dev/null || true
}

check_current_logs() {
    local failures=0
    local logs

    echo
    echo -e "${BOLD}10. Current Falco log state${RESET}"

    logs="$(get_current_boot_logs)"

    if [[ -z "$logs" ]]; then
        warn "No current-boot journal entries found"
        return 0
    fi

    if grep -q "Loaded plugin 'edera@" <<<"$logs"; then
        ok "Edera plugin was loaded by Falco"
    else
        error "No evidence that Falco loaded the Edera plugin"
        failures=$((failures + 1))
    fi

    if grep -q "Loaded event sources:.*edera_zone" <<<"$logs"; then
        ok "edera_zone is a loaded event source"
    elif grep -q "edera_zone" <<<"$logs"; then
        ok "edera_zone appears in current Falco logs"
    else
        error "No evidence of edera_zone event source"
        failures=$((failures + 1))
    fi

    if grep -q "Enabled event sources:.*edera_zone" <<<"$logs"; then
        ok "edera_zone is enabled"
    else
        warn "edera_zone is not shown as enabled"
    fi

    if grep -q "Opening 'edera_zone' source with plugin 'edera'" <<<"$logs"; then
        ok "Falco opened the edera_zone source"
    else
        warn "No evidence that Falco opened edera_zone"
    fi

    # IMPORTANT:
    # A loaded plugin is not necessarily a healthy plugin.
    #
    # The logs supplied by the user contained:
    #
    #   Client error: transport error
    #
    # Therefore we explicitly detect these errors.

    if grep -Eqi \
        "edera:.*(client error|transport error|connection refused|service unavailable|failed to watch events)" \
        <<<"$logs"; then

        error "Edera plugin reported a transport/connectivity error"

        echo
        echo -e "${RED}${BOLD}Relevant Edera connectivity messages:${RESET}"

        grep -Ei \
            "edera.*(client error|transport error|connection refused|service unavailable|failed to watch events)" \
            <<<"$logs" \
            | tail -30 || true

        failures=$((failures + 1))
    else
        ok "No Edera transport/connectivity errors detected"
    fi

    if grep -q "waiting for zones" <<<"$logs"; then
        ok "Edera plugin is waiting for zones"
        info "This is normally expected when no Edera zone is currently available."
    fi

    if grep -q "Runtime error: error in plugin edera init config" <<<"$logs"; then
        error "Falco previously reported an Edera plugin init-config error"
        failures=$((failures + 1))
    fi

    if grep -q "Main process exited" <<<"$logs"; then
        warn "Falco has exited at least once during this boot"
    fi

    if grep -q "Failed with result 'exit-code'" <<<"$logs"; then
        warn "systemd recorded a Falco exit-code failure during this boot"
    fi

    echo
    echo -e "${BOLD}Relevant current-boot messages:${RESET}"

    grep -Ei \
        "edera|error|failed|warning|loaded event sources|enabled event sources|waiting for zones|Runtime error" \
        <<<"$logs" \
        | tail -60 || true

    return "$failures"
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

    print_cmd systemctl is-enabled "$FALCO_SERVICE"

    if service_enabled; then
        ok "${FALCO_SERVICE} is enabled"
    else
        error "${FALCO_SERVICE} is NOT enabled"
        failures=$((failures + 1))
    fi

    echo
    echo -e "${BOLD}3. Service active${RESET}"

    print_cmd systemctl is-active "$FALCO_SERVICE"

    if service_active; then
        ok "${FALCO_SERVICE} is active/running"
    else
        error "${FALCO_SERVICE} is NOT active"

        echo
        warn "Current service status:"

        print_cmd systemctl status "$FALCO_SERVICE" --no-pager -l
        systemctl status "$FALCO_SERVICE" --no-pager -l || true

        failures=$((failures + 1))
    fi

    return "$failures"
}

check_files() {
    local failures=0

    echo
    echo -e "${BOLD}4. Falco configuration${RESET}"

    if [[ -f "$FALCO_MAIN_CONFIG" ]]; then
        ok "Default Falco configuration exists"
    else
        error "Missing $FALCO_MAIN_CONFIG"
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

        print_cmd ls -lh "$EDERA_PLUGIN"
        ls -lh "$EDERA_PLUGIN"
    else
        error "Edera plugin missing or not executable"
        failures=$((failures + 1))
    fi

    echo
    echo -e "${BOLD}6. Edera daemon socket${RESET}"

    if [[ -S "$EDERA_SOCKET" ]]; then
        ok "Edera daemon socket exists"

        print_cmd ls -l "$EDERA_SOCKET"
        ls -l "$EDERA_SOCKET"
    else
        error "Edera daemon socket does not exist"
        failures=$((failures + 1))
    fi

    return "$failures"
}

check_backups() {
    local failures=0

    echo
    echo -e "${BOLD}7. Edera configuration backups${RESET}"

    if [[ ! -d "$BACKUP_DIR" ]]; then
        ok "No backup directory exists"
        return 0
    fi

    local count

    print_cmd bash -c \
        'find "$1" -maxdepth 1 -type f -name "*.bak" -print' \
        bash "$BACKUP_DIR"

    count="$(
        find "$BACKUP_DIR" \
            -maxdepth 1 \
            -type f \
            -name '*.bak' \
            -print \
            | wc -l
    )"

    if [[ "$count" -eq 0 ]]; then
        ok "No configuration backups found"
    else
        info "${count} configuration backup(s) found"

        find "$BACKUP_DIR" \
            -maxdepth 1 \
            -type f \
            -name '*.bak' \
            -print \
            | sort \
            | sed 's/^/  /'
    fi

    return "$failures"
}

run_check() {
    require_root
    require_command systemctl
    require_command journalctl

    section "Falco + Edera Health Check"

    local failures=0

    check_service || failures=$((failures + 1))
    check_files || failures=$((failures + 1))
    check_backups || failures=$((failures + 1))
    validate_falco_config || failures=$((failures + 1))
    check_plugin_registration || failures=$((failures + 1))
    check_current_logs || failures=$((failures + 1))

    echo
    echo "============================================================"

    if [[ "$failures" -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}[ PASS ] Falco + Edera health check passed${RESET}"
        echo "============================================================"
        echo
        info "Falco is running and the Edera integration appears healthy."
        echo
        info "Useful commands:"
        echo
        echo "  sudo $0 --status"
        echo "  sudo $0 --logs"
        echo "  sudo $0 --follow"
        echo
        return 0
    fi

    echo -e "${RED}${BOLD}[ FAIL ] ${failures} health-check area(s) need attention${RESET}"
    echo "============================================================"
    echo

    warn "Falco may still be running, but the Edera integration is not fully healthy."
    echo
    warn "Run:"
    echo
    echo "  sudo $0 --status"
    echo "  sudo $0 --logs"
    echo

    return 1
}

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

install_falco() {
    require_root

    section "Installing Falco + Edera Integration"

    info "Falco service: ${FALCO_SERVICE}"
    info "Edera plugin:  ${EDERA_PLUGIN}"
    info "Edera socket:  ${EDERA_SOCKET}"

    # -----------------------------------------------------------------------
    # Step 1
    # -----------------------------------------------------------------------

    section "Step 1: Checking prerequisites"

    require_command systemctl
    require_command journalctl
    require_command curl
    require_command apt-get
    require_command sed
    require_command grep
    require_command find

    ok "Required commands are available"

    # -----------------------------------------------------------------------
    # Step 2
    # -----------------------------------------------------------------------

    section "Step 2: Checking Edera"

    if [[ -S "$EDERA_SOCKET" ]]; then
        ok "Edera daemon socket exists"

        print_cmd ls -l "$EDERA_SOCKET"
        ls -l "$EDERA_SOCKET"
    else
        warn "Edera daemon socket not found:"
        warn "  ${EDERA_SOCKET}"
        warn "The Falco plugin may remain in 'waiting for zones' state."
    fi

    # -----------------------------------------------------------------------
    # Step 3
    # -----------------------------------------------------------------------

    section "Step 3: Checking Falco"

    if command -v falco >/dev/null 2>&1; then
        ok "Falco is already installed"

        print_cmd falco --version
        falco --version || true
    else
        die "Falco is not installed."

        #
        # If you want this script to install Falco from scratch, put your
        # existing Falco repository/install block here.
        #
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
        info "Plugin is not executable; fixing permissions."

        print_cmd chmod +x "$EDERA_PLUGIN"
        chmod +x "$EDERA_PLUGIN"
    fi

    ok "Edera plugin exists:"
    print_cmd ls -lh "$EDERA_PLUGIN"
    ls -lh "$EDERA_PLUGIN"

    # -----------------------------------------------------------------------
    # Step 6
    # -----------------------------------------------------------------------

    section "Step 6: Enabling Falco"

    print_cmd systemctl daemon-reload
    systemctl daemon-reload

    #
    # IMPORTANT:
    #
    # Do NOT run:
    #
    #   systemctl enable falco.service
    #
    # because falco.service is an alias pointing at the real unit.
    #
    print_cmd systemctl enable "$FALCO_SERVICE"
    systemctl enable "$FALCO_SERVICE"

    ok "Enabled ${FALCO_SERVICE}"

    # -----------------------------------------------------------------------
    # Step 7
    # -----------------------------------------------------------------------

    section "Step 7: Preparing Edera plugin configuration"

    print_cmd mkdir -p "$FALCO_CONFIG_DROPIN_DIR" "$FALCO_RULES_DIR" "$BACKUP_DIR"
    mkdir -p \
        "$FALCO_CONFIG_DROPIN_DIR" \
        "$FALCO_RULES_DIR" \
        "$BACKUP_DIR"

    # Back up existing files before changing them.
    backup_file "$EDERA_CONFIG"
    backup_file "$EDERA_RULES"

    # -----------------------------------------------------------------------
    # Step 8
    # -----------------------------------------------------------------------

    section "Step 8: Writing Edera plugin configuration"

    #
    # Keep init_config as an empty YAML object.
    #
    # This is important because the Edera plugin expects an object/map,
    # rather than a YAML string.
    #
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

    show_file "$EDERA_CONFIG"

    # -----------------------------------------------------------------------
    # Step 9
    # -----------------------------------------------------------------------

    section "Step 9: Writing Edera detection rules"

    cat > "$EDERA_RULES" <<'EOF'
# Edera Falco integration rules.
#
# The Edera event source is:
#
#   edera_zone
#
# Add Edera-specific Falco rules here.
#
EOF

    ok "Created:"
    echo "  ${EDERA_RULES}"

    show_file "$EDERA_RULES"

    # -----------------------------------------------------------------------
    # Step 10
    # -----------------------------------------------------------------------

    section "Step 10: Validating Falco configuration"

    if ! validate_falco_config; then
        error "Falco configuration validation failed."
        warn "Falco was NOT restarted."
        warn "Your existing running Falco service has been left untouched."

        die "Installation stopped because configuration validation failed."
    fi

    # -----------------------------------------------------------------------
    # Step 11
    # -----------------------------------------------------------------------

    section "Step 11: Reloading systemd"

    print_cmd systemctl daemon-reload
    systemctl daemon-reload

    ok "systemd configuration reloaded"

    # -----------------------------------------------------------------------
    # Step 12
    # -----------------------------------------------------------------------

    section "Step 12: Restarting Falco"

    info "Restarting ${FALCO_SERVICE}..."

    print_cmd systemctl restart "$FALCO_SERVICE"
    systemctl restart "$FALCO_SERVICE"

    ok "Falco restart command completed"

    # -----------------------------------------------------------------------
    # Step 13
    # -----------------------------------------------------------------------

    section "Step 13: Waiting for Falco"

    local attempts=0

    while [[ "$attempts" -lt 15 ]]; do
        if service_active; then
            ok "Falco is active"
            break
        fi

        attempts=$((attempts + 1))

        info "Waiting for Falco... (${attempts}/15)"
        sleep 1
    done

    if ! service_active; then
        error "Falco did not become active."

        echo
        print_cmd systemctl status "$FALCO_SERVICE" --no-pager -l
        systemctl status "$FALCO_SERVICE" --no-pager -l || true

        echo
        warn "Recent logs:"

        print_cmd journalctl -u "$FALCO_SERVICE" -n 100 --no-pager
        journalctl -u "$FALCO_SERVICE" -n 100 --no-pager || true

        die "Falco startup failed"
    fi

    # -----------------------------------------------------------------------
    # Step 14
    # -----------------------------------------------------------------------

    section "Step 14: Verifying Edera integration"

    sleep 2

    echo
    print_cmd systemctl status "$FALCO_SERVICE" --no-pager -l
    systemctl status "$FALCO_SERVICE" --no-pager -l || true

    echo
    info "Checking current-boot Edera messages..."

    local current_logs
    current_logs="$(get_current_boot_logs)"

    echo
    grep -Ei \
        "edera|error|failed|warning|loaded event sources|enabled event sources|waiting for zones" \
        <<<"$current_logs" \
        | tail -60 \
        || true

    # -----------------------------------------------------------------------
    # Step 15
    # -----------------------------------------------------------------------

    section "Step 15: Installation Health Check"

    if run_check; then
        echo
        echo "============================================================"
        echo -e "${GREEN}${BOLD}[ SUCCESS ] Falco + Edera installation completed${RESET}"
        echo "============================================================"
        echo

        info "Falco is active."
        info "The Edera plugin is loaded."
        info "No current Edera transport errors were detected."

    else
        echo
        echo "============================================================"
        echo -e "${YELLOW}${BOLD}[ WARNING ] Installation completed, but health checks need attention${RESET}"
        echo "============================================================"
        echo

        warn "Falco itself may be running successfully."
        warn "Review the Edera-specific health-check output above."

        echo
        echo "Useful commands:"
        echo
        echo "  sudo $0 --check"
        echo "  sudo $0 --status"
        echo "  sudo $0 --logs"
        echo "  sudo $0 --follow"
    fi

    echo
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    require_root
    require_command systemctl

    section "Falco + Edera Cleanup"

    warn "This removes the Edera-specific Falco configuration and rules."
    warn "It does NOT uninstall Falco."
    warn "It does NOT remove the Edera plugin."
    warn "It does NOT remove the Edera daemon."
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

    # -----------------------------------------------------------------------
    # Stop Falco
    # -----------------------------------------------------------------------

    section "Cleanup Step 1: Stopping Falco"

    if service_exists; then
        print_cmd systemctl stop "$FALCO_SERVICE"
        systemctl stop "$FALCO_SERVICE" || true
    else
        warn "Falco service does not exist."
    fi

    # -----------------------------------------------------------------------
    # Back up existing configuration
    # -----------------------------------------------------------------------

    section "Cleanup Step 2: Backing up Edera configuration"

    backup_file "$EDERA_CONFIG"
    backup_file "$EDERA_RULES"

    # -----------------------------------------------------------------------
    # Remove Edera configuration
    # -----------------------------------------------------------------------

    section "Cleanup Step 3: Removing Edera Falco configuration"

    print_cmd rm -f "$EDERA_CONFIG" "$EDERA_RULES"
    rm -f "$EDERA_CONFIG" "$EDERA_RULES"

    ok "Removed Edera Falco configuration files"

    # -----------------------------------------------------------------------
    # Reload systemd
    # -----------------------------------------------------------------------

    section "Cleanup Step 4: Reloading systemd"

    print_cmd systemctl daemon-reload
    systemctl daemon-reload

    # -----------------------------------------------------------------------
    # Restart Falco
    # -----------------------------------------------------------------------

    section "Cleanup Step 5: Restarting Falco"

    if service_exists; then
        print_cmd systemctl start "$FALCO_SERVICE"
        systemctl start "$FALCO_SERVICE" || true
    fi

    echo
    ok "Cleanup complete."
    echo

    info "Falco itself was NOT uninstalled."
    info "The Edera plugin binary was NOT removed."
    info "The Edera daemon was NOT removed."
    info "Backups are stored under:"
    echo "  ${BACKUP_DIR}"
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

  FALCO_SERVICE=falco-modern-bpf.service sudo $0

Service:

  ${FALCO_SERVICE}

Files:

  Falco config:
    ${FALCO_MAIN_CONFIG}

  Edera plugin:
    ${EDERA_PLUGIN}

  Edera socket:
    ${EDERA_SOCKET}

  Edera Falco config:
    ${EDERA_CONFIG}

  Edera Falco rules:
    ${EDERA_RULES}

  Backups:
    ${BACKUP_DIR}

The installer prints commands as they are executed using:

  [CMD ]

For example:

  [CMD ] systemctl restart falco-modern-bpf.service

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
