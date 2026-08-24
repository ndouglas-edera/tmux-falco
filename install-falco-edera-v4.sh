#!/usr/bin/env bash

# ============================================================================
# Edera + Falco installer / configurator
#
# Designed for:
#   - Falco 0.44.x
#   - Falco modern eBPF engine
#   - Edera Protect already installed
#   - Edera Falco plugin supplied by the Edera installation
#
# This script does NOT install Edera itself.
#
# Usage:
#   sudo ./install-falco-edera-v5.sh
#   sudo ./install-falco-edera-v5.sh --check
#   sudo ./install-falco-edera-v5.sh --status
#   sudo ./install-falco-edera-v5.sh --logs
#   sudo ./install-falco-edera-v5.sh --cleanup
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

# Falco validation duration.
#
# Falco is a daemon and normally does NOT exit by itself after loading the
# configuration. Therefore a timeout is expected during validation.
readonly FALCO_VALIDATION_TIMEOUT=10

# ---------------------------------------------------------------------------
# Required Edera rules
# ---------------------------------------------------------------------------

readonly REQUIRED_EDERA_RULES=(
    "Edera Proc Environ Read"
    "Edera Reverse Shell Tool"
    "Edera Namespace Escape Attempt"
    "Edera Sensitive File Read"
    "Edera Outbound Connection"
    "Edera Shell Pipe Execution"
)

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
    printf '%s[%s INFO]%s %s\n' \
        "$BLUE" "$(timestamp)" "$RESET" "$*"
}

ok() {
    printf '%s[ OK ]%s %s\n' \
        "$GREEN" "$RESET" "$*"
}

warn() {
    printf '%s[WARN]%s %s\n' \
        "$YELLOW" "$RESET" "$*"
}

error() {
    printf '%s[ERROR]%s %s\n' \
        "$RED" "$RESET" "$*" >&2
}

section() {
    echo
    printf '%s============================================================%s\n' \
        "$BOLD" "$RESET"
    printf '%s%s%s\n' \
        "$BOLD" "$*" "$RESET"
    printf '%s============================================================%s\n' \
        "$BOLD" "$RESET"
    echo
}

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
        timeout
        mktemp
    )

    local failed=0
    local cmd

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
        "falco-modern-bpf.service"
        "falco-custom.service"
        "falco.service"
    )

    local service
    local unit_id
    local fragment
    local load_state
    local unit_file_state

    for service in "${candidates[@]}"; do

        if ! systemctl cat "$service" >/dev/null 2>&1; then
            continue
        fi

        unit_id="$(
            systemctl show "$service" \
                -p Id \
                --value \
                2>/dev/null || true
        )"

        fragment="$(
            systemctl show "$service" \
                -p FragmentPath \
                --value \
                2>/dev/null || true
        )"

        load_state="$(
            systemctl show "$service" \
                -p LoadState \
                --value \
                2>/dev/null || true
        )"

        unit_file_state="$(
            systemctl show "$service" \
                -p UnitFileState \
                --value \
                2>/dev/null || true
        )"

        if [[ "$load_state" == "loaded" &&
              "$unit_id" == "$service" &&
              -n "$fragment" &&
              "$fragment" != "/dev/null" ]]; then

            FALCO_SERVICE="$service"

            ok "Detected Falco service: $FALCO_SERVICE"

            info "Unit ID: $unit_id"
            info "Fragment: $fragment"
            info "Unit file state: ${unit_file_state:-unknown}"

            return 0
        fi

        if [[ "$service" == "falco.service" &&
              "$load_state" == "loaded" &&
              "$unit_id" != "$service" ]]; then

            info "Ignoring Falco alias: $service"
            info "Canonical unit is: ${unit_id:-unknown}"
        fi
    done

    while IFS= read -r service; do

        service="${service%% *}"

        [[ "$service" == falco*.service ]] || continue

        unit_id="$(
            systemctl show "$service" \
                -p Id \
                --value \
                2>/dev/null || true
        )"

        fragment="$(
            systemctl show "$service" \
                -p FragmentPath \
                --value \
                2>/dev/null || true
        )"

        load_state="$(
            systemctl show "$service" \
                -p LoadState \
                --value \
                2>/dev/null || true
        )"

        if [[ "$load_state" == "loaded" &&
              "$unit_id" == "$service" &&
              -n "$fragment" &&
              "$fragment" != "/dev/null" ]]; then

            FALCO_SERVICE="$service"

            ok "Detected Falco service: $FALCO_SERVICE"

            info "Unit ID: $unit_id"
            info "Fragment: $fragment"

            return 0
        fi

    done < <(
        systemctl list-unit-files \
            --type=service \
            --no-legend \
            2>/dev/null || true
    )

    error "Could not find a canonical Falco systemd service."
    return 1
}

service_exists() {
    [[ -n "$FALCO_SERVICE" ]] || return 1

    local load_state

    load_state="$(
        systemctl show "$FALCO_SERVICE" \
            -p LoadState \
            --value \
            2>/dev/null || true
    )"

    [[ "$load_state" == "loaded" ]]
}

falco_is_active() {
    [[ -n "$FALCO_SERVICE" ]] || return 1

    systemctl is-active \
        --quiet \
        "$FALCO_SERVICE"
}

falco_is_enabled() {
    [[ -n "$FALCO_SERVICE" ]] || return 1

    systemctl is-enabled \
        --quiet \
        "$FALCO_SERVICE"
}

# ---------------------------------------------------------------------------
# Edera installation checks
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

        systemctl status \
            "$EDERA_SERVICE" \
            --no-pager ||
            true

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
                head -n 1 ||
                true
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
    if [[ ! -d "$FALCO_CONFIG_DROPIN_DIR" ]]; then
        return 0
    fi

    find "$FALCO_CONFIG_DROPIN_DIR" \
        -maxdepth 1 \
        -type f \
        \( \
            -name 'falco-edera-config.yaml.bak' \
            -o -name 'falco-edera-config.yml.bak' \
            -o -name 'falco-edera-*.bak' \
        \) \
        -print0 \
        2>/dev/null
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
# Falco plugin configuration
# ---------------------------------------------------------------------------

write_edera_config() {
    section "Writing Edera Falco plugin configuration"

    install -d -m 0755 "$FALCO_CONFIG_DROPIN_DIR"

    rm -f -- "$EDERA_CONFIG_BACKUP"

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

# ---------------------------------------------------------------------------
# Edera Falco rules
#
# IMPORTANT:
#
# The Edera plugin is providing the event source:
#
#     edera_zone
#
# The output fields below deliberately avoid complicated expressions inside
# the output string. Falco 0.44.x validates output fields strictly.
# ---------------------------------------------------------------------------

write_edera_rules() {
    section "Writing Edera Falco rules"

    install -d -m 0755 "$FALCO_RULES_DIR"

    cat > "$EDERA_RULES" <<'EOF'
# ============================================================================
# Edera Falco detection rules
#
# Event source:
#
#   edera_zone
#
# Managed by the Edera + Falco installer.
# ============================================================================

- rule: Edera Proc Environ Read
  desc: >
    Detect reads of /proc/*/environ inside an Edera zone.
    Credential harvesting via procfs is a common post-exploitation
    technique for extracting secrets from neighboring workloads.
  source: edera_zone
  output: >
    Credential harvesting attempt in Edera zone
    (proc=%proc.name file=%fd.name)
  priority: WARNING
  condition: >
    evt.pluginname == "edera" and
    evt.type in (open, openat) and
    fd.name glob /proc/*/environ

- rule: Edera Reverse Shell Tool
  desc: >
    Detect execution of common reverse shell tools inside an Edera zone.
  source: edera_zone
  output: >
    Reverse shell tool executed in Edera zone
    (proc=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  condition: >
    evt.pluginname == "edera" and
    evt.type in (execve, execveat) and
    proc.name in (nc, ncat, netcat, socat, telnet)

- rule: Edera Namespace Escape Attempt
  desc: >
    Detect nsenter execution inside an Edera zone.
    nsenter is commonly used in container escape and privilege
    escalation attacks to enter other namespaces.
  source: edera_zone
  output: >
    Namespace escape attempt in Edera zone
    (proc=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  condition: >
    evt.pluginname == "edera" and
    evt.type in (execve, execveat) and
    proc.name == nsenter

- rule: Edera Sensitive File Read
  desc: >
    Detect reads of sensitive system files inside an Edera zone,
    including credential stores and security-critical configuration.
  source: edera_zone
  output: >
    Sensitive file read in Edera zone
    (proc=%proc.name file=%fd.name)
  priority: WARNING
  condition: >
    evt.pluginname == "edera" and
    evt.type in (open, openat) and
    (fd.name startswith /etc/shadow or
     fd.name startswith /etc/kubernetes or
     fd.name startswith /run/secrets)

- rule: Edera Outbound Connection
  desc: >
    Detect outbound network connections from Edera zones.
  source: edera_zone
  output: >
    Outbound connection from Edera zone
    (proc=%proc.name dest=%fd.rip:%fd.rport proto=%fd.l4proto)
  priority: NOTICE
  condition: >
    evt.pluginname == "edera" and
    evt.type == connect and
    fd.type == ipv4

- rule: Edera Shell Pipe Execution
  desc: >
    Detect pipeline execution where web fetching tools stream directly
    into shell interpreters inside an Edera zone.
  source: edera_zone
  output: >
    In-memory script execution attempt in Edera zone
    (proc=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  condition: >
    evt.pluginname == "edera" and
    evt.type in (execve, execveat) and
    (proc.cmdline contains "curl" or
     proc.cmdline contains "wget") and
    (proc.cmdline contains "| sh" or
     proc.cmdline contains "| bash" or
     proc.cmdline contains "| ash")

- rule: Edera Reconnaissance Tool Executed
  desc: >
    Detect execution of network or system discovery tools commonly
    used during container post-exploitation.
  source: edera_zone
  output: >
    Reconnaissance tool executed in Edera zone
    (proc=%proc.name cmdline=%proc.cmdline user=%user.name)
  priority: WARNING
  condition: >
    evt.pluginname == "edera" and
    evt.type in (execve, execveat) and
    proc.name in (nmap, ip, ss, netstat, arp, route, dig, nslookup, lsof)

- rule: Edera Execution from Unsafe Directory
  desc: >
    Detect binary execution originating from temporary or shared memory
    paths inside an Edera zone.
  source: edera_zone
  output: >
    Execution from ephemeral directory in Edera zone
    (proc=%proc.name path=%proc.exepath cmdline=%proc.cmdline)
  priority: WARNING
  condition: >
    evt.pluginname == "edera" and
    evt.type in (execve, execveat) and
    (proc.exepath startswith /tmp or
     proc.exepath startswith /var/tmp or
     proc.exepath startswith /dev/shm)

- rule: Edera Unexpected Shell Spawn
  desc: >
    Detect shell processes spawned by non-standard parent executables
    inside an Edera zone.
  source: edera_zone
  output: >
    Unexpected shell child process in Edera zone
    (shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: CRITICAL
  condition: >
    evt.pluginname == "edera" and
    evt.type in (execve, execveat) and
    proc.name in (sh, bash, ash, zsh) and
    proc.pname in (python, python3, node, java, nginx, httpd)

- rule: Edera Shell History Wiped
  desc: >
    Detect attempts to clear or redirect shell history files inside
    an Edera zone.
  source: edera_zone
  output: >
    Shell history alteration or wipe detected in Edera zone
    (proc=%proc.name file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  condition: >
    evt.pluginname == "edera" and
    evt.type in (open, openat, truncate) and
    (fd.name endswith .bash_history or
     fd.name endswith .ash_history or
     fd.name endswith .zsh_history) and
    proc.cmdline contains "/dev/null"
EOF

    chmod 0644 "$EDERA_RULES"

    ok "Wrote:"
    echo "    $EDERA_RULES"

    echo
    echo "--- Edera rules ---"
    cat "$EDERA_RULES"
}

# ---------------------------------------------------------------------------
# Edera rules inspection
# ---------------------------------------------------------------------------

get_edera_rule_count() {
    local count

    count="$(
        grep -cE \
            '^[[:space:]]*-[[:space:]]rule:' \
            "$EDERA_RULES" \
            2>/dev/null || true
    )"

    printf '%s\n' "${count:-0}"
}

check_edera_rules_file() {
    section "Checking Edera rules file"

    if [[ ! -f "$EDERA_RULES" ]]; then
        error "Edera rules file does not exist:"
        echo "    $EDERA_RULES"
        return 1
    fi

    if [[ ! -s "$EDERA_RULES" ]]; then
        error "Edera rules file is empty:"
        echo "    $EDERA_RULES"
        return 1
    fi

    local rule_count

    rule_count="$(get_edera_rule_count)"

    if ! [[ "$rule_count" =~ ^[0-9]+$ ]]; then
        error "Could not determine Edera rule count"
        return 1
    fi

    if (( rule_count < ${#REQUIRED_EDERA_RULES[@]} )); then
        error "Expected at least ${#REQUIRED_EDERA_RULES[@]} Edera rules, found $rule_count"

        echo
        grep -nE \
            '^[[:space:]]*-[[:space:]]rule:' \
            "$EDERA_RULES" ||
            true

        return 1
    fi

    ok "Edera rules file exists"
    ok "Found $rule_count Edera rules"

    if (( rule_count > ${#REQUIRED_EDERA_RULES[@]} )); then
        local custom_count

        custom_count=$(
            (( rule_count - ${#REQUIRED_EDERA_RULES[@]} ))
        )

        ok "Additional/custom rules detected: $custom_count"
    fi

    local rule

    for rule in "${REQUIRED_EDERA_RULES[@]}"; do

        if grep -Fq -- "- rule: $rule" "$EDERA_RULES"; then
            ok "Rule present: $rule"
        else
            error "Missing required Edera rule: $rule"
            return 1
        fi

    done

    echo
    echo "--- Installed Edera rule names ---"

    grep -nE \
        '^[[:space:]]*-[[:space:]]rule:' \
        "$EDERA_RULES" ||
        true
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

    if [[ ! -f "$EDERA_RULES" ]]; then
        error "Edera Falco rules not found:"
        echo "    $EDERA_RULES"
        return 1
    fi

    if ! command -v falco >/dev/null 2>&1; then
        error "falco executable not found"
        return 1
    fi

    local output_file
    local rc=0

    output_file="$(
        mktemp /tmp/falco-edera-validation.XXXXXX
    )"

    # Always remove temporary validation output.
    cleanup_validation_file() {
        rm -f -- "$output_file"
    }

    trap cleanup_validation_file RETURN

    info "Running Falco configuration validation..."
    info "Falco will be allowed to run for ${FALCO_VALIDATION_TIMEOUT}s."
    info "A timeout is expected if configuration loads successfully."

    #
    # IMPORTANT:
    #
    # Do not use:
    #
    #   output="$(timeout ...)" || rc=$?
    #
    # here.
    #
    # With set -Eeuo pipefail and a global ERR trap, timeout's expected
    # exit status 124 can still trigger the ERR trap through command
    # substitution.
    #
    # Instead, temporarily disable ERR handling around the expected
    # non-zero command.
    #
    trap - ERR

    timeout \
        --signal=TERM \
        --kill-after=3s \
        "${FALCO_VALIDATION_TIMEOUT}s" \
        falco \
        -c "$FALCO_CONFIG" \
        -M 1 \
        >"$output_file" \
        2>&1

    rc=$?

    trap on_error ERR

    #
    # Display Falco's actual output regardless of exit status.
    #
    sed -n '1,240p' "$output_file"

    echo

    #
    # Exit code 124 is EXPECTED when timeout terminates Falco after
    # successful initialization.
    #
    if [[ "$rc" -eq 124 ]]; then

        info "Falco reached the validation timeout."

        #
        # Look for actual configuration/rule/plugin errors.
        #
        if grep -qiE \
            'LOAD_ERR_|Error: .*Invalid|configuration.*error|failed to load|cannot load|could not load|fatal error|unknown filter|schema validation.*failed' \
            "$output_file"; then

            error "Falco reported a configuration, plugin, or rule error during validation"

            echo
            echo "--- Relevant Falco errors ---"

            grep -iE \
                'LOAD_ERR_|Error:|Invalid|failed|cannot|could not|fatal|unknown filter' \
                "$output_file" |
                sed -n '1,160p' ||
                true

            return 1
        fi

        #
        # We expect both of these when the Edera integration is loaded.
        #
        if grep -q \
            "Loaded plugin 'edera@" \
            "$output_file"; then

            ok "Falco loaded the Edera plugin"

        else

            error "Falco timed out but did not report loading the Edera plugin"
            return 1
        fi

        if grep -q \
            "rules.d/falco-edera-rules.yaml | schema validation: ok" \
            "$output_file"; then

            ok "Edera rules file passed Falco schema validation"

        else

            error "Edera rules file was not confirmed as schema-valid"
            return 1
        fi

        ok "Falco configuration validation passed"

        return 0
    fi

    #
    # Exit code 0 means Falco exited cleanly.
    #
    if [[ "$rc" -eq 0 ]]; then

        ok "Falco exited cleanly during validation"

        if grep -q \
            "Loaded plugin 'edera@" \
            "$output_file"; then

            ok "Falco loaded the Edera plugin"

        else

            warn "Falco exited cleanly but Edera plugin load was not explicitly reported"
        fi

        return 0
    fi

    #
    # Any other exit code is a genuine failure.
    #
    error "Falco validation failed with exit code $rc"

    echo
    echo "--- Relevant Falco errors ---"

    grep -iE \
        'LOAD_ERR_|Error:|Invalid|failed|cannot|could not|fatal|unknown filter|schema' \
        "$output_file" |
        sed -n '1,200p' ||
        true

    return 1
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
        falco --list-plugins 2>&1 ||
        true
    )"

    if printf '%s\n' "$output" |
        grep -qiE \
            '(^|[[:space:]])Name:[[:space:]]*edera([[:space:]]|$)'; then

        ok "Edera plugin is available to Falco"

        printf '%s\n' "$output" |
            grep -i -A8 -B1 \
                'Name:[[:space:]]*edera' ||
            true

    else

        error "Falco did not report the Edera plugin"
        printf '%s\n' "$output"

        return 1
    fi
}

check_edera_source() {
    section "Checking Edera event source"

    if ! command -v falco >/dev/null 2>&1; then
        error "falco command not found"
        return 1
    fi

    local output_file
    local rc=0

    output_file="$(
        mktemp /tmp/falco-edera-source.XXXXXX
    )"

    trap 'rm -f -- "$output_file"' RETURN

    trap - ERR

    timeout \
        --signal=TERM \
        --kill-after=3s \
        10s \
        falco \
        -c "$FALCO_CONFIG" \
        -M 1 \
        -v \
        >"$output_file" \
        2>&1

    rc=$?

    trap on_error ERR

    if grep -q 'edera_zone' "$output_file"; then

        ok "Edera event source edera_zone is available"

    else

        #
        # Do not immediately fail solely because verbose output didn't
        # print the source name. The plugin load itself is authoritative
        # for this check.
        #
        if grep -q "Loaded plugin 'edera@" "$output_file"; then

            ok "Edera plugin loaded successfully"

        else

            error "Edera event source/plugin could not be confirmed"

            grep -iE \
                'plugin|source|edera|error|warn' \
                "$output_file" |
                sed -n '1,160p' ||
                true

            return 1
        fi
    fi

    if grep -qiE \
        "Loaded plugin 'edera@" \
        "$output_file"; then

        ok "Falco loaded the Edera plugin"

    else

        warn "Could not confirm Edera plugin load from verbose output"
    fi

    #
    # timeout(124) is expected here too.
    #
    if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        warn "Falco verbose validation returned exit code $rc"
    fi

    return 0
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

    info "Restarting canonical Falco unit:"
    echo "    $FALCO_SERVICE"

    run systemctl daemon-reload
    run systemctl restart "$FALCO_SERVICE"

    sleep 2

    if falco_is_active; then

        ok "Falco is active: $FALCO_SERVICE"

    else

        error "Falco failed to become active"

        systemctl status \
            "$FALCO_SERVICE" \
            --no-pager ||
            true

        return 1
    fi
}

enable_falco() {
    section "Enabling Falco"

    if ! service_exists; then
        error "Falco service is not available"
        return 1
    fi

    if falco_is_enabled; then

        ok "Falco is already enabled: $FALCO_SERVICE"

        return 0
    fi

    run systemctl enable "$FALCO_SERVICE"

    if falco_is_enabled; then
        ok "Enabled $FALCO_SERVICE"
    else
        error "Falco service could not be enabled"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

show_status() {
    section "Edera + Falco status"

    if [[ -z "$FALCO_SERVICE" ]]; then
        detect_falco_service || true
    fi

    echo "Falco canonical service:"
    echo "  ${FALCO_SERVICE:-not detected}"
    echo

    if [[ -n "$FALCO_SERVICE" ]]; then

        echo "--- systemctl show ---"

        systemctl show \
            "$FALCO_SERVICE" \
            -p Id \
            -p Names \
            -p FragmentPath \
            -p UnitFileState \
            -p LoadState \
            -p ActiveState \
            --no-pager ||
            true

        echo
        echo "--- systemctl status ---"

        systemctl status \
            "$FALCO_SERVICE" \
            --no-pager ||
            true
    fi

    echo
    echo "Edera service:"

    systemctl status \
        "$EDERA_SERVICE" \
        --no-pager ||
        true

    echo
    echo "Edera socket:"

    ls -l \
        "$EDERA_SOCKET" \
        2>/dev/null ||
        true

    echo
    echo "Edera plugin:"

    ls -l \
        "$EDERA_PLUGIN" \
        2>/dev/null ||
        true

    echo
    echo "Edera configuration:"

    ls -l \
        "$EDERA_CONFIG" \
        2>/dev/null ||
        true

    echo
    echo "Edera rules:"

    ls -l \
        "$EDERA_RULES" \
        2>/dev/null ||
        true

    echo
    echo "--- Edera rule names ---"

    if [[ -f "$EDERA_RULES" ]]; then

        grep -nE \
            '^[[:space:]]*-[[:space:]]rule:' \
            "$EDERA_RULES" ||
            true

    else

        warn "Edera rules file does not exist"
    fi
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
        --no-pager ||
        true

    echo
    echo "--- Falco ---"

    if [[ -n "$FALCO_SERVICE" ]]; then

        journalctl \
            -u "$FALCO_SERVICE" \
            --since "30 minutes ago" \
            --no-pager ||
            true

    else

        warn "Falco service was not detected"
    fi
}

# ---------------------------------------------------------------------------
# Full health check
# ---------------------------------------------------------------------------

health_check() {
    local failures=0

    section "Edera + Falco health check"

    if ! detect_falco_service; then
        failures=$((failures + 1))
    fi

    if ! check_edera_installation; then
        failures=$((failures + 1))
    fi

    if ! check_edera_service; then
        failures=$((failures + 1))
    fi

    if ! check_edera_socket; then
        failures=$((failures + 1))
    fi

    if [[ -n "$FALCO_SERVICE" ]]; then

        if falco_is_active; then
            ok "Falco service is active"
        else
            error "Falco service is not active"
            failures=$((failures + 1))
        fi

        if falco_is_enabled; then
            ok "Falco service is enabled"
        else
            warn "Falco service is not enabled"
            failures=$((failures + 1))
        fi

    else

        error "No Falco service available"
        failures=$((failures + 1))
    fi

    if [[ -f "$EDERA_CONFIG" ]]; then
        ok "Edera Falco configuration exists"
    else
        error "Missing Edera Falco configuration:"
        echo "    $EDERA_CONFIG"

        failures=$((failures + 1))
    fi

    if ! check_edera_rules_file; then
        failures=$((failures + 1))
    fi

    if ! check_stale_backups; then
        failures=$((failures + 1))
    fi

    if ! check_edera_plugin; then
        failures=$((failures + 1))
    fi

    if ! check_edera_source; then
        failures=$((failures + 1))
    fi

    if ! validate_falco_configuration; then
        failures=$((failures + 1))
    fi

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
        falco_is_active; then

        info "Stopping $FALCO_SERVICE..."

        systemctl stop \
            "$FALCO_SERVICE" ||
            true
    fi

    rm -f -- "$EDERA_CONFIG"
    rm -f -- "$EDERA_CONFIG_BACKUP"
    rm -f -- "$EDERA_RULES"

    find "$FALCO_CONFIG_DROPIN_DIR" \
        -maxdepth 1 \
        -type f \
        \( \
            -name 'falco-edera-config.yaml.bak' \
            -o -name 'falco-edera-config.yml.bak' \
            -o -name 'falco-edera-*.bak' \
        \) \
        -delete \
        2>/dev/null ||
        true

    ok "Removed Edera Falco configuration and rules"

    if [[ -n "$FALCO_SERVICE" ]] &&
        service_exists; then

        systemctl daemon-reload

        systemctl start \
            "$FALCO_SERVICE" ||
            true
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

    run install \
        -d \
        -m 0755 \
        "$FALCO_CONFIG_DROPIN_DIR"

    run install \
        -d \
        -m 0755 \
        "$FALCO_RULES_DIR"

    ok "Falco configuration directories ready"

    section "Step 5: Remove stale Edera configuration backups"

    remove_stale_backups

    section "Step 6: Write Edera plugin configuration"

    write_edera_config

    section "Step 7: Write Edera rules"

    write_edera_rules

    section "Step 8: Verify Edera rules file"

    check_edera_rules_file

    section "Step 9: Validate configuration before restart"

    validate_falco_configuration

    section "Step 10: Restart Falco"

    restart_falco

    section "Step 11: Enable Falco"

    enable_falco

    section "Step 12: Verify Edera plugin"

    check_edera_plugin
    check_edera_source

    section "Step 13: Final health check"

    health_check

    section "Installation complete"

    ok "Falco + Edera integration is configured"

    echo
    echo "Falco canonical service:"
    echo "  $FALCO_SERVICE"

    echo
    echo "Falco alias:"
    echo "  falco.service"

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

    echo
    echo "Edera plugin configuration:"
    echo "  $EDERA_CONFIG"

    echo
    echo "Edera detection rules:"
    echo "  $EDERA_RULES"

    echo
    echo "Edera rules installed:"

    grep -nE \
        '^[[:space:]]*-[[:space:]]rule:' \
        "$EDERA_RULES" ||
        true
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

The script deliberately uses the canonical Falco systemd unit rather than
the falco.service alias.

For a modern eBPF Falco installation this will normally be:

  falco-modern-bpf.service

Edera Falco plugin configuration:

  $EDERA_CONFIG

Edera Falco detection rules:

  $EDERA_RULES

Required Edera rules:

  - Edera Proc Environ Read
  - Edera Reverse Shell Tool
  - Edera Namespace Escape Attempt
  - Edera Sensitive File Read
  - Edera Outbound Connection
  - Edera Shell Pipe Execution

Additional/custom rules are allowed.
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
