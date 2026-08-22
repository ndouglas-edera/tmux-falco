```bash
#!/usr/bin/env bash
#
# Cleanly install Falco + the Edera Falco plugin integration.
#
# Target:
#   - Ubuntu 22.04+
#   - Falco 0.44.1
#   - Standalone / single-node Edera
#   - No Kubernetes / Helm
#
# What this script does:
#   1. Verifies Ubuntu/Debian and root access
#   2. Verifies the Edera plugin and daemon socket exist
#   3. Stops/removes any existing Falco installation
#   4. Backs up any existing /etc/falco directory
#   5. Configures the official Falco APT repository
#   6. Installs Falco 0.44.1
#   7. Verifies the package restored /etc/falco/falco.yaml
#   8. Installs the Edera plugin configuration
#   9. Installs Edera detection rules
#  10. Restarts and verifies Falco
#
# Run with:
#   chmod +x install-falco-edera.sh
#   sudo ./install-falco-edera.sh
#

set -Eeuo pipefail

FALCO_VERSION="0.44.1"

FALCO_CONFIG_DIR="/etc/falco"
FALCO_MAIN_CONFIG="/etc/falco/falco.yaml"
FALCO_CONFIG_D="/etc/falco/config.d"
FALCO_RULES_D="/etc/falco/rules.d"

EDERA_PLUGIN="/var/lib/edera/protect/falco/libedera_falco_plugin.so"
EDERA_SOCKET="/var/lib/edera/protect/daemon.socket"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/etc/falco.backup.${TIMESTAMP}"

log() {
    echo
    echo "============================================================"
    echo "[INFO] $*"
    echo "============================================================"
}

success() {
    echo "[ OK ] $*"
}

warn() {
    echo "[WARN] $*" >&2
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

on_error() {
    local exit_code=$?
    echo
    echo "============================================================"
    echo "[ERROR] Script failed at line $1"
    echo "[ERROR] Exit code: ${exit_code}"
    echo "============================================================"
    echo
    echo "Useful troubleshooting commands:"
    echo "  systemctl status falco --no-pager -l"
    echo "  journalctl -u falco -n 200 --no-pager"
    echo "  ls -l ${EDERA_PLUGIN}"
    echo "  ls -l ${EDERA_SOCKET}"
    exit "${exit_code}"
}

trap 'on_error $LINENO' ERR

#
# ------------------------------------------------------------------
# STEP 0: Preconditions
# ------------------------------------------------------------------
#

log "Step 0: Checking prerequisites"

if [[ "${EUID}" -ne 0 ]]; then
    error "Please run this script with sudo."
fi

if [[ ! -f /etc/os-release ]]; then
    error "/etc/os-release not found. Unable to identify operating system."
fi

# shellcheck disable=SC1091
source /etc/os-release

if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *"debian"* ]]; then
    error "This script currently supports Ubuntu/Debian only. Detected: ${PRETTY_NAME:-unknown}"
fi

success "Operating system: ${PRETTY_NAME:-unknown}"

#
# ------------------------------------------------------------------
# STEP 1: Verify Edera prerequisites BEFORE touching Falco
# ------------------------------------------------------------------
#

log "Step 1: Verifying Edera prerequisites"

if [[ ! -f "${EDERA_PLUGIN}" ]]; then
    error "Edera Falco plugin not found: ${EDERA_PLUGIN}"
fi

success "Found Edera Falco plugin:"
ls -lh "${EDERA_PLUGIN}"

if [[ ! -S "${EDERA_SOCKET}" ]]; then
    error "Edera daemon socket not found: ${EDERA_SOCKET}"
fi

success "Found Edera daemon socket:"
ls -lh "${EDERA_SOCKET}"

#
# ------------------------------------------------------------------
# STEP 2: Stop existing Falco services
# ------------------------------------------------------------------
#

log "Step 2: Stopping any existing Falco services"

systemctl stop falco 2>/dev/null || true
systemctl stop falco-modern-bpf 2>/dev/null || true
systemctl stop falco-kmod 2>/dev/null || true
systemctl stop falcoctl-artifact-follow 2>/dev/null || true

systemctl disable falco 2>/dev/null || true
systemctl disable falco-modern-bpf 2>/dev/null || true
systemctl disable falco-kmod 2>/dev/null || true
systemctl disable falcoctl-artifact-follow 2>/dev/null || true

systemctl daemon-reload

success "Existing Falco services stopped"

#
# ------------------------------------------------------------------
# STEP 3: Remove existing Falco package
# ------------------------------------------------------------------
#

log "Step 3: Removing any existing Falco package"

if dpkg -s falco >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    FALCO_FRONTEND=noninteractive FALCOCTL_ENABLED=no \
        apt-get remove --purge -y falco
else
    success "Falco package is not currently installed"
fi

apt-get autoremove -y

success "Existing Falco package removed"

#
# ------------------------------------------------------------------
# STEP 4: Back up remaining Falco configuration
# ------------------------------------------------------------------
#

log "Step 4: Backing up any existing Falco configuration"

if [[ -e "${FALCO_CONFIG_DIR}" ]]; then
    mv "${FALCO_CONFIG_DIR}" "${BACKUP_DIR}"
    success "Backed up old configuration to:"
    echo "       ${BACKUP_DIR}"
else
    success "No existing /etc/falco directory found"
fi

#
# ------------------------------------------------------------------
# STEP 5: Configure official Falco repository
# ------------------------------------------------------------------
#

log "Step 5: Configuring official Falco APT repository"

apt-get update -y
apt-get install -y \
    ca-certificates \
    curl \
    gnupg

install -d -m 0755 /usr/share/keyrings

curl -fsSL \
    https://falco.org/repo/falcosecurity-packages.asc \
    | gpg --dearmor --yes \
    -o /usr/share/keyrings/falco-archive-keyring.gpg

cat >/etc/apt/sources.list.d/falcosecurity.list <<'EOF'
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF

apt-get update -y

success "Falco repository configured"

#
# ------------------------------------------------------------------
# STEP 6: Install Falco 0.44.1
# ------------------------------------------------------------------
#

log "Step 6: Installing Falco ${FALCO_VERSION}"

AVAILABLE_VERSION="$(
    apt-cache madison falco \
        | awk '{print $3}' \
        | grep -E "^${FALCO_VERSION}([.+:~-].*)?$" \
        | head -n1 || true
)"

if [[ -z "${AVAILABLE_VERSION}" ]]; then
    echo
    echo "Available Falco versions:"
    apt-cache madison falco || true
    echo
    error "Could not find Falco ${FALCO_VERSION} in the configured APT repository."
fi

echo "Installing package version: ${AVAILABLE_VERSION}"

export DEBIAN_FRONTEND=noninteractive

FALCO_FRONTEND=noninteractive \
FALCOCTL_ENABLED=no \
apt-get install -y "falco=${AVAILABLE_VERSION}"

success "Falco ${AVAILABLE_VERSION} installed"

#
# ------------------------------------------------------------------
# STEP 7: Verify pristine Falco installation
# ------------------------------------------------------------------
#

log "Step 7: Verifying Falco installation"

command -v falco >/dev/null \
    || error "Falco binary was not installed"

falco --version

[[ -f "${FALCO_MAIN_CONFIG}" ]] \
    || error "Expected default Falco config was not installed: ${FALCO_MAIN_CONFIG}"

success "Default Falco configuration exists:"
echo "       ${FALCO_MAIN_CONFIG}"

mkdir -p "${FALCO_CONFIG_D}"
mkdir -p "${FALCO_RULES_D}"

#
# ------------------------------------------------------------------
# STEP 8: Write Edera Falco plugin configuration
# ------------------------------------------------------------------
#

log "Step 8: Writing Edera plugin configuration"

cat >"${FALCO_CONFIG_D}/falco-edera-config.yaml" <<'EOF'
plugins:
  - name: container
    library_path: libcontainer.so
    init_config:
      label_max_len: 100
      with_size: false

  - name: edera
    library_path: /var/lib/edera/protect/falco/libedera_falco_plugin.so

load_plugins:
  - edera
EOF

chmod 0644 "${FALCO_CONFIG_D}/falco-edera-config.yaml"

success "Created:"
echo "       ${FALCO_CONFIG_D}/falco-edera-config.yaml"

#
# NOTE:
#
# The Edera preview documentation explains mirror_host_syscalls: false
# as the recommended behavior, but the node-based YAML snippet shown in
# the preview page does not include that key.
#
# Therefore this script intentionally follows the literal node-based
# YAML snippet and does NOT invent an undocumented config key.
#
# If Edera confirms the setting belongs in this file, add:
#
# mirror_host_syscalls: false
#
# as directed by Edera.
#

#
# ------------------------------------------------------------------
# STEP 9: Write Edera detection rules
# ------------------------------------------------------------------
#

log "Step 9: Writing Edera detection rules"

cat >"${FALCO_RULES_D}/falco-edera-rules.yaml" <<'EOF'
- rule: Edera Proc Environ Read
  desc: >
    Detect reads of /proc/*/environ inside an Edera zone.
    Credential harvesting via procfs is a common post-exploitation
    technique for extracting secrets from neighboring workloads.
  source: edera_zone
  output: >
    Credential harvesting attempt in zone
    (zone_id=%edera.zone.id proc=%proc.exe file=%fd.name)
  priority: WARNING
  condition: >
    evt.pluginname == "edera" and
    evt.type in (open, openat) and
    fd.name glob /proc/*/environ

- rule: Edera Reverse Shell Tool
  desc: >
    Detect execution of common reverse shell tools inside an Edera zone.
    Legitimate workloads rarely invoke netcat, socat, or similar tools.
  source: edera_zone
  output: >
    Reverse shell tool executed in zone
    (zone_id=%edera.zone.id proc=%proc.exe cmdline=%proc.cmdline)
  priority: CRITICAL
  condition: >
    evt.pluginname == "edera" and
    evt.type in (execve, execveat) and
    proc.name in (nc, ncat, netcat, socat, telnet)

- rule: Edera Namespace Escape Attempt
  desc: >
    Detect nsenter execution inside an Edera zone.
    nsenter is commonly used in container escape and privilege
    escalation attempts to enter host or other container namespaces.
  source: edera_zone
  output: >
    Namespace escape attempt in zone
    (zone_id=%edera.zone.id proc=%proc.exe cmdline=%proc.cmdline)
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
    Sensitive file read in zone
    (zone_id=%edera.zone.id proc=%proc.exe file=%fd.name)
  priority: WARNING
  condition: >
    evt.pluginname == "edera" and
    evt.type in (open, openat) and
    (fd.name startswith /etc/shadow or
     fd.name startswith /etc/kubernetes or
     fd.name startswith /run/secrets)

- rule: Edera Outbound Connection
  desc: Detect outbound network connections from Edera zones
  source: edera_zone
  output: >
    Outbound connection from zone
    (zone_id=%edera.zone.id proc=%proc.exe dest=%fd.rip:%fd.rport
    proto=%fd.l4proto)
  priority: NOTICE
  condition: >
    evt.pluginname == "edera" and
    evt.type == connect and
    fd.type == ipv4
EOF

chmod 0644 "${FALCO_RULES_D}/falco-edera-rules.yaml"

success "Created:"
echo "       ${FALCO_RULES_D}/falco-edera-rules.yaml"

#
# ------------------------------------------------------------------
# STEP 10: Show effective files before startup
# ------------------------------------------------------------------
#

log "Step 10: Verifying installed files"

echo
echo "Falco configuration:"
find "${FALCO_CONFIG_DIR}" -maxdepth 2 -type f -print | sort

echo
echo "Edera plugin:"
ls -lh "${EDERA_PLUGIN}"

echo
echo "Edera daemon socket:"
ls -lh "${EDERA_SOCKET}"

#
# ------------------------------------------------------------------
# STEP 11: Start Falco
# ------------------------------------------------------------------
#

log "Step 11: Starting Falco"

systemctl daemon-reload

# The package installation may create falco.service or a selected
# engine-specific unit. Prefer falco.service if available.
if systemctl cat falco.service >/dev/null 2>&1; then
    systemctl enable falco
    systemctl restart falco
    FALCO_UNIT="falco"
elif systemctl cat falco-modern-bpf.service >/dev/null 2>&1; then
    systemctl enable falco-modern-bpf
    systemctl restart falco-modern-bpf
    FALCO_UNIT="falco-modern-bpf"
else
    error "Could not find a Falco systemd service after installation."
fi

success "Started systemd unit: ${FALCO_UNIT}"

sleep 5

#
# ------------------------------------------------------------------
# STEP 12: Verify Falco is healthy
# ------------------------------------------------------------------
#

log "Step 12: Verifying Falco service"

if ! systemctl is-active --quiet "${FALCO_UNIT}"; then
    echo
    echo "Falco failed to remain active."
    echo
    systemctl status "${FALCO_UNIT}" --no-pager -l || true
    echo
    journalctl -u "${FALCO_UNIT}" -n 200 --no-pager || true
    error "Falco service is not healthy."
fi

success "Falco service is active"

echo
echo "Falco version:"
falco --version

echo
echo "Recent Edera-related log messages:"
journalctl -u "${FALCO_UNIT}" -n 200 --no-pager \
    | grep -i edera || warn "No Edera log messages found yet."

#
# ------------------------------------------------------------------
# COMPLETE
# ------------------------------------------------------------------
#

echo
echo "============================================================"
echo "SUCCESS"
echo "============================================================"
echo
echo "Falco has been reinstalled and configured for Edera."
echo
echo "Falco version:"
falco --version | head -n 1
echo
echo "Main Falco configuration:"
echo "  ${FALCO_MAIN_CONFIG}"
echo
echo "Edera plugin configuration:"
echo "  ${FALCO_CONFIG_D}/falco-edera-config.yaml"
echo
echo "Edera rules:"
echo "  ${FALCO_RULES_D}/falco-edera-rules.yaml"
echo
echo "Falco systemd unit:"
echo "  ${FALCO_UNIT}"
echo
echo "Old Falco configuration backup:"
if [[ -d "${BACKUP_DIR}" ]]; then
    echo "  ${BACKUP_DIR}"
else
    echo "  No old /etc/falco directory existed at script runtime."
fi
echo
echo "Next verification step:"
echo
echo "  sudo journalctl -u ${FALCO_UNIT} -f"
echo
echo "Then launch an Edera zone and look for Edera plugin messages"
echo "showing zone discovery and event streaming."
echo
```
