#!/usr/bin/env bash
# install-wazuh-agent.sh
#
# Installs and configures the Wazuh Agent + stunnel client on Ubuntu.
#
# Flow:
#   1. Install stunnel4 (apt)
#   2. Write stunnel client config with SNI tunnels for port 443
#   3. Enable and start stunnel4 service
#   4. Add Wazuh apt repository and install the agent
#   5. Patch /var/ossec/etc/ossec.conf (127.0.0.1:1514 TCP)
#   6. Enroll agent with manager via agent-auth (-P password)
#   7. Enable and start wazuh-agent service
#
# Requirements:
#   - Ubuntu 20.04 / 22.04 / 24.04 (x86_64)
#   - Run as root (sudo bash install-wazuh-agent.sh ...)
#   - Outbound TCP 443 open to agents-wazuh.carbigdata.com.br
#                                 enroll-wazuh.carbigdata.com.br
#
# Usage:
#   sudo bash install-wazuh-agent.sh -n <agent-name> -p <enrollment-password> [options]
#
# Options:
#   -n <name>       Agent name as it appears in the Wazuh Dashboard  (REQUIRED)
#   -p <password>   Enrollment password matching manager's authd.pass (REQUIRED)
#   -w <version>    Wazuh version to install (default: 4.14.5)
#   -s              Skip apt-get update (use cached package lists)
#   -h              Show this help
#
# Examples:
#   sudo bash install-wazuh-agent.sh -n ubuntu-prod-01 -p "YourEnrollSecret"
#   sudo bash install-wazuh-agent.sh -n db-server-02   -p "YourEnrollSecret" -w 4.14.5

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

step()  { echo -e "\n${CYAN}==> $*${RESET}"; }
ok()    { echo -e "    ${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "    ${YELLOW}[!!]${RESET} $*"; }
fail()  { echo -e "    ${RED}[XX]${RESET} $*" >&2; exit 1; }
log()   { echo "$(date '+%Y-%m-%d %H:%M:%S')  $*" >> "$LOG_FILE"; }

# ── Configuration — edit to match your environment ────────────────────────────
AGENTS_SNI="agents-wazuh.carbigdata.com.br"
ENROLL_SNI="enroll-wazuh.carbigdata.com.br"
TUNNEL_PORT=443
AGENT_PORT=1514
ENROLL_PORT=1515

# Paths
STUNNEL_CONF="/etc/stunnel/wazuh-agent.conf"
STUNNEL_DEFAULT="/etc/default/stunnel4"
WAZUH_DIR="/var/ossec"
OSSEC_CONF="$WAZUH_DIR/etc/ossec.conf"
CLIENT_KEYS="$WAZUH_DIR/etc/client.keys"
LOG_FILE="/tmp/wazuh-agent-install.log"
# ──────────────────────────────────────────────────────────────────────────────

# ── Defaults ──────────────────────────────────────────────────────────────────
AGENT_NAME=""
ENROLL_PASS=""
WAZUH_VERSION="4.14.5"
SKIP_UPDATE=false

usage() {
    grep '^#' "$0" | grep -E '^\# ' | sed 's/^# //' | head -40
    exit 0
}

while getopts "n:p:w:sh" opt; do
    case "$opt" in
        n) AGENT_NAME="$OPTARG" ;;
        p) ENROLL_PASS="$OPTARG" ;;
        w) WAZUH_VERSION="$OPTARG" ;;
        s) SKIP_UPDATE=true ;;
        h) usage ;;
        *) fail "Unknown option. Run with -h for help." ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "This script must be run as root. Use: sudo bash $0 $*"

[[ -z "$AGENT_NAME"  ]] && fail "Agent name is required. Use: -n <agent-name>"
[[ -z "$ENROLL_PASS" ]] && fail "Enrollment password is required. Use: -p <password>"
[[ ${#ENROLL_PASS} -lt 8 ]] && fail "Enrollment password must be at least 8 characters."

# Detect architecture
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" =~ ^(amd64|arm64|armhf)$ ]] || fail "Unsupported architecture: $ARCH"

# Detect Ubuntu version
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_NAME="$NAME"
    DISTRO_VERSION="$VERSION_ID"
else
    fail "Cannot determine OS. /etc/os-release not found."
fi

echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗"
echo -e   "║   Wazuh Agent + stunnel — Ubuntu Installer                   ║"
echo -e   "╚══════════════════════════════════════════════════════════════╝${RESET}\n"
echo -e "  Agent name   : ${BOLD}$AGENT_NAME${RESET}"
echo -e "  Wazuh version: $WAZUH_VERSION"
echo -e "  Agents SNI   : $AGENTS_SNI"
echo -e "  Enroll SNI   : $ENROLL_SNI"
echo -e "  OS           : $DISTRO_NAME $DISTRO_VERSION ($ARCH)"
echo -e "  Log file     : $LOG_FILE"
echo ""

log "=== Install started. AgentName=$AGENT_NAME WazuhVersion=$WAZUH_VERSION OS=$DISTRO_NAME $DISTRO_VERSION ==="

# =============================================================================
# STEP 1 — Install stunnel4
# =============================================================================
step "Step 1/7 — Installing stunnel4"

if command -v stunnel4 &>/dev/null || command -v stunnel &>/dev/null; then
    warn "stunnel already installed — skipping"
    log "stunnel already installed"
else
    if [[ "$SKIP_UPDATE" == false ]]; then
        echo "    Updating package lists..."
        apt-get update -qq
    fi
    apt-get install -y stunnel4 curl gnupg2 >/dev/null
    ok "stunnel4 installed"
    log "stunnel4 installed"
fi

# =============================================================================
# STEP 2 — Write stunnel client config
# =============================================================================
step "Step 2/7 — Writing stunnel client config"

mkdir -p /etc/stunnel

cat > "$STUNNEL_CONF" << EOF
; stunnel client config — Wazuh agent tunnel
; Wraps Wazuh binary protocol in TLS with SNI so it can be routed
; through the external-ingress on port $TUNNEL_PORT.
;
; DO NOT EDIT — managed by install-wazuh-agent.sh

client    = yes
foreground = no
pid       = /run/stunnel4/wazuh-agent.pid

; verify = 2  → validate server cert against system CA bundle (/etc/ssl/certs).
;               The server presents a Let's Encrypt cert — Ubuntu trusts it
;               by default via ca-certificates.
; checkHost  → enforce that cert CN/SAN matches the connected hostname.

; Agent keepalive (ossec-agentd → wazuh-master:$AGENT_PORT)
[wazuh-agents]
accept    = 127.0.0.1:$AGENT_PORT
connect   = ${AGENTS_SNI}:${TUNNEL_PORT}
sni       = $AGENTS_SNI
verify    = 2
checkHost = $AGENTS_SNI
CApath    = /etc/ssl/certs

; Agent enrollment (agent-auth → wazuh-master:$ENROLL_PORT)
[wazuh-enrollment]
accept    = 127.0.0.1:$ENROLL_PORT
connect   = ${ENROLL_SNI}:${TUNNEL_PORT}
sni       = $ENROLL_SNI
verify    = 2
checkHost = $ENROLL_SNI
CApath    = /etc/ssl/certs
EOF

ok "Config written to $STUNNEL_CONF"
log "stunnel.conf written"

# =============================================================================
# STEP 3 — Enable and start stunnel4 service
# =============================================================================
step "Step 3/7 — Enabling stunnel4 service"

# The Debian/Ubuntu stunnel4 package uses /etc/default/stunnel4 to enable the daemon
if [[ -f "$STUNNEL_DEFAULT" ]]; then
    sed -i 's/^ENABLED=0/ENABLED=1/' "$STUNNEL_DEFAULT"
    # Ensure FILES points to our config
    if grep -q '^FILES=' "$STUNNEL_DEFAULT"; then
        sed -i 's|^FILES=.*|FILES="/etc/stunnel/*.conf"|' "$STUNNEL_DEFAULT"
    else
        echo 'FILES="/etc/stunnel/*.conf"' >> "$STUNNEL_DEFAULT"
    fi
fi

systemctl daemon-reload
systemctl enable stunnel4 --quiet
systemctl restart stunnel4

# Give it a moment to bind
sleep 2

if ! systemctl is-active --quiet stunnel4; then
    journalctl -u stunnel4 --no-pager -n 20 >&2
    fail "stunnel4 failed to start — see journal above"
fi
ok "stunnel4 running"
log "stunnel4 started"

# Verify ports
for PORT in $AGENT_PORT $ENROLL_PORT; do
    echo -n "    Waiting for stunnel to listen on $PORT..."
    DEADLINE=$(( $(date +%s) + 30 ))
    until ss -tlnp 2>/dev/null | grep -q ":$PORT "; do
        [[ $(date +%s) -gt $DEADLINE ]] && fail "stunnel not listening on $PORT after 30s"
        sleep 1
    done
    echo -e " ${GREEN}OK${RESET}"
done
log "stunnel ports $AGENT_PORT and $ENROLL_PORT verified"

# =============================================================================
# STEP 4 — Add Wazuh apt repo and install the agent
# =============================================================================
step "Step 4/7 — Installing Wazuh Agent"

if systemctl is-active --quiet wazuh-agent 2>/dev/null || \
   [[ -f "$WAZUH_DIR/bin/wazuh-agentd" ]]; then
    warn "Wazuh Agent already installed — skipping package install"
    log "Wazuh already installed"
else
    WAZUH_GPG="/usr/share/keyrings/wazuh.gpg"
    WAZUH_LIST="/etc/apt/sources.list.d/wazuh.list"

    if [[ ! -f "$WAZUH_GPG" ]]; then
        echo "    Importing Wazuh GPG key..."
        curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH \
            | gpg --no-default-keyring \
                  --keyring gnupg-ring:"$WAZUH_GPG" \
                  --import
        chmod 644 "$WAZUH_GPG"
    fi

    if [[ ! -f "$WAZUH_LIST" ]]; then
        echo "deb [signed-by=$WAZUH_GPG] https://packages.wazuh.com/4.x/apt/ stable main" \
            > "$WAZUH_LIST"
    fi

    if [[ "$SKIP_UPDATE" == false ]]; then
        apt-get update -qq
    fi

    echo "    Installing wazuh-agent=$WAZUH_VERSION-1 (this may take a minute)..."
    WAZUH_MANAGER="127.0.0.1"           \
    WAZUH_MANAGER_PORT="$AGENT_PORT"    \
    WAZUH_PROTOCOL="TCP"                \
    WAZUH_AGENT_NAME="$AGENT_NAME"      \
    WAZUH_REGISTRATION_SERVER="127.0.0.1" \
    WAZUH_REGISTRATION_PORT="$ENROLL_PORT" \
    apt-get install -y "wazuh-agent=$WAZUH_VERSION-1" >/dev/null

    ok "Wazuh Agent installed"
    log "wazuh-agent $WAZUH_VERSION installed"
fi

# =============================================================================
# STEP 5 — Verify / patch ossec.conf
# =============================================================================
step "Step 5/7 — Verifying ossec.conf"

[[ -f "$OSSEC_CONF" ]] || fail "ossec.conf not found at $OSSEC_CONF"

PATCHED=false

patch_xml_value() {
    local field="$1" expected="$2"
    local current
    current=$(grep -oP "(?<=<${field}>)[^<]+" "$OSSEC_CONF" || true)
    if [[ "$current" != "$expected" ]]; then
        sed -i "s|<${field}>${current}</${field}>|<${field}>${expected}</${field}>|" "$OSSEC_CONF"
        warn "Patched: <$field> $current → $expected"
        PATCHED=true
    fi
}

patch_xml_value "address"  "127.0.0.1"
patch_xml_value "port"     "$AGENT_PORT"
patch_xml_value "protocol" "tcp"

if [[ "$PATCHED" == false ]]; then
    ok "ossec.conf already correct — no changes needed"
else
    ok "ossec.conf patched"
fi
log "ossec.conf verified PATCHED=$PATCHED"

# =============================================================================
# STEP 6 — Enroll agent
# =============================================================================
step "Step 6/7 — Enrolling agent"

if [[ -s "$CLIENT_KEYS" ]]; then
    warn "client.keys already exists — skipping enrollment (agent already registered)"
    log "Enrollment skipped — already enrolled"
else
    echo "    Running agent-auth..."
    AUTH_OUT=$("$WAZUH_DIR/bin/agent-auth" \
        -m 127.0.0.1 \
        -p "$ENROLL_PORT" \
        -A "$AGENT_NAME" \
        -P "$ENROLL_PASS" 2>&1) || true

    log "agent-auth output: $AUTH_OUT"

    if echo "$AUTH_OUT" | grep -q "Valid key received"; then
        ok "Agent enrolled successfully"
        log "Enrollment successful"
    else
        echo ""
        echo -e "  ${YELLOW}agent-auth output:${RESET}"
        echo "$AUTH_OUT" | sed 's/^/    /'
        fail "Enrollment failed — check stunnel connectivity to ${ENROLL_SNI}:${TUNNEL_PORT}"
    fi
fi

# =============================================================================
# STEP 7 — Enable and start wazuh-agent
# =============================================================================
step "Step 7/7 — Starting wazuh-agent service"

systemctl daemon-reload
systemctl enable wazuh-agent --quiet
systemctl restart wazuh-agent

sleep 3

WAZUH_STATUS=$(systemctl is-active wazuh-agent 2>/dev/null || echo "unknown")
if [[ "$WAZUH_STATUS" == "active" ]]; then
    ok "wazuh-agent running"
    log "wazuh-agent started"
else
    warn "wazuh-agent status: $WAZUH_STATUS — check $WAZUH_DIR/logs/ossec.log"
    log "wazuh-agent status=$WAZUH_STATUS"
fi

# =============================================================================
# Summary
# =============================================================================
AGENT_ID=$(awk '{print $1}' "$CLIENT_KEYS" 2>/dev/null || echo "—")

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗"
echo -e   "║   Installation complete                                       ║"
echo -e   "╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Agent name : ${BOLD}$AGENT_NAME${RESET}"
echo -e "  Agent ID   : $AGENT_ID"
echo ""
echo "  Services:"
printf "    %-12s: %s\n" "stunnel4"     "$(systemctl is-active stunnel4 2>/dev/null)"
printf "    %-12s: %s\n" "wazuh-agent"  "$(systemctl is-active wazuh-agent 2>/dev/null)"
echo ""
echo "  Log files:"
echo "    Install  : $LOG_FILE"
echo "    Wazuh    : $WAZUH_DIR/logs/ossec.log"
echo "    stunnel  : journalctl -u stunnel4 -f"
echo ""
echo -e "  ${CYAN}Verify on the manager:${RESET}"
echo "    docker exec -it \$(docker ps -q -f name=wazuh-master) \\"
echo "      /var/ossec/bin/agent_control -l"
echo ""

log "=== Install finished ==="
