#!/bin/bash
# =============================================================================
# Raspberry Pi Hardening Script — "Don't Get Pwned" Edition
#
# Goal: Create a sandboxed AI agent account that can wreak havoc on projects
#       but CANNOT escalate privileges, steal credentials, or
#       pivot to your home network.
#
# Run as:    sudo bash harden-pi.sh
# Verify as: sudo bash harden-pi.sh verify   (proves the walls hold, run AS the AI user)
# Tested on: Raspberry Pi OS (Debian-based)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${BLUE}    $1${NC}"; }

# Prompt the user to confirm a step.
# Args: step_num, title, explanation, [already_done_message]
# If already_done_message is provided, shows it and asks to re-apply.
# Returns 0 if user confirms, 1 if skipped.
confirm_step() {
    local step_num="$1"
    local title="$2"
    local explanation="$3"
    local already_done="${4:-}"

    echo ""
    clear
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  ${BLUE}Step $step_num:${NC} $title"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [[ -n "$already_done" ]]; then
        echo -e "  ${GREEN}✓ Already done:${NC}"
        while IFS= read -r line; do
            echo -e "    ${GREEN}$line${NC}"
        done <<< "$already_done"
        echo ""
        while IFS= read -r line; do
            info "$line"
        done <<< "$explanation"
        echo ""
        read -p "  Re-apply anyway? (Y/n/q to quit) " -n 1 -r
    else
        while IFS= read -r line; do
            info "$line"
        done <<< "$explanation"
        echo ""
        read -p "  Proceed with this step? (Y/n/q to quit) " -n 1 -r
    fi

    echo ""
    if [[ $REPLY =~ ^[Qq]$ ]]; then
        warn "Aborted by user at step $step_num."
        exit 0
    fi
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        warn "Skipped step $step_num: $title"
        return 1
    fi
    return 0
}

# =============================================================================
# VERIFY MODE — self-test that runs the attacks AS the AI user and proves
# each wall holds. Safe to run any time: sudo bash harden-pi.sh verify
# =============================================================================

V_PASS=0
V_FAIL=0
v_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; V_PASS=$((V_PASS + 1)); }
v_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; V_FAIL=$((V_FAIL + 1)); }
v_skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; }

run_verify() {
    # Run commands as the AI user
    as_ai() { runuser -u "$AI_USER" -- "$@"; }

    echo ""
    echo "  Verifying hardening — attacks below run AS '$AI_USER'"
    echo "  ─────────────────────────────────────────────────────"
    echo ""

    if ! id "$AI_USER" &>/dev/null; then
        v_fail "User '$AI_USER' does not exist — run the hardening script first"
        exit 1
    fi
    AI_UID=$(id -u "$AI_USER")

    # Sanity check: every "attack" below runs via runuser. If runuser itself
    # is broken, failed attacks would false-PASS and DNS/internet would
    # false-FAIL — so refuse to continue with unreliable results.
    if ! as_ai true 2>/dev/null; then
        err "Cannot run commands as '$AI_USER' (runuser failed):"
        runuser -u "$AI_USER" -- true 2>&1 | sed 's/^/    /' || true
        err "All verify results would be unreliable — fix this first."
        exit 1
    fi

    # --- Privilege escalation ---
    if as_ai sudo -n true &>/dev/null; then
        v_fail "AI can run sudo — privilege escalation possible!"
    else
        v_pass "sudo blocked for $AI_USER"
    fi

    # --- Credential theft ---
    if as_ai ls "/home/$MAIN_USER" &>/dev/null; then
        v_fail "AI can list /home/$MAIN_USER — your files are exposed!"
    else
        v_pass "/home/$MAIN_USER unreadable by AI"
    fi

    if [ -d "/srv/$MAIN_USER" ]; then
        if as_ai ls "/srv/$MAIN_USER" &>/dev/null; then
            v_fail "AI can list /srv/$MAIN_USER — your projects are exposed!"
        else
            v_pass "/srv/$MAIN_USER unreadable by AI"
        fi
    else
        v_skip "/srv/$MAIN_USER does not exist (step 9 not run)"
    fi

    # --- Network pivot ---
    GW=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
    if [ -n "$GW" ]; then
        if as_ai ping -c 1 -W 2 "$GW" &>/dev/null; then
            v_fail "AI can reach the gateway ($GW) — LAN is NOT blocked!"
        else
            v_pass "LAN blocked (gateway $GW unreachable as $AI_USER)"
        fi
    else
        v_skip "No default gateway found — cannot test LAN block"
    fi

    # --- DNS still works (the LAN block must not break it) ---
    # Multiple domains: some home routers return bogus NXDOMAIN for
    # individual domains (seen in the wild with example.com), which would
    # false-fail a single-domain check.
    if as_ai getent hosts google.com &>/dev/null \
       || as_ai getent hosts cloudflare.com &>/dev/null \
       || as_ai getent hosts api.anthropic.com &>/dev/null; then
        v_pass "DNS resolution works for AI"
    else
        v_fail "DNS is broken for AI — LAN block may be dropping resolver traffic"
    fi

    # --- Internet still works ---
    if command -v curl &>/dev/null; then
        if as_ai timeout 10 curl -sI https://www.google.com &>/dev/null \
           || as_ai timeout 10 curl -sI https://api.anthropic.com &>/dev/null; then
            v_pass "Internet (HTTPS) works for AI"
        else
            v_fail "AI cannot reach the internet — API calls will fail"
        fi
    else
        v_skip "curl not installed — cannot test internet access"
    fi

    # --- Main Caddy admin API ---
    if iptables -S OUTPUT 2>/dev/null | grep "uid-owner $AI_UID" | grep -q "dport 2019"; then
        v_pass "Firewall rule blocking main Caddy admin API (:2019) present"
    else
        v_fail "No firewall rule for :2019 — AI could reconfigure your main Caddy!"
    fi
    if systemctl is-active --quiet caddy 2>/dev/null; then
        if as_ai timeout 3 curl -s http://127.0.0.1:2019/config/ &>/dev/null; then
            v_fail "AI can reach main Caddy admin API on :2019!"
        else
            v_pass "Main Caddy admin API unreachable by AI"
        fi
    else
        v_skip "Main Caddy not running — skipped live admin API probe"
    fi

    # --- Outbound SMTP ---
    if iptables -S OUTPUT 2>/dev/null | grep "uid-owner $AI_UID" | grep -q "dport 25"; then
        v_pass "Outbound SMTP (port 25) blocked for AI"
    else
        v_fail "No firewall rule for port 25 — compromised AI could send spam"
    fi

    # --- SSH (check EFFECTIVE config, not just files) ---
    SSHD_T=$(sshd -T 2>/dev/null || true)
    if [ -n "$SSHD_T" ]; then
        if echo "$SSHD_T" | grep -qi "^passwordauthentication no"; then
            v_pass "SSH: password auth disabled (effective config)"
        else
            v_fail "SSH: password auth still enabled — check /etc/ssh/sshd_config.d/ overrides"
        fi
        if echo "$SSHD_T" | grep -qi "^permitrootlogin no"; then
            v_pass "SSH: root login disabled (effective config)"
        else
            v_fail "SSH: root login still permitted"
        fi
        if echo "$SSHD_T" | grep -qi "denyusers.*$AI_USER"; then
            v_pass "SSH: $AI_USER denied login (effective config)"
        else
            v_fail "SSH: $AI_USER is NOT denied login"
        fi
    else
        v_skip "sshd -T failed — cannot check effective SSH config"
    fi

    # --- fail2ban ---
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        if fail2ban-client status sshd &>/dev/null; then
            v_pass "fail2ban running with active sshd jail"
        else
            v_fail "fail2ban running but sshd jail is NOT active (journald backend issue?)"
        fi
    else
        v_skip "fail2ban not running (step 7 not run)"
    fi

    # --- Resource limits ---
    if [ -f "/etc/security/limits.d/${AI_USER}.conf" ]; then
        v_pass "Per-process ulimits configured"
    else
        v_fail "No ulimits file for $AI_USER"
    fi
    if [ -f "/etc/systemd/system/user-${AI_UID}.slice.d/limits.conf" ]; then
        v_pass "cgroup slice limits configured (total memory/CPU/tasks)"
    else
        v_fail "No cgroup slice limits — memory cap is per-process only"
    fi

    # --- Auto updates ---
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        v_pass "Automatic security updates configured"
    else
        v_fail "Automatic security updates NOT configured"
    fi

    # --- Disk cap ---
    if mountpoint -q "/srv/$AI_USER" 2>/dev/null; then
        v_pass "AI disk usage capped ($(df -h "/srv/$AI_USER" | awk 'NR==2 {print $2}') filesystem on /srv/$AI_USER)"
    else
        v_skip "/srv/$AI_USER not on a capped filesystem (step 12 skipped?)"
    fi

    # --- Process hiding ---
    if findmnt -no OPTIONS /proc 2>/dev/null | grep -q hidepid; then
        if as_ai test -d /proc/1 2>/dev/null; then
            v_fail "hidepid set but AI can still see other processes"
        else
            v_pass "AI cannot see other users' processes (hidepid)"
        fi
    else
        v_skip "hidepid not enabled on /proc (step 13 skipped?)"
    fi

    # --- Audit trail ---
    if systemctl is-active --quiet auditd 2>/dev/null && [ -f "/etc/audit/rules.d/${AI_USER}.rules" ]; then
        v_pass "auditd logging every command the AI runs"
    else
        v_skip "auditd not logging AI commands (step 14 skipped?)"
    fi

    # --- Cloudflare Tunnel ---
    if command -v cloudflared &>/dev/null; then
        if systemctl is-active --quiet cloudflared 2>/dev/null; then
            v_pass "Cloudflare Tunnel running"
        else
            v_fail "cloudflared installed but tunnel service not running"
        fi
        if [ -f /etc/cloudflared/tunnel.env ]; then
            TOKEN_META=$(stat -c '%a %U' /etc/cloudflared/tunnel.env 2>/dev/null)
            if [ "$TOKEN_META" = "600 root" ]; then
                v_pass "Tunnel token file is root-only (mode 600)"
            else
                v_fail "Tunnel token file perms are '$TOKEN_META' — should be '600 root'"
            fi
            if as_ai cat /etc/cloudflared/tunnel.env &>/dev/null; then
                v_fail "AI can read the tunnel token — it could hijack your traffic!"
            else
                v_pass "Tunnel token unreadable by AI"
            fi
        fi
    else
        v_skip "cloudflared not installed (step 15 skipped?)"
    fi

    echo ""
    echo "  ─────────────────────────────────────────────────────"
    if [ "$V_FAIL" -eq 0 ]; then
        echo -e "  ${GREEN}✅ $V_PASS checks passed, 0 failed${NC}"
        exit 0
    else
        echo -e "  ${RED}❌ $V_FAIL check(s) FAILED${NC} ($V_PASS passed) — re-run the hardening script"
        exit 1
    fi
}

# =============================================================================
# Startup
# =============================================================================

# Must run as root
if [ "$EUID" -ne 0 ]; then
    err "Run this script with sudo"
    exit 1
fi

MODE="${1:-harden}"
case "$MODE" in
    harden|verify) ;;
    *)
        err "Usage: sudo bash harden-pi.sh [verify]"
        exit 1
        ;;
esac

echo ""
echo "================================================"
if [ "$MODE" = "verify" ]; then
    echo "  Raspberry Pi Hardening — Verification Mode    "
else
    echo "  Raspberry Pi Hardening for AI Agent Isolation "
fi
echo "================================================"
echo ""

# Ask for main username
read -p "  Enter YOUR Linux username on this Pi: " MAIN_USER

if [[ -z "$MAIN_USER" ]]; then
    err "Username cannot be empty."
    exit 1
fi

if ! id "$MAIN_USER" &>/dev/null; then
    err "Account '$MAIN_USER' does not exist on this system."
    exit 1
fi

# Ask for AI account name
echo ""
read -p "  Enter a name for the AI agent account [ai-agent]: " AI_USER_INPUT
AI_USER="${AI_USER_INPUT:-ai-agent}"

# Validate username
if [[ ! "$AI_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    err "Invalid username '$AI_USER'. Use lowercase letters, numbers, hyphens, underscores."
    exit 1
fi

if [ "$AI_USER" = "$MAIN_USER" ]; then
    err "AI agent account cannot be the same as your account ($MAIN_USER)"
    exit 1
fi

if [ "$MODE" = "verify" ]; then
    run_verify   # exits
fi

echo ""
echo "  Your account:      $MAIN_USER"
echo "  AI agent account:  $AI_USER"
echo ""
read -p "  Start hardening? (Y/n) " -n 1 -r
echo ""
[[ $REPLY =~ ^[Nn]$ ]] && exit 1


# =============================================================================
# STEP 1: Create the AI agent user
# =============================================================================

STEP1_DONE=""
if id "$AI_USER" &>/dev/null; then
    STEP1_DONE="User '$AI_USER' already exists with home at /home/$AI_USER."
fi

confirm_step 1 "Create AI agent user" \
"Creates a sandboxed Linux account called '$AI_USER' with its own home directory.
This is the foundation of isolation — every permission and restriction
we set up later builds on this account boundary. The AI agent gets a bash
shell so it can run commands, but will have no sudo access." \
"$STEP1_DONE" && {

if id "$AI_USER" &>/dev/null; then
    warn "$AI_USER already exists, skipping creation"
else
    useradd -m -s /bin/bash "$AI_USER"
    log "Created user: $AI_USER"
fi

}


# =============================================================================
# STEP 2: Lock down your home directory
# =============================================================================

STEP2_DONE=""
if [ -d "/home/$MAIN_USER" ]; then
    PERMS=$(stat -c '%a' "/home/$MAIN_USER" 2>/dev/null)
    if [ "$PERMS" = "700" ]; then
        STEP2_DONE="/home/$MAIN_USER is already mode 700 (owner-only)."
    fi
fi

confirm_step 2 "Lock down your home directory" \
"Sets /home/$MAIN_USER to mode 700 (owner-only access).
The AI agent won't be able to list, read, or enter your home directory.
This protects your SSH keys, .env files, API tokens, bash history,
and any other personal files. Also tightens .ssh permissions." \
"$STEP2_DONE" && {

chmod 700 "/home/$MAIN_USER"
log "Set /home/$MAIN_USER to mode 700 (owner-only access)"

if [ -d "/home/$MAIN_USER/.ssh" ]; then
    chmod 700 "/home/$MAIN_USER/.ssh"
    chmod 600 "/home/$MAIN_USER/.ssh/"* 2>/dev/null || true
    log "Tightened SSH key permissions"
fi

}


# =============================================================================
# STEP 3: Ensure AI agent has NO sudo access
# =============================================================================

STEP3_DONE=""
SUDOERS_FILE="/etc/sudoers.d/${AI_USER}-deny"
if [ -f "$SUDOERS_FILE" ] && ! groups "$AI_USER" 2>/dev/null | grep -q '\bsudo\b'; then
    STEP3_DONE="$AI_USER is not in sudo group and $SUDOERS_FILE exists."
fi

confirm_step 3 "Block sudo access for AI agent" \
"Without sudo, the AI agent cannot become root, install system packages,
or modify system config. Even if fully compromised, the attacker is
stuck as an unprivileged account. This is the single most important wall.
Creates an explicit deny rule in /etc/sudoers.d/ as a safety net." \
"$STEP3_DONE" && {

if groups "$AI_USER" 2>/dev/null | grep -q '\bsudo\b'; then
    gpasswd -d "$AI_USER" sudo
    log "Removed $AI_USER from sudo group"
else
    log "$AI_USER is not in sudo group (good)"
fi

SUDOERS_FILE="/etc/sudoers.d/${AI_USER}-deny"
echo "$AI_USER ALL=(ALL) !ALL" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"
log "Created explicit sudo deny rule"

}


# =============================================================================
# STEP 4: Block AI agent from your home network (LAN) + local attack surface
# =============================================================================

STEP4_DONE=""
if id "$AI_USER" &>/dev/null; then
    AI_UID=$(id -u "$AI_USER")
    EXISTING_RULES=$(iptables -S OUTPUT 2>/dev/null | grep -c "owner --uid-owner $AI_UID" || true)
    HAS_2019=$(iptables -S OUTPUT 2>/dev/null | grep "owner --uid-owner $AI_UID" | grep -c "dport 2019" || true)
    if [ "$EXISTING_RULES" -ge 6 ] && [ "$HAS_2019" -ge 1 ]; then
        STEP4_DONE="Found $EXISTING_RULES iptables rules for UID $AI_UID (LAN + Caddy admin + SMTP)."
    fi
fi

confirm_step 4 "Block AI agent from LAN + local attack surface" \
"THE BIG ONE. If the AI gets compromised, an attacker will try to scan
your local network — router, NAS, other computers, smart home devices.
These iptables rules block ALL traffic from '$AI_USER' to private IPs:
  • 192.168.0.0/16  (most home routers)
  • 10.0.0.0/8      (some networks)
  • 172.16.0.0/12   (other private range)
  • 169.254.0.0/16  (link-local / mDNS)
Matching ip6tables rules block the IPv6 LAN too (fc00::/7, fe80::/10).
It ALSO blocks two local holes:
  • Port 2019 — the main Caddy's admin API. Without this rule the AI
    could POST a new config to localhost:2019 and hijack YOUR routes.
  • Port 25 — outbound SMTP, so a compromised agent can't send spam.
And it adds an EXCEPTION so DNS keeps working: your resolver is usually
the router itself, which the LAN block would otherwise silently break.
The AI can still reach the internet (for API calls) but cannot touch
anything on your LAN. Rules are persisted across reboots." \
"$STEP4_DONE" && {

AI_UID=$(id -u "$AI_USER")

# Flush existing rules for this UID (safe to re-run)
iptables -S OUTPUT 2>/dev/null | grep "owner --uid-owner $AI_UID" | while read -r rule; do
    iptables $(echo "$rule" | sed 's/-A/-D/')
done 2>/dev/null || true

# --- Exceptions FIRST (iptables matches in order) ---
# DNS: /etc/resolv.conf usually points at the router — a private IP that
# the LAN block below would drop, silently breaking all AI DNS lookups.
DNS_ALLOWED=""
while read -r ns; do
    case "$ns" in
        10.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
            iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d "$ns" -p udp --dport 53 -j ACCEPT
            iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d "$ns" -p tcp --dport 53 -j ACCEPT
            DNS_ALLOWED="$DNS_ALLOWED $ns"
            ;;
    esac
done < <(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null)

GW=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
if [ -z "$DNS_ALLOWED" ] && [ -n "$GW" ]; then
    iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d "$GW" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d "$GW" -p tcp --dport 53 -j ACCEPT
    DNS_ALLOWED=" $GW (default gateway)"
fi
if [ -n "$DNS_ALLOWED" ]; then
    log "DNS exception: allowed port 53 to$DNS_ALLOWED"
else
    log "No LAN resolver found in /etc/resolv.conf — no DNS exception needed"
fi

# --- Local holes ---
# Main Caddy admin API: unauthenticated on localhost:2019 by default.
# Without this, the AI could rewrite your reverse-proxy routes.
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -p tcp --dport 2019 -j DROP
# Outbound SMTP: a compromised agent shouldn't be able to send spam.
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -p tcp --dport 25 -j DROP
log "Blocked $AI_USER from main Caddy admin API (:2019) and outbound SMTP (:25)"

# --- LAN block ---
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 192.168.0.0/16 -j DROP
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 169.254.0.0/16 -j DROP

log "Blocked $AI_USER (UID $AI_UID) from all LAN traffic (IPv4)"

# Same treatment for IPv6 — otherwise the AI could pivot to LAN peers
# over IPv6 (ULA + link-local) even with the IPv4 rules in place.
if command -v ip6tables &>/dev/null; then
    ip6tables -S OUTPUT 2>/dev/null | grep "owner --uid-owner $AI_UID" | while read -r rule; do
        ip6tables $(echo "$rule" | sed 's/-A/-D/')
    done 2>/dev/null || true

    ip6tables -A OUTPUT -m owner --uid-owner "$AI_UID" -p tcp --dport 2019 -j DROP
    ip6tables -A OUTPUT -m owner --uid-owner "$AI_UID" -p tcp --dport 25 -j DROP
    ip6tables -A OUTPUT -m owner --uid-owner "$AI_UID" -d fc00::/7 -j DROP
    ip6tables -A OUTPUT -m owner --uid-owner "$AI_UID" -d fe80::/10 -j DROP
    log "Blocked $AI_USER (UID $AI_UID) over IPv6 too (LAN + :2019 + :25)"
else
    warn "ip6tables not found — IPv6 LAN not blocked (fine if IPv6 is disabled)"
fi

if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    log "iptables rules saved"
else
    apt-get install -y -qq iptables-persistent
    netfilter-persistent save
    log "Installed iptables-persistent and saved rules"
fi

}


# =============================================================================
# STEP 5: Set resource limits (ulimits + cgroup slice)
# =============================================================================

STEP5_DONE=""
AI_UID=$(id -u "$AI_USER" 2>/dev/null || true)
if [ -f "/etc/security/limits.d/${AI_USER}.conf" ] \
   && [ -n "$AI_UID" ] && [ -f "/etc/systemd/system/user-${AI_UID}.slice.d/limits.conf" ]; then
    STEP5_DONE="ulimits file and cgroup slice limits both exist."
fi

confirm_step 5 "Set resource limits for AI agent" \
"Two layers of protection:
  1. Per-process ulimits:
     • Fork bomb → capped at 200 processes
     • File descriptor exhaustion → max 4096 open files
     • Max 1GB per file, core dumps disabled
  2. cgroup slice — caps the TOTAL across ALL AI processes combined:
     • MemoryMax 2GB, CPUQuota 300% (3 cores), TasksMax 200
The old per-process 2GB virtual-memory cap ('as') is gone: it broke
mmap-heavy runtimes (Node, JVM) and was trivially bypassed by just
spawning more processes. The cgroup slice caps the real total.
NOTE: the slice applies to the AI's login sessions and user services.
If you launch the agent yourself, do it via the provided
systemd/ai-agent.service.example so the caps actually apply." \
"$STEP5_DONE" && {

AI_UID=$(id -u "$AI_USER")

cat > "/etc/security/limits.d/${AI_USER}.conf" << EOF
# Limits for $AI_USER — prevents resource exhaustion attacks
$AI_USER    hard    nproc       200
$AI_USER    hard    nofile      4096
$AI_USER    hard    fsize       1048576
$AI_USER    hard    core        0
EOF
log "Per-process ulimits configured in /etc/security/limits.d/${AI_USER}.conf"

mkdir -p "/etc/systemd/system/user-${AI_UID}.slice.d"
cat > "/etc/systemd/system/user-${AI_UID}.slice.d/limits.conf" << EOF
# cgroup limits for $AI_USER (UID $AI_UID) — total across ALL its processes
[Slice]
MemoryMax=2G
MemorySwapMax=1G
TasksMax=200
CPUQuota=300%
EOF
systemctl daemon-reload
log "cgroup slice limits configured (2GB total RAM, 3 cores, 200 tasks)"

}


# =============================================================================
# STEP 6: Harden SSH
# =============================================================================

SSH_HARDEN_CONF="/etc/ssh/sshd_config.d/00-hardening.conf"

STEP6_DONE=""
if [ -f "$SSH_HARDEN_CONF" ] && grep -q "DenyUsers $AI_USER" "$SSH_HARDEN_CONF"; then
    STEP6_DONE="$SSH_HARDEN_CONF already exists with $AI_USER denied."
fi

confirm_step 6 "Harden SSH configuration" \
"SSH is the front door to your Pi. This step:
  • Disables password login → key-only, can't be brute forced
  • Disables root login → must SSH as your account, then sudo
  • Blocks '$AI_USER' from SSH login entirely
  • Limits auth attempts to 3
  • Disables X11 and agent forwarding
Settings go in /etc/ssh/sshd_config.d/00-hardening.conf — on modern
Debian, files there are read FIRST and the first value wins, so editing
sshd_config directly can be silently overridden by cloud-init configs.
The config is validated with 'sshd -t' before finishing.
⚠️  IMPORTANT: Make sure you have SSH key access set up BEFORE
restarting SSH! The script does NOT restart SSH — you do that
manually after verifying." \
"$STEP6_DONE" && {

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
log "Backed up sshd_config"

# sshd uses first-value-wins. Debian includes sshd_config.d/* at the TOP of
# sshd_config, and 00- sorts before 50-cloud-init.conf etc, so our file wins.
mkdir -p /etc/ssh/sshd_config.d
if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/' "$SSHD_CONFIG"; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONFIG"
    log "Added Include directive for sshd_config.d to sshd_config"
fi

cat > "$SSH_HARDEN_CONF" << EOF
# Hardening — managed by harden-pi.sh
# Named 00- so it sorts first: sshd uses the FIRST value it sees,
# so this file overrides everything else in sshd_config.d/ and sshd_config.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
MaxAuthTries 3
X11Forwarding no
AllowAgentForwarding no
DenyUsers $AI_USER
EOF
log "Wrote $SSH_HARDEN_CONF"

if sshd -t 2>/dev/null; then
    log "sshd config validated (sshd -t passed)"
else
    rm -f "$SSH_HARDEN_CONF"
    err "sshd -t FAILED — removed $SSH_HARDEN_CONF, SSH config unchanged"
fi

warn "Test SSH in a NEW terminal, then: sudo systemctl restart ssh"

}


# =============================================================================
# STEP 7: Install fail2ban
# =============================================================================

STEP7_DONE=""
if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban 2>/dev/null \
   && grep -q 'backend *= *systemd' /etc/fail2ban/jail.local 2>/dev/null; then
    STEP7_DONE="fail2ban is installed, running, and using the systemd journal backend."
fi

confirm_step 7 "Install and configure fail2ban" \
"Watches SSH auth logs and automatically bans IPs that fail login
repeatedly. After 3 failed attempts within 10 minutes, the IP is
banned for 1 hour. This stops brute-force attacks and port scanners.
Uses 'backend = systemd' — modern Raspberry Pi OS logs to the journal
and often has NO /var/log/auth.log, so the default file-based jail
would silently watch nothing.
Installs the fail2ban package if not already present." \
"$STEP7_DONE" && {

if ! command -v fail2ban-client &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq fail2ban
fi

cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 3
bantime  = 3600
findtime = 600
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log "fail2ban configured (3 attempts → 1hr ban, journald backend)"

}


# =============================================================================
# STEP 8: Enable automatic security updates
# =============================================================================

STEP8_DONE=""
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ] && [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    STEP8_DONE="Unattended-upgrades config files already exist."
fi

confirm_step 8 "Enable automatic security updates" \
"Kernel and system exploits are discovered regularly. If an attacker
compromises the AI agent and finds an unpatched local privilege
escalation — game over. This enables daily automatic security patches
from Debian/Raspbian repos. NO auto-reboot — you control when to
reboot. Installs unattended-upgrades if not present." \
"$STEP8_DONE" && {

apt-get install -y -qq unattended-upgrades

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Raspbian,codename=${distro_codename},label=Raspbian";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

log "Automatic security updates enabled (daily, no auto-reboot)"

}


# =============================================================================
# STEP 9: Create project directories
# =============================================================================

STEP9_DONE=""
if [ -d "/srv/$MAIN_USER" ] && [ -d "/srv/$AI_USER" ]; then
    OWNER_MAIN=$(stat -c '%U' "/srv/$MAIN_USER" 2>/dev/null)
    OWNER_AI=$(stat -c '%U' "/srv/$AI_USER" 2>/dev/null)
    PERMS_MAIN=$(stat -c '%a' "/srv/$MAIN_USER" 2>/dev/null)
    PERMS_AI=$(stat -c '%a' "/srv/$AI_USER" 2>/dev/null)
    if [ "$OWNER_MAIN" = "$MAIN_USER" ] && [ "$OWNER_AI" = "$AI_USER" ] \
       && [ "$PERMS_MAIN" = "700" ] && [ "$PERMS_AI" = "700" ]; then
        STEP9_DONE="/srv/$MAIN_USER (owned by $MAIN_USER, 700) and /srv/$AI_USER (owned by $AI_USER, 700) already exist."
    fi
fi

confirm_step 9 "Create separated project directories" \
"Creates two isolated directories:
  • /srv/$MAIN_USER  → YOUR projects (mode 700, only you can access)
  • /srv/$AI_USER    → AI's playground (mode 700, only it can access)
Neither account can read, write, or even list the other's directory.
Also sets up an ACL so you can read the AI's directory without sudo
(the AI still cannot read yours)." \
"$STEP9_DONE" && {

mkdir -p "/srv/$MAIN_USER"
chown "$MAIN_USER:$MAIN_USER" "/srv/$MAIN_USER"
chmod 700 "/srv/$MAIN_USER"
log "/srv/$MAIN_USER → your projects (locked down)"

mkdir -p "/srv/$AI_USER"
chown "$AI_USER:$AI_USER" "/srv/$AI_USER"
chmod 700 "/srv/$AI_USER"
log "/srv/$AI_USER → AI's space (full freedom)"

# Give your account read access to AI's directories via ACL
# This does NOT give the AI access to your directory
if ! command -v setfacl &>/dev/null; then
    apt-get install -y -qq acl
fi
setfacl -R -m u:"$MAIN_USER":rX "/srv/$AI_USER"
setfacl -R -d -m u:"$MAIN_USER":rX "/srv/$AI_USER"
setfacl -R -m u:"$MAIN_USER":rX "/home/$AI_USER"
setfacl -R -d -m u:"$MAIN_USER":rX "/home/$AI_USER"
log "ACL: $MAIN_USER can read /srv/$AI_USER and /home/$AI_USER"

}


# =============================================================================
# STEP 10: Install and configure Caddy (reverse proxy)
# =============================================================================

STEP10_DONE=""
if command -v caddy &>/dev/null && [ -f "/etc/caddy/Caddyfile" ] && [ -f "/srv/$AI_USER/Caddyfile" ]; then
    STEP10_DONE="Caddy is installed, main Caddyfile and AI Caddyfile both exist."
fi

confirm_step 10 "Install and configure Caddy" \
"Sets up Caddy as a reverse proxy with two instances:
  • Main Caddy (root, :443) — handles HTTPS, routes to your apps + AI
  • AI Caddy ($AI_USER, :4000) — AI controls its own routing
The AI can reload its own Caddy via admin API (no sudo needed).
Main Caddyfile is owned by root — AI cannot modify it, and the main
Caddy's admin API (:2019) is firewalled from the AI (step 4).
⚠️  Port squatting: 'reverse_proxy localhost:3000' trusts whoever
listens on 3000. If your app is down, any local user could bind that
port and receive its traffic. For sensitive apps, prefer unix sockets
(see comments in the generated Caddyfile).
You'll be prompted for your domain name (e.g. example.com)." \
"$STEP10_DONE" && {

# Prompt for domain
echo ""
read -rp "  Enter your domain name (e.g. example.com, leave blank to set later): " DOMAIN
DOMAIN=$(echo "$DOMAIN" | xargs)  # trim whitespace

if [ -z "$DOMAIN" ]; then
    warn "No domain entered — Caddyfile will use placeholder YOUR_DOMAIN"
    warn "You can replace it later: sudo sed -i 's/YOUR_DOMAIN/yourdomain.com/g' /etc/caddy/Caddyfile"
    DOMAIN="YOUR_DOMAIN"
fi

log "Using domain: $DOMAIN"

# Install Caddy if not present
if ! command -v caddy &>/dev/null; then
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
    log "Caddy installed"
else
    log "Caddy already installed"
fi

# Detect script directory for config templates
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set up main Caddyfile if not present or still the stock package default.
# Match only UNcommented reverse_proxy — the stock Debian Caddyfile contains
# '# reverse_proxy localhost:8080' as a comment, which must not count.
if [ ! -f /etc/caddy/Caddyfile ] || ! grep -qE '^\s*reverse_proxy' /etc/caddy/Caddyfile; then
    if [ -f "$SCRIPT_DIR/caddy/Caddyfile.example" ]; then
        cp "$SCRIPT_DIR/caddy/Caddyfile.example" /etc/caddy/Caddyfile
    else
        cat > /etc/caddy/Caddyfile << CADDYEOF
# Main Caddyfile — owned by root, AI cannot modify this file
# Each block maps a subdomain to a local port where your app runs.
# Caddy automatically gets HTTPS certificates from Let's Encrypt.
#
# To add a project:   add a block, then: sudo systemctl reload caddy
# To remove a project: delete its block, then reload
#
# SECURITY: 'reverse_proxy localhost:PORT' trusts whoever listens on
# that port. If your app is down, another local user could bind the
# port and receive its traffic. For sensitive apps, use unix sockets:
#     reverse_proxy unix//run/myapp/myapp.sock

# Your projects
bloodhound.$DOMAIN {
    reverse_proxy localhost:3000
}

kaal.$DOMAIN {
    reverse_proxy localhost:3001
}

tribute.$DOMAIN {
    reverse_proxy localhost:3002
}

# AI sandbox — forwards to AI's own Caddy on :4000
ai.$DOMAIN {
    reverse_proxy localhost:4000
}
CADDYEOF
    fi
    # Replace YOUR_DOMAIN with the actual domain (handles both template and inline)
    sed -i "s/YOUR_DOMAIN/$DOMAIN/g" /etc/caddy/Caddyfile
    log "Main Caddyfile created at /etc/caddy/Caddyfile (domain: $DOMAIN)"
else
    log "Main Caddyfile already exists"
fi

chown root:root /etc/caddy/Caddyfile
chmod 644 /etc/caddy/Caddyfile

# Set up AI's Caddyfile
if [ ! -f "/srv/$AI_USER/Caddyfile" ]; then
    if [ -f "$SCRIPT_DIR/caddy/Caddyfile.ai.example" ]; then
        cp "$SCRIPT_DIR/caddy/Caddyfile.ai.example" "/srv/$AI_USER/Caddyfile"
    else
        cat > "/srv/$AI_USER/Caddyfile" << 'AICADDYEOF'
# AI Sandbox Caddyfile — you (the AI) control this file
# Main Caddy forwards ai.yourdomain.com traffic here on port 4000.
# No TLS needed — main Caddy handles HTTPS.
#
# To add a route:   add a handle_path block, then reload (no sudo needed):
#   caddy reload --config /srv/AI_USER/Caddyfile --address localhost:2020
# To remove a route: delete its block and reload.

{
    admin localhost:2020
}

:4000 {
    handle {
        respond "ai sandbox is running" 200
    }
}
AICADDYEOF
    fi
    log "AI Caddyfile created at /srv/$AI_USER/Caddyfile"
fi

chown "$AI_USER:$AI_USER" "/srv/$AI_USER/Caddyfile"
chmod 644 "/srv/$AI_USER/Caddyfile"

# Set up systemd service for AI's Caddy
cat > /etc/systemd/system/caddy-ai.service << EOF
[Unit]
Description=Caddy AI Sandbox
After=network.target caddy.service

[Service]
User=$AI_USER
Group=$AI_USER
ExecStart=/usr/bin/caddy run --config /srv/$AI_USER/Caddyfile
ExecReload=/usr/bin/caddy reload --config /srv/$AI_USER/Caddyfile --address localhost:2020
WorkingDirectory=/srv/$AI_USER
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/srv/$AI_USER
MemoryMax=256M
TasksMax=32

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable caddy
systemctl enable caddy-ai

# Start services
systemctl restart caddy
systemctl restart caddy-ai

log "Main Caddy running on :443"
log "AI Caddy running on :4000 (owned by $AI_USER)"
log "AI reloads via: caddy reload --config /srv/$AI_USER/Caddyfile --address localhost:2020"

}


# =============================================================================
# STEP 11: Disable Wi-Fi power save
# =============================================================================

STEP11_DONE=""
NM_CONF="/etc/NetworkManager/conf.d/wifi-powersave.conf"
if [ -f "$NM_CONF" ] && grep -q "wifi.powersave = 2" "$NM_CONF"; then
    STEP11_DONE="$NM_CONF already disables Wi-Fi power save."
fi

confirm_step 11 "Disable Wi-Fi power save" \
"The Pi's Broadcom Wi-Fi chip aggressively power-saves and can silently
drop off the network after long uptimes — the Pi keeps running but is
unreachable until power-cycled. This writes a NetworkManager config to
keep Wi-Fi awake. If you're connected over Wi-Fi right now, the
NetworkManager restart drops the connection for a few seconds.
Skip if the Pi is ethernet-only." \
"$STEP11_DONE" && {

mkdir -p /etc/NetworkManager/conf.d
cat > "$NM_CONF" << 'EOF'
[connection]
wifi.powersave = 2
EOF

if systemctl is-active --quiet NetworkManager; then
    systemctl restart NetworkManager
    log "Wi-Fi power save disabled (NetworkManager restarted)"
else
    log "Config written — applies when NetworkManager starts"
fi

}


# =============================================================================
# STEP 12: Cap AI disk usage (fixed-size filesystem)
# =============================================================================

STEP12_DONE=""
if mountpoint -q "/srv/$AI_USER" 2>/dev/null; then
    CAP_SIZE=$(df -h "/srv/$AI_USER" 2>/dev/null | awk 'NR==2 {print $2}')
    STEP12_DONE="/srv/$AI_USER is already a dedicated ${CAP_SIZE} filesystem."
fi

confirm_step 12 "Cap AI disk usage" \
"The ulimit 'fsize' only caps INDIVIDUAL files at 1GB — the AI could
still fill your entire SD card with a thousand of them, taking down
every service on the Pi. This creates a fixed-size disk image and
mounts it at /srv/$AI_USER, so the AI can never use more than its
allowance. The image is sparse: it only consumes real SD card space
as the AI actually writes data.
Existing contents of /srv/$AI_USER are migrated into the image
(originals are left shadowed under the mount as a one-time backup).
NOTE: /home/$AI_USER is not capped — keep the agent's work in /srv." \
"$STEP12_DONE" && {

DISK_IMG="/var/lib/${AI_USER}-disk.img"

if mountpoint -q "/srv/$AI_USER" 2>/dev/null; then
    warn "Already mounted — to resize: stop caddy-ai, umount /srv/$AI_USER,"
    warn "delete $DISK_IMG and its /etc/fstab line, then re-run this step."
else
    echo ""
    read -rp "  Max disk space for the AI in GB [10]: " DISK_GB
    DISK_GB="${DISK_GB:-10}"
    if ! [[ "$DISK_GB" =~ ^[0-9]+$ ]] || [ "$DISK_GB" -lt 1 ]; then
        warn "Invalid size '$DISK_GB' — using 10 GB"
        DISK_GB=10
    fi

    if [ ! -f "$DISK_IMG" ]; then
        truncate -s "${DISK_GB}G" "$DISK_IMG"
        mkfs.ext4 -q -F "$DISK_IMG"
        log "Created ${DISK_GB}GB sparse disk image at $DISK_IMG"
    else
        log "Disk image already exists at $DISK_IMG"
    fi

    if ! grep -q "$DISK_IMG" /etc/fstab; then
        echo "$DISK_IMG /srv/$AI_USER ext4 loop,nofail 0 2" >> /etc/fstab
        log "Added /etc/fstab entry (mounts on boot, nofail)"
    fi

    CADDY_AI_WAS_ACTIVE=false
    if systemctl is-active --quiet caddy-ai 2>/dev/null; then
        CADDY_AI_WAS_ACTIVE=true
        systemctl stop caddy-ai
        log "Stopped caddy-ai during migration"
    fi

    mkdir -p "/srv/$AI_USER"

    # Copy existing contents out BEFORE mounting (mount shadows them)
    MIGRATE_DIR=""
    if [ -n "$(ls -A "/srv/$AI_USER" 2>/dev/null)" ]; then
        MIGRATE_DIR=$(mktemp -d /var/tmp/ai-migrate.XXXXXX)
        cp -a "/srv/$AI_USER/." "$MIGRATE_DIR/"
        log "Copied existing contents to $MIGRATE_DIR"
    fi

    systemctl daemon-reload
    mount "/srv/$AI_USER"
    log "Mounted $DISK_IMG at /srv/$AI_USER"

    if [ -n "$MIGRATE_DIR" ]; then
        cp -a "$MIGRATE_DIR/." "/srv/$AI_USER/"
        rm -rf "$MIGRATE_DIR"
        log "Migrated contents into the capped filesystem"
        info "Originals remain shadowed beneath the mount — reclaim the space"
        info "later with: sudo umount /srv/$AI_USER && sudo rm -rf /srv/$AI_USER/* && sudo mount /srv/$AI_USER"
    fi

    chown "$AI_USER:$AI_USER" "/srv/$AI_USER"
    chmod 700 "/srv/$AI_USER"
    if command -v setfacl &>/dev/null; then
        setfacl -R -m u:"$MAIN_USER":rX "/srv/$AI_USER"
        setfacl -R -d -m u:"$MAIN_USER":rX "/srv/$AI_USER"
    fi

    if $CADDY_AI_WAS_ACTIVE; then
        systemctl start caddy-ai
        log "Restarted caddy-ai"
    fi

    log "AI disk usage capped at ${DISK_GB}GB"
fi

}


# =============================================================================
# STEP 13: Hide other users' processes from the AI (hidepid)
# =============================================================================

STEP13_DONE=""
if findmnt -no OPTIONS /proc 2>/dev/null | grep -q hidepid; then
    STEP13_DONE="/proc is already mounted with hidepid."
fi

confirm_step 13 "Hide other users' processes (hidepid)" \
"Right now the AI can read /proc and see EVERY process on the Pi —
including full command lines. Secrets passed as CLI arguments or
environment-revealing process names leak this way.
Remounts /proc with hidepid=2: each user only sees their OWN
processes. Your account is added to a 'proc' group that keeps full
visibility (so htop etc. still work for you — after you re-login).
Persisted via /etc/fstab." \
"$STEP13_DONE" && {

groupadd -f proc
usermod -aG proc "$MAIN_USER"
PROC_GID=$(getent group proc | cut -d: -f3)

FSTAB_LINE="proc /proc proc defaults,hidepid=2,gid=$PROC_GID 0 0"
if grep -qE '^\s*proc\s' /etc/fstab; then
    sed -i "s|^\s*proc\s.*|$FSTAB_LINE|" /etc/fstab
else
    echo "$FSTAB_LINE" >> /etc/fstab
fi
log "fstab: /proc mounted with hidepid=2, gid=proc"

mount -o "remount,hidepid=2,gid=$PROC_GID" /proc
log "Remounted /proc — AI can no longer see other users' processes"
warn "Log out and back in for YOUR 'proc' group membership to take effect"

}


# =============================================================================
# STEP 14: Audit trail — log every command the AI runs
# =============================================================================

STEP14_DONE=""
if systemctl is-active --quiet auditd 2>/dev/null && [ -f "/etc/audit/rules.d/${AI_USER}.rules" ]; then
    STEP14_DONE="auditd is running with rules for $AI_USER."
fi

confirm_step 14 "Audit trail for AI commands" \
"Installs auditd and logs every program the AI agent executes.
If something ever looks off, you get a forensic trail of exactly
what the AI (or an attacker using its account) ran and when.
View the log with:  sudo ausearch -k ai-agent -i | tail -50
Low overhead — it only records execve calls for the AI's UID." \
"$STEP14_DONE" && {

if ! command -v auditctl &>/dev/null; then
    apt-get install -y -qq auditd
fi

AI_UID=$(id -u "$AI_USER")

# Pick audit arch(s) for this machine
case "$(uname -m)" in
    aarch64|x86_64)
        AUDIT_RULES="-a always,exit -F arch=b64 -S execve -F uid=$AI_UID -k ai-agent
-a always,exit -F arch=b32 -S execve -F uid=$AI_UID -k ai-agent"
        ;;
    *)
        AUDIT_RULES="-a always,exit -F arch=b32 -S execve -F uid=$AI_UID -k ai-agent"
        ;;
esac

cat > "/etc/audit/rules.d/${AI_USER}.rules" << EOF
## Log every command executed by $AI_USER (UID $AI_UID)
$AUDIT_RULES
EOF

if ! augenrules --load 2>/dev/null; then
    # Some kernels reject the b32 compat rule — retry with b64 only
    grep -v 'arch=b32' "/etc/audit/rules.d/${AI_USER}.rules" > "/etc/audit/rules.d/${AI_USER}.rules.tmp"
    mv "/etc/audit/rules.d/${AI_USER}.rules.tmp" "/etc/audit/rules.d/${AI_USER}.rules"
    augenrules --load
    warn "b32 compat rule rejected by kernel — loaded b64-only rules"
fi

systemctl enable auditd
systemctl restart auditd 2>/dev/null || service auditd restart
log "auditd logging all commands run by $AI_USER"
log "View with: sudo ausearch -k ai-agent -i | tail -50"

}


# =============================================================================
# STEP 15: Cloudflare Tunnel (no open ports, hidden home IP)
# =============================================================================

STEP15_DONE=""
if command -v cloudflared &>/dev/null && systemctl is-active --quiet cloudflared 2>/dev/null; then
    STEP15_DONE="cloudflared is installed and the tunnel service is running."
fi

confirm_step 15 "Set up Cloudflare Tunnel" \
"Exposes your projects WITHOUT port-forwarding 80/443 on your router.
cloudflared makes an outbound-only connection to Cloudflare's edge —
your home IP stays hidden, you get DDoS protection for free, and it
works behind CGNAT. Once routes work through the tunnel, you can
remove the router port forwards: the Pi needs NO open inbound ports.
Security properties:
  • Routing lives in YOUR Cloudflare dashboard — the AI can't touch it
  • The tunnel token is stored root-only (a readable token would let
    the AI run a rogue connector and hijack your traffic)
  • cloudflared runs as its own unprivileged user, sandboxed
You'll need a free Cloudflare account with your domain on it, and a
tunnel token from the Zero Trust dashboard (instructions shown next)." \
"$STEP15_DONE" && {

# Install cloudflared from Cloudflare's apt repo
if ! command -v cloudflared &>/dev/null; then
    . /etc/os-release
    CODENAME="${VERSION_CODENAME:-bookworm}"
    mkdir -p --mode=0755 /usr/share/keyrings
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $CODENAME main" > /etc/apt/sources.list.d/cloudflared.list
    apt-get update -qq
    apt-get install -y -qq cloudflared
    log "cloudflared installed"
else
    log "cloudflared already installed"
fi

echo ""
info "Create the tunnel in the Cloudflare dashboard:"
info "  1. https://one.dash.cloudflare.com → Networks → Tunnels → Create a tunnel"
info "  2. Choose 'Cloudflared' and name it (e.g. 'maverick-pi')"
info "  3. In the install command shown, copy the long token after '--token'"
echo ""
read -rp "  Paste the tunnel token (blank to finish setup later): " TUNNEL_TOKEN
TUNNEL_TOKEN=$(echo "$TUNNEL_TOKEN" | xargs)

if [ -z "$TUNNEL_TOKEN" ]; then
    warn "No token — no changes made to any existing tunnel setup."
    warn "Re-run this step once you have a token."
else
    # --- Tear down any existing tunnel setup first (clean re-run / token rotation) ---
    # Covers a previous run of this step AND a manual 'cloudflared service
    # install <token>' — the script never runs that command itself, because
    # it embeds the token in a world-readable unit file.
    if systemctl is-enabled --quiet cloudflared 2>/dev/null || systemctl is-active --quiet cloudflared 2>/dev/null; then
        systemctl disable --now cloudflared 2>/dev/null || true
        log "Stopped and disabled existing cloudflared service"
    fi
    rm -f /etc/systemd/system/cloudflared.service \
          /etc/systemd/system/cloudflared-update.service \
          /etc/systemd/system/cloudflared-update.timer \
          /lib/systemd/system/cloudflared.service 2>/dev/null || true
    systemctl daemon-reload

    # Old configs/tokens (config.yml, cert.pem, tunnel.env, ...) can conflict
    # with token mode — move them aside rather than delete.
    if [ -d /etc/cloudflared ] && find /etc/cloudflared -maxdepth 1 -type f | grep -q .; then
        BACKUP_DIR="/etc/cloudflared/old.$(date +%s)"
        mkdir -p "$BACKUP_DIR"
        find /etc/cloudflared -maxdepth 1 -type f -exec mv {} "$BACKUP_DIR/" \;
        chmod 700 "$BACKUP_DIR"
        log "Moved previous cloudflared config/token to $BACKUP_DIR (root-only)"
    fi

    # Store the token root-only. NEVER put it on the ExecStart line or in a
    # world-readable unit file — anyone holding the token (e.g. the AI
    # reading a 644 file) could run a rogue connector and hijack traffic.
    mkdir -p /etc/cloudflared
    printf 'TUNNEL_TOKEN=%s\n' "$TUNNEL_TOKEN" > /etc/cloudflared/tunnel.env
    chown root:root /etc/cloudflared/tunnel.env
    chmod 600 /etc/cloudflared/tunnel.env
    log "Token stored in /etc/cloudflared/tunnel.env (root-only, mode 600)"

    # Dedicated unprivileged user — outbound-only daemon, no shell needed
    if ! id cloudflared &>/dev/null; then
        useradd -r -M -s /usr/sbin/nologin cloudflared
        log "Created system user 'cloudflared'"
    fi

    cat > /etc/systemd/system/cloudflared.service << 'EOF'
[Unit]
Description=Cloudflare Tunnel
After=network-online.target
Wants=network-online.target

[Service]
User=cloudflared
Group=cloudflared
EnvironmentFile=/etc/cloudflared/tunnel.env
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
MemoryMax=256M
TasksMax=64

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now cloudflared
    sleep 3
    if systemctl is-active --quiet cloudflared; then
        log "Cloudflare Tunnel is running (check dashboard: connector should show HEALTHY)"
    else
        warn "cloudflared failed to start — check: journalctl -u cloudflared -n 20"
    fi

    echo ""
    info "Now add Public Hostnames in the tunnel's dashboard page:"
    info "  ai.YOUR_DOMAIN          → HTTP → localhost:4000  (AI's sandbox Caddy)"
    info "  bloodhound.YOUR_DOMAIN  → HTTP → localhost:3000  (each app by port)"
    info "  (or route everything through main Caddy — see README, 'Cloudflare Tunnel')"
    echo ""
    info "Once routes work through the tunnel, remove the 80/443 port forwards"
    info "on your router — the Pi then has NO open inbound ports."
fi

}


# =============================================================================
# DONE
# =============================================================================

echo ""
echo "================================================"
echo "  ✅ Hardening Complete!"
echo "================================================"
echo ""
echo "  Your account:      $MAIN_USER"
echo "  AI agent account:  $AI_USER"
echo ""
echo "  Protected against:            How:"
echo "  ─────────────────────────────────────────────"
echo "  Privilege escalation          No sudo access"
echo "  Credential theft              Home dir locked (700)"
echo "  Network pivot to LAN          iptables UID-based drops (DNS excepted)"
echo "  Main Caddy route hijack       :2019 admin API firewalled from AI"
echo "  Spam relay                    Outbound SMTP blocked"
echo "  Resource exhaustion           ulimits + cgroup slice (total caps)"
echo "  Disk filling                  Fixed-size filesystem on /srv/$AI_USER"
echo "  Process snooping              hidepid=2 on /proc"
echo "  SSH brute force               Key-only + fail2ban (journald backend)"
echo "  Unpatched exploits            Auto security updates"
echo "  Silent Wi-Fi dropouts         NetworkManager power save off"
echo "  No forensic trail             auditd logs every AI command"
echo "  Exposed home IP / open ports  Cloudflare Tunnel (outbound-only)"
echo ""
echo "  Caddy:"
echo "  Main Caddyfile:  /etc/caddy/Caddyfile"
echo "  AI Caddyfile:    /srv/$AI_USER/Caddyfile (AI controls this)"
echo "  AI reloads via:  caddy reload --config /srv/$AI_USER/Caddyfile --address localhost:2020"
echo ""
echo "  Run the agent itself via the hardened systemd unit so the"
echo "  resource caps actually apply: see systemd/ai-agent.service.example"
echo ""
echo "  🔍 VERIFY THE WALLS HOLD:"
echo "  sudo bash harden-pi.sh verify"
echo ""
echo "  ⚠️  BEFORE YOU REBOOT:"
echo "  1. Verify SSH key is in /home/$MAIN_USER/.ssh/authorized_keys"
echo "  2. Test SSH in a NEW terminal"
echo "  3. Then: sudo systemctl restart ssh"
echo ""
