#!/bin/bash
# =============================================================================
# Raspberry Pi Hardening Script — "Don't Get Pwned" Edition
#
# Goal: Create an AI agent user that can wreak havoc on projects
#       but CANNOT escalate privileges, steal credentials, or
#       pivot to your home network.
#
# Run as: sudo bash harden-pi.sh
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
        read -p "  Re-apply anyway? (y/n/q to quit) " -n 1 -r
    else
        while IFS= read -r line; do
            info "$line"
        done <<< "$explanation"
        echo ""
        read -p "  Proceed with this step? (y/n/q to quit) " -n 1 -r
    fi

    echo ""
    if [[ $REPLY =~ ^[Qq]$ ]]; then
        warn "Aborted by user at step $step_num."
        exit 0
    fi
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        warn "Skipped step $step_num: $title"
        return 1
    fi
    return 0
}

# Must run as root
if [ "$EUID" -ne 0 ]; then
    err "Run this script with sudo"
    exit 1
fi

echo ""
echo "================================================"
echo "  Raspberry Pi Hardening for AI Agent Isolation  "
echo "================================================"
echo ""

# Ask for main username
read -p "  Enter YOUR username on this Pi: " MAIN_USER

if [[ -z "$MAIN_USER" ]]; then
    err "Username cannot be empty."
    exit 1
fi

if ! id "$MAIN_USER" &>/dev/null; then
    err "User '$MAIN_USER' does not exist on this system."
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
    err "AI user cannot be the same as main user ($MAIN_USER)"
    exit 1
fi

echo ""
echo "  Main user: $MAIN_USER"
echo "  AI user:   $AI_USER"
echo ""
read -p "  Start hardening? (y/n) " -n 1 -r
echo ""
[[ $REPLY =~ ^[Yy]$ ]] || exit 1


# =============================================================================
# STEP 1: Create the AI agent user
# =============================================================================

STEP1_DONE=""
if id "$AI_USER" &>/dev/null; then
    STEP1_DONE="User '$AI_USER' already exists with home at /home/$AI_USER."
fi

confirm_step 1 "Create AI agent user" \
"Creates a new Linux user named '$AI_USER' with its own home directory.
This is the foundation of isolation — every permission and restriction
we set up later builds on this user boundary. The user gets a bash shell
so it can run commands, but will have no sudo access." \
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
The AI user won't be able to list, read, or enter your home directory.
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
# STEP 3: Ensure AI user has NO sudo access
# =============================================================================

STEP3_DONE=""
SUDOERS_FILE="/etc/sudoers.d/${AI_USER}-deny"
if [ -f "$SUDOERS_FILE" ] && ! groups "$AI_USER" 2>/dev/null | grep -q '\bsudo\b'; then
    STEP3_DONE="$AI_USER is not in sudo group and $SUDOERS_FILE exists."
fi

confirm_step 3 "Block sudo access for AI user" \
"Without sudo, the AI user cannot become root, install system packages,
or modify system config. Even if fully compromised, the attacker is
stuck as an unprivileged user. This is the single most important wall.
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
# STEP 4: Block AI user from your home network (LAN)
# =============================================================================

STEP4_DONE=""
if id "$AI_USER" &>/dev/null; then
    AI_UID=$(id -u "$AI_USER")
    EXISTING_RULES=$(iptables -S OUTPUT 2>/dev/null | grep -c "owner --uid-owner $AI_UID" || true)
    if [ "$EXISTING_RULES" -ge 4 ]; then
        STEP4_DONE="Found $EXISTING_RULES iptables rules blocking LAN for UID $AI_UID."
    fi
fi

confirm_step 4 "Block AI user from LAN access" \
"THE BIG ONE. If the AI gets compromised, an attacker will try to scan
your local network — router, NAS, other computers, smart home devices.
These iptables rules block ALL traffic from '$AI_USER' to private IPs:
  • 192.168.0.0/16  (most home routers)
  • 10.0.0.0/8      (some networks)
  • 172.16.0.0/12   (other private range)
  • 169.254.0.0/16  (link-local / mDNS)
The AI can still reach the internet (for API calls) but cannot touch
anything on your LAN. Rules are persisted across reboots." \
"$STEP4_DONE" && {

AI_UID=$(id -u "$AI_USER")

# Flush existing rules for this UID (safe to re-run)
iptables -S OUTPUT 2>/dev/null | grep "owner --uid-owner $AI_UID" | while read -r rule; do
    iptables $(echo "$rule" | sed 's/-A/-D/')
done 2>/dev/null || true

iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 192.168.0.0/16 -j DROP
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 169.254.0.0/16 -j DROP

log "Blocked $AI_USER (UID $AI_UID) from all LAN traffic"

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
# STEP 5: Set resource limits
# =============================================================================

STEP5_DONE=""
if [ -f "/etc/security/limits.d/${AI_USER}.conf" ]; then
    STEP5_DONE="Limits file /etc/security/limits.d/${AI_USER}.conf already exists."
fi

confirm_step 5 "Set resource limits for AI user" \
"Prevents the AI from taking down your Pi via:
  • Fork bomb → capped at 200 processes
  • Memory exhaustion → capped at 2GB virtual memory
  • Disk filling → max 1GB per file
  • File descriptor exhaustion → max 4096 open files
  • Core dumps disabled → no leaking memory contents
Even if the AI tries, it hits these hard limits and gets killed,
while your services keep running normally." \
"$STEP5_DONE" && {

cat > "/etc/security/limits.d/${AI_USER}.conf" << EOF
# Limits for $AI_USER — prevents resource exhaustion attacks
$AI_USER    hard    nproc       200
$AI_USER    hard    nofile      4096
$AI_USER    hard    as          2097152
$AI_USER    hard    fsize       1048576
$AI_USER    hard    core        0
EOF

log "Resource limits configured in /etc/security/limits.d/${AI_USER}.conf"

}


# =============================================================================
# STEP 6: Protect critical system files
# =============================================================================

STEP6_DONE=""
IMMUTABLE_COUNT=0
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/group; do
    if [ -f "$f" ] && lsattr "$f" 2>/dev/null | grep -q '^\s*....i'; then
        IMMUTABLE_COUNT=$((IMMUTABLE_COUNT + 1))
    fi
done
if [ "$IMMUTABLE_COUNT" -eq 4 ]; then
    STEP6_DONE="All 4 critical files already have the immutable flag set."
fi

confirm_step 6 "Make critical system files immutable" \
"Sets the immutable flag (chattr +i) on:
  • /etc/passwd   — user accounts
  • /etc/shadow   — password hashes
  • /etc/sudoers  — sudo permissions
  • /etc/group    — group memberships
This prevents ANYONE — even root — from modifying these files without
first removing the flag. Stops an attacker from adding a backdoor user
or granting themselves sudo.
⚠️  To edit later: sudo chattr -i <file>, make changes, sudo chattr +i <file>" \
"$STEP6_DONE" && {

# Must remove immutable first to re-apply cleanly
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/group; do
    if [ -f "$f" ]; then
        chattr -i "$f" 2>/dev/null || true
        chattr +i "$f"
        log "Made $f immutable"
    fi
done

}


# =============================================================================
# STEP 7: Audit SUID binaries
# =============================================================================

STEP7_DONE=""
SUID_LOG="/home/$MAIN_USER/suid-audit.txt"
SUID_CLEAN=true
for bin in /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/mount /usr/bin/umount; do
    if [ -f "$bin" ] && [ -u "$bin" ]; then
        SUID_CLEAN=false
        break
    fi
done
if [ -f "$SUID_LOG" ] && $SUID_CLEAN; then
    STEP7_DONE="Audit file exists and target SUID binaries already cleaned."
fi

confirm_step 7 "Audit and reduce SUID binaries" \
"SUID binaries run as root no matter who calls them — a classic privilege
escalation vector. This step:
  1. Saves a full list of all SUID binaries to ~/suid-audit.txt
  2. Removes the SUID bit from common ones that aren't needed:
     chsh, chfn, newgrp, mount, umount
You should review the audit file and remove SUID from anything else
you don't need." \
"$STEP7_DONE" && {

SUID_LOG="/home/$MAIN_USER/suid-audit.txt"
find / -perm -4000 -type f 2>/dev/null > "$SUID_LOG"
chown "$MAIN_USER:$MAIN_USER" "$SUID_LOG"
log "SUID binary list saved to $SUID_LOG"

for bin in /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/mount /usr/bin/umount; do
    if [ -f "$bin" ]; then
        chmod u-s "$bin"
        log "Removed SUID from $bin"
    fi
done

}


# =============================================================================
# STEP 8: Harden SSH
# =============================================================================

STEP8_DONE=""
SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    SSH_HARDENED=true
    grep -q "^PermitRootLogin no" "$SSHD_CONFIG" || SSH_HARDENED=false
    grep -q "^PasswordAuthentication no" "$SSHD_CONFIG" || SSH_HARDENED=false
    grep -q "DenyUsers.*$AI_USER" "$SSHD_CONFIG" || SSH_HARDENED=false
    if $SSH_HARDENED; then
        STEP8_DONE="sshd_config already has root login disabled, password auth off, and $AI_USER denied."
    fi
fi

confirm_step 8 "Harden SSH configuration" \
"SSH is the front door to your Pi. This step:
  • Disables password login → key-only, can't be brute forced
  • Disables root login → must SSH as your user, then sudo
  • Blocks '$AI_USER' from SSH login entirely
  • Limits auth attempts to 3
  • Disables X11 and agent forwarding
⚠️  IMPORTANT: Make sure you have SSH key access set up BEFORE
restarting SSH! The script backs up sshd_config but does NOT
restart SSH — you do that manually after verifying." \
"$STEP8_DONE" && {

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
log "Backed up sshd_config"

declare -A SSH_SETTINGS=(
    ["PermitRootLogin"]="no"
    ["PasswordAuthentication"]="no"
    ["MaxAuthTries"]="3"
    ["X11Forwarding"]="no"
    ["AllowAgentForwarding"]="no"
)

for key in "${!SSH_SETTINGS[@]}"; do
    val="${SSH_SETTINGS[$key]}"
    if grep -q "^#*${key}" "$SSHD_CONFIG"; then
        sed -i "s/^#*${key}.*/${key} ${val}/" "$SSHD_CONFIG"
    else
        echo "${key} ${val}" >> "$SSHD_CONFIG"
    fi
    log "SSH: $key = $val"
done

if ! grep -q "DenyUsers $AI_USER" "$SSHD_CONFIG"; then
    echo "DenyUsers $AI_USER" >> "$SSHD_CONFIG"
    log "SSH: Blocked $AI_USER from SSH login"
fi

warn "Test SSH in a NEW terminal, then: sudo systemctl restart ssh"

}


# =============================================================================
# STEP 9: Install fail2ban
# =============================================================================

STEP9_DONE=""
if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban 2>/dev/null; then
    STEP9_DONE="fail2ban is installed and running."
fi

confirm_step 9 "Install and configure fail2ban" \
"Watches SSH auth logs and automatically bans IPs that fail login
repeatedly. After 3 failed attempts within 10 minutes, the IP is
banned for 1 hour. This stops brute-force attacks and port scanners.
Installs the fail2ban package if not already present." \
"$STEP9_DONE" && {

if ! command -v fail2ban-client &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq fail2ban
fi

cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log "fail2ban configured (3 attempts → 1hr ban)"

}


# =============================================================================
# STEP 10: Enable automatic security updates
# =============================================================================

STEP10_DONE=""
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ] && [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    STEP10_DONE="Unattended-upgrades config files already exist."
fi

confirm_step 10 "Enable automatic security updates" \
"Kernel and system exploits are discovered regularly. If an attacker
compromises the AI user and finds an unpatched local privilege
escalation — game over. This enables daily automatic security patches
from Debian/Raspbian repos. NO auto-reboot — you control when to
reboot. Installs unattended-upgrades if not present." \
"$STEP10_DONE" && {

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
# STEP 11: Create project directories
# =============================================================================

STEP11_DONE=""
if [ -d "/srv/$MAIN_USER" ] && [ -d "/srv/$AI_USER" ]; then
    OWNER_MAIN=$(stat -c '%U' "/srv/$MAIN_USER" 2>/dev/null)
    OWNER_AI=$(stat -c '%U' "/srv/$AI_USER" 2>/dev/null)
    PERMS_MAIN=$(stat -c '%a' "/srv/$MAIN_USER" 2>/dev/null)
    PERMS_AI=$(stat -c '%a' "/srv/$AI_USER" 2>/dev/null)
    if [ "$OWNER_MAIN" = "$MAIN_USER" ] && [ "$OWNER_AI" = "$AI_USER" ] \
       && [ "$PERMS_MAIN" = "700" ] && [ "$PERMS_AI" = "700" ]; then
        STEP11_DONE="/srv/$MAIN_USER (owned by $MAIN_USER, 700) and /srv/$AI_USER (owned by $AI_USER, 700) already exist."
    fi
fi

confirm_step 11 "Create separated project directories" \
"Creates two isolated directories:
  • /srv/$MAIN_USER  → YOUR projects (mode 700, only you can access)
  • /srv/$AI_USER    → AI's playground (mode 700, only it can access)
Neither user can read, write, or even list the other's directory." \
"$STEP11_DONE" && {

mkdir -p "/srv/$MAIN_USER"
chown "$MAIN_USER:$MAIN_USER" "/srv/$MAIN_USER"
chmod 700 "/srv/$MAIN_USER"
log "/srv/$MAIN_USER → your projects (locked down)"

mkdir -p "/srv/$AI_USER"
chown "$AI_USER:$AI_USER" "/srv/$AI_USER"
chmod 700 "/srv/$AI_USER"
log "/srv/$AI_USER → AI's space (full freedom)"

}


# =============================================================================
# STEP 12: Install and configure Caddy (reverse proxy)
# =============================================================================

STEP12_DONE=""
if command -v caddy &>/dev/null && [ -f "/etc/caddy/Caddyfile" ] && [ -f "/srv/$AI_USER/Caddyfile" ]; then
    STEP12_DONE="Caddy is installed, main Caddyfile and AI Caddyfile both exist."
fi

confirm_step 12 "Install and configure Caddy" \
"Sets up Caddy as a reverse proxy with two instances:
  • Main Caddy (root, :443) — handles HTTPS, routes to your apps + AI
  • AI Caddy ($AI_USER, :4000) — AI controls its own routing
The AI can reload its own Caddy via admin API (no sudo needed).
Main Caddyfile is owned by root — AI cannot modify it.
You'll be prompted for your domain name (e.g. example.com)." \
"$STEP12_DONE" && {

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

# Set up main Caddyfile if not present
if [ ! -f /etc/caddy/Caddyfile ] || ! grep -q "reverse_proxy" /etc/caddy/Caddyfile; then
    if [ -f "$SCRIPT_DIR/caddy/Caddyfile.example" ]; then
        cp "$SCRIPT_DIR/caddy/Caddyfile.example" /etc/caddy/Caddyfile
    else
        cat > /etc/caddy/Caddyfile << CADDYEOF
# Domain: $DOMAIN

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

# AI sandbox entry point
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
# DONE
# =============================================================================

echo ""
echo "================================================"
echo "  ✅ Hardening Complete!"
echo "================================================"
echo ""
echo "  Main user:  $MAIN_USER"
echo "  AI user:    $AI_USER"
echo ""
echo "  Protected against:            How:"
echo "  ─────────────────────────────────────────────"
echo "  Privilege escalation          No sudo + immutable system files"
echo "  Credential theft              Home dir locked (700)"
echo "  Network pivot to LAN          iptables UID-based drops"
echo "  Resource exhaustion           ulimits (processes, memory, files)"
echo "  SSH brute force               Key-only + fail2ban"
echo "  Unpatched exploits            Auto security updates"
echo "  SUID abuse                    Audited + neutered"
echo ""
echo "  Caddy:"
echo "  Main Caddyfile:  /etc/caddy/Caddyfile"
echo "  AI Caddyfile:    /srv/$AI_USER/Caddyfile (AI controls this)"
echo "  AI reloads via:  caddy reload --config /srv/$AI_USER/Caddyfile --address localhost:2020"
echo ""
echo "  ⚠️  BEFORE YOU REBOOT:"
echo "  1. Verify SSH key is in /home/$MAIN_USER/.ssh/authorized_keys"
echo "  2. Test SSH in a NEW terminal"
echo "  3. Then: sudo systemctl restart ssh"
echo ""
