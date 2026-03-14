#!/usr/bin/env fish
# =============================================================================
# Raspberry Pi Hardening Script — "Don't Get Pwned" Edition (Fish Shell)
#
# Goal: Create an AI agent user that can wreak havoc on projects
#       but CANNOT escalate privileges, steal credentials, or
#       pivot to your home network.
#
# Run as: sudo fish harden-pi.fish
# Tested on: Raspberry Pi OS (Debian-based) with fish shell
# =============================================================================

function log
    echo -e "\033[0;32m[✓]\033[0m $argv"
end

function warn
    echo -e "\033[1;33m[!]\033[0m $argv"
end

function err
    echo -e "\033[0;31m[✗]\033[0m $argv"
end

function info
    echo -e "\033[0;34m    $argv\033[0m"
end

# Prompt the user to confirm a step. Shows explanation, waits for y/n/q.
# If already_done (last arg) is non-empty, shows "Already done" status.
function confirm_step
    set step_num $argv[1]
    set title $argv[2]

    # Check if last arg is a status marker "__DONE__:..." 
    set already_done ""
    set explanation
    for i in (seq 3 (count $argv))
        if string match -q "__DONE__:*" "$argv[$i]"
            set already_done (string replace "__DONE__:" "" "$argv[$i]")
        else
            set -a explanation $argv[$i]
        end
    end

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  \033[0;34mStep $step_num:\033[0m $title"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if test -n "$already_done"
        echo -e "  \033[0;32m✓ Already done:\033[0m"
        echo -e "    \033[0;32m$already_done\033[0m"
        echo ""
        for line in $explanation
            info "$line"
        end
        echo ""
        read -P "  Re-apply anyway? (y/n/q to quit) " REPLY
    else
        for line in $explanation
            info "$line"
        end
        echo ""
        read -P "  Proceed with this step? (y/n/q to quit) " REPLY
    end

    if string match -qi 'q' "$REPLY"
        warn "Aborted by user at step $step_num."
        exit 0
    end
    if not string match -qi 'y' "$REPLY"
        warn "Skipped step $step_num: $title"
        return 1
    end
    return 0
end

# Must run as root
if test (id -u) -ne 0
    err "Run this script with sudo"
    exit 1
end

echo ""
echo "================================================"
echo "  Raspberry Pi Hardening for AI Agent Isolation  "
echo "================================================"
echo ""

# Ask for main username
read -P "  Enter YOUR username on this Pi: " MAIN_USER

if test -z "$MAIN_USER"
    err "Username cannot be empty."
    exit 1
end

if not id "$MAIN_USER" &>/dev/null
    err "User '$MAIN_USER' does not exist on this system."
    exit 1
end

# Ask for AI account name
echo ""
read -P "  Enter a name for the AI agent account [ai-agent]: " AI_USER_INPUT
set AI_USER (test -n "$AI_USER_INPUT"; and echo "$AI_USER_INPUT"; or echo "ai-agent")

# Validate username
if not string match -qr '^[a-z_][a-z0-9_-]*$' "$AI_USER"
    err "Invalid username '$AI_USER'. Use lowercase letters, numbers, hyphens, underscores."
    exit 1
end

if test "$AI_USER" = "$MAIN_USER"
    err "AI user cannot be the same as main user ($MAIN_USER)"
    exit 1
end

echo ""
echo "  Main user: $MAIN_USER"
echo "  AI user:   $AI_USER"
echo ""
read -P "  Start hardening? (y/n) " CONFIRM
if not string match -qi 'y' "$CONFIRM"
    exit 1
end


# =============================================================================
# STEP 1: Create the AI agent user
# =============================================================================

set STEP1_STATUS
if id "$AI_USER" &>/dev/null
    set STEP1_STATUS "__DONE__:User '$AI_USER' already exists with home at /home/$AI_USER."
end

if confirm_step 1 "Create AI agent user" \
    "Creates a sandboxed Linux account called '$AI_USER' with its own home directory." \
    "This is the foundation of isolation — every permission and restriction" \
    "we set up later builds on this account boundary. The AI agent gets a bash" \
    "shell so it can run commands, but will have no sudo access." \
    $STEP1_STATUS

    if id "$AI_USER" &>/dev/null
        warn "$AI_USER already exists, skipping creation"
    else
        useradd -m -s /bin/bash "$AI_USER"
        log "Created user: $AI_USER"
    end
end


# =============================================================================
# STEP 2: Lock down your home directory
# =============================================================================

set STEP2_STATUS
if test -d "/home/$MAIN_USER"
    set PERMS (stat -c '%a' "/home/$MAIN_USER" 2>/dev/null)
    if test "$PERMS" = "700"
        set STEP2_STATUS "__DONE__:/home/$MAIN_USER is already mode 700 (owner-only)."
    end
end

if confirm_step 2 "Lock down your home directory" \
    "Sets /home/$MAIN_USER to mode 700 (owner-only access)." \
    "The AI user won't be able to list, read, or enter your home directory." \
    "This protects your SSH keys, .env files, API tokens, bash history," \
    "and any other personal files. Also tightens .ssh permissions." \
    $STEP2_STATUS

    chmod 700 "/home/$MAIN_USER"
    log "Set /home/$MAIN_USER to mode 700 (owner-only access)"

    if test -d "/home/$MAIN_USER/.ssh"
        chmod 700 "/home/$MAIN_USER/.ssh"
        chmod 600 /home/$MAIN_USER/.ssh/* 2>/dev/null; or true
        log "Tightened SSH key permissions"
    end
end


# =============================================================================
# STEP 3: Block sudo access for AI user
# =============================================================================

set STEP3_STATUS
set SUDOERS_FILE "/etc/sudoers.d/$AI_USER-deny"
if test -f "$SUDOERS_FILE"; and not groups "$AI_USER" 2>/dev/null | grep -q '\bsudo\b'
    set STEP3_STATUS "__DONE__:$AI_USER is not in sudo group and $SUDOERS_FILE exists."
end

if confirm_step 3 "Block sudo access for AI user" \
    "Without sudo, the AI user cannot become root, install system packages," \
    "or modify system config. Even if fully compromised, the attacker is" \
    "stuck as an unprivileged user. This is the single most important wall." \
    "Creates an explicit deny rule in /etc/sudoers.d/ as a safety net." \
    $STEP3_STATUS

    if groups "$AI_USER" 2>/dev/null | grep -q '\bsudo\b'
        gpasswd -d "$AI_USER" sudo
        log "Removed $AI_USER from sudo group"
    else
        log "$AI_USER is not in sudo group (good)"
    end

    set SUDOERS_FILE "/etc/sudoers.d/$AI_USER-deny"
    echo "$AI_USER ALL=(ALL) !ALL" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    log "Created explicit sudo deny rule"
end


# =============================================================================
# STEP 4: Block AI user from LAN access
# =============================================================================

set STEP4_STATUS
if id "$AI_USER" &>/dev/null
    set AI_UID (id -u "$AI_USER")
    set EXISTING_RULES (iptables -S OUTPUT 2>/dev/null | grep -c "owner --uid-owner $AI_UID"; or echo 0)
    if test "$EXISTING_RULES" -ge 4
        set STEP4_STATUS "__DONE__:Found $EXISTING_RULES iptables rules blocking LAN for UID $AI_UID."
    end
end

if confirm_step 4 "Block AI user from LAN access" \
    "THE BIG ONE. If the AI gets compromised, an attacker will try to scan" \
    "your local network — router, NAS, other computers, smart home devices." \
    "These iptables rules block ALL traffic from '$AI_USER' to private IPs:" \
    "  • 192.168.0.0/16  (most home routers)" \
    "  • 10.0.0.0/8      (some networks)" \
    "  • 172.16.0.0/12   (other private range)" \
    "  • 169.254.0.0/16  (link-local / mDNS)" \
    "The AI can still reach the internet (for APIs) but cannot touch" \
    "anything on your LAN. Rules are persisted across reboots." \
    $STEP4_STATUS

    set AI_UID (id -u "$AI_USER")

    for rule in (iptables -S OUTPUT 2>/dev/null | grep "owner --uid-owner $AI_UID")
        eval iptables (echo "$rule" | sed 's/-A/-D/')
    end 2>/dev/null; or true

    iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 192.168.0.0/16 -j DROP
    iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 10.0.0.0/8 -j DROP
    iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 172.16.0.0/12 -j DROP
    iptables -A OUTPUT -m owner --uid-owner "$AI_UID" -d 169.254.0.0/16 -j DROP

    log "Blocked $AI_USER (UID $AI_UID) from all LAN traffic"

    if command -q netfilter-persistent
        netfilter-persistent save
        log "iptables rules saved"
    else
        apt-get install -y -qq iptables-persistent
        netfilter-persistent save
        log "Installed iptables-persistent and saved rules"
    end
end


# =============================================================================
# STEP 5: Set resource limits
# =============================================================================

set STEP5_STATUS
set LIMITS_FILE "/etc/security/limits.d/$AI_USER.conf"
if test -f "$LIMITS_FILE"
    set STEP5_STATUS "__DONE__:Limits file $LIMITS_FILE already exists."
end

if confirm_step 5 "Set resource limits for AI user" \
    "Prevents the AI from taking down your Pi via:" \
    "  • Fork bomb → capped at 200 processes" \
    "  • Memory exhaustion → capped at 2GB virtual memory" \
    "  • Disk filling → max 1GB per file" \
    "  • File descriptor exhaustion → max 4096 open files" \
    "  • Core dumps disabled → no leaking memory contents" \
    "Even if the AI tries, it hits these hard limits and gets killed," \
    "while your services keep running normally." \
    $STEP5_STATUS

    set LIMITS_FILE "/etc/security/limits.d/$AI_USER.conf"
    echo "# Limits for $AI_USER — prevents resource exhaustion attacks
$AI_USER    hard    nproc       200
$AI_USER    hard    nofile      4096
$AI_USER    hard    as          2097152
$AI_USER    hard    fsize       1048576
$AI_USER    hard    core        0" > "$LIMITS_FILE"

    log "Resource limits configured in $LIMITS_FILE"
end


# =============================================================================
# STEP 6: Make critical system files immutable
# =============================================================================

set STEP6_STATUS
set IMMUTABLE_COUNT 0
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/group
    if test -f "$f"; and lsattr "$f" 2>/dev/null | grep -q '^\s*....i'
        set IMMUTABLE_COUNT (math $IMMUTABLE_COUNT + 1)
    end
end
if test "$IMMUTABLE_COUNT" -eq 4
    set STEP6_STATUS "__DONE__:All 4 critical files already have the immutable flag set."
end

if confirm_step 6 "Make critical system files immutable" \
    "Sets the immutable flag (chattr +i) on:" \
    "  • /etc/passwd   — user accounts" \
    "  • /etc/shadow   — password hashes" \
    "  • /etc/sudoers  — sudo permissions" \
    "  • /etc/group    — group memberships" \
    "This prevents ANYONE — even root — from modifying these files without" \
    "first removing the flag. Stops an attacker from adding a backdoor user." \
    "⚠️  To edit later: sudo chattr -i <file>, make changes, sudo chattr +i <file>" \
    $STEP6_STATUS

    for f in /etc/passwd /etc/shadow /etc/sudoers /etc/group
        if test -f "$f"
            chattr -i "$f" 2>/dev/null; or true
            chattr +i "$f"
            log "Made $f immutable"
        end
    end
end


# =============================================================================
# STEP 7: Audit and reduce SUID binaries
# =============================================================================

set STEP7_STATUS
set SUID_LOG "/home/$MAIN_USER/suid-audit.txt"
set SUID_CLEAN true
for bin in /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/mount /usr/bin/umount
    if test -f "$bin" -a -u "$bin"
        set SUID_CLEAN false
        break
    end
end
if test -f "$SUID_LOG" -a "$SUID_CLEAN" = "true"
    set STEP7_STATUS "__DONE__:Audit file exists and target SUID binaries already cleaned."
end

if confirm_step 7 "Audit and reduce SUID binaries" \
    "SUID binaries run as root no matter who calls them — a classic privilege" \
    "escalation vector. This step:" \
    "  1. Saves a full list of all SUID binaries to ~/suid-audit.txt" \
    "  2. Removes the SUID bit from common ones that aren't needed:" \
    "     chsh, chfn, newgrp, mount, umount" \
    "You should review the audit file and remove SUID from anything else" \
    "you don't need." \
    $STEP7_STATUS

    set SUID_LOG "/home/$MAIN_USER/suid-audit.txt"
    find / -perm -4000 -type f 2>/dev/null > "$SUID_LOG"
    chown "$MAIN_USER:$MAIN_USER" "$SUID_LOG"
    log "SUID binary list saved to $SUID_LOG"

    for bin in /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/mount /usr/bin/umount
        if test -f "$bin"
            chmod u-s "$bin"
            log "Removed SUID from $bin"
        end
    end
end


# =============================================================================
# STEP 8: Harden SSH configuration
# =============================================================================

set STEP8_STATUS
set SSHD_CONFIG /etc/ssh/sshd_config
if test -f "$SSHD_CONFIG"
    set SSH_HARDENED true
    grep -q "^PermitRootLogin no" "$SSHD_CONFIG"; or set SSH_HARDENED false
    grep -q "^PasswordAuthentication no" "$SSHD_CONFIG"; or set SSH_HARDENED false
    grep -q "DenyUsers.*$AI_USER" "$SSHD_CONFIG"; or set SSH_HARDENED false
    if test "$SSH_HARDENED" = "true"
        set STEP8_STATUS "__DONE__:sshd_config already has root login disabled, password auth off, and $AI_USER denied."
    end
end

if confirm_step 8 "Harden SSH configuration" \
    "SSH is the front door to your Pi. This step:" \
    "  • Disables password login → key-only, can't be brute forced" \
    "  • Disables root login → must SSH as your user, then sudo" \
    "  • Blocks '$AI_USER' from SSH login entirely" \
    "  • Limits auth attempts to 3" \
    "  • Disables X11 and agent forwarding" \
    "⚠️  IMPORTANT: Make sure you have SSH key access set up BEFORE" \
    "restarting SSH! The script backs up sshd_config but does NOT" \
    "restart SSH — you do that manually after verifying." \
    $STEP8_STATUS

    set SSHD_CONFIG /etc/ssh/sshd_config
    cp "$SSHD_CONFIG" "$SSHD_CONFIG.bak."(date +%s)
    log "Backed up sshd_config"

    set -l ssh_keys   PermitRootLogin PasswordAuthentication MaxAuthTries X11Forwarding AllowAgentForwarding
    set -l ssh_vals   no              no                     3            no             no

    for i in (seq (count $ssh_keys))
        set key $ssh_keys[$i]
        set val $ssh_vals[$i]
        if grep -q "^#*$key" "$SSHD_CONFIG"
            sed -i "s/^#*$key.*/$key $val/" "$SSHD_CONFIG"
        else
            echo "$key $val" >> "$SSHD_CONFIG"
        end
        log "SSH: $key = $val"
    end

    if not grep -q "DenyUsers $AI_USER" "$SSHD_CONFIG"
        echo "DenyUsers $AI_USER" >> "$SSHD_CONFIG"
        log "SSH: Blocked $AI_USER from SSH login"
    end

    warn "Test SSH in a NEW terminal, then: sudo systemctl restart ssh"
end


# =============================================================================
# STEP 9: Install and configure fail2ban
# =============================================================================

set STEP9_STATUS
if command -q fail2ban-client; and systemctl is-active --quiet fail2ban 2>/dev/null
    set STEP9_STATUS "__DONE__:fail2ban is installed and running."
end

if confirm_step 9 "Install and configure fail2ban" \
    "Watches SSH auth logs and automatically bans IPs that fail login" \
    "repeatedly. After 3 failed attempts within 10 minutes, the IP is" \
    "banned for 1 hour. This stops brute-force attacks and port scanners." \
    "Installs the fail2ban package if not already present." \
    $STEP9_STATUS

    if not command -q fail2ban-client
        apt-get update -qq
        apt-get install -y -qq fail2ban
    end

    echo "[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600" > /etc/fail2ban/jail.local

    systemctl enable fail2ban
    systemctl restart fail2ban
    log "fail2ban configured (3 attempts → 1hr ban)"
end


# =============================================================================
# STEP 10: Enable automatic security updates
# =============================================================================

set STEP10_STATUS
if test -f /etc/apt/apt.conf.d/50unattended-upgrades -a -f /etc/apt/apt.conf.d/20auto-upgrades
    set STEP10_STATUS "__DONE__:Unattended-upgrades config files already exist."
end

if confirm_step 10 "Enable automatic security updates" \
    "Kernel and system exploits are discovered regularly. If an attacker" \
    "compromises the AI user and finds an unpatched local privilege" \
    "escalation — game over. This enables daily automatic security patches" \
    "from Debian/Raspbian repos. NO auto-reboot — you control when to" \
    "reboot. Installs unattended-upgrades if not present." \
    $STEP10_STATUS

    apt-get install -y -qq unattended-upgrades

    echo 'Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Raspbian,codename=${distro_codename},label=Raspbian";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";' > /etc/apt/apt.conf.d/50unattended-upgrades

    echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";' > /etc/apt/apt.conf.d/20auto-upgrades

    log "Automatic security updates enabled (daily, no auto-reboot)"
end


# =============================================================================
# STEP 11: Create separated project directories
# =============================================================================

set STEP11_STATUS
if test -d "/srv/$MAIN_USER" -a -d "/srv/$AI_USER"
    set OWNER_MAIN (stat -c '%U' "/srv/$MAIN_USER" 2>/dev/null)
    set OWNER_AI (stat -c '%U' "/srv/$AI_USER" 2>/dev/null)
    set PERMS_MAIN (stat -c '%a' "/srv/$MAIN_USER" 2>/dev/null)
    set PERMS_AI (stat -c '%a' "/srv/$AI_USER" 2>/dev/null)
    if test "$OWNER_MAIN" = "$MAIN_USER" -a "$OWNER_AI" = "$AI_USER" \
        -a "$PERMS_MAIN" = "700" -a "$PERMS_AI" = "700"
        set STEP11_STATUS "__DONE__:/srv/$MAIN_USER (owned by $MAIN_USER, 700) and /srv/$AI_USER (owned by $AI_USER, 700) already exist."
    end
end

if confirm_step 11 "Create separated project directories" \
    "Creates two isolated directories:" \
    "  • /srv/$MAIN_USER → YOUR projects (mode 700, only you can access)" \
    "  • /srv/$AI_USER   → AI's playground (mode 700, only it can access)" \
    "Neither user can read, write, or even list the other's directory." \
    $STEP11_STATUS

    mkdir -p "/srv/$MAIN_USER"
    chown "$MAIN_USER:$MAIN_USER" "/srv/$MAIN_USER"
    chmod 700 "/srv/$MAIN_USER"
    log "/srv/$MAIN_USER → your projects (locked down)"

    mkdir -p "/srv/$AI_USER"
    chown "$AI_USER:$AI_USER" "/srv/$AI_USER"
    chmod 700 "/srv/$AI_USER"
    log "/srv/$AI_USER → AI's space (full freedom)"
end


# =============================================================================
# STEP 12: Install and configure Caddy (reverse proxy)
# =============================================================================

set STEP12_DONE ""
if command -v caddy &>/dev/null; and test -f /etc/caddy/Caddyfile; and test -f /srv/$AI_USER/Caddyfile
    set STEP12_DONE "Caddy is installed, main Caddyfile and AI Caddyfile both exist."
end

if confirm_step 12 "Install and configure Caddy" \
"Sets up Caddy as a reverse proxy with two instances:
  • Main Caddy (root, :443) — handles HTTPS, routes to your apps + AI
  • AI Caddy ($AI_USER, :4000) — AI controls its own routing
The AI can reload its own Caddy via admin API (no sudo needed).
Main Caddyfile is owned by root — AI cannot modify it.
You'll be prompted for your domain name (e.g. example.com)." \
"$STEP12_DONE"

    # Prompt for domain
    echo ""
    read -P "  Enter your domain name (e.g. example.com, leave blank to set later): " DOMAIN
    set DOMAIN (string trim $DOMAIN)

    if test -z "$DOMAIN"
        warn "No domain entered — Caddyfile will use placeholder YOUR_DOMAIN"
        warn "You can replace it later: sudo sed -i 's/YOUR_DOMAIN/yourdomain.com/g' /etc/caddy/Caddyfile"
        set DOMAIN "YOUR_DOMAIN"
    end

    log "Using domain: $DOMAIN"

    # Install Caddy if not present
    if not command -v caddy &>/dev/null
        apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
        apt-get update -qq
        apt-get install -y -qq caddy
        log "Caddy installed"
    else
        log "Caddy already installed"
    end

    # Detect script directory for config templates
    set SCRIPT_DIR (cd (dirname (status filename)); and pwd)

    # Set up main Caddyfile if not present
    if not test -f /etc/caddy/Caddyfile; or not grep -q "reverse_proxy" /etc/caddy/Caddyfile
        if test -f "$SCRIPT_DIR/caddy/Caddyfile.example"
            cp "$SCRIPT_DIR/caddy/Caddyfile.example" /etc/caddy/Caddyfile
        else
            echo "# Main Caddyfile — owned by root, AI cannot modify this file
# Each block maps a subdomain to a local port where your app runs.
# Caddy automatically gets HTTPS certificates from Let's Encrypt.
#
# To add a project:   add a block, then: sudo systemctl reload caddy
# To remove a project: delete its block, then reload

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
}" > /etc/caddy/Caddyfile
        end
        # Replace YOUR_DOMAIN with the actual domain (handles both template and inline)
        sed -i "s/YOUR_DOMAIN/$DOMAIN/g" /etc/caddy/Caddyfile
        log "Main Caddyfile created at /etc/caddy/Caddyfile (domain: $DOMAIN)"
    else
        log "Main Caddyfile already exists"
    end

    chown root:root /etc/caddy/Caddyfile
    chmod 644 /etc/caddy/Caddyfile

    # Set up AI's Caddyfile
    if not test -f /srv/$AI_USER/Caddyfile
        if test -f "$SCRIPT_DIR/caddy/Caddyfile.ai.example"
            cp "$SCRIPT_DIR/caddy/Caddyfile.ai.example" /srv/$AI_USER/Caddyfile
        else
            echo '# AI Sandbox Caddyfile — you (the AI) control this file
# Main Caddy forwards ai.yourdomain.com traffic here on port 4000.
# No TLS needed — main Caddy handles HTTPS.
#
# To add a route:   add a handle_path block, then reload (no sudo needed):
#   caddy reload --config /srv/<ai-user>/Caddyfile --address localhost:2020
# To remove a route: delete its block and reload.

{
    admin localhost:2020
}

:4000 {
    handle {
        respond "ai sandbox is running" 200
    }
}' > /srv/$AI_USER/Caddyfile
        end
        log "AI Caddyfile created at /srv/$AI_USER/Caddyfile"
    end

    chown $AI_USER:$AI_USER /srv/$AI_USER/Caddyfile
    chmod 644 /srv/$AI_USER/Caddyfile

    # Set up systemd service for AI's Caddy
    echo "[Unit]
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
WantedBy=multi-user.target" > /etc/systemd/system/caddy-ai.service

    systemctl daemon-reload
    systemctl enable caddy
    systemctl enable caddy-ai

    # Start services
    systemctl restart caddy
    systemctl restart caddy-ai

    log "Main Caddy running on :443"
    log "AI Caddy running on :4000 (owned by $AI_USER)"
    log "AI reloads via: caddy reload --config /srv/$AI_USER/Caddyfile --address localhost:2020"
end


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
