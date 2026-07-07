# 🔒 Pi Hardening

Raspberry Pi hardening script for safely running AI agents alongside your projects.

**Goal:** Create an isolated AI agent user that can experiment freely but **cannot** escalate privileges, steal your credentials, or pivot to your home network — even if fully compromised.

## Quick Start

```bash
# Harden
sudo bash harden-pi.sh

# Verify the walls actually hold (runs the attacks AS the AI user)
sudo bash harden-pi.sh verify
```

The script will ask for your username and the AI account name, then walk you through each step interactively.

## What It Does

The script runs 15 steps, each explained and requiring your confirmation:

| Step | What | Why |
|------|-------|-----|
| 1 | Create AI agent account | Isolation foundation — separate Linux account |
| 2 | Lock down your home directory | AI can't read your SSH keys, tokens, .env files |
| 3 | Block sudo access | AI can't become root, ever |
| 4 | **Block LAN access + local holes** | **AI can't scan your home network** (IPv4 + IPv6), can't reach the main Caddy admin API (:2019), can't send spam (:25). DNS to your router stays allowed so the AI's lookups keep working |
| 5 | Resource limits (ulimits + cgroup slice) | Fork bombs capped per-process; memory/CPU/tasks capped as a **total** across all AI processes |
| 6 | Harden SSH | Key-only auth, no root login, AI blocked — written to `sshd_config.d/00-hardening.conf` so cloud-init files can't override it; validated with `sshd -t` |
| 7 | Install fail2ban | Auto-bans IPs after failed logins — uses the **systemd journal backend** (modern Pi OS has no `/var/log/auth.log`) |
| 8 | Auto security updates | Daily patches for kernel/system exploits |
| 9 | Create project directories | Separated /srv dirs with ACL for read access |
| 10 | Install & configure Caddy | Dual reverse proxy — you own routing, AI owns its sandbox |
| 11 | Disable Wi-Fi power save | Pi stays reachable — power save silently drops it off the network |
| 12 | Cap AI disk usage | Fixed-size sparse disk image mounted at `/srv/<ai-user>` — the AI can never fill your SD card |
| 13 | Hide processes (hidepid) | AI can't read other users' `/proc` entries — no snooping on command lines with secrets in them |
| 14 | Audit trail (auditd) | Every command the AI runs is logged — `sudo ausearch -k ai-agent -i` |
| 15 | Cloudflare Tunnel | Outbound-only exposure — no router port forwards, home IP hidden, routing controlled from your Cloudflare dashboard |

## Verify Mode

```bash
sudo bash harden-pi.sh verify
```

Doesn't trust config files — it runs the actual attacks **as the AI user** and checks they fail:

- try `sudo` → must fail
- list your home dir and `/srv/<you>` → must fail
- ping the gateway → must be dropped
- curl the main Caddy admin API (`:2019`) → must be unreachable
- DNS + internet **as the AI** → must still work
- SSH checked via `sshd -T` (the *effective* config, not just files)
- fail2ban jail actually active, limits/updates/disk cap/hidepid/auditd in place

Exits non-zero if anything fails. Run it after hardening, after any system change, and after reboots if you're paranoid.

## Features

- **Interactive** — explains each step before running, asks for confirmation
- **Idempotent** — detects already-completed steps and shows their status
- **Skippable** — press `n` to skip any step, `q` to quit entirely
- **Self-testing** — `verify` mode proves each wall holds
- **No assumptions** — asks for your username and AI account name

## Threat Model

This script is designed for a specific scenario:

> You run an AI agent (Claude, OpenClaw, etc.) on your Pi that can execute code.
> You're OK with it destroying its own projects. You are **not** OK with getting pwned.

### What's Protected

| Threat | Protection |
|--------|------------|
| AI escalates to root | No sudo access |
| AI steals your SSH keys / tokens | Home directory locked (mode 700) |
| AI scans your home network | iptables + ip6tables block all LAN traffic per UID (IPv4 and IPv6), with a DNS carve-out so lookups keep working |
| AI hijacks your reverse-proxy routes | Main Caddy admin API (`localhost:2019`) firewalled from the AI's UID |
| AI sends spam if compromised | Outbound SMTP (port 25) blocked |
| AI fork-bombs or OOMs the Pi | ulimits per process + cgroup slice capping the **total** (2GB RAM, 3 cores, 200 tasks) |
| AI fills your SD card | `/srv/<ai-user>` is a fixed-size disk image — hard cap |
| AI snoops your processes | `hidepid=2` — AI only sees its own `/proc` entries |
| AI brute-forces SSH | Key-only auth + fail2ban (journald backend) |
| Kernel exploit gives AI root | Automatic security updates patch daily |
| No trace of what happened | auditd logs every command the AI executes |
| Home IP exposed / ports open to the internet | Cloudflare Tunnel — outbound-only, no inbound ports needed |
| AI steals the tunnel token and hijacks traffic | Token stored root-only (mode 600), cloudflared runs as its own sandboxed user |

### Known Residual Risks

- **Port squatting** — `reverse_proxy localhost:3000` trusts whoever listens on 3000. If your app crashes, the AI could bind the port and receive that traffic. Mitigation: run sensitive apps on **unix sockets** (see comments in `caddy/Caddyfile.example`).
- `/home/<ai-user>` is not disk-capped — keep the agent's workspace in `/srv/<ai-user>`.
- The cgroup limits only apply when the agent runs as a login session or systemd service — **launch the agent via `systemd/ai-agent.service.example`**, not a bare `sudo -u`.

### What's NOT Protected

The AI **can** destroy anything in its own directory. That's by design — your safety net is:
- Git remotes (can't delete the remote)
- Backups (see below)
- The AI's playground is isolated from your projects

## Backups

The script doesn't set up backups (it can't know your destination), but the walls only protect against *theft*, not *loss*. Minimum viable safety net:

```bash
# Push your projects to git remotes — the AI can't delete those.
# For everything else, a nightly tarball to another machine:
0 3 * * * tar czf - /srv/YOUR_USER | ssh backup-host 'cat > pi-$(date +\%F).tgz'
```

## Running the Agent

Use the hardened systemd unit so the resource caps actually apply:

```bash
sudo cp systemd/ai-agent.service.example /etc/systemd/system/ai-agent.service
sudo sed -i 's/AI_USER/your-ai-user/g' /etc/systemd/system/ai-agent.service
# edit ExecStart, then:
sudo systemctl daemon-reload && sudo systemctl enable --now ai-agent
```

A bare `sudo -u ai-agent ...` keeps the processes in *your* session's cgroup — the memory/CPU caps won't bind.

## Cloudflare Tunnel

Step 15 installs `cloudflared` and runs a **dashboard-managed tunnel** (token-based — no browser login on the headless Pi). You create the tunnel at [one.dash.cloudflare.com](https://one.dash.cloudflare.com) → Networks → Tunnels, paste the token into the script, and it runs as a dedicated unprivileged user with the token readable only by root.

**Why:** no 80/443 port forwards on your router, home IP hidden, DDoS protection, works behind CGNAT. Once tunnel routes work, close the port forwards — the Pi needs **zero open inbound ports**.

**Routing — two options:**

1. **Dashboard-direct (recommended, simplest).** Add a Public Hostname per app in the tunnel's dashboard page:
   - `bloodhound.YOUR_DOMAIN` → `HTTP` → `localhost:3000`
   - `ai.YOUR_DOMAIN` → `HTTP` → `localhost:4000` (AI's sandbox Caddy)

   Routing control moves into your Cloudflare account — like the root-owned Caddyfile, the AI can't touch it. Cloudflare's edge terminates TLS; main Caddy is bypassed.

2. **Through main Caddy.** One wildcard Public Hostname `*.YOUR_DOMAIN` → `HTTPS` → `localhost:443`, with **No TLS Verify** enabled under the hostname's TLS settings. Then add a `local_certs` global option to `/etc/caddy/Caddyfile` (Let's Encrypt's HTTP challenge can't work with no inbound ports):
   ```
   {
       local_certs
   }
   ```
   Keeps all routing in the Caddyfile; note this breaks *direct* (non-tunnel) HTTPS access.

The AI's `ai.YOUR_DOMAIN` sandbox works identically in both options.

**Re-running / rotating the token:** re-run step 15 and paste the new token — it cleanly stops and removes any existing tunnel service first (including one created manually with `cloudflared service install`) and moves old configs/tokens aside to a root-only backup dir. The script never runs `cloudflared service install` itself: that command embeds the token in a world-readable unit file. Entering a blank token leaves an existing setup untouched.

## Directory Layout

After running:

```
/srv/
├── <your-user>/      ← YOUR projects (mode 700, only you)
└── <ai-user>/        ← AI's playground (mode 700, fixed-size disk image)
    └── Caddyfile     ← AI's reverse proxy config (it controls this)

/var/lib/
└── <ai-user>-disk.img ← the sparse image backing /srv/<ai-user>

/etc/caddy/
└── Caddyfile         ← Main reverse proxy config (root-owned, AI can't touch)

/home/
├── <your-user>/      ← Locked down (mode 700)
└── <ai-user>/        ← AI's home directory
```

## Caddy Architecture

The setup uses **two Caddy instances** to separate routing control:

```
Internet
    │
    ▼
┌─────────────────────────────┐
│  Main Caddy (root, :443)    │ ← HTTPS termination, root-owned config
│  /etc/caddy/Caddyfile       │
├─────────────────────────────┤
│  bloodhound.domain → :3000  │
│  kaal.domain       → :3001  │
│  tribute.domain    → :3002  │
│  ai.domain         → :4000 ─┼───┐
└─────────────────────────────┘   │
                                  ▼
                    ┌──────────────────────────┐
                    │  AI Caddy (ai-user, :4000)│ ← AI-owned config
                    │  /srv/<ai-user>/Caddyfile │
                    ├──────────────────────────┤
                    │  /dash/* → :4001          │
                    │  /api/*  → :4002          │
                    │  default → "sandbox ok"   │
                    └──────────────────────────┘
```

**Why two Caddy instances?**

- **Main Caddy** is owned by root. The AI can't modify `/etc/caddy/Caddyfile`, and its admin API on `localhost:2019` is firewalled from the AI's UID (step 4) — so it can't intercept traffic meant for your projects, add rogue routes, or disable HTTPS.
- **AI Caddy** runs as the AI agent on port 4000. It gets traffic only for `ai.YOUR_DOMAIN`, and routes it to whatever the AI is running on high ports. The AI can reload it without sudo:
  ```bash
  caddy reload --config /srv/<ai-user>/Caddyfile --address localhost:2020
  ```

**Config files:**

| File | Purpose | Owned by |
|------|---------|----------|
| `caddy/Caddyfile.example` | Template for main Caddy | root |
| `caddy/Caddyfile.ai.example` | Template for AI's Caddy | ai-user |
| `caddy/caddy-ai.service` | Systemd unit for AI's Caddy | root |
| `systemd/ai-agent.service.example` | Systemd unit for the agent itself | root |

## Re-running the Script

The script is safe to re-run. Each step checks if it's already been applied:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Step 3: Block sudo access for AI agent
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓ Already done:
    ai-agent is not in sudo group and /etc/sudoers.d/ai-agent-deny exists.

    Without sudo, the AI agent cannot become root...

  Re-apply anyway? (y/n/q to quit)
```

## Important Notes

- **Set up SSH key auth BEFORE running step 6** — it disables password login
- **Test SSH in a second terminal** before closing your current session
- The script does **not** restart SSH automatically — you do that after verifying
- After step 13 (hidepid), **log out and back in** for your `proc` group membership (tools like `htop` need it to see all processes)
- Run `sudo bash harden-pi.sh verify` at the end

## Requirements

- A Debian-family OS — tested on Ubuntu Server 25.10 (Pi) and Raspberry Pi OS. Step 8 auto-detects the distro and writes the matching security-update origins (Ubuntu vs Debian/Raspbian — wrong origins would mean no updates ever install)
- Root access (`sudo`)
- Bash 4+

## License

MIT
