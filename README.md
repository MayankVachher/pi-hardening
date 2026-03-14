# 🔒 Pi Hardening

Raspberry Pi hardening scripts for safely running AI agents alongside your projects.

**Goal:** Create an isolated AI agent user that can experiment freely but **cannot** escalate privileges, steal your credentials, or pivot to your home network — even if fully compromised.

## Quick Start

```bash
# Bash
sudo bash harden-pi.sh

# Fish shell
sudo fish harden-pi.fish
```

The script will ask for your username and the AI account name, then walk you through each step interactively.

## What It Does

The script runs 10 steps, each explained and requiring your confirmation:

| Step | What | Why |
|------|-------|-----|
| 1 | Create AI agent account | Isolation foundation — separate Linux account |
| 2 | Lock down your home directory | AI can't read your SSH keys, tokens, .env files |
| 3 | Block sudo access | AI can't become root, ever |
| 4 | **Block LAN access** | **AI can't scan your home network** (router, NAS, etc.) |
| 5 | Set resource limits | Prevents fork bombs, memory exhaustion, disk filling |
| 6 | Harden SSH | Key-only auth, no root login, AI blocked from SSH |
| 7 | Install fail2ban | Auto-bans IPs after failed login attempts |
| 8 | Auto security updates | Daily patches for kernel/system exploits |
| 9 | Create project directories | Separated /srv dirs with ACL for read access |
| 10 | Install & configure Caddy | Dual reverse proxy — you own routing, AI owns its sandbox |

## Features

- **Interactive** — explains each step before running, asks for confirmation
- **Idempotent** — detects already-completed steps and shows their status
- **Skippable** — press `n` to skip any step, `q` to quit entirely
- **No assumptions** — asks for your username and AI account name
- **Two flavors** — Bash and Fish shell versions

## Threat Model

This script is designed for a specific scenario:

> You run an AI agent (Claude, OpenClaw, etc.) on your Pi that can execute code.
> You're OK with it destroying its own projects. You are **not** OK with getting pwned.

### What's Protected

| Threat | Protection |
|--------|------------|
| AI escalates to root | No sudo access |
| AI steals your SSH keys / tokens | Home directory locked (mode 700) |
| AI scans your home network | iptables blocks all LAN traffic per UID |
| AI fork-bombs or OOMs the Pi | ulimits on processes, memory, file size |
| AI brute-forces SSH | Key-only auth + fail2ban |
| Kernel exploit gives AI root | Automatic security updates patch daily |

### What's NOT Protected

The AI **can** destroy anything in its own directory. That's by design — your safety net is:
- Git remotes (can't delete the remote)
- Backups (if you set them up)
- The AI's playground is isolated from your projects

## Directory Layout

After running:

```
/srv/
├── <your-user>/      ← YOUR projects (mode 700, only you)
└── <ai-user>/        ← AI's playground (mode 700, only it)
    └── Caddyfile     ← AI's reverse proxy config (it controls this)

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

- **Main Caddy** is owned by root. The AI can't modify `/etc/caddy/Caddyfile`, so it can't intercept traffic meant for your projects, add rogue routes, or disable HTTPS.
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

## Requirements

- Raspberry Pi OS (Debian-based)
- Root access (`sudo`)
- Fish shell (for `.fish` version) or Bash 4+ (for `.sh` version)

## License

MIT
