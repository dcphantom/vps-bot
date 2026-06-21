# Telegram VPN Bot

**Encrypted Binary** — Telegram Bot for managing VLESS & SSH VPN users. Auto-detect IP, domain, ports, and web path.

No source code exposed. Runs as a compiled PyInstaller binary.

## Features

- **VLESS** — Create, List, Delete, Extend users with auto/custom UUID
- **SSH** — Create, List, Delete, Extend users
- **Online Monitoring** — Who's connected (VLESS from access log + SSH from `who`/`ss`) with pagination
- **Auto-detect** — IP, domain, Xray ports, SSH ports detected automatically
- **Encrypted** — PyInstaller binary, source code not exposed
- **Auto-restart** — systemd service, restart on crash, boot on start

## Quick Install

```bash
git clone https://github.com/dcphantom/vps-bot.git
cd vps-bot
chmod +x setup.sh
./setup.sh
```

Enter your Telegram bot token when prompted. That's it.

## How It Works

1. `setup.sh` creates `/root/bot_config.json` with your token
2. Binary `vps_bot_bin` is copied to `/root/` and run as systemd service
3. Bot reads token from `bot_config.json` at startup
4. All config detection happens automatically

## Bot Control

```bash
systemctl stop vps-bot       # Off
systemctl start vps-bot      # On
systemctl restart vps-bot    # Restart
systemctl status vps-bot     # Check status
```

## Requirements

- Debian/Ubuntu VPS with Xray
- Python 3.8+ (runtime only; the binary bundles its own Python)
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
