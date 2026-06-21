# Telegram VPN Bot

Telegram Bot for managing VLESS & SSH VPN users. Auto-detect IP, domain, and web path.

## Features

- **VLESS** - Create, List, Delete, Extend users with auto/custom UUID
- **SSH** - Create, List, Delete, Extend users
- **Online Monitoring** - See who's currently connected (VLESS + SSH) with pagination
- **Auto-detect** - IP, domain, web path detected automatically
- **Auto-restart** - systemd service, restart on crash, start on boot

## Quick Install

```bash
git clone https://github.com/dcphantom/vps-bot.git
cd vps-bot
cp vps_bot.py /root/
chmod +x setup.sh
./setup.sh
```

Then just enter your Telegram bot token when prompted.

## Manual Install

```bash
pip install python-telegram-bot paramiko

# Upload vps_bot.py to /root/
# Edit TOKEN in vps_bot.py

# Create systemd service (or use nohup)
```

## Requirements

- Debian/Ubuntu VPS with Xray (GAS VPN script)
- Python 3.8+
- Telegram Bot Token (from @BotFather)
