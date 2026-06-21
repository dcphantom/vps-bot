#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================"
echo -e "   Telegram VPN Bot - Auto Installer"
echo -e "========================================${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}This script must be run as root.${NC}"
    exit 1
fi

while [[ -z "$BOT_TOKEN" ]]; do
    echo -ne "${GREEN}Enter your Telegram Bot Token: ${NC}"
    read -r BOT_TOKEN
done

echo ""
echo -e "${YELLOW}[1/4] Installing dependencies...${NC}"
pip3 install python-telegram-bot --break-system-packages -q 2>/dev/null || pip3 install python-telegram-bot -q

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${YELLOW}[2/4] Decrypting source & creating config...${NC}"
base64 -d < "$SCRIPT_DIR/vps_bot.enc" | gunzip > /root/vps_bot.py
chmod 755 /root/vps_bot.py

echo "{\"token\": \"$BOT_TOKEN\"}" > /root/bot_config.json
chmod 600 /root/bot_config.json

# Build encrypted binary
echo -e "${YELLOW}[3/4] Building encrypted binary (may take a minute)...${NC}"
cd /root
pip3 install pyinstaller --break-system-packages -q 2>/dev/null || true
if command -v pyinstaller &>/dev/null; then
    pyinstaller --onefile --name vps_bot_bin \
      --hidden-import telegram --hidden-import telegram.ext \
      vps_bot.py &>/tmp/pyinstaller.log && {
        cp dist/vps_bot_bin /root/vps_bot_bin
        chmod +x /root/vps_bot_bin
        rm -rf /root/build /root/dist /root/*.spec /root/__pycache__ 2>/dev/null
        BOT_CMD="/root/vps_bot_bin"
        MODE="Encrypted binary"
    } || {
        echo -e "${YELLOW}Binary build failed, using python3${NC}"
        BOT_CMD="/usr/bin/python3 /root/vps_bot.py"
        MODE="Python script"
    }
else
    echo -e "${YELLOW}PyInstaller not found, installing first...${NC}"
    pip3 install pyinstaller --break-system-packages -q 2>/dev/null || true
    pyinstaller --onefile --name vps_bot_bin \
      --hidden-import telegram --hidden-import telegram.ext \
      vps_bot.py &>/tmp/pyinstaller.log && {
        cp dist/vps_bot_bin /root/vps_bot_bin
        chmod +x /root/vps_bot_bin
        rm -rf /root/build /root/dist /root/*.spec /root/__pycache__ 2>/dev/null
        BOT_CMD="/root/vps_bot_bin"
        MODE="Encrypted binary"
    } || {
        BOT_CMD="/usr/bin/python3 /root/vps_bot.py"
        MODE="Python script"
    }
fi

# Remove source file (only binary remains if build succeeded)
rm -f /root/vps_bot.py

echo -e "${YELLOW}[4/4] Creating systemd service...${NC}"
cat > /etc/systemd/system/vps-bot.service << EOF
[Unit]
Description=Telegram VPN Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=$BOT_CMD
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vps-bot
systemctl start vps-bot
sleep 3

STATUS=$(systemctl is-active vps-bot)
if [[ "$STATUS" == "active" ]]; then
    echo ""
    echo -e "${GREEN}========================================"
    echo -e "   BOT IS RUNNING! ✅"
    echo -e "========================================"
    echo -e "   Status: $STATUS"
    echo -e "   Mode:   $MODE"
    echo -e "   Token:  $(cut -d: -f1 <<< "$BOT_TOKEN"):...hidden"
    echo -e "========================================"
    echo -e "${YELLOW}Control:${NC}"
    echo -e "   systemctl stop vps-bot       # Off"
    echo -e "   systemctl start vps-bot      # On"
    echo -e "   systemctl restart vps-bot    # Restart"
    echo -e "   systemctl status vps-bot     # Check"
    echo -e "========================================${NC}"
else
    echo -e "${YELLOW}Something went wrong. Check: systemctl status vps-bot${NC}"
    journalctl -u vps-bot --no-pager -n 10
fi
