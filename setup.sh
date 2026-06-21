#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================"
echo -e "   Telegram VPN Bot - Auto Installer"
echo -e "   Encrypted Binary Version"
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
echo -e "${YELLOW}[1/4] Creating config file...${NC}"
echo "{\"token\": \"$BOT_TOKEN\"}" > /root/bot_config.json
chmod 600 /root/bot_config.json

echo -e "${YELLOW}[2/4] Installing binary...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/vps_bot_bin" ]; then
    cp "$SCRIPT_DIR/vps_bot_bin" /root/vps_bot_bin
elif [ -f "/root/vps_bot_bin" ]; then
    echo -e "${YELLOW}Binary found at /root/vps_bot_bin${NC}"
else
    echo -e "${YELLOW}Downloading binary from GitHub...${NC}"
    wget -q -O /root/vps_bot_bin https://github.com/dcphantom/vps-bot/raw/master/vps_bot_bin
fi
chmod +x /root/vps_bot_bin

echo -e "${YELLOW}[3/4] Creating systemd service...${NC}"
cat > /etc/systemd/system/vps-bot.service << 'EOF'
[Unit]
Description=Telegram VPN Bot (Encrypted)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/root/vps_bot_bin
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vps-bot

echo -e "${YELLOW}[4/4] Starting bot...${NC}"
systemctl start vps-bot
sleep 3

STATUS=$(systemctl is-active vps-bot)
if [[ "$STATUS" == "active" ]]; then
    echo ""
    echo -e "${GREEN}========================================"
    echo -e "   BOT IS RUNNING! ✅"
    echo -e "========================================"
    echo -e "   Status: $STATUS"
    echo -e "   Mode:   Encrypted binary"
    echo -e "   Token:  $(cut -d: -f1 <<< "$BOT_TOKEN"):...hidden"
    echo -e "========================================${NC}"
else
    echo -e "${YELLOW}Something went wrong. Check: systemctl status vps-bot${NC}"
fi
