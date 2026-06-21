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

# ── Check root ──
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}This script must be run as root.${NC}"
    exit 1
fi

# ── Ask for bot token ──
while [[ -z "$BOT_TOKEN" ]]; do
    echo -ne "${GREEN}Enter your Telegram Bot Token: ${NC}"
    read -r BOT_TOKEN
done

echo ""
echo -e "${YELLOW}[1/4] Installing dependencies...${NC}"
pip install python-telegram-bot paramiko -q

echo -e "${YELLOW}[2/4] Configuring bot token...${NC}"
sed -i "s/YOUR_BOT_TOKEN/$BOT_TOKEN/" /root/vps_bot.py

echo -e "${YELLOW}[3/4] Creating systemd service...${NC}"
cat > /etc/systemd/system/vps-bot.service << 'EOF'
[Unit]
Description=Telegram VPN Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/python3 /root/vps_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vps-bot

echo -e "${YELLOW}[4/4] Starting bot...${NC}"
systemctl start vps-bot
sleep 2

# ── Check ──
STATUS=$(systemctl is-active vps-bot)
if [[ "$STATUS" == "active" ]]; then
    echo ""
    echo -e "${GREEN}========================================"
    echo -e "   BOT IS RUNNING! ✅"
    echo -e "========================================"
    echo -e "   Status: $STATUS"
    echo -e "   Domain: $(cat /etc/xray/domain 2>/dev/null || echo 'auto-detect')"
    echo -e "   IP:     $(hostname -I | awk '{print $1}')"
    echo -e "========================================${NC}"
else
    echo -e "${YELLOW}Something went wrong. Check: systemctl status vps-bot${NC}"
fi
