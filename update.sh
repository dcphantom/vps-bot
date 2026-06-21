#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}========================================"
echo -e "   VPS Bot - Update Script"
echo -e "========================================${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Must be run as root.${NC}"
    exit 1
fi

# Check token backup
if [ ! -f /root/bot_config.json ]; then
    echo -e "${RED}No bot_config.json found! Update cancelled.${NC}"
    exit 1
fi

# Backup token
TOKEN=$(python3 -c "import json; print(json.load(open('/root/bot_config.json')).get('token',''))" 2>/dev/null)
if [ -z "$TOKEN" ]; then
    echo -e "${RED}Invalid token in bot_config.json${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/4] Stopping old bot...${NC}"
systemctl stop vps-bot 2>/dev/null || true
systemctl disable vps-bot 2>/dev/null || true

echo -e "${YELLOW}[2/4] Fetching latest from GitHub...${NC}"
if [ -d /root/vps-bot ]; then
    cd /root/vps-bot
    git fetch origin 2>&1
    git reset --hard origin/master 2>&1
else
    cd /root
    git clone https://github.com/dcphantom/vps-bot.git
    cd /root/vps-bot
fi

echo -e "${YELLOW}[3/4] Building new binary...${NC}"
base64 -d < vps_bot.enc | gunzip > /root/vps_bot.py
chmod 755 /root/vps_bot.py

pip3 install pyinstaller --break-system-packages -q 2>/dev/null || true
if command -v pyinstaller &>/dev/null; then
    cd /root
    rm -rf build dist *.spec __pycache__ 2>/dev/null
    pyinstaller --onefile --name vps_bot_bin \
      --hidden-import telegram --hidden-import telegram.ext \
      vps_bot.py &>/tmp/update_pyinstaller.log && {
        cp dist/vps_bot_bin /root/vps_bot_bin
        chmod +x /root/vps_bot_bin
        rm -rf /root/build /root/dist /root/*.spec /root/__pycache__ /root/vps_bot.py 2>/dev/null
        BOT_CMD="/root/vps_bot_bin"
        echo -e "${GREEN}Binary built successfully.${NC}"
    } || {
        echo -e "${YELLOW}Binary build failed, using python3${NC}"
        BOT_CMD="/usr/bin/python3 /root/vps_bot.py"
    }
else
    BOT_CMD="/usr/bin/python3 /root/vps_bot.py"
fi

echo -e "${YELLOW}[4/4] Restarting bot...${NC}"
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
    echo -e "   UPDATE COMPLETE! ✅"
    echo -e "========================================"
    echo -e "   Status: $STATUS"
    echo -e "========================================${NC}"
else
    echo -e "${RED}Update failed. Check: systemctl status vps-bot${NC}"
    journalctl -u vps-bot --no-pager -n 10
    exit 1
fi
