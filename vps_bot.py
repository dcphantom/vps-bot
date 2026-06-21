#!/usr/bin/env python3

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import uuid as uuid_lib
from datetime import date, datetime, timedelta

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

TOKEN = "YOUR_BOT_TOKEN"
try:
    with open("/root/bot_config.json") as f:
        TOKEN = json.load(f).get("token", TOKEN)
except Exception:
    pass

XRAY_CFG = "/usr/local/etc/xray/config.json"
XRAY_NONE = "/usr/local/etc/xray/none.json"
ALLOWED_USERS: list[int] = []

UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _strip_comments(text: str) -> str:
    res, i, in_str = [], 0, False
    while i < len(text):
        c = text[i]
        if c == '"' and (i == 0 or text[i - 1] != "\\"):
            in_str = not in_str
        if not in_str:
            if c == "#":
                while i < len(text) and text[i] != "\n":
                    i += 1
                continue
            if c == "/" and i + 1 < len(text) and text[i + 1] == "*":
                i += 2
                while i < len(text):
                    if text[i] == "*" and i + 1 < len(text) and text[i + 1] == "/":
                        i += 2
                        break
                    i += 1
                continue
        res.append(c)
        i += 1
    return "".join(res)


def _read_json(path: str) -> dict:
    with open(path) as f:
        return json.loads(_strip_comments(f.read()))


def _write_json(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

# ── Universal auto-detection helpers ──

def detect_vless_inbounds():
    """Parse all xray configs and auto-detect VLESS inbounds with their types."""
    inbounds = []
    for cfg_path in (XRAY_CFG, XRAY_NONE):
        try:
            data = _read_json(cfg_path)
        except:
            continue
        file_tag = "none" if "none.json" in cfg_path else "config"
        for ib in data.get("inbounds", []):
            if ib.get("protocol") != "vless":
                continue
            port = str(ib.get("port", ""))
            ss = ib.get("streamSettings", {})
            net = ss.get("network", "tcp")
            sec = ss.get("security", "none")
            path = ""
            if net == "ws":
                path = ss.get("wsSettings", {}).get("path", "/")
            elif net == "xhttp":
                path = ss.get("xhttpSettings", {}).get("path", "/")
            elif net == "httpupgrade":
                path = ss.get("httpupgradeSettings", {}).get("path", "/")
            is_internal = ib.get("listen") == "127.0.0.1" or int(port) >= 1200
            inbounds.append({
                "port": port, "network": net, "security": sec,
                "path": path, "file_tag": file_tag, "is_internal": is_internal
            })
    
    # Determine external ports from non-internal inbounds
    ext = {"tls": "443", "non_tls": "80", "xhttp_tls": "8443", "xhttp_ntls": "8080"}
    for ib in inbounds:
        if not ib["is_internal"]:
            if ib["security"] == "tls":
                ext["tls"] = ib["port"]
            else:
                ext["non_tls"] = ib["port"]
        if ib["network"] == "xhttp":
            if ib["security"] == "tls":
                ext["xhttp_tls"] = ib["port"]
            else:
                ext["xhttp_ntls"] = ib["port"]
    
    # Build INBOUND_SECTIONS for add_user_to_cfg
    sections = {}
    for ib in inbounds:
        if ib["is_internal"]:
            prefix = "#vls"
            if ib["network"] == "httpupgrade":
                prefix = "#vls-http"
            elif ib["network"] == "xhttp":
                prefix = "#vls-xhttp"
            sections[ib["port"]] = {"tag": prefix, "file_tag": ib["file_tag"]}
    
    return inbounds, sections, ext

def detect_ssh_info():
    """Auto-detect SSH ports and services from system config."""
    info = {"openssh": [22], "dropbear": [], "stunnel": [],
            "squid": [], "ws_http": "8880", "ws_https": "2096", "ws_ovpn": "2097"}
    try:
        r = run_command(["grep", "-i", "^Port", "/etc/ssh/sshd_config"])
        ports = [int(m.group(1)) for line in r.stdout.split("\n") if (m := re.search(r"Port\s+(\d+)", line, re.IGNORECASE))]
        if ports: info["openssh"] = ports
    except: pass
    try:
        for p in ["/etc/default/dropbear", "/etc/dropbear/dropbear.conf"]:
            if os.path.exists(p):
                with open(p) as f: c = f.read()
                for m in re.finditer(r"(?:DROPBEAR_PORT|PORT)\s*[=:]\s*(\d+)", c, re.IGNORECASE):
                    info["dropbear"].append(int(m.group(1)))
                for m in re.finditer(r"-p\s+(\d+)", c):
                    info["dropbear"].append(int(m.group(1)))
    except: pass
    try:
        p = "/etc/stunnel/stunnel.conf"
        if os.path.exists(p):
            with open(p) as f: c = f.read()
            info["stunnel"] = [int(m.group(1)) for m in re.finditer(r"accept\s*=\s*(\d+)", c, re.IGNORECASE)]
    except: pass
    try:
        for p in ["/etc/squid/squid.conf", "/etc/squid3/squid.conf"]:
            if os.path.exists(p):
                with open(p) as f: c = f.read()
                info["squid"] = [int(m.group(1)) for m in re.finditer(r"http_port\s+(\d+)", c, re.IGNORECASE)]
    except: pass
    return info
XRAY_ACCESS_LOG = "/var/log/xray/access.log"
ONLINE_PAGE_SIZE = 10

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def run_command(args: list[str], timeout: int = 5) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def detect_ip() -> str:
    try:
        return run_command(["hostname", "-I"]).stdout.strip().split()[0]
    except Exception:
        return "127.0.0.1"


def detect_domain(fallback: str) -> str:
    try:
        return run_command(["cat", "/etc/xray/domain"]).stdout.strip()
    except Exception:
        return os.uname()[1] or fallback


def detect_public_html() -> str:
    candidate = "/home/vps/public_html"
    return candidate if os.path.isdir(candidate) else "/var/www/html"


IP = detect_ip()
DOMAIN = detect_domain(IP)
PUBLIC_HTML = detect_public_html()


def read_cfg(path: str) -> str:
    with open(path) as handle:
        return handle.read()


def write_cfg(path: str, content: str) -> None:
    with open(path, "w") as handle:
        handle.write(content)


def new_uuid() -> str:
    return str(uuid_lib.uuid4())


def days_left(value: str) -> int:
    try:
        return max(0, (datetime.strptime(value, "%Y-%m-%d").date() - date.today()).days)
    except Exception:
        return 0


def parse_expiry(value: str) -> str:
    for fmt in ("%Y-%m-%d", "%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(value.strip(), fmt).strftime("%Y-%m-%d")
        except Exception:
            continue
    return value


def status_label(value: str) -> str:
    remaining = days_left(value)
    return "EXPIRED" if remaining == 0 else f"{remaining}d"


def is_authorized(user_id: int) -> bool:
    return not ALLOWED_USERS or user_id in ALLOWED_USERS


def get_users() -> list[dict]:
    seen: set[str] = set()
    users: list[dict] = []
    for cfg_path in (XRAY_CFG, XRAY_NONE):
        try:
            data = _read_json(cfg_path)
        except:
            continue
        for ib in data.get("inbounds", []):
            if ib.get("protocol") != "vless":
                continue
            for client in ib.get("settings", {}).get("clients", []):
                email = client.get("email", "")
                if email in seen or not email:
                    continue
                seen.add(email)
                users.append({
                    "name": email,
                    "uuid": client.get("id", ""),
                    "expiry": client.get("expiry", "unknown"),
                    "created": client.get("created", "unknown"),
                })
    return users


def get_user(name: str) -> dict | None:
    return next((user for user in get_users() if user["name"] == name), None)


def restart_xray() -> bool:
    try:
        run_command(["pkill", "-9", "-f", "xray"])
        run_command(["systemctl", "restart", "xray.service"], timeout=10)
        run_command(["systemctl", "restart", "xray@none.service"], timeout=10)
        return True
    except Exception:
        return False


def xray_status() -> str:
    try:
        return run_command(["systemctl", "is-active", "xray"]).stdout.strip()
    except Exception:
        return "unknown"


def build_links(name: str, uid: str, expiry: str) -> list[str]:
    tls = EXT["tls"]
    ntls = EXT["non_tls"]
    xtls = EXT["xhttp_tls"]
    xntls = EXT["xhttp_ntls"]
    return [
        f"vless://{uid}@{DOMAIN}:{tls}?path=/vless&security=tls&encryption=none&type=ws&sni={DOMAIN}#{name}_{expiry}",
        f"vless://{uid}@{DOMAIN}:{ntls}?path=/&encryption=none&type=ws&host={DOMAIN}#{name}_{expiry}",
        f"vless://{uid}@{DOMAIN}:{tls}?path=/httpupgrade&security=tls&encryption=none&type=httpupgrade&sni={DOMAIN}#httpupgrade-{name}_{expiry}",
        f"vless://{uid}@{DOMAIN}:{xtls}?path=/xhttp&security=tls&encryption=none&type=xhttp&sni={DOMAIN}#xhttp-{name}_{expiry}",
        f"vless://{uid}@{DOMAIN}:{xntls}?path=/xhttp&encryption=none&type=xhttp&host={DOMAIN}#xhttpntls-{name}_{expiry}",
    ]


def format_vless_info(user: dict) -> str:
    links = build_links(user["name"], user["uuid"], user["expiry"])
    separator = "=" * 40
    tls_port = EXT["tls"]
    ntls_port = EXT["non_tls"]
    xtls_port = EXT["xhttp_tls"]
    xntls_port = EXT["xhttp_ntls"]
    blocks = [
        (f"VLESS TLS ({tls_port})", links[0]),
        (f"VLESS Non-TLS ({ntls_port})", links[1]),
        (f"HTTPUpgrade ({tls_port})", links[2]),
        (f"XHTTP TLS ({xtls_port})", links[3]),
        (f"XHTTP Non-TLS ({xntls_port})", links[4]),
    ]
    header = (
        f"{user['name']} | Exp: {user['expiry']} ({status_label(user['expiry'])}) "
        f"| ID: {user['uuid'][:8]}...\n{separator}"
    )
    body = "".join(f"\n{label}\n```\n{link}\n```\n" for label, link in blocks)
    footer = f"\U0001f4c4 {{https://{DOMAIN}}}/vless-{user['name']}.txt"
    return header + body + footer


def make_sub_file(name: str, uid: str, expiry: str) -> None:
    links = build_links(name, uid, expiry)
    tls_port = EXT["tls"]
    ntls_port = EXT["non_tls"]
    xntls_port = EXT["xhttp_ntls"]
    separator = "=" * 68
    content = f"""{separator}
             P R O J E C T  O F  N I L P H R E A K Z V P N
                       [Freedom Internet]
{separator}
             https://github.com/NiL070/oddloop
{separator}
             Format Vless WS - SPv2
{separator}

             Link Vless Account
{separator}
Remarks               : {name}
Domain                : {DOMAIN}
IP/Host               : {IP}
Port TLS              : {tls_port}
Port None TLS         : {ntls_port}, {xntls_port}
User ID               : {uid}
Encryption            : None
Network               : WebSocket
Path Ws Tls           : /vless
Path Ws None Tls      : /
Path HttpUpgrade      : /httpupgrade
Path Xhttp            : /xhttp
AllowInsecure         : True/allow
{separator}
Link Ws TLS : {links[0]}
{separator}
Link Ws NTLS : {links[1]}
{separator}
Link HttpUpgrade : {links[2]}
{separator}
Link Xhttp TLS : {links[3]}
{separator}
Link Xhttp NTLS : {links[4]}
{separator}
"""
    path = os.path.join(PUBLIC_HTML, f"vless-{name}.txt")
    try:
        write_cfg(path, content)
    except Exception:
        try:
            os.makedirs(PUBLIC_HTML, exist_ok=True)
            write_cfg(path, content)
        except Exception:
            pass


def generate_all_subs() -> None:
    for user in get_users():
        make_sub_file(user["name"], user["uuid"], user["expiry"])


def remove_sub_file(name: str) -> None:
    try:
        os.remove(os.path.join(PUBLIC_HTML, f"vless-{name}.txt"))
    except Exception:
        pass


def add_user_to_cfg(cfg_path: str, name: str, uid: str, exp_date: str, today: str) -> bool:
    try:
        data = _read_json(cfg_path)
    except:
        return False

    modified = False
    for ib in data.get("inbounds", []):
        if ib.get("protocol") != "vless":
            continue
        clients = ib.setdefault("settings", {}).setdefault("clients", [])
        clients.append({"id": uid, "email": name, "expiry": exp_date, "created": today})
        modified = True

    if not modified:
        return False
    _write_json(cfg_path, data)
    return True


def add_vless_user(name: str, days: int, uid: str | None = None) -> tuple[bool, str]:
    if any(user["name"] == name for user in get_users()):
        return False, f"User {name} already exists!"

    uid = uid or new_uuid()
    today = date.today().isoformat()
    exp_date = (date.today() + timedelta(days=days)).isoformat()

    added_tls = add_user_to_cfg(XRAY_CFG, name, uid, exp_date, today)
    added_none = add_user_to_cfg(XRAY_NONE, name, uid, exp_date, today)
    if not (added_tls or added_none):
        return False, "Failed to add user - config format not matched"

    restart_xray()
    generate_all_subs()
    parts = [label for label, ok in (("TLS", added_tls), ("nonTLS", added_none)) if ok]
    return True, f"User {name} added! ({'+'.join(parts)})\nExpires: {exp_date}\nUUID: {uid}"


def delete_vless_user(name: str) -> tuple[bool, str]:
    removed = 0
    for cfg_path in (XRAY_CFG, XRAY_NONE):
        try:
            data = _read_json(cfg_path)
        except:
            continue
        for ib in data.get("inbounds", []):
            if ib.get("protocol") != "vless":
                continue
            clients = ib.get("settings", {}).get("clients", [])
            before = len(clients)
            ib["settings"]["clients"] = [c for c in clients if c.get("email") != name]
            after = len(ib["settings"]["clients"])
            removed += before - after
        _write_json(cfg_path, data)

    if not removed:
        return False, f"User {name} not found."
    restart_xray()
    remove_sub_file(name)
    return True, f"User {name} deleted! ({removed} entries)"


def extend_vless_user(name: str, days: int) -> tuple[bool, str]:
    changed = False
    for cfg_path in (XRAY_CFG, XRAY_NONE):
        try:
            data = _read_json(cfg_path)
        except:
            continue
        modified = False
        for ib in data.get("inbounds", []):
            if ib.get("protocol") != "vless":
                continue
            for client in ib.get("settings", {}).get("clients", []):
                if client.get("email") == name:
                    try:
                        current = datetime.strptime(client.get("expiry", ""), "%Y-%m-%d").date()
                    except:
                        current = date.today()
                    client["expiry"] = (current + timedelta(days=days)).isoformat()
                    modified = True
        if modified:
            _write_json(cfg_path, data)
            changed = True

    if not changed:
        return False, f"User {name} not found."
    restart_xray()
    user = get_user(name)
    if user:
        make_sub_file(user["name"], user["uuid"], user["expiry"])
    return True, f"User {name} extended by {days} days!"


def get_ssh_users() -> list[dict]:
    result = run_command(
        ["awk", "-F:", '{if($3>=1000 && $3!=65534) print $1":"$6}', "/etc/passwd"]
    )
    users: list[dict] = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split(":")
        name, home = parts[0], parts[1]
        expiry = "never"
        info = run_command(["chage", "-l", name])
        for info_line in info.stdout.split("\n"):
            if "Account expires" in info_line:
                value = info_line.split(":")[1].strip()
                if value != "never":
                    expiry = parse_expiry(value)
                break
        users.append({"name": name, "expiry": expiry, "home": home})
    return users


def get_ssh_user(name: str) -> dict | None:
    return next((user for user in get_ssh_users() if user["name"] == name), None)


def add_ssh_user(name: str, password: str, days: int) -> tuple[bool, str]:
    if get_ssh_user(name):
        return False, f"SSH user {name} already exists!"

    exp_date = (date.today() + timedelta(days=days)).isoformat()
    created = run_command(["useradd", "-M", "-s", "/bin/false", "-e", exp_date, name])
    if created.returncode != 0:
        return False, f"Failed to create user: {created.stderr.strip()}"

    secret = subprocess.run(
        ["chpasswd"], input=f"{name}:{password}", capture_output=True, text=True
    )
    if secret.returncode != 0:
        run_command(["userdel", name])
        return False, f"Failed to set password: {secret.stderr.strip()}"
    return True, f"SSH user {name} added!"


def delete_ssh_user(name: str) -> tuple[bool, str]:
    if not get_ssh_user(name):
        return False, f"SSH user {name} not found."
    run_command(["userdel", "-r", name])
    return True, f"SSH user {name} deleted!"


def extend_ssh_user(name: str, days: int) -> tuple[bool, str]:
    user = get_ssh_user(name)
    if not user:
        return False, f"SSH user {name} not found."
    try:
        current = datetime.strptime(user["expiry"], "%Y-%m-%d").date()
    except Exception:
        current = date.today()
    new_exp = current + timedelta(days=days)
    result = run_command(["usermod", "-e", new_exp.isoformat(), name])
    if result.returncode != 0:
        return False, f"Failed to extend: {result.stderr.strip()}"
    return True, f"SSH user {name} extended by {days} days!"


def format_ssh_info(user: dict, password: str = "") -> str:
    created = date.today().isoformat()
    expiry = user["expiry"]
    separator = "=" * 68
    secret = password or "(your password)"
    auth_pass = password or "pass"

    openssh_ports = ", ".join(str(p) for p in SSH_DATA["openssh"])
    dropbear_ports = ", ".join(str(p) for p in SSH_DATA["dropbear"]) if SSH_DATA["dropbear"] else "143, 109"
    stunnel_ports = ", ".join(str(p) for p in SSH_DATA["stunnel"]) if SSH_DATA["stunnel"] else "222, 777"
    squid_ports = ", ".join(str(p) for p in SSH_DATA["squid"]) if SSH_DATA["squid"] else "3128, 8000"
    ws_http = SSH_DATA.get("ws_http", "8880")
    ws_https = SSH_DATA.get("ws_https", "2096")
    ws_ovpn = SSH_DATA.get("ws_ovpn", "2097")

    body = f"""{separator}
         [ Premium Account SSH & OpenVPN ]
{separator}
Username         : {user['name']}
Password         : {secret}
Created          : {created}
Expired          : {expiry}
{separator}
Domain           : {DOMAIN}
IP/Host          : {IP}
OpenSSH          : {openssh_ports}
Dropbear         : {dropbear_ports}
SSL/TLS          : {stunnel_ports}
SSH-UDP          : 1-65535
WS SSH(HTTP)     : {ws_http}
WS SSL(HTTPS)    : 443, {ws_https}
WS OpenVPN(HTTP) : {ws_ovpn}
OHP Dropbear     : 8585
OHP OpenSSH      : 8686
OHP OpenVPN      : 8787
Port Squid       : {squid_ports} (limit to IP Server)
Badvpn(UDPGW)    : 7100-7300
{separator}
CONFIG SSH WS
SSH Config  : {{http://{IP}}}:81/ssh-u.txt
SSH 22      : {DOMAIN}:22@{user['name']}:{auth_pass}
SSH {ws_http}    : {DOMAIN}:{ws_http}@{user['name']}:{auth_pass}
SSH 443     : {DOMAIN}:443@{user['name']}:{auth_pass}
SSH 1-65535 : {DOMAIN}:1-65535@{user['name']}:{auth_pass}
{separator}
CONFIG OPENVPN
OpenVPN TCP : 1194 {{http://{IP}}}:81/client-tcp-1194.ovpn
OpenVPN UDP : 2200 {{http://{IP}}}:81/client-udp-2200.ovpn
OpenVPN SSL : 110 {{http://{IP}}}:81/client-tcp-ssl.ovpn
OpenVPN OHP : 8787 {{http://{IP}}}:81/client-tcp-ohp1194.ovpn
{separator}
PAYLOAD WS       : GET / HTTP/1.1[crlf]Host: {DOMAIN}[crlf]Upgrade: websocket[crlf][crlf]"
{separator}
PAYLOAD WSS      : GET wss:/// HTTP/1.1[crlf]Host: {DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]"
{separator}
PAYLOAD WS OVPN  : GET wss:/// HTTP/1.1[crlf]Host: {DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]"
{separator}"""
    return f"```\n{body}\n```"


def get_online_users() -> dict:
    now = datetime.now()
    window = 600

    # ── VLESS from access log ──
    vless_map = {}
    try:
        with open(XRAY_ACCESS_LOG) as f:
            for line in f:
                if "accepted" not in line or "email:" not in line:
                    continue
                m = re.match(
                    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\..* "
                    r"from (\d+\.\d+\.\d+\.\d+):\d+ accepted.*email:\s*(\S+)",
                    line,
                )
                if not m:
                    continue
                try:
                    ts = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
                except Exception:
                    continue
                if (now - ts).total_seconds() > window:
                    continue
                ip = m.group(2)
                email = m.group(3)
                if email not in vless_map:
                    vless_map[email] = {"ips": set(), "last_seen": ts}
                vless_map[email]["ips"].add(ip)
                if ts > vless_map[email]["last_seen"]:
                    vless_map[email]["last_seen"] = ts
    except (FileNotFoundError, PermissionError):
        pass

    vless_online = sorted(
        (
            {
                "name": email,
                "ip": ", ".join(data["ips"]),
                "last_seen": data["last_seen"].strftime("%H:%M:%S"),
            }
            for email, data in vless_map.items()
        ),
        key=lambda x: x["last_seen"],
        reverse=True,
    )

    # ── SSH from who + ss ──
    ssh_seen = set()
    ssh_online = []
    try:
        for line in run_command(["who"]).stdout.strip().split("\n"):
            parts = re.split(r"\s+", line.strip())
            if len(parts) < 5:
                continue
            username, ip = parts[0], parts[4]
            login_time = parts[3] if len(parts) >= 5 else ""
            user = get_ssh_user(username)
            if user:
                ssh_seen.add(ip)
                ssh_online.append({"name": username, "ip": ip, "last_seen": login_time})
    except Exception:
        pass

    try:
        result = run_command(["ss", "-tnp"])
        for line in result.stdout.split("\n"):
            for port in (22, 109, 143, 200, 500, 51443, 58080):
                if f":{port} " not in line and f":{port})\n" not in line:
                    continue
                parts = line.split()
                for p in parts:
                    if "->" not in p:
                        continue
                    ip = p.split("->")[1].rsplit(":", 1)[0].strip("[]")
                    if ip and ip not in ssh_seen and not ip.startswith("127.") and ip != IP:
                        ssh_seen.add(ip)
                        ssh_online.append({"name": "SSH tunnel", "ip": ip, "last_seen": "active"})
    except Exception:
        pass

    return {"vless": vless_online, "ssh": ssh_online}


def format_online_page(data: dict, page: int) -> str:
    vless_list = data.get("vless", [])
    ssh_list = data.get("ssh", [])
    combined = [(u, "VLESS") for u in vless_list] + [(u, "SSH") for u in ssh_list]
    combined.sort(key=lambda x: x[0]["last_seen"], reverse=True)

    total = len(combined)
    start = page * ONLINE_PAGE_SIZE
    end = min(start + ONLINE_PAGE_SIZE, total)
    page_users = combined[start:end]
    max_page = max(0, (total - 1) // ONLINE_PAGE_SIZE) if total else 0

    sep = "▬" * 35
    lines = [
        sep,
        "       🌐 Online Users",
        f"       Total: {total} connected",
        sep,
    ]
    if total == 0:
        lines.append("  No users connected right now.")
        lines.append(sep)
    else:
        for idx, (user, kind) in enumerate(page_users, start + 1):
            icon = "📡" if kind == "VLESS" else "🔑"
            lines.append(f" {idx}.) {icon} {user['name']}")
            lines.append(f"     IP  : {user['ip']}")
            lines.append(f"     Type: {kind}")
            lines.append(f"     Last: {user['last_seen']}")
            lines.append(sep)
    lines.append(f"  Page {page + 1}/{max_page + 1}")

    return "\n".join(lines)


# Run detection once at module load (after all function defs)
_, _, EXT = detect_vless_inbounds()
SSH_DATA = detect_ssh_info()


def main_menu() -> list[list[InlineKeyboardButton]]:
    return [
        [
            InlineKeyboardButton("📡 VLESS", callback_data="menu_vless"),
            InlineKeyboardButton("🔑 SSH", callback_data="menu_ssh"),
        ],
        [
            InlineKeyboardButton("🌐 Online", callback_data="online_page_0"),
            InlineKeyboardButton("📊 Status", callback_data="status"),
            InlineKeyboardButton("❓ Help", callback_data="help"),
        ],
    ]


def vless_menu() -> list[list[InlineKeyboardButton]]:
    return [
        [
            InlineKeyboardButton("📋 List", callback_data="vless_list"),
            InlineKeyboardButton("➕ Create", callback_data="vless_create"),
        ],
        [
            InlineKeyboardButton("🗑 Delete", callback_data="vless_delete"),
            InlineKeyboardButton("⏳ Extend", callback_data="vless_extend"),
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="menu")],
    ]


def ssh_menu() -> list[list[InlineKeyboardButton]]:
    return [
        [
            InlineKeyboardButton("📋 List", callback_data="ssh_list"),
            InlineKeyboardButton("➕ Create", callback_data="ssh_create"),
        ],
        [
            InlineKeyboardButton("🗑 Delete", callback_data="ssh_delete"),
            InlineKeyboardButton("⏳ Extend", callback_data="ssh_extend"),
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="menu")],
    ]


def dashboard_text() -> str:
    sep = "▬" * 36
    return (
        f"{sep}\n"
        f"      🚀 Premium VPN Manager\n"
        f"{sep}\n"
        f"  🌐 Domain : {DOMAIN}\n"
        f"  📡 IP     : {IP}\n"
        f"  🟢 XRAY   : {xray_status()}\n"
        f"{sep}"
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update.effective_user.id):
        return
    await update.message.reply_text(
        dashboard_text(), reply_markup=InlineKeyboardMarkup(main_menu())
    )


async def button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_authorized(update.effective_user.id):
        return
    data = query.data

    if data == "menu":
        await query.edit_message_text(
            dashboard_text(), reply_markup=InlineKeyboardMarkup(main_menu())
        )
    elif data == "menu_vless":
        await query.edit_message_text(
            "📡  VLESS Configuration", reply_markup=InlineKeyboardMarkup(vless_menu())
        )
    elif data == "menu_ssh":
        await query.edit_message_text(
            "🔑  SSH Configuration", reply_markup=InlineKeyboardMarkup(ssh_menu())
        )

    elif data == "vless_list":
        users = get_users()
        if not users:
            await query.edit_message_text(
                "📡 No VLESS users found.",
                reply_markup=InlineKeyboardMarkup(vless_menu()),
            )
            return
        sep = "─" * 30
        lines = [sep, "     📡  VLESS Users", sep]
        for index, user in enumerate(users, 1):
            remaining = status_label(user["expiry"])
            expiry = user["expiry"]
            icon = "✅" if remaining != "EXPIRED" else "❌"
            lines.append(f"  {index}. {icon} {user['name']}")
            lines.append(f"      Exp: {expiry} ({remaining})")
        lines.append(sep)
        lines.append("  💡 /info username for details")
        await query.edit_message_text(
            "\n".join(lines), reply_markup=InlineKeyboardMarkup(vless_menu())
        )

    elif data == "vless_create":
        context.user_data["create_type"] = "vless"
        context.user_data["state"] = "create_username"
        await query.edit_message_text(
            "➕ Enter VLESS username:"
        )

    elif data == "vless_delete":
        users = get_users()
        if not users:
            await query.edit_message_text(
                "📡 No VLESS users to delete.",
                reply_markup=InlineKeyboardMarkup(vless_menu()),
            )
            return
        keyboard = [
            [InlineKeyboardButton(f"🗑 {user['name']}", callback_data=f"delv_{user['name']}")]
            for user in users
        ]
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="menu_vless")])
        await query.edit_message_text(
            "🗑  Select user to delete:",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    elif data == "vless_extend":
        users = get_users()
        if not users:
            await query.edit_message_text(
                "📡 No VLESS users to extend.",
                reply_markup=InlineKeyboardMarkup(vless_menu()),
            )
            return
        keyboard = [
            [
                InlineKeyboardButton(
                    f"⏳ {user['name']} ({days_left(user['expiry'])}d)",
                    callback_data=f"extv_{user['name']}",
                )
            ]
            for user in users
        ]
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="menu_vless")])
        await query.edit_message_text(
            "⏳  Select user to extend:",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    elif data.startswith("delv_"):
        name = data[5:]
        await query.edit_message_text(
            f"🗑  Delete VLESS user {name}?",
            reply_markup=InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton("✅ Yes", callback_data=f"dodelv_{name}")],
                    [InlineKeyboardButton("❌ No", callback_data="menu_vless")],
                ]
            ),
        )
    elif data.startswith("dodelv_"):
        name = data[7:]
        _, message = delete_vless_user(name)
        await query.edit_message_text(
            f"🗑 {message}", reply_markup=InlineKeyboardMarkup(vless_menu())
        )
    elif data.startswith("extv_"):
        name = data[5:]
        await query.edit_message_text(
            f"⏳  Extend {name} by:",
            reply_markup=InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton("➕ 7 days", callback_data=f"extdov_{name}_7")],
                    [InlineKeyboardButton("➕ 14 days", callback_data=f"extdov_{name}_14")],
                    [InlineKeyboardButton("➕ 30 days", callback_data=f"extdov_{name}_30")],
                    [InlineKeyboardButton("🔙 Back", callback_data="menu_vless")],
                ]
            ),
        )
    elif data.startswith("extdov_"):
        parts = data.split("_")
        if len(parts) >= 3:
            name, days = parts[1], int(parts[2])
            _, message = extend_vless_user(name, days)
            await query.edit_message_text(
                f"⏳ {message}", reply_markup=InlineKeyboardMarkup(vless_menu())
            )

    elif data == "ssh_list":
        users = get_ssh_users()
        if not users:
            await query.edit_message_text(
                "🔑 No SSH users found.",
                reply_markup=InlineKeyboardMarkup(ssh_menu()),
            )
            return
        sep = "─" * 30
        lines = [sep, "     🔑  SSH Users", sep]
        for index, user in enumerate(users, 1):
            remaining = status_label(user["expiry"])
            expiry = user["expiry"]
            icon = "✅" if remaining != "EXPIRED" else "❌"
            lines.append(f"  {index}. {icon} {user['name']}")
            lines.append(f"      Exp: {expiry} ({remaining})")
        lines.append(sep)
        await query.edit_message_text(
            "\n".join(lines), reply_markup=InlineKeyboardMarkup(ssh_menu())
        )

    elif data == "ssh_create":
        context.user_data["create_type"] = "ssh"
        context.user_data["state"] = "create_username"
        await query.edit_message_text(
            "➕ Enter SSH username:"
        )

    elif data == "ssh_delete":
        users = get_ssh_users()
        if not users:
            await query.edit_message_text(
                "🔑 No SSH users to delete.",
                reply_markup=InlineKeyboardMarkup(ssh_menu()),
            )
            return
        keyboard = [
            [InlineKeyboardButton(f"🗑 {user['name']}", callback_data=f"dels_{user['name']}")]
            for user in users
        ]
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="menu_ssh")])
        await query.edit_message_text(
            "🗑  Select SSH user to delete:",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    elif data == "ssh_extend":
        users = get_ssh_users()
        if not users:
            await query.edit_message_text(
                "🔑 No SSH users to extend.",
                reply_markup=InlineKeyboardMarkup(ssh_menu()),
            )
            return
        keyboard = [
            [
                InlineKeyboardButton(
                    f"⏳ {user['name']} ({days_left(user['expiry'])}d)",
                    callback_data=f"exts_{user['name']}",
                )
            ]
            for user in users
        ]
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="menu_ssh")])
        await query.edit_message_text(
            "⏳  Select SSH user to extend:",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    elif data.startswith("dels_"):
        name = data[5:]
        await query.edit_message_text(
            f"🗑  Delete SSH user {name}?",
            reply_markup=InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton("✅ Yes", callback_data=f"dodels_{name}")],
                    [InlineKeyboardButton("❌ No", callback_data="menu_ssh")],
                ]
            ),
        )
    elif data.startswith("dodels_"):
        name = data[7:]
        _, message = delete_ssh_user(name)
        await query.edit_message_text(
            f"🗑 {message}", reply_markup=InlineKeyboardMarkup(ssh_menu())
        )
    elif data.startswith("exts_"):
        name = data[5:]
        await query.edit_message_text(
            f"⏳  Extend {name} by:",
            reply_markup=InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton("➕ 7 days", callback_data=f"extdos_{name}_7")],
                    [InlineKeyboardButton("➕ 14 days", callback_data=f"extdos_{name}_14")],
                    [InlineKeyboardButton("➕ 30 days", callback_data=f"extdos_{name}_30")],
                    [InlineKeyboardButton("🔙 Back", callback_data="menu_ssh")],
                ]
            ),
        )
    elif data.startswith("extdos_"):
        parts = data.split("_")
        if len(parts) >= 3:
            name, days = parts[1], int(parts[2])
            _, message = extend_ssh_user(name, days)
            await query.edit_message_text(
                f"⏳ {message}", reply_markup=InlineKeyboardMarkup(ssh_menu())
            )

    elif data == "status":
        vless_users = get_users()
        ssh_users = get_ssh_users()
        vless_active = sum(1 for user in vless_users if days_left(user["expiry"]) > 0)
        ssh_active = sum(1 for user in ssh_users if days_left(user["expiry"]) > 0)
        xr = xray_status()
        xr_icon = "✅" if xr == "active" else "❌"
        sep = "▬" * 36
        message = (
            f"{sep}\n"
            f"        📊  System Status\n"
            f"{sep}\n"
            f"  🌐 Domain : {DOMAIN}\n"
            f"  📡 IP     : {IP}\n"
            f"  {xr_icon}  XRAY   : {xr}\n"
            f"{sep}\n"
            f"  📡 VLESS : {len(vless_users)} ({vless_active} active)\n"
            f"  🔑 SSH   : {len(ssh_users)} ({ssh_active} active)\n"
            f"{sep}"
        )
        await query.edit_message_text(
            message, reply_markup=InlineKeyboardMarkup(main_menu())
        )

    elif data == "help":
        sep = "─" * 30
        message = (
            f"{sep}\n"
            f"      ❓  Help & Commands\n"
            f"{sep}\n"
            f"  📡  VLESS\n"
            f"  Create & manage VLESS VPN\n"
            f"  accounts with TLS/nonTLS\n"
            f"\n"
            f"  🔑  SSH\n"
            f"  Create & manage SSH VPN\n"
            f"  accounts with port info\n"
            f"\n"
            f"  🌐  Online\n"
            f"  View currently connected users\n"
            f"\n"
            f"{sep}\n"
            f"  Commands:\n"
            f"  /start - Main menu\n"
            f"  /info username - User details\n"
            f"{sep}"
        )
        await query.edit_message_text(
            message, reply_markup=InlineKeyboardMarkup(main_menu())
        )

    elif data.startswith("online_page_"):
        page = int(data.split("_")[-1])
        online_data = get_online_users()
        text = format_online_page(online_data, page)
        total = len(online_data["vless"]) + len(online_data["ssh"])
        max_page = max(0, (total - 1) // ONLINE_PAGE_SIZE)
        buttons = []
        if page > 0:
            buttons.append(InlineKeyboardButton("Prev", callback_data=f"online_page_{page - 1}"))
        if page < max_page:
            buttons.append(InlineKeyboardButton("Next", callback_data=f"online_page_{page + 1}"))
        nav = [buttons] if buttons else []
        nav.append([
            InlineKeyboardButton("Refresh", callback_data=f"online_page_{page}"),
            InlineKeyboardButton("Back", callback_data="menu"),
        ])
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(nav))

    elif data == "create_auto_uuid":
        await finalize_create(query, context, None)
    elif data == "create_custom_uuid":
        context.user_data["state"] = "create_custom_uuid"
        await query.edit_message_text("Enter custom UUID:")


async def finalize_create(query, context: ContextTypes.DEFAULT_TYPE, custom_uuid: str | None) -> None:
    try:
        name = context.user_data.get("create_name")
        days = context.user_data.get("create_days")
        if not name or not days:
            await query.edit_message_text("❌ Session expired.")
            context.user_data.clear()
            return

        ok, message = add_vless_user(name, days, custom_uuid or new_uuid())
        await query.edit_message_text(message)
        if ok:
            user = get_user(name)
            if user:
                await query.message.reply_text(format_vless_info(user), parse_mode="Markdown")
        context.user_data.clear()
    except Exception as error:
        logger.error("finalize_create error", exc_info=True)
        try:
            await query.edit_message_text(f"Error: {error}")
        except Exception:
            pass
        context.user_data.clear()


async def finalize_create_msg(message_obj, context: ContextTypes.DEFAULT_TYPE, custom_uuid: str | None) -> None:
    try:
        name = context.user_data.get("create_name")
        days = context.user_data.get("create_days")
        if not name or not days:
            await message_obj.reply_text("❌ Session expired.")
            context.user_data.clear()
            return

        ok, message = add_vless_user(name, days, custom_uuid or new_uuid())
        await message_obj.reply_text(message)
        if ok:
            user = get_user(name)
            if user:
                await message_obj.reply_text(format_vless_info(user), parse_mode="Markdown")
        context.user_data.clear()
    except Exception as error:
        logger.error("finalize_create_msg error", exc_info=True)
        await message_obj.reply_text(f"Error creating user: {error}")
        context.user_data.clear()


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        if not is_authorized(update.effective_user.id):
            return
        state = context.user_data.get("state")
        if not state:
            return
        text = update.message.text.strip()

        if state == "create_username":
            create_type = context.user_data.get("create_type", "vless")
            if create_type == "vless" and any(user["name"] == text for user in get_users()):
                await update.message.reply_text(f'❌ User "{text}" already exists!')
                return
            if create_type == "ssh" and get_ssh_user(text):
                await update.message.reply_text(f'❌ SSH user "{text}" already exists!')
                return
            context.user_data["create_name"] = text
            context.user_data["state"] = "create_days"
            await update.message.reply_text("📅  Enter days (1-365):")

        elif state == "create_days":
            try:
                days = int(text)
            except Exception:
                await update.message.reply_text("❌ Must be a number. Try again:")
                return
            if days < 1 or days > 365:
                await update.message.reply_text("❌ Days must be 1-365. Try again:")
                return

            context.user_data["create_days"] = days
            create_type = context.user_data.get("create_type", "vless")
            if create_type == "ssh":
                context.user_data["state"] = "create_ssh_pass"
                await update.message.reply_text("🔑  Enter SSH password:")
            else:
                context.user_data["state"] = "create_uuid_choice"
                keyboard = [
                    [InlineKeyboardButton("🎲 Auto Generate", callback_data="create_auto_uuid")],
                    [InlineKeyboardButton("✏️ Custom UUID", callback_data="create_custom_uuid")],
                ]
                sep = "─" * 25
                await update.message.reply_text(
                    f"{sep}\n"
                    f"  ➕ Create VLESS User\n"
                    f"{sep}\n"
                    f"  👤 Username: {context.user_data['create_name']}\n"
                    f"  📅 Days: {days}\n"
                    f"{sep}\n"
                    f"  Select UUID option:",
                    reply_markup=InlineKeyboardMarkup(keyboard),
                )

        elif state == "create_ssh_pass":
            name = context.user_data.get("create_name")
            days = context.user_data.get("create_days")
            if not name or not days:
                await update.message.reply_text("❌ Session expired.")
                context.user_data.clear()
                return
            ok, message = add_ssh_user(name, text, days)
            await update.message.reply_text(message)
            if ok:
                user = get_ssh_user(name)
                if user:
                    await update.message.reply_text(
                        format_ssh_info(user, text), parse_mode="Markdown"
                    )
            context.user_data.clear()

        elif state == "create_custom_uuid":
            if not UUID_PATTERN.match(text.lower()):
                await update.message.reply_text("❌ Invalid UUID format!")
                return
            await finalize_create_msg(update.message, context, text)

    except Exception as error:
        logger.error("handle_text error", exc_info=True)
        await update.message.reply_text(f"Error: {error}")


async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Usage: /info username")
        return

    name = context.args[0]
    user = get_user(name)
    if user:
        await update.message.reply_text(format_vless_info(user), parse_mode="Markdown")
        return

    ssh_user = get_ssh_user(name)
    if ssh_user:
        await update.message.reply_text(format_ssh_info(ssh_user), parse_mode="Markdown")
        return

    await update.message.reply_text(f"❌ User {name} not found")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Update caused error %s", context.error, exc_info=True)


def main() -> None:
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("info", cmd_info))
    app.add_handler(CallbackQueryHandler(button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)
    logger.info("Bot starting...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
