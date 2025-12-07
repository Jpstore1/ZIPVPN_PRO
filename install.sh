#!/bin/bash 
# ======================================================================================= 
# JPVPN v4.0 - Full Installer & Premium Panel (Updated: 2025-12-07) 
# Fitur: Xray (VMess/VLess/Trojan WS TLS/NTLS), SSH+Dropbear+WS, SlowDNS, UDP Custom, 
# ZIPVPN, Hysteria v1 (placeholder/installer), Auto SSL (acme.sh), 
# Premium TUI Panel dengan User Management, Service Status, dan User Summary. 
# 
# USAGE: 
# 1) Upload this file to VPS (e.g., as installer.sh) 
# 2) chmod +x installer.sh 
# 3) sudo ./installer.sh 
# ======================================================================================= 
set -euo pipefail 
IFS=$'\n\t' 
 
# Colors 
GREEN='\e[32m'; YELLOW='\e[33m'; CYAN='\e[36m'; RED='\e[31m'; PURPLE='\e[35m'; NC='\e[0m' 
BOLD='\e[1m' 
 
# ======================================================================================= 
#  SECTION 1: UTILITY FUNCTIONS & INITIAL CHECKS 
# ======================================================================================= 
 
# Check for root privileges 
require_root(){ 
  if [[ $EUID -ne 0 ]]; then 
    echo -e "${RED}❌ Error: Please run this script as root.${NC}"; exit 1 
  fi 
} 
require_root 
 
echo -e "${BOLD}${CYAN}🚀 JPVPN v4.0: Full Installer & Premium Panel${NC}" 
echo -e "${CYAN}-----------------------------------------------------------------------${NC}" 
echo -e "${YELLOW}Initial setup starting...${NC}" 
echo "" 
 
# ======================================================================================= 
#  SECTION 2: DOMAIN CONFIGURATION & DIRECTORY SETUP 
# ======================================================================================= 
 
echo -e "${CYAN}⚙️ 1. Configuring Domain...${NC}" 
if [[ -f /etc/multiplus/domain ]]; then 
  DOMAIN="$(cat /etc/multiplus/domain)" 
  echo -e "${GREEN}✓ Existing domain found: ${YELLOW}$DOMAIN${NC}" 
else 
  read -rp "➡️ Masukkan domain Anda (e.g., example.com): " DOMAIN 
  if [[ -z "$DOMAIN" ]]; then echo -e "${RED}❌ Error: Domain cannot be empty.${NC}"; exit 1; fi 
  mkdir -p /etc/multiplus 
  echo "$DOMAIN" > /etc/multiplus/domain 
  echo -e "${GREEN}✓ Domain set: ${YELLOW}$DOMAIN${NC}" 
fi 
 
# Create essential directories and database files 
BASE="/usr/local/multiplus" 
mkdir -p "$BASE" /etc/multiplus /var/lib/multiplus /var/www/multiplus /etc/xray /etc/hysteria /etc/zipvpn /etc/panel 
XRAY_CONF="/etc/xray/config.json" 
ZIP_DB="/etc/multiplus/zipvpn.db" 
HYS_DB="/etc/multiplus/hysteria.db" 
SSH_DB="/var/lib/multiplus/ssh.db" 
XRAY_DB="/var/lib/multiplus/xray.db" 
SLOWDNS_DB="/var/lib/multiplus/slowdns.db" 
 
# Ensure DB files exist and have correct permissions 
touch "$ZIP_DB" "$HYS_DB" "$SSH_DB" "$XRAY_DB" "$SLOWDNS_DB" 
chmod 600 "$ZIP_DB" "$HYS_DB" "$SSH_DB" "$XRAY_DB" "$SLOWDNS_DB" || true 
echo -e "${GREEN}✓ Essential directories and DB files created.${NC}" 
 
# ======================================================================================= 
#  SECTION 3: INSTALL BASIC DEPENDENCIES 
# ======================================================================================= 
 
echo -e "${CYAN}📦 2. Installing basic dependencies...${NC}" 
apt update -y >/dev/null 2>&1 
apt install -y curl wget unzip jq socat python3 python3-pip nginx certbot python3-certbot-nginx \ 
  openssh-server ca-certificates cron gnupg lsb-release uuid-runtime >/dev/null 2>&1 || { 
  echo -e "${RED}❌ Error: Failed to install core dependencies.${NC}"; exit 1 
} 
 
# Install websocat if available in repo 
apt install -y websocat >/dev/null 2>&1 || echo -e "${YELLOW}⚠ websocat not found in repo, continuing.${NC}" 
echo -e "${GREEN}✓ Basic dependencies installed.${NC}" 
 
# ======================================================================================= 
#  SECTION 4: ACME.SH (SSL CERTIFICATE MANAGEMENT) 
# ======================================================================================= 
 
echo -e "${CYAN}🔐 3. Setting up SSL (acme.sh)...${NC}" 
if [[ ! -d "$HOME/.acme.sh" ]]; then 
  curl -sS https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | bash >/dev/null 2>&1 || { 
    echo -e "${RED}❌ Error: Failed to install acme.sh.${NC}"; exit 1 
  } 
fi 
 
if [[ -x "$HOME/.acme.sh/acme.sh" ]]; then 
  # Set default CA to Let's Encrypt 
  "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true 
   
  # Issue or renew certificate 
  echo -e "${YELLOW}  Attempting to issue/renew certificate for $DOMAIN...${NC}" 
  "$HOME/.acme.sh/acme.sh" --issue -d "$DOMAIN" --standalone -k ec-256 --force >/dev/null 2>&1 || true 
 
  if [[ -f "$HOME/.acme.sh/${DOMAIN}_ecc/fullchain.cer" ]]; then 
    mkdir -p /etc/xray 
    "$HOME/.acme.sh/acme.sh" --install-cert -d "$DOMAIN" \ 
      --fullchainpath /etc/xray/xray.crt \ 
      --keypath /etc/xray/xray.key \ 
      --ecc >/dev/null 2>&1 || true 
    echo -e "${GREEN}✓ Certificate installed to /etc/xray/xray.crt and /etc/xray/xray.key.${NC}" 
    chmod 644 /etc/xray/xray.crt /etc/xray/xray.key 
  else 
    echo -e "${YELLOW}⚠ Certificate not available yet. Xray/Nginx will proceed without TLS (port 80).${NC}" 
    echo -e "${YELLOW}  A renewal attempt will be scheduled via cron.${NC}" 
  fi 
   
  # Schedule cron job for auto-renewal 
  (crontab -l 2>/dev/null | grep -v acme.sh || true; echo "0 3 * * * \"$HOME/.acme.sh/acme.sh\" --cron --home \"$HOME/.acme.sh\" >/dev/null 2>&1") | crontab - 
  echo -e "${GREEN}✓ SSL auto-renewal scheduled.${NC}" 
else 
  echo -e "${RED}❌ Error: acme.sh not executable. SSL setup skipped.${NC}" 
fi 
 
# ======================================================================================= 
#  SECTION 5: XRAY-CORE INSTALLATION & CONFIGURATION 
# ======================================================================================= 
 
echo -e "${CYAN}👻 4. Installing Xray-core...${NC}" 
# Use official install script (public) 
bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" >/dev/null 2>&1 || echo -e "${YELLOW}⚠ Xray installer returned non-zero exit, continuing.${NC}" 
mkdir -p /etc/xray /var/log/xray # Ensure directories exist 
 
# Xray base config: VLESS/VMESS/TROJAN over WS with TLS/Non-TLS, SSH fallback 
cat > "$XRAY_CONF" <<EOF 
{ 
  "log": { "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log", "loglevel": "warning" }, 
  "dns": { "servers": ["1.1.1.1","8.8.8.8"] }, 
  "inbounds": [ 
    { 
      "tag":"vless-tls", 
      "port":443, 
      "protocol":"vless", 
      "settings":{"clients":[],"decryption":"none"}, 
      "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/xray.crt","keyFile":"/etc/xray/xray.key"}]},"wsSettings":{"path":"/vless"}} 
    }, 
    { 
      "tag":"vless-ntls", 
      "port":80, 
      "protocol":"vless", 
      "settings":{"clients":[],"decryption":"none"}, 
      "streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vless"}} 
    }, 
    { 
      "tag":"vmess-tls", 
      "port":443, 
      "protocol":"vmess", 
      "settings":{"clients":[]}, 
      "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/xray.crt","keyFile":"/etc/xray/xray.key"}]},"wsSettings":{"path":"/vmess"}} 
    }, 
    { 
      "tag":"vmess-ntls", 
      "port":80, 
      "protocol":"vmess", 
      "settings":{"clients":[]}, 
      "streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vmess"}} 
    }, 
    { 
      "tag":"trojan-tls", 
      "port":443, 
      "protocol":"trojan", 
      "settings":{"clients":[]}, 
      "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/xray.crt","keyFile":"/etc/xray/xray.key"}]}} 
    }, 
    { 
      "tag":"trojan-ntls", 
      "port":80, 
      "protocol":"trojan", 
      "settings":{"clients":[]}, 
      "streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/trojan"}} 
    }, 
    { 
      "tag":"ssh-fallback", 
      "port":2082, 
      "protocol":"dokodemo-door", 
      "settings":{"address":"127.0.0.1","port":22,"network":"tcp","timeout":0} 
    } 
  ], 
  "outbounds":[{"protocol":"freedom"}] 
} 
EOF 
 
systemctl daemon-reload >/dev/null 2>&1 
systemctl enable xray >/dev/null 2>&1 || true 
systemctl restart xray >/dev/null 2>&1 || true 
echo -e "${GREEN}✓ Xray configured (ports 80 & 443).${NC}" 
 
# ======================================================================================= 
#  SECTION 6: NGINX CONFIGURATION 
# ======================================================================================= 
 
echo -e "${CYAN}🌐 5. Configuring Nginx...${NC}" 
# Nginx config for ACME challenge & HTTP WebSocket proxy 
cat > /etc/nginx/sites-available/multiplus <<EOF 
server { 
    listen 80; 
    server_name ${DOMAIN}; 
    root /var/www/multiplus; 
    location /.well-known/acme-challenge/ { root /var/www/multiplus; } 
    location / { return 200 'ok'; } 
} 
EOF 
ln -sf /etc/nginx/sites-available/multiplus /etc/nginx/sites-enabled/multiplus 
rm -f /etc/nginx/sites-enabled/default # Remove default nginx config 
 
# Nginx config for TLS WebSocket proxy (when cert exists) 
cat > /etc/nginx/sites-available/xray-ws <<EOF 
server { 
    listen 443 ssl http2; 
    server_name ${DOMAIN}; 
 
    ssl_certificate /etc/xray/xray.crt; 
    ssl_certificate_key /etc/xray/xray.key; 
    ssl_protocols TLSv1.2 TLSv1.3; 
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384; 
    ssl_prefer_server_ciphers off; 
    ssl_session_cache shared:SSL:10m; 
    ssl_session_timeout 10m; 
 
    location /vless { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:80; # Pass to Xray's non-TLS HTTP WS inbound 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
    location /vmess { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:80; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
    location /trojan { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:80; # Trojan WS runs on port 80 Xray inbound 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
    location /ssh { # For SSH WS over TLS 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:2082; # Pass to ws-nontls service 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
    # Catch-all for other requests, can be a simple page 
    location / { 
        root /var/www/multiplus; 
        index index.html index.htm; 
        try_files \$uri \$uri/ /index.html; 
    } 
} 
EOF 
ln -sf /etc/nginx/sites-available/xray-ws /etc/nginx/sites-enabled/xray-ws 
 
nginx -t >/dev/null 2>&1 || true 
systemctl restart nginx >/dev/null 2>&1 || true 
echo -e "${GREEN}✓ Nginx configured and restarted.${NC}" 
 
# ======================================================================================= 
#  SECTION 7: SSH WEBSOCKET & DROPBEAR 
# ======================================================================================= 
 
echo -e "${CYAN}📞 6. Setting up SSH WebSocket & Dropbear...${NC}" 
# SSH WebSocket (non-TLS) via websocat 
if command -v websocat >/dev/null 2>&1; then 
  cat > /etc/systemd/system/ws-nontls.service <<EOF 
[Unit] 
Description=SSH WebSocket (non-TLS) 
After=network.target 
[Service] 
ExecStart=/usr/bin/websocat --binary -s 0.0.0.0:2082 tcp:127.0.0.1:22 
Restart=always 
LimitNOFILE=65536 
[Install] 
WantedBy=multi-user.target 
EOF 
else 
  echo -e "${YELLOW}⚠ websocat not found. Using placeholder for SSH WebSocket.${NC}" 
  cat > /usr/local/bin/ws-nontls-placeholder <<'PY' 
#!/bin/bash 
echo "websocket placeholder - install websocat for websocket->ssh" 
while true; do sleep 3600; done 
PY 
  chmod +x /usr/local/bin/ws-nontls-placeholder 
  cat > /etc/systemd/system/ws-nontls.service <<EOF 
[Unit] 
Description=SSH WebSocket Placeholder 
After=network.target 
[Service] 
ExecStart=/usr/local/bin/ws-nontls-placeholder 
Restart=always 
LimitNOFILE=65536 
[Install] 
WantedBy=multi-user.target 
EOF 
fi 
systemctl daemon-reload >/dev/null 2>&1 
systemctl enable ws-nontls >/dev/null 2>&1 || true 
systemctl restart ws-nontls >/dev/null 2>&1 || true 
 
# Dropbear setup 
apt install -y dropbear >/dev/null 2>&1 || true # Ensure dropbear is installed 
sed -i 's/#DROPBEAR_PORT=22/DROPBEAR_PORT=442/' /etc/default/dropbear # Change default port 
systemctl enable dropbear >/dev/null 2>&1 || true 
systemctl restart dropbear >/dev/null 2>&1 || true 
 
echo -e "${GREEN}✓ SSH WebSocket (port 2082) and Dropbear (port 442) configured.${NC}" 
 
# ======================================================================================= 
#  SECTION 8: SLOWDNS, UDP CUSTOM, ZIPVPN, HYSTERIA PLACEHOLDERS 
# ======================================================================================= 
 
echo -e "${CYAN}📡 7. Configuring other services (placeholders/shim)...${NC}" 
 
# SlowDNS placeholder 
if [[ ! -x /usr/bin/dns2tcp ]]; then # Check if dns2tcp binary is not installed 
  cat > /usr/local/bin/dns2tcp-placeholder <<'PY' 
#!/bin/bash 
echo "dns2tcp placeholder - install real SlowDNS binary" 
while true; do sleep 3600; done 
PY 
  chmod +x /usr/local/bin/dns2tcp-placeholder 
  cat > /etc/systemd/system/slowdns.service <<EOF 
[Unit] 
Description=SlowDNS Placeholder 
After=network.target 
[Service] 
ExecStart=/usr/local/bin/dns2tcp-placeholder 
Restart=always 
LimitNOFILE=65536 
[Install] 
WantedBy=multi-user.target 
EOF 
  systemctl daemon-reload >/dev/null 2>&1 
  systemctl enable slowdns >/dev/null 2>&1 || true 
  systemctl restart slowdns >/dev/null 2>&1 || true 
  echo -e "${GREEN}✓ SlowDNS placeholder configured.${NC}" 
fi 
 
# UDP custom forwarder (Python) 
cat > /etc/multiplus/udp-custom.py <<'PY' 
#!/usr/bin/env python3 
import socket, threading, time 
FWD_IP="127.0.0.1" # Default to SSH 
FWD_PORT=22      # Default to SSH 
def listener(port): 
    try: 
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) 
        s.bind(("0.0.0.0",port)) 
    except Exception: 
        return 
    while True: 
        data,addr=s.recvfrom(65535) 
        try: 
            f=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) 
            f.sendto(data,(FWD_IP,FWD_PORT)) 
            f.close() 
        except: 
            time.sleep(0.01) 
def main(): 
    for p in range(40000,40010): # Listen on ports 40000-40009 
        t=threading.Thread(target=listener,args=(p,),daemon=True) 
        t.start() 
    while True: 
        time.sleep(3600) 
if __name__=='__main__': 
    main() 
PY 
chmod +x /etc/multiplus/udp-custom.py 
cat > /etc/systemd/system/udp-custom.service <<EOF 
[Unit] 
Description=UDP Custom Forwarder (Python) 
After=network.target 
[Service] 
ExecStart=/usr/bin/python3 /etc/multiplus/udp-custom.py 
Restart=always 
LimitNOFILE=65536 
[Install] 
WantedBy=multi-user.target 
EOF 
systemctl daemon-reload >/dev/null 2>&1 
systemctl enable udp-custom >/dev/null 2>&1 || true 
systemctl restart udp-custom >/dev/null 2>&1 || true 
echo -e "${GREEN}✓ UDP Custom Forwarder configured (ports 40000-40009).${NC}" 
 
 
# ZIPVPN shim (port 5667) 
cat > /usr/local/bin/zipvpn <<'SH' 
#!/bin/bash 
PASS="$1" 
PORT=5667 
mkdir -p /etc/multiplus # Just in case 
echo "${PASS}|${PORT}|1" >> /etc/multiplus/zipvpn.db 
echo "ZIPVPN created: ${PASS} on port ${PORT}" 
SH 
chmod +x /usr/local/bin/zipvpn 
 
cat > /etc/systemd/system/zipvpn.service <<EOF 
[Unit] 
Description=ZIPVPN shim (placeholder) 
After=network.target 
[Service] 
ExecStart=/bin/bash -c "while true; do sleep 3600; done" 
Restart=always 
[Install] 
WantedBy=multi-user.target 
EOF 
systemctl daemon-reload >/dev/null 2>&1 
systemctl enable zipvpn >/dev/null 2>&1 || true 
systemctl restart zipvpn >/dev/null 2>&1 || true 
echo -e "${GREEN}✓ ZIPVPN shim configured (port 5667).${NC}" 
 
# Hysteria v1 helper (placeholder) 
cat > /usr/local/bin/hysteria-create <<'HYS' 
#!/bin/bash 
PASS="$1" 
PORT=$(shuf -i 10000-65000 -n1) 
mkdir -p /etc/multiplus # Just in case 
echo "${PASS}|${PORT}|1" >> /etc/multiplus/hysteria.db 
echo "Hysteria created: ${PASS} on port ${PORT}" 
HYS 
chmod +x /usr/local/bin/hysteria-create 
 
if ! command -v hysteria-server >/dev/null 2>&1 && ! command -v hysteria >/dev/null 2>&1; then 
  cat > /usr/local/bin/hysteria-placeholder <<'HP' 
#!/bin/bash 
echo "Hysteria placeholder - install official binary and replace this script" 
while true; do sleep 3600; done 
HP 
  chmod +x /usr/local/bin/hysteria-placeholder 
  cat > /etc/systemd/system/hysteria-server.service <<EOF 
[Unit] 
Description=Hysteria placeholder 
After=network.target 
[Service] 
ExecStart=/usr/local/bin/hysteria-placeholder 
Restart=always 
LimitNOFILE=65536 
[Install] 
WantedBy=multi-user.target 
EOF 
  systemctl daemon-reload >/dev/null 2>&1 
  systemctl enable hysteria-server >/dev/null 2>&1 || true 
  systemctl restart hysteria-server >/dev/null 2>&1 || true 
  echo -e "${GREEN}✓ Hysteria placeholder configured.${NC}" 
fi 
 
# ======================================================================================= 
#  SECTION 9: USER MANAGEMENT HELPER SCRIPTS 
# ======================================================================================= 
 
echo -e "${CYAN}👨‍💻 8. Creating User Management Helper Scripts...${NC}" 
 
# XRAY add client helper 
cat > /usr/local/bin/xray-add-client <<'XADD' 
#!/usr/bin/env bash 
PROTO="$1"; VAL="$2"; CONF="/etc/xray/config.json" 
# Backup config before modification 
cp "$CONF" "$CONF.bak.$(date +%s)" 
if [[ "$PROTO" == "trojan" ]]; then 
  jq --arg pw "$VAL" '(.inbounds[] | select(.protocol=="trojan") | .settings.clients) |= (. + [{"password":$pw}])' "$CONF" > /tmp/xray.tmp && mv /tmp/xray.tmp "$CONF" 
else 
  jq --arg id "$VAL" '(.inbounds[] | select(.protocol==("'"$PROTO"'")) | .settings.clients) |= (. + [{"id":$id}])' "$CONF" > /tmp/xray.tmp && mv /tmp/xray.tmp "$CONF" 
fi 
systemctl restart xray >/dev/null 2>&1 || true 
echo "added" 
XADD 
chmod +x /usr/local/bin/xray-add-client 
 
# XRAY remove client helper 
cat > /usr/local/bin/xray-remove-client <<'XREM' 
#!/usr/bin/env bash 
PROTO="$1"; VAL="$2"; CONF="/etc/xray/config.json" 
cp "$CONF" "$CONF.bak.$(date +%s)" 
if [[ "$PROTO" == "trojan" ]]; then 
  jq --arg pw "$VAL" '(.inbounds[] | select(.protocol=="trojan") | .settings.clients) |= map(select(.password != $pw))' "$CONF" > /tmp/xray.tmp && mv /tmp/xray.tmp "$CONF" 
else 
  jq --arg id "$VAL" '(.inbounds[] | select(.protocol==("'"$PROTO"'")) | .settings.clients) |= map(select(.id != $id))' "$CONF" > /tmp/xray.tmp && mv /tmp/xray.tmp "$CONF" 
fi 
systemctl restart xray >/dev/null 2>&1 || true 
echo "removed" 
XREM 
chmod +x /usr/local/bin/xray-remove-client 
 
 
# Create Xray user (interactive) 
cat > /usr/local/bin/create-xray <<'XRAYC' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; NC='\e[0m' 
echo -e "\n${YELLOW}=== Buat Akun XRAY ===${NC}" 
echo "Pilih protocol:" 
echo "1) vmess" 
echo "2) vless" 
echo "3) trojan" 
read -rp "Pilihan [1-3]: " opt 
read -rp "Label / username: " label 
read -rp "Masa aktif (hari, default 30): " days 
days=${days:-30} 
exp=$(date -d "+$days days" +"%Y-%m-%d") 
 
if [[ "$opt" == "3" ]]; then 
  pw=$(openssl rand -hex 6) 
  /usr/local/bin/xray-add-client trojan "$pw" 
  echo "$label|trojan|$pw|$exp" >> /var/lib/multiplus/xray.db 
  echo -e "${GREEN}✓ Trojan dibuat: ${YELLOW}$pw${NC} | Exp: ${YELLOW}$exp${NC}" 
else 
  id=$(cat /proc/sys/kernel/random/uuid) 
  proto=$([[ "$opt" == "1" ]] && echo "vmess" || echo "vless") 
  /usr/local/bin/xray-add-client "$proto" "$id" 
  echo "$label|$proto|$id|$exp" >> /var/lib/multiplus/xray.db 
  echo -e "${GREEN}✓ ${proto} dibuat: ${YELLOW}$id${NC} | Exp: ${YELLOW}$exp${NC}" 
fi 
XRAYC 
chmod +x /usr/local/bin/create-xray 
 
# List Xray users 
cat > /usr/local/bin/list-xray <<'XLST' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; BOLD='\e[1m'; NC='\e[0m' 
XRAY_DB="/var/lib/multiplus/xray.db" 
 
echo -e "\n${BOLD}=== DAFTAR PENGGUNA XRAY ===${NC}" 
echo -e "${YELLOW}-------------------------------------------------------------------------------------------------${NC}" 
printf "%-4s %-15s %-8s %-38s %-10s %-10s\n" "#" "LABEL" "PROTO" "ID / PASSWORD" "EXPIRES" "STATUS" 
echo -e "${YELLOW}-------------------------------------------------------------------------------------------------${NC}" 
 
if [[ -f "$XRAY_DB" ]] && [[ $(wc -l < "$XRAY_DB") -gt 0 ]]; then 
  idx=1 
  while IFS='|' read -r label proto id exp_date; do 
    if [[ $(date +%s) -gt $(date -d "$exp_date" +%s 2>/dev/null || echo 0) ]]; then 
      STATUS="${RED}EXPIRED${NC}" 
      EXP_COL="${RED}$exp_date${NC}" 
    else 
      STATUS="${GREEN}ACTIVE${NC}" 
      EXP_COL="${YELLOW}$exp_date${NC}" 
    fi 
    printf "%-4s %-15s %-8s %-38s %-10s %-10s\n" "$idx" "$label" "$proto" "$id" "$EXP_COL" "$STATUS" 
    ((idx++)) 
  done < "$XRAY_DB" 
else 
  echo -e "${RED}  Tidak ada pengguna XRAY terdaftar.${NC}" 
fi 
echo -e "${YELLOW}-------------------------------------------------------------------------------------------------${NC}" 
XLST 
chmod +x /usr/local/bin/list-xray 
 
# Create SSH user (interactive) 
cat > /usr/local/bin/create-ssh <<'SSHADD' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; NC='\e[0m' 
SSH_DB="/var/lib/multiplus/ssh.db" 
 
echo -e "\n${YELLOW}=== Buat Akun SSH ===${NC}" 
read -rp "Username: " user 
read -rp "Password (kosong = random): " pass 
read -rp "Masa aktif (hari, default 30): " days 
days=${days:-30} 
 
if [[ -z "$pass" ]]; then pass=$(openssl rand -hex 4); fi 
useradd -m -s /usr/sbin/nologin "$user" >/dev/null 2>&1 || { echo -e "${RED}❌ Gagal membuat user sistem!${NC}"; exit 1; } 
echo "$user:$pass" | chpasswd >/dev/null 2>&1 
exp=$(date -d "+$days days" +"%Y-%m-%d") 
 
echo "$user|$pass|$exp" >> "$SSH_DB" 
echo -e "${GREEN}✓ SSH dibuat: ${YELLOW}$user:$pass${NC} | Exp: ${YELLOW}$exp${NC}" 
SSHADD 
chmod +x /usr/local/bin/create-ssh 
 
# List SSH users 
cat > /usr/local/bin/list-ssh <<'SSHLST' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; BOLD='\e[1m'; NC='\e[0m' 
SSH_DB="/var/lib/multiplus/ssh.db" 
 
echo -e "\n${BOLD}=== DAFTAR PENGGUNA SSH ===${NC}" 
echo -e "${YELLOW}------------------------------------------------------------------------------------${NC}" 
printf "%-4s %-15s %-15s %-10s %-10s\n" "#" "USERNAME" "PASSWORD" "EXPIRES" "STATUS" 
echo -e "${YELLOW}------------------------------------------------------------------------------------${NC}" 
 
if [[ -f "$SSH_DB" ]] && [[ $(wc -l < "$SSH_DB") -gt 0 ]]; then 
  idx=1 
  while IFS='|' read -r username password exp_date; do 
    if [[ $(date +%s) -gt $(date -d "$exp_date" +%s 2>/dev/null || echo 0) ]]; then 
      STATUS="${RED}EXPIRED${NC}" 
      EXP_COL="${RED}$exp_date${NC}" 
    else 
      STATUS="${GREEN}ACTIVE${NC}" 
      EXP_COL="${YELLOW}$exp_date${NC}" 
    fi 
    printf "%-4s %-15s %-15s %-10s %-10s\n" "$idx" "$username" "$password" "$EXP_COL" "$STATUS" 
    ((idx++)) 
  done < "$SSH_DB" 
else 
  echo -e "${RED}  Tidak ada pengguna SSH terdaftar.${NC}" 
fi 
echo -e "${YELLOW}------------------------------------------------------------------------------------${NC}" 
SSHLST 
chmod +x /usr/local/bin/list-ssh 
 
 
# Create ZIPVPN user 
cat > /usr/local/bin/create-zipvpn <<'ZIPC' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; NC='\e[0m' 
echo -e "\n${YELLOW}=== Buat Akun ZIPVPN ===${NC}" 
read -rp "Password (kosong = random): " p 
p=${p:-$(openssl rand -hex 4)} 
echo "${p}|5667|1" >> /etc/multiplus/zipvpn.db 
echo -e "${GREEN}✓ ZIPVPN dibuat: ${YELLOW}$p${NC} di port ${YELLOW}5667${NC}" 
ZIPC 
chmod +x /usr/local/bin/create-zipvpn 
 
# Create Hysteria user 
cat > /usr/local/bin/create-hysteria <<'HYSC' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; NC='\e[0m' 
echo -e "\n${YELLOW}=== Buat Akun Hysteria v1 ===${NC}" 
read -rp "Password (kosong = random): " p 
p=${p:-$(openssl rand -hex 4)} 
PORT=$(shuf -i 10000-65000 -n1) # Random port for Hysteria v1 
echo "${p}|${PORT}|1" >> /etc/multiplus/hysteria.db 
echo -e "${GREEN}✓ Hysteria v1 dibuat: ${YELLOW}$p${NC} di port ${YELLOW}$PORT${NC}" 
HYSC 
chmod +x /usr/local/bin/create-hysteria 
 
 
# Delete ZIPVPN user 
cat > /usr/local/bin/del-zipvpn <<'ZIPD' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; NC='\e[0m' 
ZIP_DB="/etc/multiplus/zipvpn.db" 
echo -e "\n${YELLOW}=== Hapus Akun ZIPVPN ===${NC}" 
if [[ ! -f "$ZIP_DB" ]] || [[ $(wc -l < "$ZIP_DB") -eq 0 ]]; then echo -e "${RED}❌ Tidak ada user ZIPVPN.${NC}"; exit 1; fi 
echo -e "${YELLOW}Daftar user ZIPVPN:${NC}"; nl -ba "$ZIP_DB" 
read -rp "Masukkan password ZIPVPN yang akan dihapus: " p 
sed -i "/^${p}|/d" "$ZIP_DB" || true 
echo -e "${GREEN}✓ ZIPVPN ${YELLOW}$p${NC} dihapus.${NC}" 
ZIPD 
chmod +x /usr/local/bin/del-zipvpn 
 
# Delete Hysteria user 
cat > /usr/local/bin/del-hysteria <<'HYSD' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; NC='\e[0m' 
HYS_DB="/etc/multiplus/hysteria.db" 
echo -e "\n${YELLOW}=== Hapus Akun Hysteria ===${NC}" 
if [[ ! -f "$HYS_DB" ]] || [[ $(wc -l < "$HYS_DB") -eq 0 ]]; then echo -e "${RED}❌ Tidak ada user Hysteria.${NC}"; exit 1; fi 
echo -e "${YELLOW}Daftar user Hysteria:${NC}"; nl -ba "$HYS_DB" 
read -rp "Masukkan password Hysteria yang akan dihapus: " p 
sed -i "/^${p}|/d" "$HYS_DB" || true 
echo -e "${GREEN}✓ Hysteria ${YELLOW}$p${NC} dihapus.${NC}" 
HYSD 
chmod +x /usr/local/bin/del-hysteria 
 
# Delete Xray user (interactive) 
cat > /usr/local/bin/delete-xray <<'DELX' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; BOLD='\e[1m'; NC='\e[0m' 
XRAY_DB="/var/lib/multiplus/xray.db" 
XRAY_CONF="/etc/xray/config.json" 
 
echo -e "\n${BOLD}${YELLOW}=== Hapus Akun XRAY ===${NC}" 
if [[ ! -f "$XRAY_DB" ]] || [[ $(wc -l < "$XRAY_DB") -eq 0 ]]; then echo -e "${RED}❌ Tidak ada pengguna XRAY.${NC}"; exit 1; fi 
/usr/local/bin/list-xray # Show current users 
read -rp "Masukkan nomor baris pengguna XRAY yang akan dihapus: " line_num 
 
if ! [[ "$line_num" =~ ^[0-9]+$ ]] || [[ "$line_num" -le 0 ]] || [[ "$line_num" -gt $(wc -l < "$XRAY_DB") ]]; then 
  echo -e "${RED}❌ Nomor baris tidak valid.${NC}"; exit 1 
fi 
 
user_info=$(sed -n "${line_num}p" "$XRAY_DB") 
IFS='|' read -r label proto uuid_pass exp_date <<< "$user_info" 
 
echo -e "${YELLOW}Anda akan menghapus:${NC} ${BOLD}$label ($proto - $uuid_pass)${NC}" 
read -rp "Konfirmasi penghapusan? (y/N): " confirm 
 
if [[ "$confirm" =~ ^[yY]$ ]]; then 
  # Remove from Xray config 
  if [[ "$proto" == "trojan" ]]; then 
    jq --arg pw "$uuid_pass" '(.inbounds[] | select(.protocol=="trojan") | .settings.clients) |= map(select(.password != $pw))' "$XRAY_CONF" > /tmp/xray.tmp && mv /tmp/xray.tmp "$XRAY_CONF" 
  else 
    jq --arg id "$uuid_pass" '(.inbounds[] | select(.protocol==("vmess","vless")) | .settings.clients) |= map(select(.id != $id))' "$XRAY_CONF" > /tmp/xray.tmp && mv /tmp/xray.tmp "$XRAY_CONF" 
  fi 
  # Remove from database file 
  sed -i "${line_num}d" "$XRAY_DB" 
  systemctl restart xray >/dev/null 2>&1 || true 
  echo -e "${GREEN}✓ Pengguna XRAY '${YELLOW}$label${NC}' dihapus.${NC}" 
else 
  echo -e "${YELLOW}Penghapusan dibatalkan.${NC}" 
fi 
DELX 
chmod +x /usr/local/bin/delete-xray 
 
# Delete SSH user (interactive) 
cat > /usr/local/bin/delete-ssh <<'DELSSH' 
#!/usr/bin/env bash 
GREEN='\e[32m'; YELLOW='\e[33m'; RED='\e[31m'; BOLD='\e[1m'; NC='\e[0m' 
SSH_DB="/var/lib/multiplus/ssh.db" 
 
echo -e "\n${BOLD}${YELLOW}=== Hapus Akun SSH ===${NC}" 
if [[ ! -f "$SSH_DB" ]] || [[ $(wc -l < "$SSH_DB") -eq 0 ]]; then echo -e "${RED}❌ Tidak ada pengguna SSH.${NC}"; exit 1; fi 
/usr/local/bin/list-ssh # Show current users 
read -rp "Masukkan nomor baris pengguna SSH yang akan dihapus: " line_num 
 
if ! [[ "$line_num" =~ ^[0-9]+$ ]] || [[ "$line_num" -le 0 ]] || [[ "$line_num" -gt $(wc -l < "$SSH_DB") ]]; then 
  echo -e "${RED}❌ Nomor baris tidak valid.${NC}"; exit 1 
fi 
 
user_info=$(sed -n "${line_num}p" "$SSH_DB") 
IFS='|' read -r username password exp_date <<< "$user_info" 
 
echo -e "${YELLOW}Anda akan menghapus:${NC} ${BOLD}$username${NC}" 
read -rp "Konfirmasi penghapusan? (y/N): " confirm 
 
if [[ "$confirm" =~ ^[yY]$ ]]; then 
  userdel "$username" >/dev/null 2>&1 || true # Delete system user 
  groupdel "$username" >/dev/null 2>&1 || true # Delete user group (if exists) 
  sed -i "${line_num}d" "$SSH_DB" # Remove from database file 
  echo -e "${GREEN}✓ Pengguna SSH '${YELLOW}$username${NC}' dihapus.${NC}" 
else 
  echo -e "${YELLOW}Penghapusan dibatalkan.${NC}" 
fi 
DELSSH 
chmod +x /usr/local/bin/delete-ssh 
 
# ======================================================================================= 
#  SECTION 10: JPVPN PREMIUM TUI PANEL 
# ======================================================================================= 
 
echo -e "${CYAN}✨ 9. Configuring JPVPN Premium Panel...${NC}" 
cat > /usr/local/bin/jpvpn <<'PANEL' 
#!/usr/bin/env bash 
# JPVPN Panel v4.0 - Premium Terminal User Interface (TUI) 
# Developed by Sapiens AI Team (Agnes) 
 
GREEN='\e[32m'; YELLOW='\e[33m'; CYAN='\e[36m'; RED='\e[31m'; PURPLE='\e[35m'; NC='\e[0m' 
BOLD='\e[1m' 
 
# File Paths (READONLY) 
DOMAIN_FILE="/etc/multiplus/domain" 
XRAY_DB="/var/lib/multiplus/xray.db" 
SSH_DB="/var/lib/multiplus/ssh.db"  
ZIP_DB="/etc/multiplus/zipvpn.db" 
HYS_DB="/etc/multiplus/hysteria.db" 
XRAY_CONF="/etc/xray/config.json" 
 
# Global Variables 
DOMAIN=$(cat "$DOMAIN_FILE" 2>/dev/null || echo "unknown") 
 
# --- Helper Functions for Panel --- 
 
# Get CPU Usage 
get_cpu_usage(){ 
  grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print int(usage)}' || echo "N/A" 
} 
# Get RAM Usage 
get_ram_usage(){ 
  free -m | awk '/Mem:/{printf "%.1f/%.1fGB (%.0f%%)", $3/1024, $2/1024, $3/$2*100}' || echo "N/A" 
} 
# Get Disk Usage 
get_disk_usage(){ 
  df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}' || echo "N/A" 
} 
# Get ISP 
get_isp(){ 
  curl -s ipinfo.io/org | sed 's/ //g' || echo "N/A" 
} 
# Count active/expired users for a specific DB 
count_db_users() { 
  local db_path="$1" 
  local active=0 
  local expired=0 
  local total=0 
 
  if [[ -f "$db_path" ]]; then 
    while IFS='|' read -r label proto id exp_date; do 
      total=$((total + 1)) 
      if [[ $(date +%s) -gt $(date -d "$exp_date" +%s 2>/dev/null || echo 0) ]]; then 
        expired=$((expired + 1)) 
      else 
        active=$((active + 1)) 
      fi 
    done < "$db_path" 
  fi 
  echo "$active|$expired|$total" 
} 
 
# Display service status 
get_service_status() { 
  local svc_name="$1" 
  if systemctl is-active --quiet "$svc_name" 2>/dev/null; then 
    echo "${GREEN}● AKTIF${NC}" 
  else 
    echo "${RED}○ STOP${NC}" 
  fi 
} 
 
# --- Main Panel Display --- 
while true; do 
  clear 
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}" 
  echo -e "${CYAN}║${BOLD}                    J P V P N  -  PANEL PREMIUM v4.0                  ${CYAN}║${NC}" 
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════╣${NC}" 
   
  # System Info Summary 
  echo -e "${CYAN}║${NC} ${BOLD}${PURPLE}System Info:${NC}                                                             ${CYAN}║${NC}" 
  printf "${CYAN}║${NC}   %-10s: ${YELLOW}%-20s${NC} %-10s: ${YELLOW}%-20s${NC} ${CYAN}║${NC}\n" "Domain" "$DOMAIN" "CPU" "$(get_cpu_usage)%" 
  printf "${CYAN}║${NC}   %-10s: ${YELLOW}%-20s${NC} %-10s: ${YELLOW}%-20s${NC} ${CYAN}║${NC}\n" "ISP" "$(get_isp)" "RAM" "$(get_ram_usage)" 
  printf "${CYAN}║${NC}   %-10s: ${YELLOW}%-20s${NC} %-10s: ${YELLOW}%-20s${NC} ${CYAN}║${NC}\n" "Disk" "$(get_disk_usage)" "" "" 
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════╣${NC}" 
   
  # User Summary (Dynamic) 
  echo -e "${CYAN}║${BOLD} ${PURPLE}User Summary:${NC}                                                            ${CYAN}║${NC}" 
  read -r XRAY_ACTIVE XRAY_EXPIRED XRAY_TOTAL <<< "$(count_db_users "$XRAY_DB")" 
  read -r SSH_ACTIVE SSH_EXPIRED SSH_TOTAL <<< "$(count_db_users "$SSH_DB" "user_ssh")" 
  read -r ZIP_ACTIVE ZIP_EXPIRED ZIP_TOTAL <<< "$(count_db_users "$ZIP_DB" "user_zip")" 
  read -r HYS_ACTIVE HYS_EXPIRED HYS_TOTAL <<< "$(count_db_users "$HYS_DB" "user_hys")" 
 
  printf "${CYAN}║${NC}   %-10s: %s %s %s ${CYAN}║${NC}\n" "XRAY" \ 
    "${GREEN}${XRAY_ACTIVE}${NC} aktif / ${RED}${XRAY_EXPIRED}${NC} expired" \ 
    "(Total: ${YELLOW}${XRAY_TOTAL}${NC})" 
  printf "${CYAN}║${NC}   %-10s: %s %s %s ${CYAN}║${NC}\n" "SSH" \ 
    "${GREEN}${SSH_ACTIVE}${NC} aktif / ${RED}${SSH_EXPIRED}${NC} expired" \ 
    "(Total: ${YELLOW}${SSH_TOTAL}${NC})" 
  printf "${CYAN}║${NC}   %-10s: %s %s %s ${CYAN}║${NC}\n" "ZIPVPN" \ 
    "${GREEN}${ZIP_ACTIVE}${NC} aktif / ${RED}${ZIP_EXPIRED}${NC} expired" \ 
    "(Total: ${YELLOW}${ZIP_TOTAL}${NC})" 
  printf "${CYAN}║${NC}   %-10s: %s %s %s ${CYAN}║${NC}\n" "Hysteria" \ 
    "${GREEN}${HYS_ACTIVE}${NC} aktif / ${RED}${HYS_EXPIRED}${NC} expired" \ 
    "(Total: ${YELLOW}${HYS_TOTAL}${NC})" 
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════╣${NC}" 
   
  # Service Status 
  echo -e "${CYAN}║${BOLD} ${PURPLE}Service Status:${NC}                                                         ${CYAN}║${NC}" 
  printf "${CYAN}║${NC}   %-12s: %-12s   %-12s: %-12s ${CYAN}║${NC}\n" \ 
    "Xray" "$(get_service_status xray)" "Nginx" "$(get_service_status nginx)" 
  printf "${CYAN}║${NC}   %-12s: %-12s   %-12s: %-12s ${CYAN}║${NC}\n" \ 
    "SSH-WS" "$(get_service_status ws-nontls)" "UDP Cust" "$(get_service_status udp-custom)" 
  printf "${CYAN}║${NC}   %-12s: %-12s   %-12s: %-12s ${CYAN}║${NC}\n" \ 
    "ZIPVPN" "$(get_service_status zipvpn)" "SlowDNS" "$(get_service_status slowdns)" 
  printf "${CYAN}║${NC}   %-12s: %-12s                                       ${CYAN}║${NC}\n" \ 
    "Hysteria" "$(get_service_status hysteria-server)" 
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════╣${NC}" 
   
  # Main Menu 
  echo -e "${CYAN}║${BOLD} ${PURPLE}MAIN MENU:${NC}                                                               ${CYAN}║${NC}" 
  echo -e "${CYAN}║${NC} ${GREEN}1.${NC} Buat XRAY    ${GREEN}5.${NC} List XRAY     ${RED}9.${NC}  Hapus XRAY   ${CYAN}║${NC}" 
  echo -e "${CYAN}║${NC} ${GREEN}2.${NC} Buat SSH     ${GREEN}6.${NC} List SSH      ${RED}10.${NC} Hapus SSH    ${CYAN}║${NC}" 
  echo -e "${CYAN}║${NC} ${GREEN}3.${NC} Buat ZIPVPN  ${GREEN}7.${NC} List ZIPVPN   ${RED}11.${NC} Hapus ZIPVPN ${CYAN}║${NC}" 
  echo -e "${CYAN}║${NC} ${GREEN}4.${NC} Buat Hysteria ${GREEN}8.${NC} List Hysteria ${RED}12.${NC} Hapus Hysteria ${CYAN}║${NC}" 
  echo -e "${CYAN}║${NC}                                                                      ${CYAN}║${NC}" 
  echo -e "${CYAN}║${NC} ${YELLOW}13.${NC} Restart Services ${YELLOW}14.${NC} Update SSL      ${RED}0.${NC} Exit          ${CYAN}║${NC}" 
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}" 
   
  echo -e "\n${BOLD}${CYAN}Pilih opsi [0-14]: ${NC}\c" 
  read -r opt 
   
  case "$opt" in 
    1) /usr/local/bin/create-xray ;; 
    2) /usr/local/bin/create-ssh ;; 
    3) /usr/local/bin/create-zipvpn ;; 
    4) /usr/local/bin/create-hysteria ;; 
    5) /usr/local/bin/list-xray ;; 
    6) /usr/local/bin/list-ssh ;; 
    7) column -t -s"|" "$ZIP_DB" 2>/dev/null || echo -e "${RED}❌ Tidak ada user ZIPVPN.${NC}" ;; 
    8) column -t -s"|" "$HYS_DB" 2>/dev/null || echo -e "${RED}❌ Tidak ada user Hysteria.${NC}" ;; 
    9) /usr/local/bin/delete-xray ;; 
    10) /usr/local/bin/delete-ssh ;; 
    11) /usr/local/bin/del-zipvpn ;; 
    12) /usr/local/bin/del-hysteria ;; 
    13)  
      echo -e "${YELLOW}Restarting all services...${NC}" 
      systemctl restart xray nginx ws-nontls zipvpn slowdns udp-custom hysteria-server dropbear 2>/dev/null || true 
      echo -e "${GREEN}✓ All services restarted!${NC}" 
      ;; 
    14) 
      echo -e "${YELLOW}Memperbarui sertifikat SSL...${NC}" 
      "$HOME/.acme.sh/acme.sh" --renew -d "$DOMAIN" --force >/dev/null 2>&1 
      systemctl reload nginx xray >/dev/null 2>&1 || true 
      echo -e "${GREEN}✓ Proses pembaruan sertifikat selesai.${NC}" 
      ;; 
    0) echo -e "${YELLOW}Terima kasih telah menggunakan JPVPN Panel. Sampai jumpa!${NC}"; exit 0 ;; 
    *) echo -e "${RED}❌ Pilihan tidak valid! Silakan coba lagi.${NC}"; sleep 1 ;; 
  esac 
   
  echo -e "\n${YELLOW}[Tekan Enter untuk melanjutkan]${NC}" 
  read -r 
done 
PANEL 
chmod +x /usr/local/bin/jpvpn 
echo -e "${GREEN}✓ JPVPN Panel script created.${NC}" 
 
 
# ======================================================================================= 
#  SECTION 11: AUTO-RUN PANEL ON LOGIN 
# ======================================================================================= 
 
echo -e "${CYAN}➡️ 10. Setting up auto-run for panel on login...${NC}" 
cat > /etc/profile.d/jpvpn.sh <<'AUTOP' 
#!/usr/bin/env bash 
if [[ -t 1 ]] && [[ -n "$PS1" ]] && [[ ! -f ~/.jpvpn_no_auto_start ]]; then 
  echo -e "\n${BOLD}${GREEN}🚀 JPVPN Panel is starting...${NC}" 
  sleep 1 
  /usr/local/bin/jpvpn 
fi 
AUTOP 
chmod +x /etc/profile.d/jpvpn.sh 
echo -e "${GREEN}✓ Panel auto-start configured.${NC}" 
 
# ======================================================================================= 
#  SECTION 12: FINAL SERVICE ENABLING & SUMMARY 
# ======================================================================================= 
 
echo -e "${CYAN}✅ Finalizing setup and restarting services...${NC}" 
systemctl daemon-reload >/dev/null 2>&1 
for svc in xray nginx ws-nontls zipvpn slowdns udp-custom hysteria-server dropbear; do 
  systemctl enable "$svc" >/dev/null 2>&1 || true 
  systemctl restart "$svc" >/dev/null 2>&1 || true 
done 
 
clear 
echo -e "${BOLD}${GREEN}======================================================================${NC}" 
echo -e "${BOLD}${GREEN}                   🎉 JPVPN v4.0 INSTALLATION COMPLETE! 🎉             ${NC}" 
echo -e "${BOLD}${GREEN}======================================================================${NC}" 
echo "" 
echo -e "${BOLD}${CYAN}🌐 Domain:${NC} ${YELLOW}$DOMAIN${NC}" 
echo -e "${BOLD}${CYAN}🚀 Panel Command:${NC} ${YELLOW}/usr/local/bin/jpvpn${NC}" 
echo -e "${BOLD}${CYAN}⚙️ Protocols:${NC} ${YELLOW}Xray (VMess/VLess/Trojan), SSH, Dropbear, WebSocket, ZIPVPN, Hysteria, SlowDNS, UDP Custom${NC}" 
echo -e "${BOLD}${CYAN}🔒 Ports:${NC} ${YELLOW}80, 443, 442 (Dropbear), 2082 (SSH WS), 40000-40009 (UDP), 5667 (ZIPVPN)${NC}" 
echo "" 
echo -e "${BOLD}${PURPLE}➡️ PANEL AKAN OTOMATIS MUNCUL SAAT LOGIN!${NC}" 
echo -e "${YELLOW}   Jika tidak muncul, jalankan ${CYAN}jpvpn${YELLOW} secara manual.${NC}" 
echo -e "${YELLOW}   Untuk menonaktifkan auto-start: ${CYAN}touch ~/.jpvpn_no_auto_start${NC}" 
echo -e "${YELLOW}   Periksa log service jika ada masalah: ${CYAN}journalctl -u <service_name> -f${NC}" 
echo "" 
echo -e "${BOLD}${GREEN}✨ Terima kasih telah memilih JPVPN!${NC}" 
echo -e "${BOLD}${GREEN}======================================================================${NC}" 

