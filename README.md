#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# SENSEI-TUNNEL ULTIMATE v7.1 - FULL AUTO INSTALLER + DASHBOARD PANEL
# Features:
#  - Dropbear SSH
#  - SSH over WebSocket (TLS / Non-TLS via wstunnel or socat fallback)
#  - Hysteria V1 server manager
#  - ZipVPN UDP basic manager
#  - PROTEC DDoS (iptables UDPLIMIT using hashlimit)
#  - Auto backup, user DB (sqlite3), port manager, vnstat bandwidth
#  - Blue panel UI, immediate entry to panel after install
# Final combined version — adapted & fixed (Dec 2025)
# =============================================================================

# -------------------------
# CONFIG
# -------------------------
DEBUG=false          # set true for verbose logs
AUTO_ACCEPT_PROMPTS=true   # set to false to require confirmations
DB="/root/sensei.db"
BACKUP_DIR="/backup"
SNAP_DIR="/root/.sensei/snapshots"
ROLLBACK_SCRIPT="/usr/local/bin/sensei-rollback.sh"

# Colors (blue theme)
NC='\e[0m'
CB='\e[1;34m'   # Bold Blue
CC='\e[0;36m'   # Cyan
CG='\e[1;32m'   # Green
CR='\e[1;31m'   # Red
CY='\e[1;33m'   # Yellow
CM='\e[1;35m'   # Magenta
WHITE='\e[1;37m'

log()    { $DEBUG && echo -e "${CC}[INFO]${NC} $*"; }
success(){ echo -e "${CG}[OK]${NC} $*"; }
warn()   { echo -e "${CY}[WARN]${NC} $*"; }
error()  { echo -e "${CR}[ERROR]${NC} $*"; }
info()   { echo -e "${CB}[INFO]${NC} $*"; }

# -------------------------
# Auto detect
# -------------------------
IP=$(curl -4 --silent ipinfo.io/ip 2>/dev/null || curl -4 --silent icanhazip.com 2>/dev/null || echo "127.0.0.1")
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
MAIN_IFACE=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}' || echo "eth0")

# Default ports (can change via port manager)
declare -A PORTS=(
  ["dropbear"]="22 109 143 442"
  ["ws_tls"]="443"
  ["ws_nontls"]="80"
  ["hysteria"]="36712"
  ["zipvpn"]="5667"
)

# Ensure directories
mkdir -p "$BACKUP_DIR"/{daily,weekly,monthly}
mkdir -p "$SNAP_DIR"
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
chmod 755 "$BACKUP_DIR" 2>/dev/null || true

# -------------------------
# Helpers
# -------------------------
command_exists() { command -v "$1" &>/dev/null; }

sqlite3_exec() {
  sqlite3 "$DB" "$1" 2>/dev/null
}

sqlite3_escape() {
  local s="$1"
  printf "%s" "${s//\'/\'\'}"
}

ensure_chain_udplimit() {
  if ! iptables -L UDPLIMIT -n 2>/dev/null; then
    iptables -N UDPLIMIT 2>/dev/null || true
  fi
}

save_ports() {
  sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS ports (service TEXT PRIMARY KEY, ports TEXT);"
  for svc in "${!PORTS[@]}"; do
    sqlite3 "$DB" "INSERT OR REPLACE INTO ports (service, ports) VALUES('$(sqlite3_escape "$svc")', '$(sqlite3_escape "${PORTS[$svc]}")');" 2>/dev/null || true
  done
}

load_ports() {
  if [ -f "$DB" ]; then
    while IFS='|' read -r service ports; do
      [[ -n "$service" && -n "$ports" ]] && PORTS["$service"]="$ports"
    done < <(sqlite3 "$DB" "SELECT service || '|' || ports FROM ports;" 2>/dev/null || true)
  fi
}

record_state() {
  local ts d
  ts=$(date +%Y%m%d_%H%M%S)
  d="$SNAP_DIR/$ts"
  mkdir -p "$d"
  log "Saving snapshot to $d ..."
  iptables-save > "$d/iptables-save" 2>/dev/null || true
  cp -a /etc/nginx/sites-available "$d/" 2>/dev/null || true
  cp -a /etc/nginx/sites-enabled "$d/" 2>/dev/null || true
  cp -a /etc/default/dropbear "$d/dropbear.default" 2>/dev/null || true
  cp -a /etc/hysteria/config.json "$d/hysteria.config.json" 2>/dev/null || true
  [ -f "$DB" ] && cp -a "$DB" "$d/sensei.db" 2>/dev/null || true
  ln -sfn "$d" "$SNAP_DIR/latest"
  success "Snapshot saved: $d"
}

create_rollback_script() {
  cat > "$ROLLBACK_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
SNAP_DIR="/root/.sensei/snapshots"
LATEST="$(readlink -f $SNAP_DIR/latest || echo "")"
if [ -z "$LATEST" ] || [ ! -d "$LATEST" ]; then
  echo "No snapshot available."
  exit 1
fi
echo "[INFO] Restoring from $LATEST"
if [ -f "$LATEST/iptables-save" ]; then
  iptables-restore < "$LATEST/iptables-save" || echo "iptables restore failed"
fi
if [ -d "$LATEST/sites-available" ]; then
  cp -a "$LATEST/sites-available" /etc/nginx/ || true
fi
if [ -d "$LATEST/sites-enabled" ]; then
  cp -a "$LATEST/sites-enabled" /etc/nginx/ || true
fi
if [ -f "$LATEST/dropbear.default" ]; then
  cp -a "$LATEST/dropbear.default" /etc/default/dropbear || true
fi
if [ -f "$LATEST/hysteria.config.json" ]; then
  mkdir -p /etc/hysteria
  cp -a "$LATEST/hysteria.config.json" /etc/hysteria/config.json || true
fi
if [ -f "$LATEST/sensei.db" ]; then
  cp -a "$LATEST/sensei.db" /root/sensei.db || true
fi
echo "[INFO] Restore completed. Please restart services as needed."
EOF
  chmod +x "$ROLLBACK_SCRIPT"
  success "Rollback script created at $ROLLBACK_SCRIPT"
}

# -------------------------
# Initialization
# -------------------------
init_system() {
  info "Initializing system & installing dependencies (best-effort)..."

  if [ "$EUID" -ne 0 ]; then
    error "Run as root."
    exit 1
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt update -qq || warn "apt update failed"
  apt install -y sqlite3 jq vnstat htop nginx certbot dropbear iptables-persistent fail2ban net-tools iproute2 rsync curl wget unzip socat openvpn python3-certbot-nginx &>/dev/null || warn "Some packages failed to install"

  systemctl enable --now vnstat nginx dropbear fail2ban 2>/dev/null || warn "Failed to enable core services"
  if command_exists vnstat && [ -n "$MAIN_IFACE" ]; then
    vnstat -u -i "$MAIN_IFACE" 2>/dev/null || true
  fi

  mkdir -p /etc/hysteria /etc/hysteria/backups 2>/dev/null || true
  sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, created TEXT);" 2>/dev/null || true
  sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS ports (service TEXT PRIMARY KEY, ports TEXT);" 2>/dev/null || true

  load_ports
  success "System initialized."
}

# -------------------------
# Hardening (conservative)
# -------------------------
apply_hardening() {
  log "Applying safe sysctl hardening..."
  cp -a /etc/sysctl.conf /etc/sysctl.conf.sensei.bak 2>/dev/null || true
  cat >> /etc/sysctl.conf <<'EOF'

# Added by SENSEI
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF
  sysctl -p 2>/dev/null || true
  success "Basic hardening applied."
}

# -------------------------
# Port management functions
# -------------------------
change_dropbear_port() {
  echo -e "${CC}Current Dropbear ports:${NC} ${PORTS[dropbear]}"
  read -rp "Enter new ports (space separated, ex: '22 109 444'): " new_ports
  if [[ -n "$new_ports" ]]; then
    PORTS[dropbear]="$new_ports"
    if grep -q '^DROPBEAR_PORTS=' /etc/default/dropbear 2>/dev/null; then
      sed -i "s|^DROPBEAR_PORTS=.*|DROPBEAR_PORTS=\"${PORTS[dropbear]}\"|" /etc/default/dropbear
    else
      echo "DROPBEAR_PORTS=\"${PORTS[dropbear]}\"" >> /etc/default/dropbear
    fi
    systemctl.restart dropbear 2>/dev/null || true
    save_ports
    success "Dropbear ports changed to: ${PORTS[dropbear]}"
  fi
}

change_ws_tls_port() {
  echo -e "${CC}Current WS TLS port:${NC} ${PORTS[ws_tls]}"
  read -rp "Enter new WS TLS port (ex: 8443): " new_port
  if [[ -n "$new_port" ]]; then
    PORTS[ws_tls]="$new_port"
    if [ -f /etc/nginx/sites-available/ws ]; then
      sed -i -E "s/listen[[:space:]]+[0-9]+[[:space:]]+ssl/listen ${PORTS[ws_tls]} ssl/" /etc/nginx/sites-available/ws || true
      nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || warn "nginx reload failed"
    fi
    save_ports
    success "WS TLS port set to ${PORTS[ws_tls]}"
  fi
}

change_ws_nontls_port() {
  echo -e "${CC}Current WS Non-TLS port:${NC} ${PORTS[ws_nontls]}"
  read -rp "Enter new WS Non-TLS port (ex: 8080): " new_port
  if [[ -n "$new_port" ]]; then
    PORTS[ws_nontls]="$new_port"
    if [ -f /etc/nginx/sites-available/ws-nontls ]; then
      sed -i -E "s/listen[[:space:]]+[0-9]+;/listen ${PORTS[ws_nontls]};/g" /etc/nginx/sites-available/ws-nontls || true
      nginx -t 2>/dev/null && systemctl.reload nginx 2>/dev/null || warn "nginx reload failed"
    fi
    save_ports
    success "WS Non-TLS port set to ${PORTS[ws_nontls]}"
  fi
}

change_hysteria_port() {
  echo -e "${CC}Current Hysteria port:${NC} ${PORTS[hysteria]}"
  read -rp "Enter new Hysteria UDP port (ex: 45678): " new_port
  if [[ -n "$new_port" ]]; then
    ensure_chain_udplimit
    iptables -D INPUT -p udp --dport "${PORTS[hysteria]}" -j UDPLIMIT 2>/dev/null || true
    PORTS[hysteria]="$new_port"
    if [ -f /etc/hysteria/config.json ]; then
      sed -i -E "s/\"listen\"[[:space:]]*:[[:space:]]*\"?:?[0-9]+\"?/\"listen\": \":${PORTS[hysteria]}\"/" /etc/hysteria/config.json || true
      systemctl restart hysteria-server 2>/dev/null || true
    else
      warn "/etc/hysteria/config.json not found; update manually"
    fi
    iptables -I INPUT -p udp --dport "${PORTS[hysteria]}" -j UDPLIMIT || true
    netfilter-persistent save 2>/dev/null || true
    save_ports
    success "Hysteria port changed to UDP: ${PORTS[hysteria]}"
  fi
}

change_zipvpn_port() {
  echo -e "${CC}Current ZipVPN port:${NC} ${PORTS[zipvpn]}"
  read -rp "Enter new ZipVPN UDP port (ex: 8443): " new_port
  if [[ -n "$new_port" ]]; then
    ensure_chain_udplimit
    iptables -D INPUT -p udp --dport "${PORTS[zipvpn]}" -j UDPLIMIT 2>/dev/null || true
    PORTS[zipvpn]="$new_port"
    warn "ZipVPN internal config may need manual update depending on installer"
    iptables -I INPUT -p udp --dport "${PORTS[zipvpn]}" -j UDPLIMIT || true
    netfilter-persistent save 2>/dev/null || true
    save_ports
    success "ZipVPN port set to UDP: ${PORTS[zipvpn]}"
  fi
}

# -------------------------
# Snapshot + Rollback before risky ops
# -------------------------
preflight_snapshot() {
  record_state
  create_rollback_script
  apply_hardening
}

# -------------------------
# Auto install all services
# -------------------------
auto_install_all() {
  info "Installing all core services (best-effort). This may take several minutes..."
  preflight_snapshot

  # Dropbear
  if ! command_exists dropbear; then
    apt install -y dropbear &>/dev/null || warn "dropbear install failed"
  fi
  if [ -f /etc/default/dropbear ]; then
    if grep -q '^DROPBEAR_PORTS=' /etc/default/dropbear 2>/dev/null; then
      sed -i "s|^DROPBEAR_PORTS=.*|DROPBEAR_PORTS=\"${PORTS[dropbear]}\"|" /etc/default/dropbear || true
    else
      echo "DROPBEAR_PORTS=\"${PORTS[dropbear]}\"" >> /etc/default/dropbear || true
    fi
  fi
  systemctl restart dropbear 2>/dev/null || true

  # Certbot / Nginx best-effort cert
  if command_exists certbot; then
    if ss -ltnp | grep -q ':80\|:443'; then
      warn "Port 80/443 in use; skipping certbot standalone. Place certs in /etc/letsencrypt/live/${HOSTNAME} if you need SSL."
    else
      certbot certonly --standalone -d "$HOSTNAME" --email "admin@$IP" --agree-tos --non-interactive 2>/dev/null || warn "certbot failed or skipped"
    fi
  fi

  # Hysteria (best-effort installer)
  if ! [ -f /usr/local/bin/hysteria ]; then
    if command_exists curl; then
      log "Attempting Hysteria installer script..."
      bash -c "$(curl -fsSL https://raw.githubusercontent.com/evozi/hysteria-install/main/hy1/hysteria1.sh 2>/dev/null || echo '# hysteria not installed')" || true
    fi
  fi
  if [ -f /etc/hysteria/config.json ]; then
    sed -i -E "s/\"listen\"[[:space:]]*:[[:space:]]*\"?:?[0-9]+\"?/\"listen\": \":${PORTS[hysteria]}\"/" /etc/hysteria/config.json || true
    systemctl restart hysteria-server 2>/dev/null || true
  fi

  # ZipVPN (best-effort)
  if command_exists curl; then
    log "Attempting ZipVPN installer (best-effort)"
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/zi.sh 2>/dev/null || echo '# zipvpn not installed')" || true
    # Ensure service name may vary (zivpn / zipvpn); user must verify
  fi

  # wstunnel (or socat fallback)
  ARCH=$(uname -m)
  WST_BIN="/usr/local/bin/wstunnel"
  if [ ! -f "$WST_BIN" ]; then
    case "$ARCH" in
      x86_64|amd64) wst_arch="wstunnel-x86_64-unknown-linux-musl" ;;
      aarch64|arm64) wst_arch="wstunnel-aarch64-unknown-linux-musl" ;;
      armv7l) wst_arch="wstunnel-armv7-unknown-linux-musl" ;;
      *) wst_arch="wstunnel-x86_64-unknown-linux-musl" ;;
    esac
    wget -q "https://github.com/erebe/wstunnel/releases/latest/download/${wst_arch}" -O "$WST_BIN" || true
    chmod +x "$WST_BIN" 2>/dev/null || true
  fi

  # Nginx WS configs
  cat > /etc/nginx/sites-available/ws <<EOF
server {
    listen ${PORTS[ws_tls]} ssl http2; server_name _;
    ssl_certificate /etc/letsencrypt/live/${HOSTNAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${HOSTNAME}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

  cat > /etc/nginx/sites-available/ws-nontls <<EOF
server {
    listen ${PORTS[ws_nontls]}; server_name _;
    location /ws-nt {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

  ln -sf /etc/nginx/sites-available/ws /etc/nginx/sites-enabled/ws
  ln -sf /etc/nginx/sites-available/ws-nontls /etc/nginx/sites-enabled/ws-nontls
  nginx -t 2>/dev/null && systemctl restart nginx 2>/dev/null || warn "nginx test/restart failed"

  # wstunnel systemd units (if binary exists)
  if [ -f "$WST_BIN" ]; then
    cat > /etc/systemd/system/wstunnel.service <<EOF
[Unit]
Description=wstunnel WS TLS
After=network.target

[Service]
ExecStart=${WST_BIN} server --port 8080 --restrict-to 127.0.0.1:22
Restart=always
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/wstunnel-nontls.service <<EOF
[Unit]
Description=wstunnel WS Non-TLS
After=network.target

[Service]
ExecStart=${WST_BIN} server --port 8081 --restrict-to 127.0.0.1:22
Restart=always
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || true
    systemctl enable --now wstunnel wstunnel-nontls 2>/dev/null || true
  else
    # fallback: create socat units (simple)
    cat > /etc/systemd/system/ws-nontls.service <<'EOF'
[Unit]
Description=WS Non-TLS (socat)
After=network.target
[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:8081,fork,reuseaddr TCP:127.0.0.1:22
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/ws-tls.service <<'EOF'
[Unit]
Description=WS TLS (socat OPENSSL-LISTEN)
After=network.target
[Service]
ExecStart=/usr/bin/socat OPENSSL-LISTEN:8080,cert=/etc/ssl/certs/ssl-cert-snakeoil.pem,key=/etc/ssl/private/ssl-cert-snakeoil.key,fork,reuseaddr TCP:127.0.0.1:22
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || true
    systemctl enable --now ws-nontls ws-tls 2>/dev/null || true
  fi

  # PROTEC UDPLIMIT chain
  ensure_chain_udplimit
  iptables -F UDPLIMIT 2>/dev/null || true
  iptables -A UDPLIMIT -p udp --dport "${PORTS[zipvpn]}" -m hashlimit --hashlimit-upto 300/s --hashlimit-burst 1000 --hashlimit-mode srcip -j ACCEPT || true
  iptables -A UDPLIMIT -p udp --dport "${PORTS[hysteria]}" -m hashlimit --hashlimit-upto 200/s --hashlimit-burst 500 --hashlimit-mode srcip -j ACCEPT || true
  iptables -A UDPLIMIT -j DROP || true
  iptables -C INPUT -p udp --dport "${PORTS[zipvpn]}" -j UDPLIMIT 2>/dev/null || iptables -I INPUT -p udp --dport "${PORTS[zipvpn]}" -j UDPLIMIT
  iptables -C INPUT -p udp --dport "${PORTS[hysteria]}" -j UDPLIMIT 2>/dev/null || iptables -I INPUT -p udp --dport "${PORTS[hysteria]}" -j UDPLIMIT
  netfilter-persistent save 2>/dev/null || true

  save_ports
  success "ALL SERVICES installed/configured (best-effort). Please verify Hysteria/ZipVPN internal configs."
}

# -------------------------
# Backup setup
# -------------------------
setup_auto_backup() {
  log "Configuring daily backup..."
  cat > /usr/local/bin/sensei-backup <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DATE=$(date +%Y%m%d_%H%M)
BASE="/backup"
mkdir -p "$BASE/daily/$DATE"
tar -czf "$BASE/daily/$DATE/sensei-backup-$DATE.tar.gz" /etc/hysteria /etc/nginx /etc/default/dropbear /root/sensei.db /usr/local/bin/wstunnel 2>/dev/null || true
iptables-save > "$BASE/daily/$DATE/iptables-$DATE.txt" 2>/dev/null || true
find "$BASE/daily" -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
echo "[$(date)] Backup $DATE" >> /var/log/sensei.log
EOF
  chmod +x /usr/local/bin/sensei-backup
  echo "0 2 * * * root /usr/local/bin/sensei-backup >/dev/null 2>&1" > /etc/cron.d/sensei-backup
  success "Auto backup configured (daily 02:00)."
}

# -------------------------
# User management (SSH / WS / Hysteria / ZipVPN)
# -------------------------
create_ssh_user() {
  read -rp "Username: " u
  if [[ -z "$u" ]]; then error "Empty username"; return; fi
  if getent passwd "$u" &>/dev/null; then error "User exists on system"; return; fi
  read -rp "Password (leave empty to auto-gen): " p
  if [[ -z "$p" ]]; then
    p=$(openssl rand -base64 12 | tr -dc A-Za-z0-9 | head -c 12)
  fi
  useradd -M -N -s /usr/sbin/nologin "$u" 2>/dev/null || useradd -M -s /bin/false "$u" 2>/dev/null || true
  echo "${u}:${p}" | chpasswd 2>/dev/null || true
  sqlite3 "$DB" "INSERT OR IGNORE INTO users (username,password,created) VALUES('$(sqlite3_escape "$u")','$(sqlite3_escape "$p")',datetime('now'));" 2>/dev/null || true
  success "SSH user $u created (system user). Password: $p"
  info "Use SSH to connect via server IP and chosen Dropbear port(s)."
}

create_ws_account() {
  # For WebSocket SSH we create a system user as well (same as SSH)
  create_ssh_user
  info "WS account created — if using SSH over WebSocket, same credentials apply."
}

create_hysteria_account() {
  read -rp "Hysteria username: " hu
  if [[ -z "$hu" ]]; then error "Empty username"; return; fi
  read -rp "Password (leave empty to auto-gen): " hp
  if [[ -z "$hp" ]]; then
    hp=$(openssl rand -base64 16 | tr -dc A-Za-z0-9 | head -c 16)
  fi
  HYST_F="/etc/hysteria/users.json"
  if [ ! -f "$HYST_F" ]; then
    echo '{"users":{}}' > "$HYST_F"
  fi
  # Add user via jq
  if command_exists jq; then
    tmp=$(mktemp)
    jq --arg u "$hu" --arg p "$hp" '.users += {($u): {"password": $p}}' "$HYST_F" > "$tmp" && mv "$tmp" "$HYST_F"
    systemctl reload hysteria-server 2>/dev/null || true
    sqlite3 "$DB" "INSERT OR IGNORE INTO users (username,password,created) VALUES('$(sqlite3_escape "$hu")','$(sqlite3_escape "$hp")',datetime('now'));" 2>/dev/null || true
    success "Hysteria user added: $hu"
    info "Hysteria connect string: hysteria://$hp@$HOSTNAME:${PORTS[hysteria]}/?masquerade=$HOSTNAME"
  else
    warn "jq not installed. Installing jq..."
    apt update -qq 2>/dev/null || true
    apt install -y jq &>/dev/null || warn "Failed to install jq"
    if command_exists jq; then
      create_hysteria_account
    else
      error "jq still missing; cannot add hysteria user via JSON automatically"
    fi
  fi
}

list_users() {
  sqlite3 -header -column "$DB" "SELECT id, username, password, created FROM users ORDER BY id DESC LIMIT 200;" 2>/dev/null || echo "No users or sqlite not available."
}

delete_user() {
  read -rp "Username to delete: " du
  if [[ -z "$du" ]]; then error "Empty username"; return; fi
  sqlite3 "$DB" "DELETE FROM users WHERE username='$(sqlite3_escape "$du")';" 2>/dev/null || true
  if [ -f /etc/hysteria/users.json ] && command_exists jq; then
    tmp=$(mktemp)
    jq "del(.users.\"$du\")" /etc/hysteria/users.json > "$tmp" && mv "$tmp" /etc/hysteria/users.json 2>/dev/null
