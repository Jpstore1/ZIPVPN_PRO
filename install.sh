#!/bin/bash
# ==========================================================
#  ZIPVPN PRO PANEL v4
#  Fully Automated Installer
#  By: JP_OFFICIAL
# ==========================================================

set -euo pipefail

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"

clear
echo "============================================"
echo "        ZIPVPN PRO v4 INSTALLER"
echo "        By JP_OFFICIAL"
echo "============================================"
sleep 2

echo "[1] Updating system..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip curl jq git ufw

echo "[2] Installing ZIPVPN binary..."
mkdir -p $ZIVPN_DIR
curl -L -o $ZIVPN_BIN https://github.com/zipvpn/zipvpn/releases/latest/download/zivpn-linux-amd64
chmod +x $ZIVPN_BIN

echo "[3] Generating server config..."
cat > $ZIVPN_CFG <<EOF
{
  "listen": ":9000",
  "protocol": "udp",
  "key": "$(openssl rand -hex 32)"
}
EOF

echo "[4] Creating systemd service..."
cat > /etc/systemd/system/$ZIVPN_SVC <<EOF
[Unit]
Description=ZIPVPN Core
After=network.target

[Service]
ExecStart=$ZIVPN_BIN -c $ZIVPN_CFG
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $ZIVPN_SVC

echo "[5] Installing JP PRO PANEL..."
rm -rf $ADMIN_DIR
git clone https://github.com/Jpstore1/ZIPVPN_PANEL_PRO_V4 $ADMIN_DIR

cd $ADMIN_DIR
python3 -m venv $VENV
source $VENV/bin/activate
pip install -r requirements.txt

echo "[6] Creating panel environment..."
cat > $ENV_FILE <<EOF
PANEL_PORT=8088
ADMIN_USER=jp
ADMIN_PASS=89
EOF

echo "[7] Creating panel service..."
cat > /etc/systemd/system/$PANEL_SVC <<EOF
[Unit]
Description=ZIPVPN PRO Panel
After=network.target

[Service]
WorkingDirectory=$ADMIN_DIR
ExecStart=$VENV/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $PANEL_SVC

echo "[8] Opening ports..."
ufw allow 9000/udp
ufw allow 8088/tcp

echo ""
echo "============================================"
echo " ZIPVPN PRO PANEL v4 Installed Successfully!"
echo ""
echo " PANEL URL  : http://IPVPS:8088"
echo " USER       : jp"
echo " PASS       : 89"
echo " CORE PORT  : 9000 UDP"
echo "============================================"
