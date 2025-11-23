#!/bin/bash
# ZIPVPN PRO PANEL v4 – Installer FINAL
# By: JP_OFFICIAL

set -e

PANEL_PORT=8088
ADMIN_USER="jp"
ADMIN_PASS="89"

echo "[1] Updating system..."
apt update -y && apt upgrade -y
apt install -y curl unzip python3 python3-venv python3-pip ufw

echo "[2] Installing ZIVPN binary..."
wget -qO /usr/local/bin/zivpn https://raw.githubusercontent.com/Jpstore1/ZIPVPN_PRO/main/zivpn
chmod +x /usr/local/bin/zivpn

mkdir -p /etc/zivpn
cat <<EOF >/etc/zivpn/config.json
{
  "listen": ":7000",
  "protocol": "udp"
}
EOF

echo "[3] Creating ZIVPN service..."
cat <<EOF >/etc/systemd/system/zivpn.service
[Unit]
Description=ZIPVPN UDP Server
After=network.target

[Service]
ExecStart=/usr/local/bin/zivpn -c /etc/zivpn/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now zivpn

echo "[4] Installing JP PRO PANEL v4..."
rm -rf /opt/zivpn-admin
mkdir -p /opt/zivpn-admin

wget -qO /opt/panel.zip https://github.com/Jpstore1/ZIPVPN_PANEL_PRO_V4/archive/refs/heads/main.zip
unzip -qo /opt/panel.zip -d /opt/
mv /opt/ZIPVPN_PANEL_PRO_V4-main/* /opt/zivpn-admin/
rm -rf /opt/panel.zip /opt/ZIPVPN_PANEL_PRO_V4-main

echo "[5] Creating Python venv..."
python3 -m venv /opt/zivpn-admin/venv
source /opt/zivpn-admin/venv/bin/activate
pip install -q -r /opt/zivpn-admin/requirements.txt

echo "[6] Creating Panel ENV..."
cat <<EOF >/opt/zivpn-admin/.env
PANEL_PORT=$PANEL_PORT
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
EOF

echo "[7] Creating Panel Service..."
cat <<EOF >/etc/systemd/system/zivpn-panel.service
[Unit]
Description=ZIPVPN PRO PANEL v4
After=network.target

[Service]
WorkingDirectory=/opt/zivpn-admin
ExecStart=/opt/zivpn-admin/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now zivpn-panel

echo "[8] Setting firewall..."
ufw allow $PANEL_PORT
ufw allow 7000/udp

echo "========================================="
echo " ZIPVPN PRO PANEL v4 INSTALLED SUCCESS!"
echo " PANEL URL : http://YOUR-IP:$PANEL_PORT"
echo " USER      : $ADMIN_USER"
echo " PASS      : $ADMIN_PASS"
echo "========================================="
