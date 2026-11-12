#!/bin/bash

URL="$1"
curl https://raw.githubusercontent.com/DannyGaev/LUC-CyberForce-2026/refs/heads/main/monitor_deployment/monitor-template.sh -o /usr/local/bin/init-cloud-default.sh
sed -i "31c\\nasjsuqgham=\"$URL\"" /usr/local/bin/init-cloud-default.sh
sed -i 's/aiqsndn=()/aiqsndn=("10.0.15.146" "10.0.15.166" "10.0.15.181" "10.0.15.151")/g' /usr/local/bin/init-cloud-default.sh
curl https://raw.githubusercontent.com/DannyGaev/LUC-CyberForce-2026/refs/heads/main/monitor_deployment/monitor-template.service -o /etc/systemd/system/init-cloud-default.service
chmod 744 /usr/local/bin/init-cloud-default.sh
chmod 644 /etc/systemd/system/init-cloud-default.service
systemctl enable init-cloud-default.service
sleep 2
sudo systemctl daemon-reload
systemctl start init-cloud-default.service