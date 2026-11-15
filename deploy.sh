
# For general monitoring
curl -fsSL https://raw.githubusercontent.com/DannyGaev/LUC-CyberForce-2026/refs/heads/main/monitor_deployment/rapid-deployment.sh | bash -s -- "$1"

# For log exporting
curl -fsSL https://raw.githubusercontent.com/DannyGaev/LUC-CyberForce-2026/refs/heads/main/monitor_deployment/rapid-log-export-deployment.sh | bash -s -- "$1"