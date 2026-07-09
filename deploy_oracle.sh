#!/bin/bash
# TQSC v2.0 — Deploy to Oracle Cloud Free Tier
# Uso: bash deploy_oracle.sh
# Requiere: IP, usuario, key SSH de Oracle

set -e

IP="${1:-192.168.1.1}"
USER="${2:-ubuntu}"
KEY="${3:-key.pem}"

echo "🚀 Desplegando TQSC en Oracle Cloud..."
echo "   IP: $IP"
echo "   Usuario: $USER"

# 1. Transferir código
echo "📦 Transfiriendo código..."
rsync -avz --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
      --exclude='.git' --exclude='target' --exclude='data' \
      -e "ssh -i $KEY" \
      /c/Users/raem9/Desktop/Proyecto\ TQSC/v1.0/ \
      $USER@$IP:/opt/tqsc/

# 2. Instalar dependencias en la VM
echo "🛠 Instalando dependencias..."
ssh -i $KEY $USER@$IP << 'EOF'
sudo apt-get update -qq
sudo apt-get install -y -qq docker.io docker-compose-v2 ufw net-tools
sudo systemctl enable docker
sudo usermod -aG docker ubuntu

# Firewall: SOLO honeypot
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp comment 'TQSC honeypot'
sudo ufw allow 8080/tcp comment 'TQSC HTTP honeypot'
sudo ufw --force enable

echo "✅ Dependencias instaladas"
EOF

# 3. Build + arrancar
echo "🐳 Build Docker..."
ssh -i $KEY $USER@$IP << 'EOF'
cd /opt/tqsc

# Generar certificados mTLS
docker compose build --quiet
docker compose run --rm tqsc-init-certs

# Arrancar todos los servicios
docker compose up -d

echo ""
echo "✅ TQSC desplegado"
echo "📊 Contenedores:"
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
EOF

echo ""
echo "=== TQSC DESPLEGADO EN ORACLE ==="
echo "IP: $IP"
echo "Honeypot SSH:  ssh -p 2222 root@$IP"
echo "Honeypot HTTP: http://$IP:8080"
echo ""
echo "Para ver logs:"
echo "  ssh -i $KEY $USER@$IP 'docker compose -f /opt/tqsc/docker-compose.yml logs -f'"
echo ""
echo "Para pentest: ataca los puertos 2222 y 8080 desde cualquier máquina"
