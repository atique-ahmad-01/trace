#!/usr/bin/env bash
# One-time setup of an Oracle Cloud Ubuntu (22.04/24.04, aarch64) VM for the TRACE API.
#   curl -fsSL https://raw.githubusercontent.com/atique-ahmad-01/trace/main/deploy/oracle/setup.sh | bash
# Installs Docker, opens ports 80/443 in the host firewall, and clones the repository to ~/trace.
set -euo pipefail

REPO="${REPO:-https://github.com/atique-ahmad-01/trace.git}"
REF="${REF:-main}"
DIR="${DIR:-$HOME/trace}"

if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
fi

# Oracle's Ubuntu images ship iptables rules that reject everything except SSH, even when the
# VCN security list allows the port. Allow HTTP/HTTPS ahead of the REJECT rule and persist it.
for port in 80 443; do
  sudo iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null \
    || sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport "$port" -j ACCEPT
done
sudo iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null \
  || sudo iptables -I INPUT 6 -p udp --dport 443 -j ACCEPT
if command -v netfilter-persistent >/dev/null; then
  sudo netfilter-persistent save
fi

if [ ! -d "$DIR/.git" ]; then
  git clone --branch "$REF" "$REPO" "$DIR"
fi

cat <<EOF

Done. Next:
  cd $DIR/deploy/oracle
  cp .env.example .env && nano .env     # API_DOMAIN, DATABASE_URL, secrets
  sudo docker compose up -d --build     # or log out and back in to use docker without sudo
EOF
