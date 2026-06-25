#!/bin/bash
# Aarchai setup script for Kali Linux
# Usage: sudo bash setup.sh
set -e

echo "[*] Updating packages..."
apt-get update -qq

echo "[*] Installing recon tools..."
apt-get install -y -qq \
    nmap masscan \
    gobuster dirb ffuf nikto \
    whatweb wafw00f \
    amass subfinder dnsrecon dnsx \
    theharvester recon-ng \
    sslscan testssl.sh sslyze \
    sqlmap wpscan nuclei \
    eyewitness \
    whois dnsutils curl wget \
    postgresql postgresql-client redis-server \
    python3 python3-pip python3-venv \
    wkhtmltopdf

echo "[*] Installing rustscan..."
which rustscan 2>/dev/null || (
    wget -q https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb -O /tmp/rustscan.deb
    dpkg -i /tmp/rustscan.deb
)

echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

echo "[*] Starting services..."
systemctl enable --now postgresql redis-server

echo "[*] Creating DB user & database..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename='aarchai'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER aarchai WITH PASSWORD '"'"'aarchai'"'"';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='aarchai'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE aarchai OWNER aarchai;"

echo "[*] Initialising Aarchai schema..."
python3 aarchai.py init

cp -n .env.example .env
echo ""
echo "[+] Setup complete!"
echo "[+] Edit .env to add your API keys."
echo "[+] Run: python3 aarchai.py scan --target example.com"
