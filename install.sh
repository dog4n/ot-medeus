#!/usr/bin/env bash
# OT-Medeus kurulum — Ubuntu/Debian
set -e

echo "[*] Sistem paketleri (nmap + python venv)..."
sudo apt-get update -y
sudo apt-get install -y nmap python3-venv python3-pip

echo "[*] Sanal ortam ve paket kurulumu..."
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install .                 # çekirdek motor
pip install '.[passive]'      # scapy — iç ağ ARP/pasif dinleme (opsiyonel)

echo
echo "[✓] Kurulum tamam."
echo "    Ortamı aç: source .venv/bin/activate"
echo "    Dene     : ot-medeus -h"
echo
echo "    (İsteğe bağlı) Geniş üretici kapsamı için IEEE OUI kaydını indir:"
echo "      curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv"
echo "      ot-medeus ... --oui-file oui.csv"
