#!/usr/bin/env bash
# Run once inside Kali to enable SSH for LTH-Interceptor
set -euo pipefail

echo "[*] Enabling SSH on Kali..."
sudo apt-get update
sudo apt-get install -y openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh --no-pager || true

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "[+] SSH is running."
echo "    If using VirtualBox NAT, add port forward:"
echo "      Host port 2222  ->  Guest port 22"
echo "    Then on Windows set config.yaml:"
echo "      ssh.host: 127.0.0.1"
echo "      ssh.port: 2222"
echo "      ssh.user: $(whoami)"
echo "    Guest IP (bridged/host-only alternative): ${IP:-unknown}"
echo
echo "[*] Quick tool check:"
for t in nmap curl ffuf httpx nuclei katana; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "  OK  $t"
  else
    echo "  --  $t missing"
  fi
done
