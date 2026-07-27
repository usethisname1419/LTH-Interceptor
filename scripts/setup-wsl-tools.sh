#!/usr/bin/env bash
# Optional helper: install common scanner tools inside WSL Ubuntu
set -euo pipefail

echo "[*] Updating apt..."
sudo apt-get update
sudo apt-get install -y curl nmap ffuf git python3

if ! command -v go >/dev/null 2>&1; then
  echo "[*] Installing golang..."
  sudo apt-get install -y golang-go
fi

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

echo "[*] Installing ProjectDiscovery tools (httpx, katana, nuclei)..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

if [ ! -d /usr/share/seclists ]; then
  echo "[*] Installing seclists wordlists (large)..."
  sudo apt-get install -y seclists || true
fi

echo "[*] Done. Ensure GOPATH/bin is on PATH:"
echo "    echo 'export PATH=\$PATH:\$HOME/go/bin' >> ~/.bashrc"
