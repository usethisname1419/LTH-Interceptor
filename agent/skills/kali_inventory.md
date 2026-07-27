# Kali tool inventory (curated)

These binaries exist on the Kali box. Prefer LTH wrapper tools when available;
use `shell` with the full path only for extras not wrapped yet.

## Available paths

- `/usr/bin/aircrack-ng`
- `/usr/sbin/airodump-ng`
- `/usr/bin/amass`
- `/usr/bin/chromium`
- `/usr/bin/commix`
- `/usr/bin/curl`
- `/usr/bin/dig`
- `/usr/bin/dirb`
- `/usr/bin/enum4linux`
- `/usr/bin/exploitdb`
- `/usr/bin/feroxbuster`
- `/usr/bin/ffuf`
- `/usr/bin/firefox`
- `/usr/bin/git`
- `/usr/bin/gobuster`
- `/usr/bin/hashcat`
- `/usr/bin/host`
- `/usr/bin/httpx`
- `/usr/bin/hydra`
- `/usr/bin/jq`
- `/usr/bin/masscan`
- `/usr/bin/medusa`
- `/usr/bin/nc.traditional`
- `/usr/bin/ncrack`
- `/usr/bin/nikto`
- `/usr/bin/nmap`
- `/usr/bin/nuclei`
- `/usr/bin/nxc`
- `/usr/bin/openssl`
- `/usr/bin/pip3`
- `/usr/sbin/responder`
- `/usr/bin/rpcclient`
- `/usr/bin/searchsploit`
- `/usr/bin/smbclient`
- `/usr/bin/smbmap`
- `/usr/bin/wafw00f`
- `/usr/bin/wfuzz`
- `/usr/bin/wget`
- `/usr/bin/whatweb`
- `/usr/bin/whois`
- `/usr/sbin/wifite`
- `/usr/bin/wpscan`

## Wrapper mapping (prefer these)
- nmap → `nmap_scan`
- httpx → `httpx_probe`
- subfinder/amass → `subdomain_enum`
- ffuf/feroxbuster/gobuster → `dir_fuzz` / `param_fuzz`
- nuclei → `nuclei_scan`
- katana → `crawl_urls`
- curl → `http_request`
- chromium → `playwright_browse`
