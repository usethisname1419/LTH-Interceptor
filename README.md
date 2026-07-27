# LTH-Interceptor

Local authorized **penetration-testing / bug-bounty agent** with a CLI and Web UI.

| Piece | Where |
|-------|--------|
| Brain (Ollama) | Windows (GPU recommended) |
| Tools | Kali over SSH |
| Findings / todos / notes | SQLite `data/lth.db` |
| Playbooks | recon, surface, web-bounty, ports, report |
| UI | http://127.0.0.1:8787 |

Models are **not** shipped in this repo. Install them with Ollama on your machine.

## Requirements

- Windows host with [Ollama](https://ollama.com/) installed
- Kali Linux reachable over SSH (tools: nmap, httpx, ffuf, nuclei, etc.)
- Python 3.11+ on Windows
- Optional: SOCKS5 proxies in `proxies.txt`

## Quick start

```powershell
git clone https://github.com/<YOU>/LTH-Interceptor.git
cd LTH-Interceptor

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy config.example.yaml config.yaml
# edit config.yaml — SSH, scope domains, model names

.\ui.ps1
```

Open http://127.0.0.1:8787

CLI:

```powershell
.\agent.ps1
.\agent.ps1 -Model 1
.\agent.ps1 -VerboseOutput
```

## Ollama models (required)

This project expects two coder models by default (edit in `config.yaml`):

| Slot | Default tag | Role |
|------|-------------|------|
| M1 | `qwen2.5-coder:14b` | Faster / lighter |
| M2 | `qwen2.5-coder:32b` | Stronger (default) |

Pull them yourself (large downloads — not in git):

```powershell
ollama pull qwen2.5-coder:14b
ollama pull qwen2.5-coder:32b
ollama list
```

Confirm Ollama is listening at `http://127.0.0.1:11434` (or change `ollama_host` in config).

Any Ollama chat model can be used — set `model_1` / `model_2` to tags you have pulled.

## Config

1. Copy `config.example.yaml` → `config.yaml` (gitignored — keep secrets local).
2. Set `ssh` host/user/password or `key_path`.
3. Set `scope.domains` to the engagement target only.
4. Optional: `proxies.txt` (one SOCKS5 URL per line). See `proxies.example.txt`.

## Kali side

- SSH user with access to scanner tools
- Optional: place a full binary list at `/home/<user>/kali_tools.txt` — on startup the agent curates offensive tools into `agent/skills/kali_inventory.md`
- Playwright sandbox (optional): Python venv at `~/lth-pw` with `playwright` + Chromium (used by `playwright_browse`)

## Web UI

```powershell
.\ui.ps1
```

- **Left** — AI / tool stream (collapsible reasoning when the model emits it)
- **Right** — Findings (severity filters), Todos, Notes, Analysis, Runs
- **Playbooks** + **Chart** (lean endpoint/service map)
- **Config** editor, Save / Resume / Clear / Stop

## Playbooks

- `recon` — subdomains + HTTP probe + quick ports
- `surface` — crawl / inspect pages
- `web-bounty` — nuclei + dir/param fuzz + xss checks + report
- `ports` — common-port sweep
- `report` — compile findings → `reports/`

In chat: `/playbook web-bounty`

## Skills / identity

- `agent/skills/pentest.md` — pentest / bug-bounty behavior (edit to tune)
- `agent/skills/kali_inventory.md` — curated Kali tool paths (auto-refreshed)

## Safety

- Authorized testing only. Stay in `scope`.
- Non-destructive by default; reckless shell patterns are blocked.
- Never commit `config.yaml`, live `data/`, or engagement notes with secrets.

## License

Use only against systems you are authorized to test.
