from __future__ import annotations

import json
import shlex
from typing import Any, Callable

from .config import AppConfig
from .db import Store
from .findings import ingest_tool_result
from .guardrails import assert_shell_safe
from .proxy import ProxyRotator, to_curl_proxy, to_ffuf_proxy, to_nuclei_proxy
from .runner import CommandRunner
from .scope import assert_command_in_scope, assert_target_in_scope
from .surface import analyze_html, analyze_js, same_site


ToolFn = Callable[..., str]


class ToolBelt:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner,
        proxies: ProxyRotator,
        *,
        verbose: bool = False,
        store: Store | None = None,
    ):
        self.config = config
        self.runner = runner
        self.proxies = proxies
        self.verbose = verbose
        self.store = store

    def _proxy(self) -> str | None:
        return self.proxies.next()

    def _fmt(self, result) -> str:
        return result.text(self.config.output_chars, verbose=self.verbose)

    def _finish(self, proxy: str | None, result_text: str, failed: bool) -> str:
        if failed:
            self.proxies.mark_dead(proxy)
        else:
            self.proxies.mark_ok(proxy)
        # Always show which SOCKS hop Kali used (tools run over SSH on Kali).
        tag = f"[kali+proxy={_short_proxy(proxy)}]" if proxy else "[kali+proxy=DIRECT]"
        return f"{tag}\n{result_text}"

    def schemas(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "nmap_scan",
                    "description": "Port scan a host with nmap (common ports by default; fast settings). Host must be in scope.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Hostname or IP in scope"},
                            "ports": {
                                "type": "string",
                                "description": "Ports e.g. 80,443 or 1-1000. Default=common web/admin ports.",
                            },
                            "extra_args": {
                                "type": "string",
                                "description": "Extra nmap args. Default is fast (-T4 --max-retries 2).",
                            },
                        },
                        "required": ["target"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "http_request",
                    "description": "Fetch a URL with curl through SOCKS5. Good for headers, tech, basic XSS reflection checks.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "method": {"type": "string", "description": "GET/POST/PUT/DELETE", "default": "GET"},
                            "headers": {
                                "type": "string",
                                "description": "Optional headers as 'Name: value' lines",
                            },
                            "data": {"type": "string", "description": "Optional request body"},
                            "follow_redirects": {"type": "boolean", "default": True},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "httpx_probe",
                    "description": "Probe host/URL list for live HTTP/HTTPS (status, final URL, title). Pass comma/newline separated hosts or URLs. Do not invent CLI flags; this tool handles probing internally.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "string",
                                "description": "Newline or comma-separated URLs/hosts in scope",
                            },
                        },
                        "required": ["targets"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "subdomain_enum",
                    "description": "Enumerate subdomains for an in-scope root domain (subfinder/amass/host).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Root domain in scope, e.g. example.com",
                            },
                        },
                        "required": ["domain"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "dir_fuzz",
                    "description": "Directory/file fuzzing with ffuf against an in-scope base URL.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "URL containing FUZZ, e.g. https://example.com/FUZZ",
                            },
                            "wordlist": {
                                "type": "string",
                                "description": "Wordlist path inside WSL/runtime. Default: common.txt if present.",
                            },
                            "extensions": {
                                "type": "string",
                                "description": "Comma extensions e.g. php,html,js",
                            },
                            "threads": {"type": "integer", "default": 20},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "param_fuzz",
                    "description": "Fuzz query/body params with ffuf. URL should include FUZZ for the param name or value.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "wordlist": {"type": "string"},
                            "method": {"type": "string", "default": "GET"},
                            "data": {"type": "string", "description": "POST body template with FUZZ"},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "crawl_urls",
                    "description": "Crawl/collect URLs with katana if installed, else wget spider fallback.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "depth": {"type": "integer", "default": 2},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "nuclei_scan",
                    "description": "Run nuclei templates against an in-scope target URL/host.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "severity": {
                                "type": "string",
                                "description": "Optional severity filter: low,medium,high,critical",
                            },
                            "tags": {"type": "string", "description": "Optional nuclei tags"},
                        },
                        "required": ["target"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "xss_reflect_check",
                    "description": "Simple reflected XSS probe: inject a canary into a URL/param and check if it comes back unencoded.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "Full URL. Use {XSS} where payload should go.",
                            },
                            "param": {
                                "type": "string",
                                "description": "If set, append/replace ?param=payload instead of {XSS}",
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "dns_lookup",
                    "description": "DNS lookup from Kali (dig/host). Args: host, optional record (A/AAAA/CNAME/MX/TXT).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string"},
                            "record": {"type": "string", "default": "A"},
                        },
                        "required": ["host"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "proxy_status",
                    "description": "Show SOCKS5 proxy pool status.",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "save_report",
                    "description": "Write a markdown summary report to the reports/ folder.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "markdown": {"type": "string"},
                            "filename": {"type": "string"},
                        },
                        "required": ["title", "markdown"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "save_note",
                    "description": "Append/write an engagement note (recon notes, interesting params, ideas) to notes/.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "content": {"type": "string"},
                            "filename": {"type": "string"},
                            "append": {
                                "type": "boolean",
                                "description": "If true, append to existing note file",
                                "default": True,
                            },
                        },
                        "required": ["title", "content"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "save_poc",
                    "description": "Save a proof-of-concept file (html/js/py/sh/txt payload or repro steps) to pocs/.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "content": {"type": "string"},
                            "filename": {
                                "type": "string",
                                "description": "e.g. reflected-xss.html or sqli-login.py",
                            },
                            "ext": {
                                "type": "string",
                                "description": "Fallback extension if filename omitted: md, html, js, py, txt",
                                "default": "md",
                            },
                        },
                        "required": ["title", "content"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "inspect_page",
                    "description": "Fetch a page, parse HTML, list forms/links/scripts/endpoints, and flag secrets/DOM sinks/CSRF hints. Optionally follow and analyze linked JS (same-site).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "follow_js": {
                                "type": "boolean",
                                "default": True,
                                "description": "Also fetch and analyze same-site script src files",
                            },
                            "max_scripts": {"type": "integer", "default": 8},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "inspect_js",
                    "description": "Fetch a JavaScript file and extract API endpoints, secrets, and dangerous DOM sinks.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "playwright_browse",
                    "description": "Browse an in-scope URL in a headless Chromium sandbox on Kali (Playwright). Returns title, final URL, visible text, links, and forms. Use for real browser assessment after recon.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "wait_ms": {
                                "type": "integer",
                                "default": 2500,
                                "description": "Wait after load before snapshot",
                            },
                            "click": {
                                "type": "string",
                                "description": "Optional CSS selector to click before snapshot",
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "shell",
                    "description": "Run a shell command on Kali over SSH (or local/WSL). Any hosts in the command must be in scope. Prefer specialized tools when possible.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                        },
                        "required": ["command"],
                    },
                },
            },
        ]

    def known_tools(self) -> set[str]:
        return set(self._tool_map().keys())

    def _tool_map(self) -> dict[str, ToolFn]:
        return {
            "nmap_scan": self.nmap_scan,
            "http_request": self.http_request,
            "httpx_probe": self.httpx_probe,
            "subdomain_enum": self.subdomain_enum,
            "dir_fuzz": self.dir_fuzz,
            "param_fuzz": self.param_fuzz,
            "crawl_urls": self.crawl_urls,
            "inspect_page": self.inspect_page,
            "inspect_js": self.inspect_js,
            "nuclei_scan": self.nuclei_scan,
            "xss_reflect_check": self.xss_reflect_check,
            "dns_lookup": self.dns_lookup,
            "playwright_browse": self.playwright_browse,
            "proxy_status": self.proxy_status,
            "save_report": self.save_report,
            "save_note": self.save_note,
            "save_poc": self.save_poc,
            "shell": self.shell,
        }

    def resolve_tool_name(self, name: str) -> str:
        """Map model aliases / typos onto real tool names."""
        n = (name or "").strip()
        aliases = {
            "httpx": "httpx_probe",
            "probe": "httpx_probe",
            "nmap": "nmap_scan",
            "port_scan": "nmap_scan",
            "nuclei": "nuclei_scan",
            "ffuf": "dir_fuzz",
            "dirb": "dir_fuzz",
            "gobuster": "dir_fuzz",
            "katana": "crawl_urls",
            "crawl": "crawl_urls",
            "subfinder": "subdomain_enum",
            "amass": "subdomain_enum",
            "subs": "subdomain_enum",
            "dns": "dns_lookup",
            "dig": "dns_lookup",
            "nslookup": "dns_lookup",
            "whois": "dns_lookup",
            "inspect": "inspect_page",
            "page": "inspect_page",
            "xss": "xss_reflect_check",
            "playwright": "playwright_browse",
            "browser": "playwright_browse",
            "browse": "playwright_browse",
        }
        mapped = aliases.get(n.lower(), n)
        return mapped if mapped in self._tool_map() else n

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        name = self.resolve_tool_name(name)
        mapping = self._tool_map()
        if name not in mapping:
            known = ", ".join(sorted(mapping))
            return (
                f"Unknown tool: {name}. Use one of: {known}. "
                "Do not invent tool names."
            )
        # Soft-adapt common wrong arg shapes
        arguments = _coerce_args(name, arguments)
        try:
            result = mapping[name](**arguments)
        except TypeError as exc:
            return f"Bad arguments for {name}: {exc}"
        except PermissionError as exc:
            return f"SCOPE BLOCKED: {exc}"
        except Exception as exc:  # noqa: BLE001 - surface tool errors to model
            return f"Tool error ({name}): {exc}"
        if self.store is not None and not str(result).startswith("SCOPE BLOCKED"):
            try:
                ingest_tool_result(self.store, name, result, arguments)
            except Exception:
                pass
        return result

    def nmap_scan(self, target: str, ports: str | None = None, extra_args: str | None = None) -> str:
        assert_target_in_scope(target, self.config.scope)
        note = ""
        # Cloudflare / filtered hosts: full or 1000-port -sV scans often timeout.
        if ports and ports.replace(" ", "") in {"1-65535", "-"}:
            ports = "80,443,8080,8443,22,21,25,53,110,143,993,995,3306,3389,8081,8888"
            note = "NOTE: full-range scan reduced to common ports to avoid timeout.\n"
        if ports is None:
            ports = "80,443,8080,8443,22,21,25,53,110,143,993,995,3306,3389,8081,8888"
        if extra_args is None:
            extra_args = "-T4 --max-retries 2 --host-timeout 60s"
        args = ["nmap", "--open", "-Pn", "-n", "-p", ports]
        if extra_args:
            args += shlex.split(extra_args)
        args.append(target)
        cmd = " ".join(shlex.quote(a) for a in args)
        # Give nmap a bit more room than default web calls
        result = self.runner.run(cmd, timeout=max(self.config.timeout_sec, 240))
        body = note + self._fmt(result)
        return self._finish(None, body, result.exit_code not in (0, 1) or result.timed_out)

    def subdomain_enum(self, domain: str) -> str:
        assert_target_in_scope(domain, self.config.scope)
        # Prefer subfinder/amass on Kali; always try crt.sh JSON fallback via python.
        cmd = (
            f"D={shlex.quote(domain)}; OUT=/tmp/lth-subs.txt; : > \"$OUT\"; "
            f"command -v subfinder >/dev/null && subfinder -d \"$D\" -silent >> \"$OUT\" || true; "
            f"command -v amass >/dev/null && amass enum -passive -d \"$D\" 2>/dev/null >> \"$OUT\" || true; "
            f"curl -sS --max-time 45 \"https://crt.sh/?q=%25.$D&output=json\" -o /tmp/lth-crt.json || true; "
            "python3 - <<'PY'\n"
            "import json\n"
            "from pathlib import Path\n"
            f"domain = {domain!r}.lower()\n"
            "out = Path('/tmp/lth-subs.txt')\n"
            "names = set(x.strip().lower() for x in out.read_text().splitlines() if x.strip()) if out.exists() else set()\n"
            "p = Path('/tmp/lth-crt.json')\n"
            "if p.exists() and p.stat().st_size > 2:\n"
            "    try:\n"
            "        data = json.loads(p.read_text() or '[]')\n"
            "    except Exception:\n"
            "        data = []\n"
            "    for row in data if isinstance(data, list) else []:\n"
            "        for name in str(row.get('name_value', '')).splitlines():\n"
            "            name = name.strip().lower().lstrip('*.')\n"
            "            if name == domain or name.endswith('.' + domain):\n"
            "                names.add(name)\n"
            "for n in sorted(names):\n"
            "    print(n)\n"
            "print('---')\n"
            "print(f'count={len(names)}')\n"
            "PY"
        )
        result = self.runner.run(cmd, timeout=max(self.config.timeout_sec, 120))
        return self._finish(None, self._fmt(result), result.exit_code not in (0, 1))

    def http_request(
        self,
        url: str,
        method: str = "GET",
        headers: str | None = None,
        data: str | None = None,
        follow_redirects: bool = True,
    ) -> str:
        assert_target_in_scope(url, self.config.scope)
        proxy = self._proxy()
        args = ["curl", "-sS", "-i", "-X", method.upper(), "--max-time", str(min(60, self.config.timeout_sec))]
        if follow_redirects:
            args.append("-L")
        if proxy:
            args += ["--proxy", to_curl_proxy(proxy)]
        if headers:
            for line in headers.splitlines():
                line = line.strip()
                if line:
                    args += ["-H", line]
        if data is not None:
            args += ["--data-binary", data]
        args.append(url)
        cmd = " ".join(shlex.quote(a) for a in args)
        result = self.runner.run(cmd)
        failed = result.exit_code != 0 or result.timed_out
        return self._finish(proxy, self._fmt(result), failed)

    def httpx_probe(self, targets: str) -> str:
        """Probe hosts/URLs for live HTTP(S).

        Kali's /usr/bin/httpx is often *Python* httpx, not ProjectDiscovery.
        This tool uses curl (reliable) and ignores any invented CLI flags.
        """
        items = [t.strip() for t in targets.replace(",", "\n").splitlines() if t.strip()]
        if not items:
            return "No targets provided"
        for t in items:
            assert_target_in_scope(t, self.config.scope)

        urls: list[str] = []
        for t in items:
            if t.startswith("http://") or t.startswith("https://"):
                urls.append(t)
            else:
                urls.append(f"https://{t}")
                urls.append(f"http://{t}")

        proxy = self._proxy()
        proxy_arg = f"--proxy {shlex.quote(to_curl_proxy(proxy))} " if proxy else ""
        listed = "\n".join(urls)

        # Keep remote script simple: curl + sed title extract (no nested python heredocs)
        cmd = (
            f"printf '%s\\n' {shlex.quote(listed)} > /tmp/lth-http-targets.txt\n"
            "echo 'url|status|final_url|title'\n"
            "while IFS= read -r u; do\n"
            "  [ -z \"$u\" ] && continue\n"
            f"  meta=$(curl -sS -o /tmp/lth-http-body -w '%{{http_code}}|%{{url_effective}}' "
            f"{proxy_arg}--max-time 20 -k -L -A 'LTH-Interceptor/0.1' \"$u\" 2>/dev/null "
            f"|| echo '000|')\n"
            "  title=$(tr '\\n' ' ' < /tmp/lth-http-body 2>/dev/null "
            "| sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\\([^<]*\\).*/\\1/p' "
            "| head -c 120 | tr '|' '/')\n"
            "  echo \"$u|$meta|$title\"\n"
            "done < /tmp/lth-http-targets.txt\n"
        )
        result = self.runner.run(cmd, timeout=max(self.config.timeout_sec, 180))
        return self._finish(proxy, self._fmt(result), result.exit_code != 0 and "000|" in (result.stdout or ""))

    def _default_wordlist(self, custom: str | None) -> str:
        if custom:
            return custom
        candidates = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ]
        # pick first existing wordlist
        cmd = "for f in " + " ".join(shlex.quote(c) for c in candidates) + "; do [ -f \"$f\" ] && echo \"$f\" && break; done"
        result = self.runner.run(cmd, timeout=30)
        path = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        if not path:
            raise FileNotFoundError(
                "No wordlist found. Set wordlist= or install seclists/dirb wordlists in WSL."
            )
        return path

    def dir_fuzz(
        self,
        url: str,
        wordlist: str | None = None,
        extensions: str | None = None,
        threads: int = 20,
    ) -> str:
        assert_target_in_scope(url, self.config.scope)
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        wl = self._default_wordlist(wordlist)
        proxy = self._proxy()
        # Cap wordlist for speed/safety; keep ffuf args minimal (bad flags → help dump)
        args = [
            "ffuf",
            "-u",
            url,
            "-w",
            f"{wl}:FUZZ",
            "-t",
            str(max(1, min(int(threads or 20), 40))),
            "-mc",
            "200,201,202,204,301,302,307,401,403",
            "-fc",
            "404",
            "-timeout",
            "10",
            "-s",
            "-of",
            "json",
            "-o",
            "/tmp/lth-ffuf-out.json",
        ]
        if extensions:
            # ffuf -e wants comma list without spaces
            ext = str(extensions).replace(" ", "")
            args += ["-e", ext]
        if proxy:
            args += ["-x", to_ffuf_proxy(proxy)]
        # Avoid nested heredocs over SSH login shells — they break and ffuf prints help
        cmd = (
            "rm -f /tmp/lth-ffuf-out.json; "
            + " ".join(shlex.quote(a) for a in args)
            + "; ec=$?; "
            "if [ -f /tmp/lth-ffuf-out.json ]; then "
            "python3 -c \"import json; d=json.load(open('/tmp/lth-ffuf-out.json')); "
            "rs=d.get('results') or []; "
            "print('hits=%d' % len(rs)); "
            "[print('%s %s' % (r.get('status'), r.get('url'))) for r in rs[:80]]; "
            "print(json.dumps(d)[:12000])\"; "
            "else echo FFUF_NO_OUTPUT; fi; exit $ec"
        )
        result = self.runner.run(cmd, timeout=max(self.config.timeout_sec, 240))
        out = (result.stdout or "") + "\n" + (result.stderr or "")
        low = out.lower()
        if "ffuf: not found" in low or result.exit_code == 127:
            return self._finish(proxy, "ffuf not installed on Kali. Install: sudo apt install ffuf", True)
        if "http options:" in low and "hits=" not in low:
            return self._finish(
                proxy,
                "ffuf rejected arguments (printed help). "
                "Try without custom extensions, confirm FUZZ is in the URL, "
                f"and proxy format socks5://…\n{self._fmt(result)[:1500]}",
                True,
            )
        failed = result.exit_code not in (0, 1) or "FFUF_NO_OUTPUT" in out
        return self._finish(proxy, self._fmt(result), failed)

    def param_fuzz(
        self,
        url: str,
        wordlist: str | None = None,
        method: str = "GET",
        data: str | None = None,
    ) -> str:
        assert_target_in_scope(url, self.config.scope)
        if "FUZZ" not in url and (not data or "FUZZ" not in str(data)):
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}FUZZ=test"
        wl = self._default_wordlist(wordlist)
        proxy = self._proxy()
        args = [
            "ffuf",
            "-u",
            url,
            "-w",
            f"{wl}:FUZZ",
            "-X",
            (method or "GET").upper(),
            "-mc",
            "200,201,302,400,401,403,500",
            "-t",
            "20",
            "-timeout",
            "10",
            "-s",
            "-of",
            "json",
            "-o",
            "/tmp/lth-param-ffuf.json",
        ]
        if data:
            args += ["-d", data]
        if proxy:
            args += ["-x", to_ffuf_proxy(proxy)]
        cmd = (
            "rm -f /tmp/lth-param-ffuf.json; "
            + " ".join(shlex.quote(a) for a in args)
            + "; ec=$?; "
            "if [ -f /tmp/lth-param-ffuf.json ]; then "
            "python3 -c \"import json; d=json.load(open('/tmp/lth-param-ffuf.json')); "
            "rs=d.get('results') or []; print('hits=%d' % len(rs)); "
            "[print('%s %s' % (r.get('status'), r.get('url'))) for r in rs[:80]]; "
            "print(json.dumps(d)[:12000])\"; "
            "else echo FFUF_NO_OUTPUT; fi; exit $ec"
        )
        result = self.runner.run(cmd, timeout=max(self.config.timeout_sec, 240))
        out = (result.stdout or "") + "\n" + (result.stderr or "")
        low = out.lower()
        if "http options:" in low and "hits=" not in low:
            return self._finish(
                proxy,
                "ffuf rejected arguments (printed help).\n" + self._fmt(result)[:1500],
                True,
            )
        failed = result.exit_code not in (0, 1) or "FFUF_NO_OUTPUT" in out
        return self._finish(proxy, self._fmt(result), failed)

    def crawl_urls(self, url: str, depth: int = 2) -> str:
        assert_target_in_scope(url, self.config.scope)
        proxy = self._proxy()
        depth = max(1, min(int(depth), 3))
        proxy_env = (
            f"HTTPS_PROXY={shlex.quote(to_curl_proxy(proxy))} HTTP_PROXY={shlex.quote(to_curl_proxy(proxy))} "
            if proxy
            else ""
        )
        # Prefer katana; include JS crawl hints when available
        katana = (
            f"{proxy_env}katana -u {shlex.quote(url)} -d {depth} -silent -jc -fx -jsl 2>/dev/null "
            f"| sort -u | head -n 300"
        )
        result = self.runner.run(katana, timeout=max(self.config.timeout_sec, 180))
        if result.exit_code == 0 and result.stdout.strip():
            return self._finish(proxy, self._fmt(result), False)

        # Fallback: recursive-ish curl of page + extract links
        proxy_arg = f"--proxy {shlex.quote(to_curl_proxy(proxy))} " if proxy else ""
        cmd = (
            f"curl -sS -L -k --max-time 45 {proxy_arg}{shlex.quote(url)} "
            r"| grep -Eo 'https?://[^\"\x27 <>]+|href=\"[^\"]+\"|src=\"[^\"]+\"' "
            "| sed 's/href=\"//;s/src=\"//;s/\"$//' | sort -u | head -n 250"
        )
        result = self.runner.run(cmd)
        return self._finish(
            proxy,
            "katana unavailable/empty; link extract fallback:\n" + self._fmt(result),
            result.exit_code != 0,
        )

    def _curl_body(self, url: str, proxy: str | None) -> tuple[str, int]:
        proxy_arg = f"--proxy {shlex.quote(to_curl_proxy(proxy))} " if proxy else ""
        cmd = (
            f"curl -sS -L -k --max-time 45 {proxy_arg}"
            f"-A 'LTH-Interceptor/0.2' {shlex.quote(url)}"
        )
        result = self.runner.run(cmd, timeout=60)
        return result.stdout or "", result.exit_code

    def inspect_page(self, url: str, follow_js: bool = True, max_scripts: int = 8) -> str:
        assert_target_in_scope(url, self.config.scope)
        proxy = self._proxy()
        body, code = self._curl_body(url, proxy)
        if code != 0 and not body:
            return self._finish(proxy, f"Failed to fetch {url}", True)

        report = analyze_html(body, url)
        scope_hosts = list(self.config.scope.domains) + list(self.config.scope.hosts)

        js_reports = []
        if follow_js:
            max_scripts = max(1, min(int(max_scripts), 15))
            for src in report.get("script_srcs", [])[:max_scripts]:
                if not same_site(src, scope_hosts):
                    continue
                try:
                    assert_target_in_scope(src, self.config.scope)
                except PermissionError:
                    continue
                js_body, js_code = self._curl_body(src, proxy)
                if js_code == 0 and js_body:
                    js_reports.append(analyze_js(js_body, src))

        # Merge JS findings into top-level findings list
        for jr in js_reports:
            for f in jr.get("findings", []):
                f = dict(f)
                f["title"] = f.get("title", "") + f" ({jr.get('url')})"
                report.setdefault("findings", []).append(f)
            for ep in jr.get("endpoints", []):
                if ep not in report["endpoints"]:
                    report["endpoints"].append(ep)

        report["js_analyzed"] = [j.get("url") for j in js_reports]
        report["html_bytes"] = len(body)
        # Keep response bounded for the model
        slim = {
            "url": report["url"],
            "title": report["title"],
            "forms": report["forms"],
            "inputs": report["inputs"][:30],
            "script_srcs": report["script_srcs"],
            "js_analyzed": report["js_analyzed"],
            "links_sample": report["links"][:40],
            "endpoints": report["endpoints"][:80],
            "findings": report.get("findings", [])[:40],
            "comments": report.get("comments", [])[:10],
        }
        return self._finish(proxy, json.dumps(slim, indent=2)[: self.config.output_chars], False)

    def inspect_js(self, url: str) -> str:
        assert_target_in_scope(url, self.config.scope)
        proxy = self._proxy()
        body, code = self._curl_body(url, proxy)
        if code != 0 and not body:
            return self._finish(proxy, f"Failed to fetch JS {url}", True)
        report = analyze_js(body, url)
        slim = {
            "url": report["url"],
            "size": report["size"],
            "endpoints": report["endpoints"],
            "findings": report["findings"][:40],
            "excerpt": report["excerpt"],
        }
        return self._finish(proxy, json.dumps(slim, indent=2)[: self.config.output_chars], False)

    def dns_lookup(self, host: str, record: str | None = None) -> str:
        """Resolve DNS from Kali (dig/host). Not proxied — DNS is local/resolver side."""
        assert_target_in_scope(host, self.config.scope)
        host = host.strip().split("/")[0].replace("https:", "").replace("http:", "").strip(":/")
        rr = (record or "A").upper()
        cmd = (
            f"(command -v dig >/dev/null && dig +short {shlex.quote(rr)} {shlex.quote(host)}) "
            f"|| (command -v host >/dev/null && host {shlex.quote(host)}) "
            f"|| getent hosts {shlex.quote(host)} "
            f"|| echo DNS_LOOKUP_FAILED"
        )
        result = self.runner.run(cmd, timeout=30)
        out = self._fmt(result)
        failed = result.exit_code != 0 or "DNS_LOOKUP_FAILED" in out
        # DNS does not use SOCKS; keep tag honest
        tag = "[kali+dns=direct]"
        return f"{tag}\n{out}" if not failed else f"{tag}\n{out}"

    def nuclei_scan(self, target: str, severity: str | None = None, tags: str | None = None) -> str:
        assert_target_in_scope(target, self.config.scope)
        proxy = self._proxy()
        # Check binary first for clear errors
        which = self.runner.run("command -v nuclei || echo MISSING", timeout=10)
        if "MISSING" in (which.stdout or "") or which.exit_code != 0:
            return self._finish(
                proxy,
                "nuclei not installed on Kali. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                True,
            )
        args = ["nuclei", "-u", target, "-silent", "-nc", "-timeout", "10"]
        if severity:
            args += ["-severity", severity]
        if tags:
            args += ["-tags", tags]
        if proxy:
            args += ["-proxy", to_nuclei_proxy(proxy)]
        cmd = " ".join(shlex.quote(a) for a in args)
        result = self.runner.run(cmd, timeout=max(self.config.timeout_sec, 180))
        text = self._fmt(result)
        if not (result.stdout or "").strip():
            err = (result.stderr or "").strip()
            # Don't treat nuclei's empty-findings exit(1) as a dead SOCKS hop when
            # the failure is clearly a proxy-format / config issue.
            format_fail = "invalid proxy format" in err.lower()
            text = (
                f"(no nuclei findings, exit={result.exit_code})\n"
                f"stderr: {err[:500] or '(empty)'}"
            )
            if format_fail:
                return (
                    f"[kali+proxy={_short_proxy(proxy)}]\n{text}\n"
                    "HINT: nuclei needs socks5:// (not socks5h). Retry after fix."
                )
        # exit 1 with empty stdout is normal "no matches" for nuclei
        failed = result.exit_code not in (0, 1) or "invalid proxy format" in (result.stderr or "").lower()
        return self._finish(proxy, text, failed)

    def xss_reflect_check(self, url: str, param: str | None = None) -> str:
        canary = 'lthxss"\'<>'
        if param:
            assert_target_in_scope(url, self.config.scope)
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={canary}"
        else:
            if "{XSS}" not in url:
                return "URL must contain {XSS} placeholder or provide param="
            test_url = url.replace("{XSS}", canary)
            assert_target_in_scope(test_url, self.config.scope)

        proxy = self._proxy()
        args = ["curl", "-sS", "-L", "--max-time", "45", test_url]
        if proxy:
            args += ["--proxy", to_curl_proxy(proxy)]
        cmd = " ".join(shlex.quote(a) for a in args)
        result = self.runner.run(cmd)
        body = result.stdout
        reflected = canary in body
        # rough encoding checks
        encoded_hits = {
            "lt": "&lt;" in body and "lthxss" in body.lower(),
            "quot": "&quot;" in body and "lthxss" in body.lower(),
        }
        summary = {
            "url": test_url,
            "reflected_raw": reflected,
            "likely_encoded": encoded_hits,
            "exit_code": result.exit_code,
            "snippet": body[:1500],
        }
        failed = result.exit_code != 0
        return self._finish(proxy, json.dumps(summary, indent=2), failed)

    def proxy_status(self) -> str:
        return json.dumps(self.proxies.status(), indent=2)

    @staticmethod
    def _safe_name(name: str) -> str:
        safe = name.lower().strip()
        safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in safe).strip("-")
        return safe or "untitled"

    def save_report(self, title: str, markdown: str, filename: str | None = None) -> str:
        self.config.reports_path.mkdir(parents=True, exist_ok=True)
        safe = self._safe_name(filename or title)
        if not safe.endswith(".md"):
            safe += ".md"
        path = self.config.reports_path / safe
        path.write_text(f"# {title}\n\n{markdown.strip()}\n", encoding="utf-8")
        return f"Wrote report: {path}"

    def save_note(
        self,
        title: str,
        content: str,
        filename: str | None = None,
        append: bool = True,
    ) -> str:
        self.config.notes_path.mkdir(parents=True, exist_ok=True)
        safe = self._safe_name(filename or title)
        if not safe.endswith(".md"):
            safe += ".md"
        path = self.config.notes_path / safe
        block = f"## {title}\n\n{content.strip()}\n\n"
        if append and path.exists():
            with path.open("a", encoding="utf-8") as fh:
                fh.write(block)
            msg = f"Appended note: {path}"
        else:
            path.write_text(f"# {title}\n\n{content.strip()}\n", encoding="utf-8")
            msg = f"Wrote note: {path}"
        if self.store is not None:
            try:
                self.store.add_analysis(title, content.strip(), kind="note")
            except Exception:
                pass
        return msg

    def save_poc(
        self,
        title: str,
        content: str,
        filename: str | None = None,
        ext: str = "md",
    ) -> str:
        self.config.pocs_path.mkdir(parents=True, exist_ok=True)
        if filename:
            safe = self._safe_name(filename)
        else:
            safe = self._safe_name(title) + f".{(ext or 'md').lstrip('.')}"
        path = self.config.pocs_path / safe
        text = content if content.startswith(("#", "<!", "<?", "//")) else f"# {title}\n\n{content.strip()}\n"
        if path.suffix.lower() in {".html", ".htm", ".js", ".py", ".sh"}:
            text = content
        path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        return f"Wrote PoC: {path}"

    def playwright_browse(
        self,
        url: str,
        wait_ms: int = 2500,
        click: str | None = None,
    ) -> str:
        """Headless Chromium snapshot on Kali via Playwright (sandbox)."""
        import base64

        assert_target_in_scope(url, self.config.scope)
        wait_ms = max(500, min(int(wait_ms or 2500), 15000))
        payload = json.dumps({"url": url, "wait_ms": wait_ms, "click": click})
        runner_py = (
            "import json,sys\n"
            "cfg=json.loads(sys.argv[1])\n"
            "url=cfg['url']; wait_ms=int(cfg.get('wait_ms') or 2500); click=cfg.get('click')\n"
            "try:\n"
            " from playwright.sync_api import sync_playwright\n"
            "except Exception as e:\n"
            " print(json.dumps({'ok':False,'error':'playwright_not_installed','detail':str(e),"
            "'hint':'pip3 install --user playwright && python3 -m playwright install chromium'})); raise SystemExit(0)\n"
            "out={'ok':True,'url':url}\n"
            "try:\n"
            " with sync_playwright() as p:\n"
            "  launch_kwargs={'headless':True,'args':['--no-sandbox','--disable-dev-shm-usage']}\n"
            "  import os\n"
            "  for cand in ('/usr/bin/chromium','/usr/bin/chromium-browser','/usr/bin/google-chrome'):\n"
            "   if os.path.exists(cand):\n"
            "    launch_kwargs['executable_path']=cand; break\n"
            "  b=p.chromium.launch(**launch_kwargs)\n"
            "  ctx=b.new_context(ignore_https_errors=True,viewport={'width':1400,'height':900})\n"
            "  page=ctx.new_page()\n"
            "  page.goto(url,wait_until='domcontentloaded',timeout=45000)\n"
            "  page.wait_for_timeout(wait_ms)\n"
            "  if click:\n"
            "   try:\n"
            "    page.click(click,timeout=5000); page.wait_for_timeout(1000)\n"
            "   except Exception as e: out['click_error']=str(e)\n"
            "  out['final_url']=page.url; out['title']=page.title()\n"
            "  out['forms']=page.eval_on_selector_all('form',"
            "'(els)=>els.slice(0,20).map(f=>({action:f.getAttribute(\"action\")||\"\","
            "method:(f.getAttribute(\"method\")||\"get\").toLowerCase(),"
            "inputs:Array.from(f.querySelectorAll(\"input,select,textarea\")).slice(0,30)"
            ".map(i=>({name:i.getAttribute(\"name\")||\"\",type:i.getAttribute(\"type\")||i.tagName.toLowerCase()}))}))')\n"
            "  out['links']=page.eval_on_selector_all('a[href]',"
            "'(els)=>[...new Set(els.map(a=>a.href))].slice(0,80)')\n"
            "  out['text']=(page.inner_text('body') or '')[:6000]\n"
            "  b.close()\n"
            "except Exception as e:\n"
            " out={'ok':False,'error':str(e),'url':url}\n"
            "print(json.dumps(out,ensure_ascii=False)[:20000])\n"
        )
        b64 = base64.b64encode(runner_py.encode("utf-8")).decode("ascii")
        # Prefer dedicated Kali venv (~/lth-pw) for Playwright + bundled Chromium
        cmd = (
            "PYBIN=\"$HOME/lth-pw/bin/python\"; "
            "if [ ! -x \"$PYBIN\" ]; then PYBIN=python3; fi; "
            f"$PYBIN -c \"import base64; open('/tmp/lth_playwright_snap.py','wb')"
            f".write(base64.b64decode('{b64}'))\" && "
            f"$PYBIN /tmp/lth_playwright_snap.py {shlex.quote(payload)}"
        )
        result = self.runner.run(cmd, timeout=max(90, self.config.timeout_sec))
        return f"[kali+playwright=direct]\n{self._fmt(result)}"

    def shell(self, command: str) -> str:
        assert_command_in_scope(command, self.config.scope)
        assert_shell_safe(command)
        proxy = self._proxy()
        if proxy and "PROXY" not in command.upper() and "--proxy" not in command:
            env = (
                f"export ALL_PROXY={shlex.quote(to_curl_proxy(proxy))} "
                f"HTTPS_PROXY=$ALL_PROXY HTTP_PROXY=$ALL_PROXY; "
            )
            command = env + command
        result = self.runner.run(command)
        failed = result.exit_code != 0 or result.timed_out
        return self._finish(proxy, self._fmt(result), failed)


def _short_proxy(proxy: str | None) -> str:
    if not proxy:
        return "DIRECT"
    try:
        from urllib.parse import urlparse

        p = urlparse(proxy if "://" in proxy else "socks5://" + proxy)
        return f"{p.hostname}:{p.port}"
    except Exception:
        return proxy[:40]


def _coerce_args(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Fix common wrong argument shapes from local models."""
    args = dict(arguments or {})
    if name == "httpx_probe":
        if "targets" not in args:
            for key in ("target", "url", "host", "hosts", "urls"):
                if key in args and args[key]:
                    args["targets"] = args.pop(key)
                    break
        if isinstance(args.get("targets"), list):
            args["targets"] = ",".join(str(x) for x in args["targets"])
    if name == "dns_lookup":
        if "host" not in args:
            for key in ("target", "domain", "url", "name"):
                if key in args and args[key]:
                    args["host"] = str(args.pop(key))
                    break
        host = str(args.get("host") or "")
        if "://" in host:
            from urllib.parse import urlparse

            args["host"] = urlparse(host).hostname or host
    if name in {"nuclei_scan", "nmap_scan"} and "target" not in args:
        for key in ("url", "host", "domain"):
            if key in args and args[key]:
                args["target"] = args.pop(key)
                break
    if name in {"inspect_page", "crawl_urls", "dir_fuzz", "param_fuzz", "playwright_browse"} and "url" not in args:
        for key in ("target", "host"):
            if key in args and args[key]:
                val = str(args.pop(key))
                if not val.startswith("http"):
                    val = "https://" + val
                args["url"] = val
                break
    # Drop unknown kwargs that would break TypeError for common extras
    return args

