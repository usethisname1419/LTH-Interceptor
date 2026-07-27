from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass

from typing import Callable

from .config import AppConfig


ProgressFn = Callable[[dict], None]


@dataclass
class RunResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    def for_model(self, limit: int = 12000) -> str:
        """Stdout-focused text for the LLM (no SSH plumbing)."""
        parts: list[str] = []
        if self.timed_out:
            parts.append("TIMEOUT")
        if self.stdout.strip():
            parts.append(self.stdout.strip())
        if self.exit_code not in (0, 1) and self.stderr.strip():
            parts.append("stderr:\n" + self.stderr.strip())
        elif self.timed_out and self.stderr.strip():
            parts.append(self.stderr.strip())
        if not parts:
            parts.append(f"(no output, exit={self.exit_code})")
        out = "\n".join(parts)
        if len(out) > limit:
            out = out[:limit] + f"\n...[truncated {len(out) - limit} chars]"
        return out

    def text(self, limit: int = 12000, *, verbose: bool = False) -> str:
        if not verbose:
            return self.for_model(limit)
        parts = [
            f"$ {self.command}",
            f"exit={self.exit_code}" + (" TIMEOUT" if self.timed_out else ""),
        ]
        if self.stdout.strip():
            parts.append("--- stdout ---\n" + self.stdout.strip())
        if self.stderr.strip():
            parts.append("--- stderr ---\n" + self.stderr.strip())
        out = "\n".join(parts)
        if len(out) > limit:
            out = out[:limit] + f"\n...[truncated {len(out) - limit} chars]"
        return out


class CommandRunner:
    """Runs tool commands on Windows locally, WSL, or Kali over SSH."""

    def __init__(self, config: AppConfig, cancel=None, on_progress: ProgressFn | None = None):
        self.config = config
        self.cancel = cancel
        self.on_progress = on_progress
        self._ssh_client = None
        self._active_channel = None
        self._current_cmd = ""

    def close(self) -> None:
        if self._active_channel is not None:
            try:
                self._active_channel.close()
            except Exception:
                pass
            self._active_channel = None
        if self._ssh_client is not None:
            try:
                self._ssh_client.close()
            except Exception:
                pass
            self._ssh_client = None

    def interrupt(self) -> None:
        """Best-effort kill of in-flight remote/local command."""
        self.close()

    def run(self, command: str, timeout: int | None = None) -> RunResult:
        if self.cancel is not None:
            self.cancel.check()
        timeout = timeout or self.config.timeout_sec
        self._current_cmd = command
        runtime = self.config.runtime
        if runtime == "ssh":
            return self._run_ssh(command, timeout)
        if runtime == "wsl":
            return self._run_wsl(command, timeout)
        return self._run_local(command, timeout)

    def _emit_progress(self, elapsed: float, phase: str = "running") -> None:
        if not self.on_progress:
            return
        try:
            preview = self._current_cmd
            if len(preview) > 100:
                preview = preview[:100] + "…"
            self.on_progress(
                {
                    "type": "tool_progress",
                    "phase": phase,
                    "elapsed_sec": round(elapsed, 1),
                    "command": preview,
                }
            )
        except Exception:
            pass

    def _run_local(self, command: str, timeout: int) -> RunResult:
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
            return RunResult(command, proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return RunResult(
                command,
                124,
                (exc.stdout or "") if isinstance(exc.stdout, str) else "",
                (exc.stderr or "") if isinstance(exc.stderr, str) else "timed out",
                timed_out=True,
            )

    def _run_wsl(self, command: str, timeout: int) -> RunResult:
        wrapped = f"bash -lc {shlex.quote(command)}"
        args = ["wsl", "-d", self.config.wsl_distro, "--", "bash", "-lc", command]
        display = f"wsl -d {self.config.wsl_distro} -- {wrapped}"
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
            return RunResult(display, proc.returncode, proc.stdout, proc.stderr)
        except FileNotFoundError:
            return RunResult(display, 127, "", "wsl.exe not found. Use runtime: ssh for Kali VM.")
        except subprocess.TimeoutExpired as exc:
            return RunResult(
                display,
                124,
                (exc.stdout or "") if isinstance(exc.stdout, str) else "",
                (exc.stderr or "") if isinstance(exc.stderr, str) else "timed out",
                timed_out=True,
            )

    def _get_ssh(self):
        if self._ssh_client is not None:
            transport = self._ssh_client.get_transport()
            if transport is not None and transport.is_active():
                return self._ssh_client

        try:
            import paramiko
        except ImportError as exc:
            raise RuntimeError("paramiko not installed. Run: .\\agent.ps1 -Setup") from exc

        ssh_cfg = self.config.ssh
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": ssh_cfg.host,
            "port": ssh_cfg.port,
            "username": ssh_cfg.user,
            "timeout": 20,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if ssh_cfg.key_path:
            connect_kwargs["key_filename"] = ssh_cfg.key_path
        if ssh_cfg.password:
            connect_kwargs["password"] = ssh_cfg.password

        try:
            client.connect(**connect_kwargs)
        except Exception as exc:
            raise RuntimeError(
                f"SSH connect failed to {ssh_cfg.user}@{ssh_cfg.host}:{ssh_cfg.port}. "
                f"Is Kali running, SSH enabled, and VirtualBox port-forward set? ({exc})"
            ) from exc

        self._ssh_client = client
        return client

    def _run_ssh(self, command: str, timeout: int) -> RunResult:
        display = f"ssh://{self.config.ssh.user}@{self.config.ssh.host}:{self.config.ssh.port} # {command}"
        try:
            client = self._get_ssh()
        except RuntimeError as exc:
            return RunResult(display, 255, "", str(exc))

        # Login shell so PATH includes user go/bin and kali defaults
        if self.config.ssh.use_login_shell:
            remote = f"bash -lc {shlex.quote(command)}"
        else:
            remote = command

        try:
            stdin, stdout, stderr = client.exec_command(remote, timeout=timeout)
            # paramiko timeout on exec_command is channel open; enforce overall read timeout
            channel = stdout.channel
            self._active_channel = channel
            deadline = time.time() + timeout
            started = time.time()
            last_hb = 0.0
            self._emit_progress(0.0, "started")
            while not channel.exit_status_ready():
                if self.cancel is not None and self.cancel.is_set:
                    channel.close()
                    return RunResult(display, 130, "", "Stopped by user", timed_out=False)
                now = time.time()
                if now - last_hb >= 2.0:
                    self._emit_progress(now - started, "running")
                    last_hb = now
                if now > deadline:
                    channel.close()
                    out = stdout.read().decode("utf-8", errors="replace")
                    err = stderr.read().decode("utf-8", errors="replace")
                    return RunResult(display, 124, out, err or "timed out", timed_out=True)
                time.sleep(0.2)
            exit_code = channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            self._emit_progress(time.time() - started, "done")
            return RunResult(display, exit_code, out, err)
        except Exception as exc:
            self.close()
            return RunResult(display, 255, "", f"SSH exec error: {exc}")
        finally:
            self._active_channel = None

    def which(self, binary: str) -> bool:
        result = self.run(f"command -v {shlex.quote(binary)} >/dev/null 2>&1 && echo OK || echo MISSING", timeout=30)
        return "OK" in result.stdout

    def test_connection(self) -> str:
        if self.config.runtime != "ssh":
            return f"runtime={self.config.runtime} (no SSH test needed)"
        result = self.run("echo LTH_SSH_OK && hostname && whoami && command -v nmap; command -v ffuf; command -v curl", timeout=30)
        return result.text(4000)
