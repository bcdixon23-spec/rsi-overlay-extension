"""Run the collection script locally or on a remote host over SSH.

Remote collection uses the system OpenSSH client, so it automatically honours
~/.ssh/config, ssh-agent, jump hosts, certificates and known_hosts - and adds no
Python dependencies. The whole collection happens in a single SSH session.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field


class CollectionError(RuntimeError):
    pass


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    used_sudo: bool = False


def _run(cmd: list[str], script: str, timeout: int) -> RunResult:
    try:
        proc = subprocess.run(
            cmd,
            input=script,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise CollectionError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CollectionError(f"collection timed out after {timeout}s") from exc
    return RunResult(proc.returncode, proc.stdout, proc.stderr)


def _sudo_refused(result: RunResult) -> bool:
    err = result.stderr.lower()
    return result.returncode != 0 and (
        "password is required" in err or "no tty present" in err or "not in the sudoers" in err
    )


class LocalRunner:
    """Collect from the machine Sightline is running on."""

    def __init__(self, sudo: bool = False):
        self.sudo = sudo
        self.description = "local"

    def run_script(self, script: str, timeout: int = 180) -> RunResult:
        if self.sudo and shutil.which("sudo"):
            result = _run(["sudo", "-n", "sh", "-s"], script, timeout)
            if not _sudo_refused(result):
                result.used_sudo = True
                return result
        return _run(["sh", "-s"], script, timeout)


@dataclass
class SSHRunner:
    host: str
    user: str | None = None
    port: int = 22
    key: str | None = None
    sudo: bool = False
    strict_host_keys: bool = False
    connect_timeout: int = 10
    extra_options: list[str] = field(default_factory=list)
    ssh_binary: str = "ssh"

    @property
    def description(self) -> str:
        who = f"{self.user}@" if self.user else ""
        return f"ssh {who}{self.host}:{self.port}"

    def command(self, remote: str) -> list[str]:
        cmd = [
            self.ssh_binary,
            "-T",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "StrictHostKeyChecking=" + ("yes" if self.strict_host_keys else "accept-new"),
            "-o", "LogLevel=ERROR",
            "-p", str(self.port),
        ]  # fmt: skip
        if self.key:
            cmd += ["-i", self.key, "-o", "IdentitiesOnly=yes"]
        for opt in self.extra_options:
            cmd += ["-o", opt]
        cmd += [f"{self.user}@{self.host}" if self.user else self.host, remote]
        return cmd

    def run_script(self, script: str, timeout: int = 180) -> RunResult:
        if not shutil.which(self.ssh_binary):
            raise CollectionError(
                "the OpenSSH client ('ssh') is not installed; install openssh-client to "
                "run credentialed scans"
            )
        if self.sudo:
            result = _run(self.command("sudo -n sh -s"), script, timeout)
            if result.returncode == 255:
                raise CollectionError(_ssh_error(result))
            if not _sudo_refused(result):
                result.used_sudo = True
                return result
        result = _run(self.command("sh -s"), script, timeout)
        if result.returncode == 255:
            raise CollectionError(_ssh_error(result))
        return result


def _ssh_error(result: RunResult) -> str:
    msg = result.stderr.strip().splitlines()
    detail = msg[-1] if msg else "connection failed"
    return f"SSH failed: {detail}"
