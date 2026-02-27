from __future__ import annotations

import json
import platform
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Any

from osi_diagnose.model import HostContext, LayerResult, RunConfig


@dataclass(slots=True)
class CommandOutput:
    ok: bool
    stdout: str
    stderr: str
    returncode: int


def run_cmd(args: list[str], timeout: float = 8.0) -> CommandOutput:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandOutput(
            ok=proc.returncode == 0,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            returncode=proc.returncode,
        )
    except FileNotFoundError:
        return CommandOutput(ok=False, stdout="", stderr="command not found", returncode=127)
    except subprocess.TimeoutExpired:
        return CommandOutput(ok=False, stdout="", stderr="timeout", returncode=124)
    except OSError as exc:
        return CommandOutput(ok=False, stdout="", stderr=str(exc), returncode=126)


def which(name: str) -> str | None:
    return shutil.which(name)


def parse_default_gateway(route_output: str) -> tuple[str | None, str | None]:
    gw_match = re.search(r"gateway:\s*([0-9.]+)", route_output)
    iface_match = re.search(r"interface:\s*(\S+)", route_output)
    return (gw_match.group(1) if gw_match else None, iface_match.group(1) if iface_match else None)


def detect_dns_servers() -> list[str]:
    out = run_cmd(["scutil", "--dns"])
    if not out.ok:
        return []
    servers: list[str] = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("nameserver["):
            _, value = line.split(":", 1)
            servers.append(value.strip())
    return servers


def detect_interfaces() -> list[str]:
    out = run_cmd(["ifconfig", "-l"])
    if not out.ok:
        return []
    return [i for i in out.stdout.split() if i]


def detect_local_ip(default_iface: str | None) -> str | None:
    if not default_iface:
        return None
    out = run_cmd(["ipconfig", "getifaddr", default_iface])
    if out.ok and out.stdout:
        return out.stdout.strip()
    return None


def detect_context(config: RunConfig) -> HostContext:
    route_out = run_cmd(["route", "-n", "get", "default"])
    gw, iface = parse_default_gateway(route_out.stdout)
    if config.gateway_override:
        gw = config.gateway_override
    interfaces = detect_interfaces()
    return HostContext(
        os_name=platform.platform(),
        hostname=socket.gethostname(),
        interfaces=interfaces,
        default_interface=iface,
        local_ip=detect_local_ip(iface),
        gateway_ip=gw,
        dns_servers=detect_dns_servers(),
    )


def parse_network_quality_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


class LayerCheck:
    layer: int = 0
    title: str = "Unknown"

    def run(self, config: RunConfig, context: HostContext) -> LayerResult:
        raise NotImplementedError
