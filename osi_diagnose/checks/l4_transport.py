from __future__ import annotations

import socket

from osi_diagnose.checks.base import command_exists, run_command
from osi_diagnose.model import CheckResult, DiagnosticContext, LayerResult


SAFE_PORTS = [22, 53, 80, 443]


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run_layer(context: DiagnosticContext) -> LayerResult:
    checks: list[CheckResult] = []

    for port, name in [(53, "DNS TCP"), (443, "HTTPS TCP")]:
        ok = tcp_connect(context.target_host, port)
        checks.append(CheckResult(f"l4_tcp_{port}", name, "pass" if ok else "warn", 0 if ok else 20, f"TCP {port} {'reachable' if ok else 'unreachable'}", metrics={"host": context.target_host, "port": port}))

    if command_exists("nc"):
        code, _, err = run_command(["nc", "-z", "-u", "-G", "2", context.target_host, "123"])
        checks.append(CheckResult("l4_ntp_udp", "NTP UDP reachability", "pass" if code == 0 else "warn", 0 if code == 0 else 20, "UDP/123 test complete", details=[err] if err else []))
    else:
        checks.append(CheckResult("l4_ntp_udp", "NTP UDP reachability", "skip", 5, "nc unavailable for UDP test"))

    if context.scan_gateway_ports and context.gateway:
        if command_exists("nmap"):
            port_arg = context.nmap_ports or ",".join(map(str, SAFE_PORTS))
            code, out, err = run_command(["nmap", "-Pn", "-p", port_arg, context.gateway], timeout=30)
            checks.append(CheckResult("l4_gateway_scan", "Gateway safe port scan", "pass" if code == 0 else "warn", 0 if code == 0 else 25, "nmap scan complete" if code == 0 else "nmap failed", details=out.splitlines()[:20] if out else [err]))
        else:
            results = {str(p): tcp_connect(context.gateway, p) for p in SAFE_PORTS}
            checks.append(CheckResult("l4_gateway_scan", "Gateway safe port scan", "pass", 0, "Socket-based lightweight scan complete", metrics=results))
    else:
        checks.append(CheckResult("l4_gateway_scan", "Gateway safe port scan", "skip", 3, "Safe scan disabled by default"))

    return LayerResult(layer=4, name="Transport", checks=checks)
