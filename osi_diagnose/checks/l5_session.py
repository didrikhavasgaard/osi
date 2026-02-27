from __future__ import annotations

import re

from osi_diagnose.checks.base import run_command
from osi_diagnose.model import CheckResult, DiagnosticContext, LayerResult


def parse_vpn_interfaces(ifconfig_output: str) -> list[str]:
    return sorted(set(re.findall(r"^(utun\d+|tun\d+|wg\d+):", ifconfig_output, flags=re.MULTILINE)))


def run_layer(context: DiagnosticContext) -> LayerResult:
    checks: list[CheckResult] = []
    code, out, err = run_command(["ifconfig"])
    if code != 0:
        checks.append(CheckResult("l5_vpn_detect", "VPN tunnel detection", "warn", 20, "ifconfig failed", details=[err]))
    else:
        vpn_ifaces = parse_vpn_interfaces(out)
        checks.append(CheckResult("l5_vpn_detect", "VPN tunnel detection", "warn" if vpn_ifaces else "pass", 10 if vpn_ifaces else 0, "VPN-like interfaces present" if vpn_ifaces else "No VPN tunnel interface detected", metrics={"interfaces": vpn_ifaces}))

    code, out, _ = run_command(["netstat", "-rn"])
    via_tunnel = bool(re.search(r"\butun\d+\b", out)) if code == 0 else False
    checks.append(CheckResult("l5_vpn_routes", "VPN route indicators", "warn" if via_tunnel else "pass", 10 if via_tunnel else 0, "Routes indicate active tunnel" if via_tunnel else "No tunnel routes detected"))

    return LayerResult(layer=5, name="Session", checks=checks)
