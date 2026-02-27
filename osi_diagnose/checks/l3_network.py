from __future__ import annotations

import re

from osi_diagnose.checks.base import command_exists, run_command
from osi_diagnose.model import CheckResult, DiagnosticContext, LayerResult


def parse_ping_stats(output: str) -> dict[str, float]:
    loss_match = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
    rtt_match = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/", output)
    return {
        "packet_loss_percent": float(loss_match.group(1)) if loss_match else 100.0,
        "rtt_min_ms": float(rtt_match.group(1)) if rtt_match else 0.0,
        "rtt_avg_ms": float(rtt_match.group(2)) if rtt_match else 0.0,
        "rtt_max_ms": float(rtt_match.group(3)) if rtt_match else 0.0,
    }


def run_layer(context: DiagnosticContext) -> LayerResult:
    checks: list[CheckResult] = []

    route_info: dict[str, str] = {}
    code, out, _ = run_command(["netstat", "-rn"])
    if code == 0:
        route_info["default_route_seen"] = "default" if "default" in out else "missing"
    checks.append(CheckResult("l3_ip_summary", "IP and route summary", "pass", 0, "Collected route table", metrics=route_info))

    if context.gateway:
        code, out, err = run_command(["ping", "-c", "4", context.gateway], timeout=10)
        if code == 0:
            m = parse_ping_stats(out)
            status = "pass" if m["packet_loss_percent"] == 0 else "warn"
            checks.append(CheckResult("l3_ping_gateway", "Ping default gateway", status, 0 if status == "pass" else 30, "Gateway ping complete", metrics=m))
        else:
            checks.append(CheckResult("l3_ping_gateway", "Ping default gateway", "warn", 30, "Gateway ping failed", details=[err]))

    code, out, err = run_command(["ping", "-c", "4", context.ping_host], timeout=12)
    if code == 0:
        m = parse_ping_stats(out)
        status = "pass" if m["packet_loss_percent"] < 5 else "warn"
        checks.append(CheckResult("l3_ping_public", f"Ping {context.ping_host}", status, 0 if status == "pass" else 35, "Public ping complete", metrics=m))
    else:
        checks.append(CheckResult("l3_ping_public", f"Ping {context.ping_host}", "warn", 35, "Public ping failed", details=[err]))

    if command_exists("traceroute"):
        code, out, err = run_command(["traceroute", "-m", "8", "-w", "1", context.ping_host], timeout=20)
        status = "pass" if code == 0 else "warn"
        checks.append(CheckResult("l3_traceroute", "Traceroute", status, 10 if code != 0 else 0, "Traceroute complete" if code == 0 else "Traceroute failed", details=out.splitlines()[:8] if out else [err]))
    else:
        checks.append(CheckResult("l3_traceroute", "Traceroute", "skip", 5, "traceroute utility unavailable"))

    return LayerResult(layer=3, name="Network", checks=checks)
