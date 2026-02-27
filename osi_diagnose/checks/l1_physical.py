from __future__ import annotations

import re

from osi_diagnose.checks.base import BaseCheck, command_exists, run_command
from osi_diagnose.model import CheckResult, DiagnosticContext, LayerResult


def parse_ifconfig_status(output: str, interface: str | None) -> dict[str, str]:
    if not interface:
        return {"status": "unknown"}
    pattern = rf"{re.escape(interface)}:.*?(?:\n\t.*?)*status: (\w+)"
    match = re.search(pattern, output, flags=re.DOTALL)
    return {"status": match.group(1) if match else "unknown"}


class InterfaceLinkCheck(BaseCheck):
    check_id = "l1_interface_link"
    name = "Interface link status"

    def run(self, context: DiagnosticContext) -> CheckResult:
        code, out, err = run_command(["ifconfig"])
        if code != 0:
            return CheckResult(self.check_id, self.name, "warn", 20, "ifconfig unavailable", details=[err])
        metrics = parse_ifconfig_status(out, context.interface)
        status = "pass" if metrics.get("status") == "active" else "warn"
        severity = 0 if status == "pass" else 30
        return CheckResult(self.check_id, self.name, status, severity, f"Link status {metrics.get('status')}", metrics=metrics)


class NetworkQualityCheck(BaseCheck):
    check_id = "l1_network_quality"
    name = "macOS network quality"

    def run(self, context: DiagnosticContext) -> CheckResult:
        if not command_exists("networkQuality"):
            return CheckResult(self.check_id, self.name, "skip", 5, "networkQuality not found")
        code, out, err = run_command(["networkQuality", "-c"], timeout=35)
        if code != 0:
            return CheckResult(self.check_id, self.name, "warn", 20, "networkQuality failed", details=[err])
        down = re.search(r"Downlink capacity:\s+([\d.]+)", out)
        up = re.search(r"Uplink capacity:\s+([\d.]+)", out)
        metrics = {
            "downlink_mbps": float(down.group(1)) if down else None,
            "uplink_mbps": float(up.group(1)) if up else None,
        }
        return CheckResult(self.check_id, self.name, "pass", 0, "Collected network quality", metrics=metrics)


def run_layer(context: DiagnosticContext) -> LayerResult:
    checks = [InterfaceLinkCheck().run(context), NetworkQualityCheck().run(context)]
    checks.append(
        CheckResult(
            "l1_link_flaps",
            "Link flap history",
            "skip",
            5,
            "Local historical flap detection is limited without privileged telemetry",
        )
    )
    return LayerResult(layer=1, name="Physical", checks=checks)
