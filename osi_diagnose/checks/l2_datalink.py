from __future__ import annotations

import ipaddress
import re

from osi_diagnose.checks.base import run_command
from osi_diagnose.model import CheckResult, DiagnosticContext, LayerResult


def parse_arp_table(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        m = re.search(r"\(([^)]+)\) at ([0-9a-f:]+|\(incomplete\)) on (\w+)", line, flags=re.I)
        if m:
            rows.append({"ip": m.group(1), "mac": m.group(2), "interface": m.group(3)})
    return rows


def wifi_details() -> tuple[dict[str, str], str | None]:
    try:
        from CoreWLAN import CWInterface  # type: ignore

        iface = CWInterface.interface()
        if not iface:
            return {}, "CoreWLAN interface unavailable"
        return {
            "ssid": iface.ssid() or "",
            "rssi": str(iface.rssiValue()),
            "noise": str(iface.noiseMeasurement()),
            "tx_rate": str(iface.transmitRate()),
        }, None
    except Exception as exc:  # noqa: BLE001
        return {}, str(exc)


def run_layer(context: DiagnosticContext) -> LayerResult:
    checks: list[CheckResult] = []
    code, out, err = run_command(["arp", "-a"])
    if code != 0:
        checks.append(CheckResult("l2_arp", "ARP snapshot", "warn", 20, "ARP query failed", details=[err]))
    else:
        arp_rows = parse_arp_table(out)
        gw_mac_found = any(r["ip"] == context.gateway for r in arp_rows) if context.gateway else False
        checks.append(
            CheckResult(
                "l2_arp",
                "ARP snapshot",
                "pass" if arp_rows else "warn",
                0 if arp_rows else 20,
                f"ARP entries: {len(arp_rows)}",
                metrics={"entries": len(arp_rows), "gateway_mac_present": gw_mac_found},
            )
        )

        dup_hints = len({r['ip'] for r in arp_rows}) != len(arp_rows)
        checks.append(
            CheckResult(
                "l2_duplicate_symptoms",
                "Duplicate IP/MAC symptoms",
                "warn" if dup_hints else "pass",
                25 if dup_hints else 0,
                "Potential duplicate ARP records" if dup_hints else "No duplicate symptoms visible",
            )
        )

    details, error = wifi_details()
    if details:
        checks.append(CheckResult("l2_wifi_phy", "Wi-Fi PHY details", "pass", 0, "Collected CoreWLAN metrics", metrics=details))
    else:
        checks.append(CheckResult("l2_wifi_phy", "Wi-Fi PHY details", "skip", 5, "CoreWLAN unavailable", details=[error] if error else []))

    return LayerResult(layer=2, name="Data Link", checks=checks)
