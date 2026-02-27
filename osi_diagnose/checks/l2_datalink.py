from __future__ import annotations

import hashlib
import re

from osi_diagnose.checks.base import LayerCheck, run_cmd
from osi_diagnose.model import CheckResult, HostContext, LayerResult, RunConfig, Status


class Layer2DataLinkCheck(LayerCheck):
    layer = 2
    title = "Data Link"

    def run(self, config: RunConfig, context: HostContext) -> LayerResult:
        result = LayerResult(layer=self.layer, title=self.title)

        arp_out = run_cmd(["arp", "-a"])
        if arp_out.ok:
            gateway_seen = bool(context.gateway_ip and context.gateway_ip in arp_out.stdout)
            status = Status.PASS if gateway_seen else Status.WARN
            summary = "Gateway MAC present in ARP table" if gateway_seen else "Gateway MAC not seen in ARP snapshot"
            result.checks.append(
                CheckResult(
                    name="ARP snapshot",
                    status=status,
                    summary=summary,
                    metrics={"entries": len([l for l in arp_out.stdout.splitlines() if l.strip()])},
                )
            )

            mac_to_ips: dict[str, set[str]] = {}
            for line in arp_out.stdout.splitlines():
                m = re.search(r"\(([^)]+)\) at ([0-9a-f:]+)", line, re.IGNORECASE)
                if not m:
                    continue
                ip, mac = m.group(1), m.group(2).lower()
                mac_to_ips.setdefault(mac, set()).add(ip)
            suspicious = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 3}
            result.checks.append(
                CheckResult(
                    name="Duplicate IP/MAC symptoms",
                    status=Status.WARN if suspicious else Status.PASS,
                    summary="Potential duplicate-address symptom observed" if suspicious else "No obvious duplicate ARP symptom",
                    details={"suspicious": suspicious},
                )
            )
        else:
            result.checks.append(
                CheckResult(
                    name="ARP snapshot",
                    status=Status.SKIP,
                    summary="Could not read ARP table",
                    details={"error": arp_out.stderr},
                )
            )

        wifi_detail = _collect_corewlan_best_effort()
        if wifi_detail:
            rssi = wifi_detail.get("rssi")
            status = Status.PASS if isinstance(rssi, int) and rssi >= -67 else Status.WARN
            ssid = wifi_detail.get("ssid")
            ssid_hash = hashlib.sha256(ssid.encode()).hexdigest()[:10] if ssid else None
            result.checks.append(
                CheckResult(
                    name="Wi-Fi PHY details",
                    status=status,
                    summary="Collected via CoreWLAN",
                    metrics={
                        "ssid_hash": ssid_hash,
                        "rssi": rssi,
                        "noise": wifi_detail.get("noise"),
                        "tx_rate": wifi_detail.get("tx_rate"),
                    },
                )
            )
        else:
            result.checks.append(
                CheckResult(
                    name="Wi-Fi PHY details",
                    status=Status.SKIP,
                    summary="PyObjC/CoreWLAN not available or no Wi-Fi interface",
                )
            )
        return result


def _collect_corewlan_best_effort() -> dict[str, int | str] | None:
    try:
        from CoreWLAN import CWWiFiClient  # type: ignore
    except Exception:
        return None
    try:
        client = CWWiFiClient.sharedWiFiClient()
        iface = client.interface()
        if iface is None:
            return None
        return {
            "ssid": iface.ssid() or "",
            "rssi": int(iface.rssiValue()),
            "noise": int(iface.noiseMeasurement()),
            "tx_rate": int(iface.transmitRate()),
        }
    except Exception:
        return None
