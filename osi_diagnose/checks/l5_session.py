from __future__ import annotations

from osi_diagnose.checks.base import LayerCheck, run_cmd
from osi_diagnose.model import CheckResult, HostContext, LayerResult, RunConfig, Status


class Layer5SessionCheck(LayerCheck):
    layer = 5
    title = "Session"

    def run(self, config: RunConfig, context: HostContext) -> LayerResult:
        result = LayerResult(layer=self.layer, title=self.title)

        vpn_ifaces = [i for i in context.interfaces if i.startswith(("utun", "tun", "wg"))]
        result.checks.append(
            CheckResult(
                name="VPN interface detection",
                status=Status.WARN if vpn_ifaces else Status.PASS,
                summary="Possible VPN interface(s) detected" if vpn_ifaces else "No VPN interfaces detected",
                metrics={"vpn_interfaces": vpn_ifaces},
            )
        )

        route = run_cmd(["netstat", "-rn"])
        if route.ok:
            has_split = any("utun" in line and "default" in line for line in route.stdout.splitlines())
            result.checks.append(
                CheckResult(
                    name="VPN route posture",
                    status=Status.WARN if has_split else Status.PASS,
                    summary="VPN default route may be active" if has_split else "No default VPN route seen",
                )
            )
        else:
            result.checks.append(
                CheckResult(
                    name="VPN route posture",
                    status=Status.SKIP,
                    summary="Could not inspect routes",
                    details={"error": route.stderr},
                )
            )

        return result
