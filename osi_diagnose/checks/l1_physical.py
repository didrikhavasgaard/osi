from __future__ import annotations

from osi_diagnose.checks.base import LayerCheck, parse_network_quality_json, run_cmd, which
from osi_diagnose.model import CheckResult, HostContext, LayerResult, RunConfig, Status


class Layer1PhysicalCheck(LayerCheck):
    layer = 1
    title = "Physical"

    def run(self, config: RunConfig, context: HostContext) -> LayerResult:
        result = LayerResult(layer=self.layer, title=self.title)

        if context.default_interface:
            iface = context.default_interface
            out = run_cmd(["ifconfig", iface])
            if out.ok:
                summary = "Interface appears active" if "status: active" in out.stdout else "Interface may be inactive"
                status = Status.PASS if "status: active" in out.stdout else Status.WARN
                result.checks.append(
                    CheckResult(
                        name="Interface link state",
                        status=status,
                        summary=summary,
                        metrics={"interface": iface},
                    )
                )
            else:
                result.checks.append(
                    CheckResult(
                        name="Interface link state",
                        status=Status.SKIP,
                        summary="Could not read interface state",
                        details={"error": out.stderr},
                    )
                )

        if which("networkQuality"):
            out = run_cmd(["networkQuality", "-c", "-v", "-J"], timeout=20)
            if out.ok:
                parsed = parse_network_quality_json(out.stdout)
                down = parsed.get("dl_throughput")
                up = parsed.get("ul_throughput")
                resp = parsed.get("responsiveness")
                result.checks.append(
                    CheckResult(
                        name="Line quality",
                        status=Status.PASS,
                        summary="Measured with networkQuality",
                        metrics={
                            "downlink_Mbps": down,
                            "uplink_Mbps": up,
                            "responsiveness": resp,
                        },
                    )
                )
            else:
                result.checks.append(
                    CheckResult(
                        name="Line quality",
                        status=Status.WARN,
                        summary="networkQuality command failed",
                        details={"error": out.stderr},
                    )
                )
        else:
            result.checks.append(
                CheckResult(
                    name="Line quality",
                    status=Status.SKIP,
                    summary="networkQuality not available on this macOS",
                )
            )

        result.checks.append(
            CheckResult(
                name="Link flap detection",
                status=Status.SKIP,
                summary="Historical interface flap detection requires log sampling and is not enabled by default",
            )
        )
        return result
