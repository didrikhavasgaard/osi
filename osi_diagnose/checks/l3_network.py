from __future__ import annotations

import re

from osi_diagnose.checks.base import LayerCheck, run_cmd
from osi_diagnose.model import CheckResult, HostContext, LayerResult, RunConfig, Status


PING_PACKET_RE = re.compile(r"(?P<tx>\d+) packets transmitted, (?P<rx>\d+) packets received, (?P<loss>[0-9.]+)% packet loss")
PING_RTT_RE = re.compile(
    r"round-trip min/avg/max(?:/stddev)? = (?P<min>[0-9.]+)/(?P<avg>[0-9.]+)/(?P<max>[0-9.]+)(?:/(?P<stddev>[0-9.]+))? ms"
)


class Layer3NetworkCheck(LayerCheck):
    layer = 3
    title = "Network"

    def run(self, config: RunConfig, context: HostContext) -> LayerResult:
        result = LayerResult(layer=self.layer, title=self.title)

        route = run_cmd(["netstat", "-rn"])
        if route.ok:
            result.checks.append(
                CheckResult(
                    name="IP config summary",
                    status=Status.PASS,
                    summary="Collected routes and local addressing",
                    metrics={
                        "local_ip": context.local_ip,
                        "gateway": context.gateway_ip,
                        "default_interface": context.default_interface,
                    },
                )
            )
        else:
            result.checks.append(
                CheckResult(
                    name="IP config summary",
                    status=Status.SKIP,
                    summary="Could not collect route table",
                    details={"error": route.stderr},
                )
            )

        if context.gateway_ip:
            gw_ping = run_cmd(["ping", "-c", "4", "-W", "1000", context.gateway_ip], timeout=8)
            result.checks.append(_ping_result("Ping gateway", context.gateway_ip, gw_ping.stdout if gw_ping.ok else gw_ping.stderr))

        pub_ping = run_cmd(["ping", "-c", "4", "-W", "1000", config.ping_host], timeout=8)
        result.checks.append(_ping_result("Ping public host", config.ping_host, pub_ping.stdout if pub_ping.ok else pub_ping.stderr))

        trace = run_cmd(["traceroute", "-m", "8", "-w", "1", config.ping_host], timeout=15)
        if trace.ok:
            hops = len([l for l in trace.stdout.splitlines()[1:] if l.strip()])
            result.checks.append(
                CheckResult(
                    name="Traceroute",
                    status=Status.PASS,
                    summary="Traceroute completed",
                    metrics={"hops_observed": hops},
                )
            )
        else:
            result.checks.append(
                CheckResult(
                    name="Traceroute",
                    status=Status.WARN,
                    summary="Traceroute failed or timed out",
                    details={"error": trace.stderr or trace.stdout},
                )
            )

        return result


def parse_ping_output(text: str) -> dict[str, float | int]:
    parsed: dict[str, float | int] = {}
    pkt = PING_PACKET_RE.search(text)
    if pkt:
        parsed["tx"] = int(pkt.group("tx"))
        parsed["rx"] = int(pkt.group("rx"))
        parsed["loss_pct"] = float(pkt.group("loss"))
    rtt = PING_RTT_RE.search(text)
    if rtt:
        parsed["min_ms"] = float(rtt.group("min"))
        parsed["avg_ms"] = float(rtt.group("avg"))
        parsed["max_ms"] = float(rtt.group("max"))
        stddev = rtt.group("stddev")
        if stddev is not None:
            parsed["jitter_ms"] = float(stddev)
    return parsed


def _ping_result(name: str, host: str, text: str) -> CheckResult:
    metrics = parse_ping_output(text)
    loss = float(metrics.get("loss_pct", 100.0)) if metrics else 100.0
    if loss == 0:
        status = Status.PASS
    elif loss < 30:
        status = Status.WARN
    else:
        status = Status.FAIL
    return CheckResult(
        name=name,
        status=status,
        summary=f"ICMP test to {host}",
        metrics=metrics,
    )
