from __future__ import annotations

import socket

from osi_diagnose.checks.base import LayerCheck, run_cmd, which
from osi_diagnose.model import CheckResult, HostContext, LayerResult, RunConfig, Status


COMMON_TARGETS = [("DNS TCP", 53), ("HTTPS", 443)]


class Layer4TransportCheck(LayerCheck):
    layer = 4
    title = "Transport"

    def run(self, config: RunConfig, context: HostContext) -> LayerResult:
        result = LayerResult(layer=self.layer, title=self.title)

        host = config.target_host
        for label, port in COMMON_TARGETS:
            ok, err = _tcp_connect(host, port)
            result.checks.append(
                CheckResult(
                    name=f"TCP connect {label}",
                    status=Status.PASS if ok else Status.WARN,
                    summary=f"{host}:{port} reachable" if ok else f"{host}:{port} connect failed",
                    details={} if ok else {"error": err},
                )
            )

        if which("dig"):
            dig = run_cmd(["dig", "+time=2", "+tries=1", config.target_host])
            result.checks.append(
                CheckResult(
                    name="DNS query via dig",
                    status=Status.PASS if dig.ok else Status.WARN,
                    summary="dig query succeeded" if dig.ok else "dig query failed",
                    details={} if dig.ok else {"error": dig.stderr or dig.stdout},
                )
            )
        else:
            result.checks.append(
                CheckResult(
                    name="DNS query via dig",
                    status=Status.SKIP,
                    summary="dig not installed",
                )
            )

        udp_ntp = _udp_probe("time.apple.com", 123)
        result.checks.append(
            CheckResult(
                name="UDP NTP best-effort",
                status=Status.PASS if udp_ntp else Status.WARN,
                summary="UDP packet send to NTP endpoint succeeded" if udp_ntp else "Could not validate UDP NTP reachability",
            )
        )

        if config.scan_gateway_ports and context.gateway_ip:
            ports = [22, 53, 80, 443, 445]
            if which("nmap"):
                args = ["nmap", "-Pn", "-p", ",".join(str(p) for p in ports), context.gateway_ip]
                out = run_cmd(args, timeout=20)
                result.checks.append(
                    CheckResult(
                        name="Gateway safe port scan",
                        status=Status.PASS if out.ok else Status.WARN,
                        summary="nmap gateway scan completed" if out.ok else "nmap gateway scan failed",
                        details={"output": out.stdout[-1200:] if out.stdout else out.stderr},
                    )
                )
            else:
                open_ports = [p for p in ports if _tcp_connect(context.gateway_ip, p)[0]]
                result.checks.append(
                    CheckResult(
                        name="Gateway safe port scan",
                        status=Status.PASS,
                        summary="Lightweight TCP connect scan completed",
                        metrics={"open_ports": open_ports},
                    )
                )

        if config.nmap_ports:
            if which("nmap"):
                result.checks.append(
                    CheckResult(
                        name="Advanced nmap scan",
                        status=Status.WARN,
                        summary="Only run scans on authorized targets",
                    )
                )
                target = context.gateway_ip or config.ping_host
                out = run_cmd(["nmap", "-Pn", "-p", config.nmap_ports, target], timeout=25)
                result.checks.append(
                    CheckResult(
                        name="Advanced nmap scan result",
                        status=Status.PASS if out.ok else Status.WARN,
                        summary="Advanced scan completed" if out.ok else "Advanced scan failed",
                        details={"output": out.stdout[-1500:] if out.stdout else out.stderr},
                    )
                )
            else:
                result.checks.append(
                    CheckResult(
                        name="Advanced nmap scan",
                        status=Status.SKIP,
                        summary="nmap not installed",
                    )
                )

        return result


def _tcp_connect(host: str, port: int, timeout: float = 2.5) -> tuple[bool, str | None]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, None
    except OSError as exc:
        return False, str(exc)


def _udp_probe(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.0)
            sock.sendto(b"\x1b" + 47 * b"\0", (host, port))
        return True
    except OSError:
        return False
