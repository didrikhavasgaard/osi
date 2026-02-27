from __future__ import annotations

import socket
import time
import urllib.request

from osi_diagnose.checks.base import LayerCheck
from osi_diagnose.model import CheckResult, HostContext, LayerResult, RunConfig, Status


DOMAINS = ["example.com", "openai.com", "apple.com"]


class Layer7ApplicationCheck(LayerCheck):
    layer = 7
    title = "Application"

    def run(self, config: RunConfig, context: HostContext) -> LayerResult:
        result = LayerResult(layer=self.layer, title=self.title)

        resolver_results: dict[str, list[str]] = {}
        dns_ok = True
        for domain in DOMAINS:
            try:
                infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
                resolver_results[domain] = sorted({info[4][0] for info in infos})
            except OSError:
                resolver_results[domain] = []
                dns_ok = False
        result.checks.append(
            CheckResult(
                name="DNS resolution",
                status=Status.PASS if dns_ok else Status.WARN,
                summary="System resolver test across sample domains",
                metrics={"domains": resolver_results},
            )
        )

        url = f"https://{config.target_host}/"
        try:
            start = time.perf_counter()
            with urllib.request.urlopen(url, timeout=6) as resp:
                _ = resp.read(256)
            ttfb_ms = (time.perf_counter() - start) * 1000.0
            status = Status.PASS if ttfb_ms < 800 else Status.WARN
            result.checks.append(
                CheckResult(
                    name="HTTPS latency",
                    status=status,
                    summary="Small HTTPS fetch to estimate TTFB",
                    metrics={"url": url, "ttfb_ms": round(ttfb_ms, 2)},
                )
            )
        except Exception as exc:
            result.checks.append(
                CheckResult(
                    name="HTTPS latency",
                    status=Status.WARN,
                    summary="HTTPS latency test failed",
                    details={"error": str(exc)},
                )
            )

        portal_url = "http://captive.apple.com/hotspot-detect.html"
        try:
            with urllib.request.urlopen(portal_url, timeout=4) as resp:
                body = resp.read(512).decode(errors="ignore")
            captive = "Success" not in body
            result.checks.append(
                CheckResult(
                    name="Captive portal detection",
                    status=Status.WARN if captive else Status.PASS,
                    summary="Potential captive portal or interception detected" if captive else "No captive portal signature detected",
                )
            )
        except Exception as exc:
            result.checks.append(
                CheckResult(
                    name="Captive portal detection",
                    status=Status.SKIP,
                    summary="Could not complete captive portal check",
                    details={"error": str(exc)},
                )
            )

        ntp_ok = _best_effort_ntp()
        result.checks.append(
            CheckResult(
                name="NTP reachability",
                status=Status.PASS if ntp_ok else Status.WARN,
                summary="NTP endpoint appears reachable" if ntp_ok else "NTP reachability uncertain",
            )
        )

        return result


def _best_effort_ntp() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.sendto(b"\x1b" + 47 * b"\0", ("time.apple.com", 123))
        return True
    except OSError:
        return False
