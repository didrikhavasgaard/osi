from __future__ import annotations

import socket
import time
import urllib.request

from osi_diagnose.checks.base import command_exists, run_command
from osi_diagnose.model import CheckResult, DiagnosticContext, LayerResult


def dns_lookup(domain: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(domain, None)})


def run_layer(context: DiagnosticContext) -> LayerResult:
    checks: list[CheckResult] = []

    test_domains = ["example.com", "openai.com", context.target_host]
    resolved: dict[str, list[str]] = {}
    for domain in test_domains:
        try:
            resolved[domain] = dns_lookup(domain)
        except OSError:
            resolved[domain] = []
    status = "pass" if all(resolved.values()) else "warn"
    checks.append(CheckResult("l7_dns", "DNS resolution", status, 0 if status == "pass" else 30, "DNS resolution check complete", metrics=resolved))

    try:
        t0 = time.perf_counter()
        with urllib.request.urlopen(f"https://{context.target_host}", timeout=5) as resp:
            resp.read(128)
            elapsed = (time.perf_counter() - t0) * 1000
            checks.append(CheckResult("l7_https_latency", "HTTPS TTFB", "pass", 0, "HTTPS request successful", metrics={"status": resp.status, "ttfb_ms": round(elapsed, 2)}))
    except Exception as exc:  # noqa: BLE001
        checks.append(CheckResult("l7_https_latency", "HTTPS TTFB", "warn", 20, "HTTPS request failed", details=[str(exc)]))

    if command_exists("nc"):
        code, _, err = run_command(["nc", "-z", "-u", "-G", "2", "time.apple.com", "123"])
        checks.append(CheckResult("l7_ntp", "NTP reachability", "pass" if code == 0 else "warn", 0 if code == 0 else 15, "NTP probe complete", details=[err] if err else []))
    else:
        checks.append(CheckResult("l7_ntp", "NTP reachability", "skip", 5, "nc utility unavailable"))

    portal = False
    try:
        with urllib.request.urlopen("http://captive.apple.com/hotspot-detect.html", timeout=5) as resp:
            body = resp.read(512).decode(errors="ignore")
            portal = "Success" not in body
    except Exception:
        portal = False
    checks.append(CheckResult("l7_captive_portal", "Captive portal heuristic", "warn" if portal else "pass", 20 if portal else 0, "Captive portal likely detected" if portal else "No captive portal signs"))

    return LayerResult(layer=7, name="Application", checks=checks)
