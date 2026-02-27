from __future__ import annotations

import socket
import ssl

from osi_diagnose.model import CheckResult, DiagnosticContext, LayerResult


def tls_probe(host: str, port: int = 443) -> dict[str, str]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=4) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            return {
                "tls_version": ssock.version() or "unknown",
                "cipher": ssock.cipher()[0] if ssock.cipher() else "unknown",
                "subject": str(cert.get("subject", "")),
                "issuer": str(cert.get("issuer", "")),
            }


def run_layer(context: DiagnosticContext) -> LayerResult:
    checks: list[CheckResult] = []
    try:
        metrics = tls_probe(context.target_host)
        checks.append(CheckResult("l6_tls", "TLS handshake sanity", "pass", 0, "TLS handshake successful", metrics=metrics))
    except Exception as exc:  # noqa: BLE001
        checks.append(CheckResult("l6_tls", "TLS handshake sanity", "warn", 30, "TLS handshake failed", details=[str(exc)]))

    return LayerResult(layer=6, name="Presentation", checks=checks)
