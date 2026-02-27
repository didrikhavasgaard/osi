from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from osi_diagnose.checks.base import LayerCheck
from osi_diagnose.model import CheckResult, HostContext, LayerResult, RunConfig, Status


class Layer6PresentationCheck(LayerCheck):
    layer = 6
    title = "Presentation"

    def run(self, config: RunConfig, context: HostContext) -> LayerResult:
        result = LayerResult(layer=self.layer, title=self.title)
        host = config.target_host
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    tls_ver = tls.version()
            not_after = cert.get("notAfter")
            expiry = None
            if not_after:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
            result.checks.append(
                CheckResult(
                    name="TLS sanity",
                    status=Status.PASS,
                    summary="TLS handshake succeeded",
                    metrics={
                        "tls_version": tls_ver,
                        "subject": cert.get("subject", []),
                        "issuer": cert.get("issuer", []),
                        "expires": expiry,
                    },
                )
            )
        except Exception as exc:
            result.checks.append(
                CheckResult(
                    name="TLS sanity",
                    status=Status.WARN,
                    summary="TLS handshake failed",
                    details={"error": str(exc)},
                )
            )
        return result
