from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckResult:
    check_id: str
    name: str
    status: str  # pass|warn|fail|skip
    severity: int  # 0-100
    summary: str
    metrics: dict[str, Any] = field(default_factory=dict)
    details: list[str] = field(default_factory=list)


@dataclass
class LayerResult:
    layer: int
    name: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def status(self) -> str:
        if any(c.status == "fail" for c in self.checks):
            return "fail"
        if any(c.status == "warn" for c in self.checks):
            return "warn"
        if all(c.status == "skip" for c in self.checks) and self.checks:
            return "skip"
        return "pass"


@dataclass
class DiagnosticContext:
    target_host: str = "example.com"
    ping_host: str = "1.1.1.1"
    gateway: str | None = None
    local_ip: str | None = None
    interface: str | None = None
    dns_resolvers: list[str] = field(default_factory=list)
    scan_gateway_ports: bool = False
    nmap_ports: str | None = None


@dataclass
class ReportBundle:
    generated_at: str
    host: str
    context: DiagnosticContext
    layers: list[LayerResult]
    warnings: list[str] = field(default_factory=list)
    ai_summary: str | None = None

    @property
    def health_score(self) -> int:
        all_checks = [c for layer in self.layers for c in layer.checks]
        if not all_checks:
            return 0
        penalties = sum(c.severity for c in all_checks)
        baseline = len(all_checks) * 100
        return max(0, min(100, int((baseline - penalties) / max(1, len(all_checks)))))


def build_report(context: DiagnosticContext, layers: list[LayerResult], warnings: list[str]) -> ReportBundle:
    import socket

    return ReportBundle(
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        host=socket.gethostname(),
        context=context,
        layers=layers,
        warnings=warnings,
    )
