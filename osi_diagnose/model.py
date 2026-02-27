from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(slots=True)
class CheckResult:
    name: str
    status: Status
    summary: str
    metrics: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class LayerResult:
    layer: int
    title: str
    checks: list[CheckResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RunConfig:
    target_host: str = "example.com"
    ping_host: str = "1.1.1.1"
    gateway_override: str | None = None
    out_prefix: str | None = None
    json_only: bool = False
    openai_enabled: bool = False
    openai_redact: bool = True
    openai_allow_sensitive: bool = False
    scan_gateway_ports: bool = False
    nmap_ports: str | None = None
    html_report: bool = False


@dataclass(slots=True)
class HostContext:
    os_name: str
    hostname: str
    interfaces: list[str]
    default_interface: str | None
    local_ip: str | None
    gateway_ip: str | None
    dns_servers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DiagnosticReport:
    generated_at: str
    config: RunConfig
    context: HostContext
    layers: list[LayerResult]
    warnings: list[str] = field(default_factory=list)
    ai_summary: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def new(cls, config: RunConfig, context: HostContext) -> "DiagnosticReport":
        return cls(
            generated_at=datetime.now(timezone.utc).isoformat(),
            config=config,
            context=context,
            layers=[],
            warnings=[],
            ai_summary=None,
        )


def layer_status(layer: LayerResult) -> Status:
    statuses = {c.status for c in layer.checks}
    if Status.FAIL in statuses:
        return Status.FAIL
    if Status.WARN in statuses:
        return Status.WARN
    if statuses == {Status.SKIP}:
        return Status.SKIP
    return Status.PASS


def health_score(report: DiagnosticReport) -> int:
    score = 100
    for layer in report.layers:
        for check in layer.checks:
            if check.status == Status.FAIL:
                score -= 15
            elif check.status == Status.WARN:
                score -= 7
            elif check.status == Status.SKIP:
                score -= 2
    return max(0, score)
