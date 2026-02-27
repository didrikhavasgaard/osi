from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime

from rich.console import Console
from rich.prompt import Confirm, Prompt

from osi_diagnose.checks.base import run_command
from osi_diagnose.checks import l1_physical, l2_datalink, l3_network, l4_transport, l5_session, l6_presentation, l7_application
from osi_diagnose.model import DiagnosticContext, build_report
from osi_diagnose.openai_ai.summarize import generate_ai_summary
from osi_diagnose.rendering.redact import redact_payload
from osi_diagnose.rendering.report_md import write_reports
from osi_diagnose.rendering.terminal import render_report


def detect_defaults() -> DiagnosticContext:
    gateway = None
    code, out, _ = run_command(["route", "-n", "get", "default"])
    if code == 0:
        for line in out.splitlines():
            if "gateway:" in line:
                gateway = line.split(":", 1)[1].strip()
            if "interface:" in line:
                interface = line.split(":", 1)[1].strip()
                break
        else:
            interface = None
    else:
        interface = None

    local_ip = None
    if interface:
        code, ip_out, _ = run_command(["ipconfig", "getifaddr", interface])
        if code == 0:
            local_ip = ip_out.strip()

    dns_resolvers: list[str] = []
    code, scutil_out, _ = run_command(["scutil", "--dns"])
    if code == 0:
        for line in scutil_out.splitlines():
            line = line.strip()
            if line.startswith("nameserver["):
                dns_resolvers.append(line.split(":", 1)[1].strip())

    return DiagnosticContext(gateway=gateway, interface=interface, local_ip=local_ip, dns_resolvers=sorted(set(dns_resolvers)))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OSI diagnostics tool")
    p.add_argument("--json-only", action="store_true")
    p.add_argument("--no-openai", action="store_true")
    p.add_argument("--openai", action="store_true")
    p.add_argument("--out", default=f"reports/osi-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    p.add_argument("--target-host", default="example.com")
    p.add_argument("--ping-host", default="1.1.1.1")
    p.add_argument("--gateway")
    p.add_argument("--scan-gateway-ports", action="store_true")
    p.add_argument("--nmap-ports")
    return p.parse_args()


def wizard(console: Console, defaults: DiagnosticContext, args: argparse.Namespace) -> tuple[DiagnosticContext, bool]:
    console.print("[bold]osi-diagnose interactive wizard[/bold]")
    target = Prompt.ask("Target host for TLS/HTTP", default=args.target_host or defaults.target_host)
    ping_host = Prompt.ask("Public ping host", default=args.ping_host or defaults.ping_host)
    gateway_default = args.gateway or defaults.gateway or ""
    gateway = Prompt.ask("Gateway IP", default=gateway_default) if gateway_default else None
    scan = Confirm.ask("Run safe gateway port scan?", default=args.scan_gateway_ports)
    openai_enabled = False if args.no_openai else Confirm.ask("Enhance report with OpenAI?", default=args.openai)
    if openai_enabled:
        console.print("[yellow]Privacy note:[/] SSIDs are hashed and internal IPs masked by default before OpenAI submission.")
    return (
        DiagnosticContext(
            target_host=target,
            ping_host=ping_host,
            gateway=gateway,
            local_ip=defaults.local_ip,
            interface=defaults.interface,
            dns_resolvers=defaults.dns_resolvers,
            scan_gateway_ports=scan,
            nmap_ports=args.nmap_ports,
        ),
        openai_enabled,
    )


def run_checks(context: DiagnosticContext):
    return [
        l1_physical.run_layer(context),
        l2_datalink.run_layer(context),
        l3_network.run_layer(context),
        l4_transport.run_layer(context),
        l5_session.run_layer(context),
        l6_presentation.run_layer(context),
        l7_application.run_layer(context),
    ]


def main() -> None:
    args = parse_args()
    console = Console()

    defaults = detect_defaults()
    warnings: list[str] = []

    if any([args.openai, args.no_openai, args.json_only, args.gateway, args.scan_gateway_ports, args.nmap_ports]):
        context = defaults
        context.target_host = args.target_host
        context.ping_host = args.ping_host
        if args.gateway:
            context.gateway = args.gateway
        context.scan_gateway_ports = args.scan_gateway_ports
        context.nmap_ports = args.nmap_ports
        openai_enabled = args.openai and not args.no_openai
    else:
        context, openai_enabled = wizard(console, defaults, args)

    layers = run_checks(context)
    report = build_report(context, layers, warnings)

    if openai_enabled:
        payload = asdict(report)
        redacted = redact_payload(payload)
        try:
            report.ai_summary = generate_ai_summary(redacted)
        except Exception as exc:  # noqa: BLE001
            msg = f"OpenAI enhancement unavailable: {exc}"
            report.warnings.append(msg)
            console.print(f"[yellow]{msg}[/yellow]")

    json_path, md_path = write_reports(report, args.out)

    if not args.json_only:
        render_report(console, report)
        console.print(f"\n[green]Saved JSON:[/] {json_path}")
        console.print(f"[green]Saved Markdown:[/] {md_path}")


if __name__ == "__main__":
    main()
