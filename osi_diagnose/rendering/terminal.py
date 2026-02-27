from __future__ import annotations

from osi_diagnose.model import DiagnosticReport, Status, health_score, layer_status


ICON = {
    Status.PASS: "[green]✔[/green]",
    Status.WARN: "[yellow]⚠[/yellow]",
    Status.FAIL: "[red]✖[/red]",
    Status.SKIP: "[blue]•[/blue]",
}


def render_terminal(report: DiagnosticReport, console: Console | None = None) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        console = console or Console()
        score = health_score(report)
        color = "green" if score >= 85 else "yellow" if score >= 65 else "red"
        banner = Text(f"OSI Diagnose Health Score: {score}/100", style=f"bold {color}")
        console.print(Panel(banner, title="osi-diagnose", subtitle="macOS diagnostics"))

        context = Table(title="Host Context", show_header=True, header_style="bold cyan")
        context.add_column("Key")
        context.add_column("Value")
        context.add_row("Hostname", report.context.hostname)
        context.add_row("OS", report.context.os_name)
        context.add_row("Interface", str(report.context.default_interface))
        context.add_row("Local IP", str(report.context.local_ip))
        context.add_row("Gateway", str(report.context.gateway_ip))
        context.add_row("DNS", ", ".join(report.context.dns_servers) or "n/a")
        console.print(context)

        for layer in report.layers:
            status = layer_status(layer)
            table = Table(title=f"Layer {layer.layer}: {layer.title} {ICON[status]}", show_lines=True)
            table.add_column("Status", width=8)
            table.add_column("Check")
            table.add_column("Summary")
            table.add_column("Metrics")
            for check in layer.checks:
                metrics = ", ".join(f"{k}={v}" for k, v in check.metrics.items()) if check.metrics else "-"
                table.add_row(ICON[check.status], check.name, check.summary, metrics)
            console.print(table)

        if report.warnings:
            warn_text = "\n".join(f"- {w}" for w in report.warnings)
            console.print(Panel(warn_text, title="Warnings", border_style="yellow"))

        if report.ai_summary:
            ai = report.ai_summary
            console.print(Panel(ai.get("executive_summary", ""), title="AI Executive Summary", border_style="magenta"))
    except Exception:
        _render_plain(report)


def _render_plain(report: DiagnosticReport) -> None:
    print(f"osi-diagnose health score: {health_score(report)}/100")
    print(f"host={report.context.hostname} local_ip={report.context.local_ip} gateway={report.context.gateway_ip}")
    for layer in report.layers:
        print(f"[L{layer.layer}] {layer.title} ({layer_status(layer).value})")
        for check in layer.checks:
            print(f"  - {check.status.value.upper()} {check.name}: {check.summary}")
    if report.warnings:
        print("warnings:")
        for warning in report.warnings:
            print(f"  - {warning}")
