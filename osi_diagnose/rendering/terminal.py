from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osi_diagnose.model import ReportBundle

ICON = {"pass": "✅", "warn": "⚠️", "fail": "❌", "skip": "⏭"}
COLOR = {"pass": "green", "warn": "yellow", "fail": "red", "skip": "cyan"}


def render_report(console: Console, report: ReportBundle) -> None:
    score = report.health_score
    color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
    console.print(Panel.fit(f"[bold {color}]󰓅 Health Score: {score}/100[/]", title="osi-diagnose"))

    for layer in report.layers:
        table = Table(title=f"Layer {layer.layer}: {layer.name}", show_lines=True)
        table.add_column("Status", width=8)
        table.add_column("Check")
        table.add_column("Summary")
        for check in layer.checks:
            style = COLOR.get(check.status, "white")
            table.add_row(f"[{style}]{ICON.get(check.status, '•')} {check.status}[/{style}]", check.name, check.summary)
        console.print(table)

    if report.warnings:
        console.print(Panel("\n".join(f"⚠️ {w}" for w in report.warnings), title="Warnings", border_style="yellow"))
