from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from osi_diagnose.model import DiagnosticReport, Status, health_score


def write_json_report(report: DiagnosticReport, out_prefix: Path) -> Path:
    path = out_prefix.with_suffix(".json")
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path


def write_markdown_report(report: DiagnosticReport, out_prefix: Path) -> Path:
    path = out_prefix.with_suffix(".md")
    lines: list[str] = []
    lines.append("# OSI Diagnose Report")
    lines.append("")
    lines.append(f"- Generated at: `{report.generated_at}`")
    lines.append(f"- Health score: **{health_score(report)}/100**")
    lines.append("")
    lines.append("## Host Context")
    lines.append("")
    lines.append(f"- Hostname: `{report.context.hostname}`")
    lines.append(f"- OS: `{report.context.os_name}`")
    lines.append(f"- Default interface: `{report.context.default_interface}`")
    lines.append(f"- Local IP: `{report.context.local_ip}`")
    lines.append(f"- Gateway: `{report.context.gateway_ip}`")
    lines.append(f"- DNS servers: `{', '.join(report.context.dns_servers)}`")
    lines.append("")

    for layer in report.layers:
        lines.append(f"## Layer {layer.layer} - {layer.title}")
        lines.append("")
        lines.append("| Status | Check | Summary | Metrics |")
        lines.append("|---|---|---|---|")
        for check in layer.checks:
            metric_text = _fmt_metrics(check.metrics)
            lines.append(f"| {check.status.value.upper()} | {check.name} | {check.summary} | {metric_text} |")
        lines.append("")

    if report.ai_summary:
        lines.append("## AI Summary")
        lines.append("")
        lines.append("### Executive Summary")
        lines.append(report.ai_summary.get("executive_summary", ""))
        lines.append("")
        lines.append("### Top OSI Problems")
        for item in report.ai_summary.get("top_problems", []):
            lines.append(f"- {item}")
        lines.append("")
        lines.append("### Prioritized Remediation Checklist")
        for item in report.ai_summary.get("remediation", []):
            lines.append(f"- {item}")
        lines.append("")
        lines.append("### Package Recommendation")
        lines.append(report.ai_summary.get("package_recommendation", ""))
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_report(report: DiagnosticReport, out_prefix: Path) -> Path:
    path = out_prefix.with_suffix(".html")
    md_path = write_markdown_report(report, out_prefix)
    md = md_path.read_text(encoding="utf-8")
    html = f"""<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>OSI Diagnose Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; max-width: 980px; margin: 2rem auto; line-height: 1.5; }}
    pre, code {{ background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 4px; }}
  </style>
</head>
<body>
<pre>{md}</pre>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return path


def _fmt_metrics(metrics: dict[str, Any]) -> str:
    if not metrics:
        return "-"
    chunks: list[str] = []
    for key, value in metrics.items():
        if isinstance(value, dict):
            chunks.append(f"{key}={json.dumps(value)}")
        else:
            chunks.append(f"{key}={value}")
    return "<br/>".join(chunks)
