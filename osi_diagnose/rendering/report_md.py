from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from osi_diagnose.model import ReportBundle


def write_reports(report: ReportBundle, out_prefix: str) -> tuple[Path, Path]:
    prefix = Path(out_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)

    json_path = prefix.with_suffix(".json")
    md_path = prefix.with_suffix(".md")

    json_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")

    lines = [
        f"# osi-diagnose report",
        "",
        f"Generated: `{report.generated_at}`",
        f"Host: `{report.host}`",
        f"Health score: **{report.health_score}/100**",
        "",
    ]

    for layer in report.layers:
        lines.append(f"## Layer {layer.layer}: {layer.name}")
        lines.append("")
        for check in layer.checks:
            lines.append(f"- **{check.name}** ({check.status}): {check.summary}")
            if check.metrics:
                lines.append(f"  - Metrics: `{json.dumps(check.metrics)}`")
            for detail in check.details:
                lines.append(f"  - Detail: {detail}")
        lines.append("")

    if report.ai_summary:
        lines.append("## AI Summary")
        lines.append("")
        lines.append(report.ai_summary)
        lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
