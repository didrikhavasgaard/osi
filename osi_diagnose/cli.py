from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from osi_diagnose.checks import ALL_CHECKS
from osi_diagnose.checks.base import detect_context
from osi_diagnose.model import DiagnosticReport, RunConfig
from osi_diagnose.openai_ai.summarize import summarize_with_openai
from osi_diagnose.rendering.redact import redact_report_payload
from osi_diagnose.rendering.report_md import write_html_report, write_json_report, write_markdown_report
from osi_diagnose.rendering.terminal import render_terminal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="osi-diagnose", description="OSI-model based macOS network diagnostics")
    parser.add_argument("--json-only", action="store_true", help="Skip rich terminal output")
    parser.add_argument("--no-openai", action="store_true", help="Disable OpenAI summary")
    parser.add_argument("--openai", action="store_true", help="Enable OpenAI summary")
    parser.add_argument("--allow-sensitive-openai", action="store_true", help="Allow sensitive fields to be sent to OpenAI")
    parser.add_argument("--out", type=str, default=None, help="Output prefix, e.g. reports/run1")
    parser.add_argument("--target-host", type=str, default="example.com")
    parser.add_argument("--ping-host", type=str, default="1.1.1.1")
    parser.add_argument("--gateway", type=str, default=None)
    parser.add_argument("--scan-gateway-ports", action="store_true")
    parser.add_argument("--nmap-ports", type=str, default=None)
    parser.add_argument("--html", action="store_true", help="Write HTML report")
    parser.add_argument("--non-interactive", action="store_true", help="Disable wizard prompts")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = RunConfig(
        target_host=args.target_host,
        ping_host=args.ping_host,
        gateway_override=args.gateway,
        out_prefix=args.out,
        json_only=args.json_only,
        openai_enabled=args.openai and not args.no_openai,
        openai_redact=not args.allow_sensitive_openai,
        openai_allow_sensitive=args.allow_sensitive_openai,
        scan_gateway_ports=args.scan_gateway_ports,
        nmap_ports=args.nmap_ports,
        html_report=args.html,
    )

    if _should_prompt(args):
        config = run_wizard(config)

    context = detect_context(config)
    report = DiagnosticReport.new(config=config, context=context)

    for check_cls in ALL_CHECKS:
        check = check_cls()
        try:
            report.layers.append(check.run(config, context))
        except Exception as exc:
            report.warnings.append(f"Layer {check.layer} {check.title} failed: {exc}")

    if config.openai_enabled:
        try:
            payload = report.to_dict()
            if config.openai_redact:
                payload = redact_report_payload(payload, allow_sensitive=False)
            report.ai_summary = summarize_with_openai(payload)
        except Exception as exc:
            report.warnings.append(f"OpenAI summary skipped: {exc}")

    out_prefix = _output_prefix(config)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = write_json_report(report, out_prefix)
    md_path = write_markdown_report(report, out_prefix)
    html_path = write_html_report(report, out_prefix) if config.html_report else None

    if not config.json_only:
        render_terminal(report)
        print(f"\nArtifacts: {json_path} | {md_path}" + (f" | {html_path}" if html_path else ""))

    return 0


def _should_prompt(args: argparse.Namespace) -> bool:
    if args.non_interactive:
        return False
    return sys.stdin.isatty() and len(sys.argv) == 1


def run_wizard(defaults: RunConfig) -> RunConfig:
    print("osi-diagnose wizard (press Enter to accept defaults)")
    target = _ask("Target host for TLS/HTTP checks", defaults.target_host)
    ping_host = _ask("Ping host", defaults.ping_host)
    gateway = _ask("Gateway override (blank to auto-detect)", defaults.gateway_override or "") or None
    scan = _ask_yes_no("Run safe gateway port scan", defaults.scan_gateway_ports)
    openai = _ask_yes_no("Enhance report with OpenAI", defaults.openai_enabled)
    allow_sensitive = False
    if openai:
        print("Privacy note: sensitive fields are redacted by default before OpenAI upload.")
        allow_sensitive = _ask_yes_no("Allow raw SSID/internal IPs to be sent", False)
    html = _ask_yes_no("Write optional HTML report", defaults.html_report)

    return RunConfig(
        target_host=target,
        ping_host=ping_host,
        gateway_override=gateway,
        out_prefix=defaults.out_prefix,
        json_only=defaults.json_only,
        openai_enabled=openai,
        openai_redact=not allow_sensitive,
        openai_allow_sensitive=allow_sensitive,
        scan_gateway_ports=scan,
        nmap_ports=defaults.nmap_ports,
        html_report=html,
    )


def _output_prefix(config: RunConfig) -> Path:
    if config.out_prefix:
        return Path(config.out_prefix)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("reports") / f"osi-diagnose-{stamp}"


def _ask(prompt: str, default: str) -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def _ask_yes_no(prompt: str, default: bool) -> bool:
    default_char = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({default_char}): ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}
