# osi-diagnose

`osi-diagnose` is an OSI-model based network diagnostics CLI focused on macOS, with graceful fallbacks when optional tools are missing.

## Features

- Interactive wizard by default (`python -m osi_diagnose`)
- Layered diagnostics (L1-L7) with pass/warn/fail/skip statuses
- Rich terminal report (color, tables, health score)
- Artifacts in `./reports`:
  - JSON raw measurements
  - Markdown report
  - Optional HTML report
- Optional OpenAI-enhanced summary and remediation plan
- Privacy-first OpenAI mode: sensitive fields redacted by default

## macOS setup

1. Optional Homebrew tools (recommended):

```bash
brew install nmap iperf3
```

2. Install package in editable mode:

```bash
pip install -e .
```

3. Optional extras:

```bash
pip install -e ".[macos-wifi,ai,dev]"
```

4. If using Wi-Fi scan via CoreWLAN, enable Location Services for your terminal app in macOS Privacy settings.

## Usage

Interactive wizard (default):

```bash
python -m osi_diagnose
```

Console script:

```bash
osi-diagnose
```

Non-interactive examples:

```bash
osi-diagnose --non-interactive --json-only
osi-diagnose --non-interactive --target-host example.com --ping-host 1.1.1.1
osi-diagnose --non-interactive --scan-gateway-ports
osi-diagnose --non-interactive --nmap-ports 22,80,443
osi-diagnose --non-interactive --openai
osi-diagnose --non-interactive --openai --allow-sensitive-openai
osi-diagnose --non-interactive --out reports/my-run --html
```

## OpenAI mode

- Enable with `--openai` in non-interactive mode or via wizard toggle.
- Reads `OPENAI_API_KEY` from environment.
- Uses OpenAI Responses API and stores output under `AI Summary` in Markdown report.
- If key is missing, package not installed, or API call fails, the run continues with a warning.

## Notes

- No sudo is assumed. Privileged checks are skipped or downgraded with a warning.
- `nmap`, `dig`, `networkQuality`, and CoreWLAN are optional and auto-detected.
