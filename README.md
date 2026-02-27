# osi-diagnose

OSI-model based network diagnostics CLI for macOS (Apple Silicon-friendly) with Rich-powered reports and optional OpenAI-enhanced executive summary.

## Features

- Interactive wizard by default (`python -m osi_diagnose`)
- OSI layer checks (L1-L7) with graceful fallback if optional tools are missing
- Beautiful terminal output with health score, icons, and severity colors
- Artifacts in `./reports`:
  - JSON raw findings
  - Markdown report
  - Optional OpenAI summary section
- Privacy-first OpenAI mode with default redaction

## Install (macOS)

```bash
# Optional utilities for deeper diagnostics
brew install nmap iperf3

# Install package
pip install -e .

# Optional OpenAI support
pip install -e .[openai]

# Optional CoreWLAN support for richer Wi-Fi details
pip install -e .[mac-wifi]
```

> For Wi-Fi scan details from CoreWLAN, Terminal may need Location Services permission in macOS System Settings.

## Usage

```bash
python -m osi_diagnose
# or
osi-diagnose
```

### Non-interactive flags

```bash
osi-diagnose --json-only
osi-diagnose --no-openai
osi-diagnose --openai
osi-diagnose --out reports/myrun
osi-diagnose --target-host example.com
osi-diagnose --ping-host 1.1.1.1
osi-diagnose --gateway 192.168.1.1
osi-diagnose --scan-gateway-ports
osi-diagnose --nmap-ports 22,80,443
```

## OpenAI-enhanced report

When `--openai` is enabled (or selected in wizard):
- Reads `OPENAI_API_KEY`
- Sends redacted diagnostics JSON by default
- Appends AI output under **AI Summary** in Markdown report

If key/model/network is unavailable, tool logs warning and continues without failing.

## Development

```bash
pip install -e .[dev]
pytest
```
