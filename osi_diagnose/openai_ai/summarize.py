from __future__ import annotations

import json
import os
from typing import Any

DEFAULT_MODEL = "gpt-5-mini"


def generate_ai_summary(redacted_payload: dict[str, Any], model: str = DEFAULT_MODEL) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("openai package not installed") from exc

    client = OpenAI(api_key=api_key)
    rubric = (
        "You are a senior network architect. Return markdown with sections: "
        "1) Executive summary for non-technical stakeholder; "
        "2) OSI-layer root-cause analysis of top issues; "
        "3) Prioritized remediation checklist; "
        "4) NaaS package recommendation (Basic/Standard/Premium) with reasons and risks."
    )

    response = client.responses.create(
        model=model,
        input=[
            {"role": "system", "content": "Be concise, practical, and risk-aware."},
            {"role": "user", "content": rubric + "\n\nDiagnostics JSON:\n" + json.dumps(redacted_payload, indent=2)},
        ],
    )
    return response.output_text
