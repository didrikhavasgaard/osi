from __future__ import annotations

import json
import os
from typing import Any


def summarize_with_openai(redacted_payload: dict[str, Any]) -> dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

    try:
        from openai import OpenAI
    except Exception as exc:
        raise RuntimeError("openai package is not installed") from exc

    client = OpenAI(api_key=api_key)
    rubric = {
        "tasks": [
            "Executive summary for non-technical stakeholders",
            "Top problems mapped to OSI layers",
            "Prioritized remediation checklist",
            "Recommend Basic/Standard/Premium managed network package with reasons",
        ],
        "format": {
            "executive_summary": "string",
            "top_problems": ["string"],
            "remediation": ["string"],
            "package_recommendation": "string",
        },
    }
    prompt = (
        "You are a senior network consultant. Analyze the redacted diagnostics JSON and produce concise, practical output "
        "as JSON only with keys executive_summary, top_problems, remediation, package_recommendation. "
        f"Rubric: {json.dumps(rubric)}. Diagnostics: {json.dumps(redacted_payload)}"
    )

    response = client.responses.create(
        model="gpt-5-mini",
        input=prompt,
    )
    text = response.output_text
    if not text:
        raise RuntimeError("Empty response from OpenAI")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OpenAI output was not valid JSON") from exc
