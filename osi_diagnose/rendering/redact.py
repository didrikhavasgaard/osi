from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


SENSITIVE_KEYS = {
    "local_ip",
    "gateway_ip",
    "gateway",
    "dns_servers",
    "ssid",
    "ssid_hash",
    "interfaces",
    "hostname",
}


def mask_ipv4(value: str) -> str:
    parts = value.split(".")
    if len(parts) != 4:
        return value
    return f"{parts[0]}.{parts[1]}.{parts[2]}.x"


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def redact_report_payload(payload: dict[str, Any], allow_sensitive: bool = False) -> dict[str, Any]:
    if allow_sensitive:
        return payload
    redacted = copy.deepcopy(payload)
    _walk(redacted)
    return redacted


def _walk(node: Any) -> None:
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if isinstance(value, str) and IP_RE.match(value):
                node[key] = mask_ipv4(value)
                continue
            if key in SENSITIVE_KEYS:
                node[key] = _redact_value(value)
                continue
            _walk(value)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str) and IP_RE.match(v):
                node[i] = mask_ipv4(v)
            else:
                _walk(v)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        if IP_RE.match(value):
            return mask_ipv4(value)
        return f"hash:{hash_value(value)}"
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[k] = _redact_value(v)
        return out
    return value
