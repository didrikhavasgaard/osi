from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any


SENSITIVE_KEYS = {"local_ip", "gateway", "dns_resolvers", "ssid"}


def mask_ip(value: str) -> str:
    parts = value.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["x"])
    return value


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    data = deepcopy(payload)

    def walk(obj: Any, key: str | None = None) -> Any:
        if isinstance(obj, dict):
            return {k: walk(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [walk(v, key) for v in obj]
        if isinstance(obj, str):
            if key in {"local_ip", "gateway"}:
                return mask_ip(obj)
            if key == "dns_resolvers":
                return mask_ip(obj)
            if key == "ssid":
                return f"ssid_hash:{hash_value(obj)}"
        return obj

    return walk(data)
