from __future__ import annotations

from dataclasses import asdict
import json
import shutil
import subprocess
from typing import Any

from osi_diagnose.model import CheckResult, DiagnosticContext


class BaseCheck:
    check_id = "base"
    name = "Base"

    def run(self, context: DiagnosticContext) -> CheckResult:
        raise NotImplementedError


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_command(args: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def to_jsonable(data: Any) -> Any:
    try:
        json.dumps(data)
        return data
    except TypeError:
        return asdict(data)
