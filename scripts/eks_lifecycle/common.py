"""Shared fail-closed helpers for EKS lifecycle tooling."""

from __future__ import annotations

import contextlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator


REPO_ROOT = Path(__file__).resolve().parents[2]
EKS_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-eks"
LOCK_FILE = EKS_ROOT / "versions.lock.yaml"
SCHEMA_MANIFEST = EKS_ROOT / "tests" / "schemas" / "manifest.yaml"
SCHEMA_DIRECTORY = EKS_ROOT / "tests" / "schemas" / "generated"

PLACEHOLDER_PATTERNS = (
    re.compile(r"__REPLACE_[A-Z0-9_]+__"),
    re.compile(r"(?:^|[.:/-])TEST-ONLY(?:$|[.:/-])", re.IGNORECASE),
    re.compile(r"\.invalid(?:[/:]|$)", re.IGNORECASE),
    re.compile(r"\b000000000000\b"),
    re.compile(r"\bami-0{17}\b"),
)

REDACTION_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[opsu]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
)


class ToolError(RuntimeError):
    """Expected tooling or validation error."""


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise ToolError(f"required tool is missing: {name}")
    return resolved


def run_checked(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise ToolError(
            f"command timed out after {timeout}s ({command[0]})"
        ) from error
    if result.returncode != 0:
        streams = [
            value.strip() for value in (result.stdout, result.stderr) if value.strip()
        ]
        detail = redact("\n".join(streams) or "no diagnostic")
        raise ToolError(f"command failed ({command[0]}): {detail}")
    return result


def load_yaml(path: Path) -> Any:
    require_tool("yq")
    if not path.is_file():
        raise ToolError(f"YAML file is missing: {path}")
    result = run_checked(["yq", "eval", "-o=json", ".", str(path)])
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ToolError(f"invalid YAML in {path}: {error}") from error


def redact(value: str) -> str:
    redacted = value
    for pattern in REDACTION_PATTERNS:
        if "authorization" in pattern.pattern.lower():
            redacted = pattern.sub(r"\1<redacted>", redacted)
        else:
            redacted = pattern.sub("<redacted>", redacted)
    return redacted


def find_placeholders(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            findings.extend(find_placeholders(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(find_placeholders(child, f"{path}[{index}]"))
    elif isinstance(value, str) and any(pattern.search(value) for pattern in PLACEHOLDER_PATTERNS):
        findings.append(path)
    return findings


def assert_deployment_safe(path: Path) -> None:
    findings = find_placeholders(load_yaml(path))
    if findings:
        locations = ", ".join(findings[:8])
        suffix = " ..." if len(findings) > 8 else ""
        raise ToolError(f"deployment input contains test placeholders at {locations}{suffix}")


@contextlib.contextmanager
def output_directory(requested: Path | None, prefix: str) -> Iterator[Path]:
    if requested is not None:
        requested.mkdir(parents=True, exist_ok=True)
        yield requested.resolve()
        return
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        yield Path(temporary)


def resolve_repo_path(value: str) -> Path:
    candidate = (REPO_ROOT / value).resolve()
    repository = REPO_ROOT.resolve()
    if candidate != repository and repository not in candidate.parents:
        raise ToolError(f"path escapes repository: {value}")
    return candidate
