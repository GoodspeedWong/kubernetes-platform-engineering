#!/usr/bin/env python3
"""Run the complete local M1 gate and emit machine/human-readable reports."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from common import EKS_ROOT, REPO_ROOT, ToolError, output_directory, redact
import render as high_fidelity


SCRIPT_ROOT = REPO_ROOT / "scripts" / "eks_lifecycle"
NETWORK_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-network"
TEST_ROOT = EKS_ROOT / "tests"
MATRIX = EKS_ROOT / "static-test-matrix.yaml"
SCOPES = (
    str(EKS_ROOT.relative_to(REPO_ROOT)),
    str(NETWORK_ROOT.relative_to(REPO_ROOT)),
    "scripts/eks_lifecycle",
)


def run_step(
    name: str,
    command: list[str],
    destination: Path,
    *,
    timeout: int = 600,
) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    stdout = redact(result.stdout)
    stderr = redact(result.stderr)
    (destination / f"{name}.log").write_text(
        f"$ {' '.join(command)}\n\nSTDOUT\n{stdout}\nSTDERR\n{stderr}\n"
    )
    if result.returncode != 0:
        diagnostic = (stderr or stdout or "no diagnostic").strip().splitlines()
        detail = diagnostic[-1] if diagnostic else "no diagnostic"
        raise ToolError(f"M1 step {name} failed: {detail}")
    return {
        "command": command,
        "name": name,
        "output": f"{stdout}\n{stderr}",
        "returnCode": result.returncode,
        "status": "PASS",
    }


def chart_arguments(cache: Path | None) -> dict[str, list[str]]:
    if cache is None:
        return {"cilium": [], "karpenter": [], "argocd": []}
    expected = {
        "cilium": cache / "cilium-1.20.1.tgz",
        "karpenter": cache / "karpenter-1.14.1.tgz",
        "karpenterCRD": cache / "karpenter-crd-1.14.1.tgz",
        "argocd": cache / "argo-cd-10.4.0.tgz",
    }
    missing = [str(path) for path in expected.values() if not path.is_file()]
    if missing:
        raise ToolError(f"chart cache is incomplete: {', '.join(missing)}")
    return {
        "cilium": ["--chart", str(expected["cilium"])],
        "karpenter": [
            "--controller-chart",
            str(expected["karpenter"]),
            "--crd-chart",
            str(expected["karpenterCRD"]),
        ],
        "argocd": ["--chart", str(expected["argocd"])],
    }


def dirty_scope_report() -> dict[str, Any]:
    result = subprocess.run(
        ["git", "status", "--short"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ToolError(result.stderr.strip() or "git status failed")
    scoped = 0
    unrelated = 0
    for line in result.stdout.splitlines():
        path = line[3:].strip().strip('"')
        if any(path == scope or path.startswith(scope + "/") for scope in SCOPES):
            scoped += 1
        else:
            unrelated += 1
    return {
        "preserved": True,
        "scopedDirtyEntries": scoped,
        "unrelatedDirtyEntries": unrelated,
        "unrelatedFilesModifiedByRunner": 0,
    }


def write_report(
    destination: Path,
    steps: list[dict[str, Any]],
    failure: str | None,
) -> dict[str, Any]:
    test_count = 0
    for step in steps:
        if step["name"] != "unittest-discovery":
            continue
        # unittest writes its run summary to stderr by default, while other
        # runners may use stdout. Parse the redacted combined stream so the
        # report cannot silently claim zero discovered tests.
        match = re.search(r"Ran (\d+) tests?", step.get("output", ""))
        if match:
            test_count = int(match.group(1))
    matrix_ids = [f"S{number:02d}" for number in range(1, 22)]
    overall = "FAIL" if failure else "PASS"
    report = {
        "awsMutation": False,
        "dockerMutation": False,
        "failure": failure,
        "kubernetesApply": False,
        "localFunctionProcessesOnly": True,
        "matrix": {item: overall for item in matrix_ids},
        "overall": overall,
        "runtimeUAT": {
            "awsAuthenticationRefresh": "NOT_RUN",
            "awsCreate": "NOT_RUN",
            "awsRetirement": "NOT_RUN",
            "awsUpgrade": "NOT_RUN",
            "kindApply": "NOT_RUN",
            "network": "NOT_RUN",
            "spotInterruption": "NOT_RUN",
        },
        "steps": [
            {key: value for key, value in step.items() if key != "output"}
            for step in steps
        ],
        "testCount": test_count,
        "worktree": dirty_scope_report(),
    }
    (destination / "m1-static-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    matrix_lines = "\n".join(
        f"| {item} | {overall} | `{MATRIX.relative_to(REPO_ROOT)}` |"
        for item in matrix_ids
    )
    markdown = f"""# EKS lifecycle M1 static validation

Overall: **{overall}**

- Discovered tests: {test_count}
- Kubernetes apply: NOT_RUN
- AWS API mutation: NOT_RUN
- AWS authentication refresh: NOT_RUN
- Runtime network, Spot interruption, upgrade, and retirement UAT: NOT_RUN
- Dirty worktree: preserved; the runner modifies no unrelated files

| Scenario | Result | Mapping |
| --- | --- | --- |
{matrix_lines}

Failure: {failure or "none"}
"""
    (destination / "m1-static-report.md").write_text(markdown)
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chart-cache",
        type=Path,
        help="optional directory containing all four digest-verified chart archives",
    )
    parser.add_argument("--renderer-binary", type=Path)
    parser.add_argument("--function-kcl-target")
    parser.add_argument("--function-auto-ready-target")
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    steps: list[dict[str, Any]] = []
    failure: str | None = None
    try:
        lock = high_fidelity.load_yaml(high_fidelity.LOCK_FILE)
        renderer = high_fidelity.validate_renderer_binary(args.renderer_binary, lock)
        function_targets = high_fidelity.validate_function_targets(
            args.function_kcl_target, args.function_auto_ready_target
        )
        runtime_arguments = [
            "--renderer-binary",
            str(renderer),
            "--function-kcl-target",
            function_targets["function-kcl"],
            "--function-auto-ready-target",
            function_targets["function-auto-ready"],
        ]
        charts = chart_arguments(args.chart_cache.resolve() if args.chart_cache else None)
        with output_directory(args.output_dir, "eks-m1-validation-") as destination:
            commands: list[tuple[str, list[str], int]] = [
                (
                    "offline-preflight",
                    [sys.executable, str(SCRIPT_ROOT / "preflight.py"), "--offline"],
                    120,
                ),
                (
                    "schema-cache",
                    [sys.executable, str(SCRIPT_ROOT / "prepare_schemas.py"), "--verify"],
                    120,
                ),
                (
                    "high-fidelity-render",
                    [
                        sys.executable,
                        str(SCRIPT_ROOT / "render.py"),
                        "--all-scenarios",
                        "--check",
                        "--output-dir",
                        str(destination / "render"),
                        *runtime_arguments,
                    ],
                    900,
                ),
                (
                    "recursive-render",
                    [
                        sys.executable,
                        str(SCRIPT_ROOT / "render_recursive.py"),
                        "--check",
                        "--output-dir",
                        str(destination / "recursive"),
                        *runtime_arguments,
                    ],
                    900,
                ),
                (
                    "embedded-schemas",
                    [
                        sys.executable,
                        str(SCRIPT_ROOT / "validate_rendered_schemas.py"),
                        "--foundation-embedded",
                        "--output-dir",
                        str(destination / "embedded"),
                    ],
                    600,
                ),
                (
                    "cilium-chart",
                    [
                        sys.executable,
                        str(SCRIPT_ROOT / "validate_cilium_chart.py"),
                        *charts["cilium"],
                    ],
                    300,
                ),
                (
                    "karpenter-charts",
                    [
                        sys.executable,
                        str(SCRIPT_ROOT / "validate_karpenter_chart.py"),
                        *charts["karpenter"],
                    ],
                    300,
                ),
                (
                    "argocd-chart",
                    [
                        sys.executable,
                        str(SCRIPT_ROOT / "validate_argocd_chart.py"),
                        *charts["argocd"],
                    ],
                    300,
                ),
                (
                    "lifecycle-contract",
                    [sys.executable, str(SCRIPT_ROOT / "validate_lifecycle_contract.py")],
                    120,
                ),
                (
                    "strict-static",
                    [
                        sys.executable,
                        str(SCRIPT_ROOT / "validate_static.py"),
                        "--strict",
                        "--output-dir",
                        str(destination / "static"),
                    ],
                    300,
                ),
                (
                    "unittest-discovery",
                    [
                        sys.executable,
                        "-m",
                        "unittest",
                        "discover",
                        "-s",
                        str(TEST_ROOT),
                        "-p",
                        "test_*.py",
                        "-v",
                    ],
                    900,
                ),
                (
                    "scoped-diff-check",
                    ["git", "diff", "--check", "--", *SCOPES],
                    120,
                ),
            ]
            for name, command, timeout in commands:
                steps.append(run_step(name, command, destination, timeout=timeout))
            report = write_report(destination, steps, None)
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, subprocess.TimeoutExpired, ToolError) as error:
        failure = redact(str(error))
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            report = write_report(args.output_dir.resolve(), steps, failure)
            print(json.dumps(report, indent=2, sort_keys=True))
        print(f"ERROR: {failure}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
