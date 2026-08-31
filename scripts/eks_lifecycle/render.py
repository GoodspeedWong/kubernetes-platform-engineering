#!/usr/bin/env python3
"""Render declared Crossplane scenarios locally with pinned engines and schemas."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from common import (
    EKS_ROOT,
    LOCK_FILE,
    REPO_ROOT,
    SCHEMA_DIRECTORY,
    ToolError,
    load_yaml,
    output_directory,
    require_tool,
    resolve_repo_path,
    run_checked,
)


DEFAULT_SCENARIOS = EKS_ROOT / "tests" / "fixtures" / "render-scenarios.yaml"
NETWORK_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-network"
XRD_PATHS = (
    EKS_ROOT / "environment" / "xrd.yaml",
    NETWORK_ROOT / "xrd.yaml",
    EKS_ROOT / "cluster" / "xrd.yaml",
    EKS_ROOT / "foundation" / "xrd.yaml",
)
FUNCTION_RUNTIME = "render.crossplane.io/runtime"
FUNCTION_TARGET = "render.crossplane.io/runtime-development-target"
FUNCTIONS = ("function-kcl", "function-auto-ready")


def render_engine(lock: dict[str, object]) -> dict[str, str]:
    """Return and validate the source renderer contract locked for M1."""

    targets = lock.get("targets", {})
    management = targets.get("managementPlane", {}) if isinstance(targets, dict) else {}
    engine = management.get("renderEngine", {}) if isinstance(management, dict) else {}
    if not isinstance(engine, dict):
        raise ToolError("managementPlane.renderEngine must be a mapping")
    required = ("mode", "version", "module", "moduleSum", "command")
    values = {key: str(engine.get(key, "")) for key in required}
    if any(not value for value in values.values()):
        raise ToolError("source render engine lock is incomplete")
    if values["mode"] != "source-cli":
        raise ToolError("M1 requires the source-cli render engine mode")
    core = str(management.get("crossplaneCore", ""))
    if values["version"] != core:
        raise ToolError("render engine version must match the Crossplane core version")
    if values["command"] != "cmd/crank":
        raise ToolError("Crossplane v2.2.1 rendering must use cmd/crank")
    if not values["moduleSum"].startswith("h1:"):
        raise ToolError("render engine moduleSum must be checksum pinned")
    return values


def validate_renderer_binary(path: Path | None, lock: dict[str, object]) -> Path:
    """Fail closed unless the binary embeds the exact locked Go module."""

    engine = render_engine(lock)
    if path is None:
        raise ToolError(
            "--renderer-binary is required; build the locked renderer with "
            f"go install {engine['module']}/{engine['command']}@{engine['version']}"
        )
    binary = path.expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ToolError(f"renderer binary is missing or not executable: {binary}")
    metadata = run_checked([require_tool("go"), "version", "-m", str(binary)]).stdout
    expected = (
        f"mod\t{engine['module']}\t{engine['version']}\t{engine['moduleSum']}"
    )
    if expected not in metadata:
        raise ToolError(
            "renderer binary does not embed the locked module, version, and checksum"
        )
    help_text = run_checked([str(binary), "render", "--help"]).stdout
    for flag in (
        "--include-full-xr",
        "--observed-resources",
        "--required-resources",
        "--required-schemas",
        "--xrd",
    ):
        if flag not in help_text:
            raise ToolError(f"locked renderer does not support required flag {flag}")
    return binary


def validate_function_targets(kcl: str | None, auto_ready: str | None) -> dict[str, str]:
    targets = {
        "function-kcl": str(kcl or "").strip(),
        "function-auto-ready": str(auto_ready or "").strip(),
    }
    for name, target in targets.items():
        if not target or any(character.isspace() for character in target):
            raise ToolError(f"{name} Development target is missing or invalid")
    if len(set(targets.values())) != len(targets):
        raise ToolError("Function Development targets must be distinct")
    return targets


def write_development_functions(
    source: Path, destination: Path, targets: dict[str, str]
) -> Path:
    """Copy locked Function resources with explicit per-function local targets."""

    result = run_checked(
        [require_tool("yq"), "eval-all", "-o=json", "-I=0", ".", str(source)]
    )
    try:
        documents = [
            json.loads(line) for line in result.stdout.splitlines() if line.strip()
        ]
    except json.JSONDecodeError as error:
        raise ToolError(f"invalid Function manifest {source}: {error}") from error
    names: list[str] = []
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != "Function":
            raise ToolError(f"Development runtime input contains a non-Function: {source}")
        metadata = document.setdefault("metadata", {})
        name = str(metadata.get("name", ""))
        if name not in targets or name in names:
            raise ToolError(f"unexpected or duplicate Function resource: {name!r}")
        package = str(document.get("spec", {}).get("package", ""))
        if "@sha256:" not in package:
            raise ToolError(f"Function/{name} package is not digest pinned")
        annotations = metadata.setdefault("annotations", {})
        annotations.pop("render.crossplane.io/runtime-docker-pull-policy", None)
        annotations[FUNCTION_RUNTIME] = "Development"
        annotations[FUNCTION_TARGET] = targets[name]
        names.append(name)
    if set(names) != set(FUNCTIONS):
        raise ToolError(
            f"Function set differs: expected {sorted(FUNCTIONS)}, got {sorted(names)}"
        )
    destination.write_text(
        "\n---\n".join(json.dumps(item, indent=2, sort_keys=True) for item in documents)
        + "\n"
    )
    return destination


def write_required_schema_bundle(destination: Path) -> Path:
    """Convert the locked CRD/XRD cache to the OpenAPI v3 JSON render expects."""

    schemas: dict[str, object] = {}
    sources = [*XRD_PATHS, *sorted(SCHEMA_DIRECTORY.rglob("*.yaml"))]
    for source in sources:
        definition = load_yaml(source)
        try:
            group = str(definition["spec"]["group"])
            kind = str(definition["spec"]["names"]["kind"])
            versions = definition["spec"]["versions"]
        except (KeyError, TypeError) as error:
            raise ToolError(f"schema source has no CRD/XRD identity: {source}") from error
        for version in versions:
            if version.get("served") is False:
                continue
            version_name = str(version.get("name", ""))
            schema = copy.deepcopy(version.get("schema", {}).get("openAPIV3Schema"))
            if not version_name or not isinstance(schema, dict):
                raise ToolError(f"schema source has an incomplete served version: {source}")
            schema["x-kubernetes-group-version-kind"] = [
                {"group": group, "kind": kind, "version": version_name}
            ]
            key = f"{group}.{version_name}.{kind}"
            if key in schemas:
                raise ToolError(f"duplicate render schema identity: {key}")
            schemas[key] = schema
    if not schemas:
        raise ToolError("required render schema bundle is empty")
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / "locked-platform.json"
    output.write_text(
        json.dumps({"components": {"schemas": schemas}}, indent=2, sort_keys=True)
        + "\n"
    )
    return output


def canonical_digest(path: Path) -> str:
    """Hash logical YAML documents independently of map formatting."""

    rendered = run_checked(
        [require_tool("yq"), "eval-all", "-o=json", "-I=0", ".", str(path)]
    ).stdout
    documents = [json.loads(line) for line in rendered.splitlines() if line.strip()]
    normalized = [json.dumps(item, separators=(",", ":"), sort_keys=True) for item in documents]
    normalized.sort()
    return hashlib.sha256(("\n".join(normalized) + "\n").encode()).hexdigest()


def resolve_scenario_path(value: object, generated_root: Path | None = None) -> Path:
    if isinstance(value, Path):
        candidate = value.resolve()
        if generated_root is None:
            raise ToolError("generated scenario paths require an explicit output root")
        root = generated_root.resolve()
        if candidate != root and root not in candidate.parents:
            raise ToolError(f"generated scenario path escapes output root: {candidate}")
        return candidate
    return resolve_repo_path(str(value))


def render_scenario(
    scenario: dict[str, object],
    destination: Path,
    lock: dict[str, object],
    required_schemas: Path,
    renderer_binary: Path,
    function_targets: dict[str, str],
    generated_root: Path | None = None,
) -> Path:
    name = str(scenario.get("name", ""))
    if not name or not name.replace("-", "").isalnum():
        raise ToolError(f"invalid render scenario name: {name!r}")
    required = ("xr", "composition", "functions", "xrd")
    missing = [key for key in required if not scenario.get(key)]
    if missing:
        raise ToolError(f"scenario {name} is missing fields: {', '.join(missing)}")
    render_engine(lock)
    with tempfile.TemporaryDirectory(prefix=f"eks-{name}-functions-") as temporary:
        functions = write_development_functions(
            resolve_scenario_path(scenario["functions"], generated_root),
            Path(temporary) / "functions.yaml",
            function_targets,
        )
        command = [
            str(renderer_binary),
            "render",
            str(resolve_scenario_path(scenario["xr"], generated_root)),
            str(resolve_scenario_path(scenario["composition"], generated_root)),
            str(functions),
            "--include-full-xr",
            f"--xrd={resolve_scenario_path(scenario['xrd'], generated_root)}",
            f"--required-schemas={required_schemas}",
        ]
        for key, flag in (
            ("observedResources", "--observed-resources"),
            ("requiredResources", "--required-resources"),
        ):
            if scenario.get(key):
                command.append(
                    f"{flag}={resolve_scenario_path(scenario[key], generated_root)}"
                )
        result = run_checked(command, timeout=180)
    output = destination / f"{name}.yaml"
    output.write_text(result.stdout)
    return output


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render EKS platform fixtures locally; never deploy rendered resources."
    )
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--all-scenarios", action="store_true")
    selection.add_argument("--scenario", help="render one named scenario")
    parser.add_argument("--check", action="store_true", help="compare output with expected fixtures")
    parser.add_argument("--scenario-file", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--renderer-binary",
        type=Path,
        help="locked Crossplane v2.2.1 cmd/crank binary built from the source module",
    )
    parser.add_argument("--function-kcl-target", help="Function KCL gRPC Development target")
    parser.add_argument(
        "--function-auto-ready-target",
        help="Function Auto Ready gRPC Development target",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        require_tool("yq")
        lock = load_yaml(LOCK_FILE)
        document = load_yaml(args.scenario_file)
        scenarios = document.get("scenarios", []) if isinstance(document, dict) else []
        if not scenarios:
            raise ToolError(f"no render scenarios are declared in {args.scenario_file}")
        selected = scenarios if args.all_scenarios else [item for item in scenarios if item.get("name") == args.scenario]
        if not selected:
            raise ToolError(f"unknown render scenario: {args.scenario}")
        renderer_binary = validate_renderer_binary(args.renderer_binary, lock)
        function_targets = validate_function_targets(
            args.function_kcl_target, args.function_auto_ready_target
        )
        with tempfile.TemporaryDirectory(prefix="eks-required-schemas-") as schema_temp:
            required_schemas = Path(schema_temp)
            write_required_schema_bundle(required_schemas)
            with output_directory(args.output_dir, "eks-render-") as destination:
                outputs = [
                    render_scenario(
                        item,
                        destination,
                        lock,
                        required_schemas,
                        renderer_binary,
                        function_targets,
                    )
                    for item in selected
                ]
                if args.check:
                    for item, output in zip(selected, outputs, strict=True):
                        expected = str(item.get("expectedSha256", ""))
                        if len(expected) != 64:
                            raise ToolError(
                                f"scenario {item.get('name')} has no expectedSha256"
                            )
                        actual = canonical_digest(output)
                        if actual != expected:
                            raise ToolError(
                                f"render output digest differs for scenario {item.get('name')}: "
                                f"expected {expected}, got {actual}"
                            )
                        repeated = render_scenario(
                            item,
                            destination,
                            lock,
                            required_schemas,
                            renderer_binary,
                            function_targets,
                        )
                        if canonical_digest(repeated) != actual:
                            raise ToolError(
                                f"render output is not repeatable for scenario {item.get('name')}"
                            )
            print(f"RENDER PASS: {len(outputs)} scenario(s)")
        return 0
    except (OSError, ToolError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
