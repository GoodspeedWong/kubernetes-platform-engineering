#!/usr/bin/env python3
"""Render XEKSEnvironment and recursively render every emitted child XR."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import EKS_ROOT, LOCK_FILE, ToolError, load_yaml, output_directory, run_checked
import render as high_fidelity
import validate_rendered_schemas


SCENARIOS = EKS_ROOT / "tests" / "fixtures" / "render-scenarios.yaml"
EXPECTED = EKS_ROOT / "tests" / "fixtures" / "p10" / "recursive-render.lock.yaml"
FUNCTIONS = EKS_ROOT / "tests" / "fixtures" / "p2" / "functions.yaml"
CHILDREN = {
    "XNetwork": {
        "name": "network",
        "composition": (
            high_fidelity.REPO_ROOT
            / "kind-goodnotes-k8s-demo"
            / "crossplane-platform-aws-network"
            / "composition.yaml"
        ),
        "xrd": (
            high_fidelity.REPO_ROOT
            / "kind-goodnotes-k8s-demo"
            / "crossplane-platform-aws-network"
            / "xrd.yaml"
        ),
    },
    "XEKSCluster": {
        "name": "cluster",
        "composition": EKS_ROOT / "cluster" / "composition.yaml",
        "xrd": EKS_ROOT / "cluster" / "xrd.yaml",
    },
    "XClusterFoundation": {
        "name": "foundation",
        "composition": EKS_ROOT / "foundation" / "composition.yaml",
        "xrd": EKS_ROOT / "foundation" / "xrd.yaml",
    },
}


def load_documents(path: Path) -> list[dict[str, Any]]:
    result = run_checked(["yq", "eval-all", "-o=json", "-I=0", ".", str(path)])
    documents = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return [item for item in documents if isinstance(item, dict) and item.get("kind")]


def write_document(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def root_scenario() -> dict[str, object]:
    manifest = load_yaml(SCENARIOS)
    matches = [
        item
        for item in manifest.get("scenarios", [])
        if item.get("name") == "environment-active"
    ]
    if len(matches) != 1:
        raise ToolError("render scenarios must declare one environment-active root")
    return matches[0]


def assert_expected(digests: dict[str, str], counts: dict[str, int]) -> None:
    expected = load_yaml(EXPECTED)
    if expected.get("schemaVersion") != 1:
        raise ToolError("recursive render lock schemaVersion must be 1")
    if expected.get("digests") != digests:
        raise ToolError(
            f"recursive render digests differ: expected {expected.get('digests')}, got {digests}"
        )
    if expected.get("documentCounts") != counts:
        raise ToolError(
            "recursive render document counts differ: "
            f"expected {expected.get('documentCounts')}, got {counts}"
        )


def run_recursive(
    destination: Path,
    check: bool,
    renderer_binary: Path | None,
    function_targets: dict[str, str],
) -> dict[str, Any]:
    lock = load_yaml(LOCK_FILE)
    validation_contract = validate_rendered_schemas.schema_validation_contract(lock)
    renderer = high_fidelity.validate_renderer_binary(renderer_binary, lock)
    engine = high_fidelity.render_engine(lock)
    required_resources = (
        EKS_ROOT / "tests" / "fixtures" / "p10" / "required-catalog.yaml"
    )
    with tempfile.TemporaryDirectory(prefix="eks-recursive-schemas-") as schema_temp:
        schema_directory = Path(schema_temp)
        high_fidelity.write_required_schema_bundle(schema_directory)
        root = high_fidelity.render_scenario(
            root_scenario(),
            destination,
            lock,
            schema_directory,
            renderer,
            function_targets,
        )
        root_digest = high_fidelity.canonical_digest(root)
        root_documents = load_documents(root)
        emitted: dict[str, dict[str, Any]] = {}
        for document in root_documents:
            kind = document.get("kind")
            if kind not in CHILDREN:
                continue
            if kind in emitted:
                raise ToolError(f"aggregate rendered duplicate child kind {kind}")
            emitted[kind] = document
        if set(emitted) != set(CHILDREN):
            raise ToolError(
                f"aggregate child set differs: expected {sorted(CHILDREN)}, got {sorted(emitted)}"
            )

        outputs = {"environment": root}
        digests = {"environment": root_digest}
        counts = {"environment": len(root_documents)}
        for kind, contract in CHILDREN.items():
            name = str(contract["name"])
            child_path = destination / f"recursive-{name}-xr.yaml"
            write_document(child_path, emitted[kind])
            scenario: dict[str, object] = {
                "name": f"recursive-{name}",
                "xr": child_path,
                "composition": str(
                    Path(contract["composition"]).relative_to(high_fidelity.REPO_ROOT)
                ),
                "functions": str(FUNCTIONS.relative_to(high_fidelity.REPO_ROOT)),
                "xrd": str(Path(contract["xrd"]).relative_to(high_fidelity.REPO_ROOT)),
                "requiredResources": str(
                    required_resources.relative_to(high_fidelity.REPO_ROOT)
                ),
            }
            rendered = high_fidelity.render_scenario(
                scenario,
                destination,
                lock,
                schema_directory,
                renderer,
                function_targets,
                generated_root=destination,
            )
            outputs[name] = rendered
            digests[name] = high_fidelity.canonical_digest(rendered)
            counts[name] = len(load_documents(rendered))

        for path in outputs.values():
            validate_rendered_schemas.strict_validate(path)
        if check:
            assert_expected(digests, counts)
        report = {
            "children": sorted(item["name"] for item in CHILDREN.values()),
            "digests": digests,
            "documentCounts": counts,
            "rendererModule": engine["module"],
            "rendererVersion": engine["version"],
            "schemaValidationMode": validation_contract["mode"],
            "layers": 4,
            "missingSchemas": 0,
        }
        (destination / "recursive-render.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
        return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--renderer-binary", type=Path)
    parser.add_argument("--function-kcl-target")
    parser.add_argument("--function-auto-ready-target")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        function_targets = high_fidelity.validate_function_targets(
            args.function_kcl_target, args.function_auto_ready_target
        )
        with output_directory(args.output_dir, "eks-recursive-render-") as destination:
            report = run_recursive(
                destination, args.check, args.renderer_binary, function_targets
            )
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (KeyError, OSError, ToolError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
