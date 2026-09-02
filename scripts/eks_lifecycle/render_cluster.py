#!/usr/bin/env python3
"""Render an XEKSCluster fixture with local KCL; never submit the output."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from common import EKS_ROOT, REPO_ROOT, ToolError, load_yaml


CLUSTER_ROOT = EKS_ROOT / "cluster"
CATALOG_FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p2"
RESOURCE_NAME_ANNOTATION = "krm.kcl.dev/composition-resource-name"


def default_extra_resources() -> dict[str, Any]:
    return {
        "platform-release": [
            {
                "Resource": load_yaml(
                    CATALOG_FIXTURES / "platform-release-compatible.yaml"
                )
            }
        ]
    }


def render(
    instance: dict[str, Any],
    observed: dict[str, Any] | None = None,
    standalone_names: bool = False,
    extra_resources: dict[str, Any] | None = None,
) -> dict[str, Any]:
    composition = load_yaml(CLUSTER_ROOT / "composition.yaml")
    try:
        source = composition["spec"]["pipeline"][0]["input"]["spec"]["source"]
        desired = {
            "apiVersion": instance["apiVersion"],
            "kind": instance["kind"],
            "metadata": {"name": instance["metadata"]["name"]},
            "status": {},
        }
    except (KeyError, TypeError) as error:
        raise ToolError(f"invalid XEKSCluster render input: {error}") from error
    params = {
        "oxr": instance,
        "dxr": desired,
        "ocds": observed or {},
        "extraResources": default_extra_resources()
        if extra_resources is None
        else extra_resources,
    }
    result = subprocess.run(
        [
            "kcl",
            "run",
            "-",
            "--format",
            "json",
            "--no_style",
            "-D",
            f"params={json.dumps(params, separators=(',', ':'))}",
        ],
        input=source,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ToolError(result.stderr.strip() or "KCL render failed")
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ToolError(f"KCL returned invalid JSON: {error}") from error
    items: list[dict[str, Any]] = []
    for item in output.get("items", []):
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            continue
        annotations = metadata.get("annotations", {})
        if not isinstance(annotations, dict) or RESOURCE_NAME_ANNOTATION not in annotations:
            continue
        if standalone_names:
            metadata["name"] = f"dryrun-{annotations[RESOURCE_NAME_ANNOTATION]}"
        items.append(item)
    return {"apiVersion": "v1", "kind": "List", "items": items}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render XEKSCluster composed resources locally."
    )
    parser.add_argument("--instance", type=Path, required=True)
    parser.add_argument(
        "--observed",
        type=Path,
        help="optional test-only observed composed-resource map",
    )
    parser.add_argument(
        "--standalone-names",
        action="store_true",
        help="add deterministic test-only names for API server dry-run validation",
    )
    parser.add_argument(
        "--platform-release",
        type=Path,
        default=CATALOG_FIXTURES / "platform-release-compatible.yaml",
        help="reviewed EnvironmentConfig used to resolve platformReleaseRef",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        instance = load_yaml(args.instance)
        observed = load_yaml(args.observed) if args.observed else None
        extra_resources = {
            "platform-release": [{"Resource": load_yaml(args.platform_release)}]
        }
        print(
            json.dumps(
                render(instance, observed, args.standalone_names, extra_resources),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
