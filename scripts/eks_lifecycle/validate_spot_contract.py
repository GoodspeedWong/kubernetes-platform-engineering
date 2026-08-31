#!/usr/bin/env python3
"""Fail closed unless every rendered Karpenter NodePool is dynamic and Spot-only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from common import ToolError, load_yaml


CAPACITY_TYPE_KEY = "karpenter.sh/capacity-type"
CPU_LIMITS = {"4", "8", "16", "32", "64"}
MEMORY_LIMITS = {"16Gi", "32Gi", "64Gi", "128Gi", "256Gi"}
REQUIRED_REQUIREMENTS = {
    "kubernetes.io/arch": ("In", {"amd64"}),
    "kubernetes.io/os": ("In", {"linux"}),
    "karpenter.k8s.aws/instance-category": ("In", {"c", "m", "r"}),
    "karpenter.k8s.aws/instance-hypervisor": ("In", {"nitro"}),
    "karpenter.k8s.aws/instance-cpu": ("In", {"2", "4", "8"}),
}


def collect_node_pools(value: Any) -> list[dict[str, Any]]:
    """Extract direct NodePools and NodePools wrapped by provider-kubernetes Objects."""
    if isinstance(value, list):
        pools: list[dict[str, Any]] = []
        for child in value:
            pools.extend(collect_node_pools(child))
        return pools
    if not isinstance(value, dict):
        return []
    if value.get("apiVersion") == "karpenter.sh/v1" and value.get("kind") == "NodePool":
        return [value]
    if value.get("kind") == "Object":
        manifest = (
            value.get("spec", {}).get("forProvider", {}).get("manifest")
            if isinstance(value.get("spec"), dict)
            else None
        )
        return collect_node_pools(manifest)
    pools = []
    for key in ("items", "resources"):
        if key in value:
            pools.extend(collect_node_pools(value[key]))
    return pools


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolError(f"{path} must be an object")
    return value


def _requirement_index(node_pool: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
    spec = _mapping(node_pool.get("spec"), f"NodePool/{name}.spec")
    template = _mapping(spec.get("template"), f"NodePool/{name}.spec.template")
    template_spec = _mapping(template.get("spec"), f"NodePool/{name}.spec.template.spec")
    requirements = template_spec.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ToolError(f"NodePool/{name} must declare non-empty scheduling requirements")
    index: dict[str, dict[str, Any]] = {}
    for position, requirement in enumerate(requirements):
        item = _mapping(requirement, f"NodePool/{name}.requirements[{position}]")
        key = item.get("key")
        if not isinstance(key, str) or not key:
            raise ToolError(f"NodePool/{name}.requirements[{position}].key is required")
        if key in index:
            raise ToolError(f"NodePool/{name} declares duplicate requirement {key}")
        index[key] = item
    return index


def _assert_requirement(
    index: dict[str, dict[str, Any]],
    node_pool_name: str,
    key: str,
    operator: str,
    values: set[str],
) -> None:
    requirement = index.get(key)
    if requirement is None:
        raise ToolError(f"NodePool/{node_pool_name} is missing requirement {key}")
    if requirement.get("operator") != operator:
        raise ToolError(f"NodePool/{node_pool_name} requirement {key} must use {operator}")
    actual = requirement.get("values")
    if not isinstance(actual, list) or set(actual) != values or len(actual) != len(values):
        expected = ",".join(sorted(values))
        raise ToolError(
            f"NodePool/{node_pool_name} requirement {key} must contain exactly [{expected}]"
        )


def validate_node_pool(
    node_pool: dict[str, Any], expected_zones: set[str] | None = None
) -> str:
    metadata = _mapping(node_pool.get("metadata"), "NodePool.metadata")
    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        raise ToolError("every NodePool must have metadata.name")
    spec = _mapping(node_pool.get("spec"), f"NodePool/{name}.spec")
    if "replicas" in spec:
        raise ToolError(f"NodePool/{name} must remain dynamic; spec.replicas is forbidden")

    requirements = _requirement_index(node_pool, name)
    _assert_requirement(requirements, name, CAPACITY_TYPE_KEY, "In", {"spot"})
    for key, (operator, values) in REQUIRED_REQUIREMENTS.items():
        _assert_requirement(requirements, name, key, operator, values)

    zone_requirement = requirements.get("topology.kubernetes.io/zone")
    if zone_requirement is None or zone_requirement.get("operator") != "In":
        raise ToolError(f"NodePool/{name} must select its two availability zones with In")
    zones = zone_requirement.get("values")
    if not isinstance(zones, list) or len(zones) != 2 or len(set(zones)) != 2:
        raise ToolError(f"NodePool/{name} must contain exactly two distinct availability zones")
    if expected_zones is not None and set(zones) != expected_zones:
        raise ToolError(f"NodePool/{name} availability zones do not match the environment")

    template_spec = _mapping(
        _mapping(spec.get("template"), f"NodePool/{name}.spec.template").get("spec"),
        f"NodePool/{name}.spec.template.spec",
    )
    node_class = _mapping(template_spec.get("nodeClassRef"), f"NodePool/{name}.nodeClassRef")
    if node_class != {
        "group": "karpenter.k8s.aws",
        "kind": "EC2NodeClass",
        "name": "spot-general",
    }:
        raise ToolError(f"NodePool/{name} must use the reviewed spot-general EC2NodeClass")
    startup_taints = template_spec.get("startupTaints")
    if startup_taints != [
        {
            "effect": "NoExecute",
            "key": "node.cilium.io/agent-not-ready",
            "value": "true",
        }
    ]:
        raise ToolError(f"NodePool/{name} must use the exact Cilium startup taint")

    disruption = _mapping(spec.get("disruption"), f"NodePool/{name}.spec.disruption")
    if disruption != {
        "budgets": [{"nodes": "1"}],
        "consolidateAfter": "5m",
        "consolidationPolicy": "WhenEmpty",
    }:
        raise ToolError(f"NodePool/{name} disruption policy is outside the reviewed bounds")
    limits = _mapping(spec.get("limits"), f"NodePool/{name}.spec.limits")
    if limits.get("cpu") not in CPU_LIMITS or limits.get("memory") not in MEMORY_LIMITS:
        raise ToolError(f"NodePool/{name} must use finite platform CPU and memory limits")
    return name


def validate_spot_contract(
    document: Any, expected_zones: set[str] | None = None
) -> dict[str, Any]:
    pools = collect_node_pools(document)
    if not pools:
        raise ToolError("no karpenter.sh/v1 NodePool manifests were found")
    names = [validate_node_pool(pool, expected_zones) for pool in pools]
    if len(names) != len(set(names)):
        raise ToolError("NodePool names must be unique")
    return {
        "capacityType": "spot",
        "dynamicCapacity": True,
        "nodePoolCount": len(names),
        "nodePools": sorted(names),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate that every rendered Karpenter NodePool is dynamic and Spot-only."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument(
        "--expected-zone",
        action="append",
        default=[],
        help="expected availability zone; provide exactly twice when used",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        zones = set(args.expected_zone) if args.expected_zone else None
        if zones is not None and len(zones) != 2:
            raise ToolError("--expected-zone must be supplied for exactly two distinct zones")
        result = validate_spot_contract(load_yaml(args.input), zones)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
