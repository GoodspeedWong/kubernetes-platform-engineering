#!/usr/bin/env python3
"""Validate P9 retirement inventory, policy, and Composition guardrails offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from common import EKS_ROOT, ToolError, load_yaml, run_checked


STAGES = (
    "DrainWorkloads",
    "RemoveGitOps",
    "DrainCapacity",
    "RemoveFoundation",
    "DeleteReady",
)


def _documents(path: Path) -> list[dict[str, Any]]:
    result = run_checked(["yq", "eval-all", "-o=json", "-I=0", ".", str(path)])
    documents = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    if not documents:
        raise ToolError(f"no YAML documents in {path}")
    return documents


def _inventory_hash(stage: dict[str, Any]) -> str:
    payload = json.dumps(
        {"remove": stage["remove"], "retain": stage["retain"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def validate_lifecycle_contract() -> dict[str, Any]:
    inventory = load_yaml(EKS_ROOT / "lifecycle-inventory.yaml")
    stages = inventory.get("spec", {}).get("stages", {})
    if tuple(stages) != STAGES:
        raise ToolError("retirement inventory stages are missing or out of order")
    all_resources: set[str] = set()
    for name, stage in stages.items():
        if stage.get("inventorySha256") != _inventory_hash(stage):
            raise ToolError(f"retirement inventory hash mismatch for {name}")
        remove = stage.get("remove", [])
        retain = stage.get("retain", [])
        if not remove or set(remove) & set(retain):
            raise ToolError(f"retirement inventory overlap or empty removal for {name}")
        if not stage.get("requiredEvidence"):
            raise ToolError(f"retirement evidence contract is empty for {name}")
        all_resources.update(remove)
        all_resources.update(retain)

    policy_docs = _documents(
        EKS_ROOT / "lifecycle-policy" / "validating-admission-policy.yaml"
    )
    policy = next(
        (item for item in policy_docs if item.get("kind") == "ValidatingAdmissionPolicy"),
        None,
    )
    binding = next(
        (
            item
            for item in policy_docs
            if item.get("kind") == "ValidatingAdmissionPolicyBinding"
        ),
        None,
    )
    if not policy or policy.get("spec", {}).get("failurePolicy") != "Fail":
        raise ToolError("lifecycle admission policy must fail closed")
    validations = json.dumps(policy.get("spec", {}).get("validations", []), sort_keys=True)
    if "platform-eks-lifecycle-approvers" not in validations or "evidenceRef" not in validations:
        raise ToolError("lifecycle admission policy lacks approver/evidence gates")
    if not binding or binding.get("spec", {}).get("validationActions") != ["Deny"]:
        raise ToolError("lifecycle admission policy binding must deny invalid changes")

    environment = load_yaml(EKS_ROOT / "environment" / "composition.yaml")
    source = environment["spec"]["pipeline"][0]["input"]["spec"]["source"]
    for required in (
        '"krm.kcl.dev/composition-resource-name" = "root-deletion-protection"',
        "replayDeletion = False",
        'kind = "XClusterFoundation"',
        'kind = "XEKSEnvironment"',
        "release_root_protection",
    ):
        if required not in source:
            raise ToolError(f"aggregate root protection contract is missing: {required}")

    foundation = load_yaml(EKS_ROOT / "foundation" / "composition.yaml")
    foundation_source = foundation["spec"]["pipeline"][0]["input"]["spec"]["source"]
    for name, stage in stages.items():
        if stage["inventorySha256"] not in foundation_source:
            raise ToolError(f"Composition does not bind the {name} inventory hash")
    for required in (
        'managementPolicies = ["Observe"]',
        'name = "eks-lifecycle-evidence"',
        "environment_generation",
        "foundation_generation",
        "retirement_evidence_valid",
        "retirement_cleanup_complete",
    ):
        if required not in foundation_source:
            raise ToolError(f"foundation evidence contract is missing: {required}")

    return {
        "stages": len(stages),
        "inventoryResources": len(all_resources),
        "admissionPolicy": "fail-closed",
        "rootReplayDeletion": False,
        "awsMutation": False,
        "kubernetesMutation": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    return argparse.ArgumentParser(
        description="Validate lifecycle contracts without contacting Kubernetes or AWS."
    ).parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    parse_args(argv or sys.argv[1:])
    try:
        print(json.dumps(validate_lifecycle_contract(), indent=2, sort_keys=True))
        return 0
    except (OSError, ToolError, TypeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
