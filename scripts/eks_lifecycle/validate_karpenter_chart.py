#!/usr/bin/env python3
"""Render and audit the two digest-locked Karpenter charts used by P6."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import EKS_ROOT, LOCK_FILE, ToolError, load_yaml, require_tool
from prepare_schemas import fetch_oci_chart


RUNTIME_VALUES = {
    "serviceAccount": {
        "annotations": {
            "eks.amazonaws.com/role-arn": (
                "arn:aws:iam::000000000000:role/eks-dev-spot-karpenter"
            )
        }
    },
    "settings": {
        "clusterCABundle": "VEVTVC1PTkxZLUNB",
        "clusterEndpoint": "https://test-only.eks.invalid",
        "clusterName": "eks-dev-spot-cluster",
        "eksControlPlane": True,
        "interruptionQueue": "eks-dev-spot-interruption",
    },
}


def merge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(left)
    for key, value in right.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def replace_region(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: replace_region(child) for key, child in value.items()}
    if isinstance(value, list):
        return [replace_region(child) for child in value]
    if isinstance(value, str):
        return value.replace("__INJECTED_AWS_REGION__", "us-east-1")
    return value


def read_chart(path: Path | None, lock: dict[str, Any], label: str) -> bytes:
    expected = str(lock["contentSha256"])
    payload = path.read_bytes() if path else fetch_oci_chart(lock)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise ToolError(
            f"{label} chart digest mismatch: expected {expected}, got {actual}"
        )
    return payload


def render_documents(
    payload: bytes,
    *,
    release: str,
    values: dict[str, Any] | None,
    include_crds: bool,
) -> list[dict[str, Any]]:
    require_tool("helm")
    require_tool("yq")
    with tempfile.TemporaryDirectory(prefix="karpenter-chart-audit-") as temporary:
        root = Path(temporary)
        chart = root / "chart.tgz"
        output = root / "rendered.yaml"
        chart.write_bytes(payload)
        command = [
            "helm",
            "template",
            release,
            str(chart),
            "--namespace",
            "kube-system",
            "--kube-version",
            "1.35.0",
        ]
        if include_crds:
            command.append("--include-crds")
        if values is not None:
            values_file = root / "values.json"
            values_file.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n")
            command.extend(("--values", str(values_file)))
        rendered = subprocess.run(
            command, text=True, capture_output=True, check=False
        )
        if rendered.returncode != 0:
            raise ToolError(rendered.stderr.strip() or "Karpenter Helm render failed")
        output.write_text(rendered.stdout)
        converted = subprocess.run(
            ["yq", "eval-all", "-o=json", "[.]", str(output)],
            text=True,
            capture_output=True,
            check=False,
        )
        if converted.returncode != 0:
            raise ToolError(converted.stderr.strip() or "Karpenter YAML parsing failed")
        try:
            documents = json.loads(converted.stdout)
        except json.JSONDecodeError as error:
            raise ToolError(f"Karpenter chart returned invalid JSON: {error}") from error
    return [item for item in documents if isinstance(item, dict) and item.get("kind")]


def select_one(
    documents: list[dict[str, Any]], kind: str, name: str
) -> dict[str, Any]:
    matches = [
        item
        for item in documents
        if item.get("kind") == kind and item.get("metadata", {}).get("name") == name
    ]
    if len(matches) != 1:
        raise ToolError(f"expected one {kind}/{name}; found {len(matches)}")
    return matches[0]


def expect(actual: Any, expected: Any, path: str) -> None:
    if actual != expected:
        raise ToolError(f"{path} must be {expected!r}; got {actual!r}")


def audit(
    controller_chart: Path | None = None,
    crd_chart: Path | None = None,
) -> dict[str, Any]:
    lock = load_yaml(LOCK_FILE)
    controller_lock = lock["charts"]["karpenter"]
    crd_lock = lock["charts"]["karpenterCRD"]
    values = replace_region(load_yaml(EKS_ROOT / "values" / "karpenter.yaml"))
    values = merge(values, RUNTIME_VALUES)
    controller_documents = render_documents(
        read_chart(controller_chart, controller_lock, "Karpenter controller"),
        release="karpenter",
        values=values,
        include_crds=False,
    )
    crd_documents = render_documents(
        read_chart(crd_chart, crd_lock, "Karpenter CRD"),
        release="karpenter-crd",
        values=None,
        include_crds=True,
    )

    deployment = select_one(controller_documents, "Deployment", "karpenter")
    pod = deployment["spec"]["template"]
    pod_spec = pod["spec"]
    expect(deployment["spec"].get("replicas"), 2, "Karpenter replicas")
    expect(pod_spec.get("hostNetwork", False), False, "Karpenter hostNetwork")
    expect(pod_spec.get("dnsPolicy"), "Default", "Karpenter dnsPolicy")
    expect(pod_spec.get("serviceAccountName"), "karpenter", "Karpenter service account")
    expected_labels = {
        "app.kubernetes.io/instance": "karpenter",
        "app.kubernetes.io/name": "karpenter",
    }
    for key, value in expected_labels.items():
        expect(pod.get("metadata", {}).get("labels", {}).get(key), value, f"pod label {key}")
    required_affinity = (
        pod_spec.get("affinity", {})
        .get("nodeAffinity", {})
        .get("requiredDuringSchedulingIgnoredDuringExecution", {})
        .get("nodeSelectorTerms", [])
    )
    if not any(
        any(
            expression.get("key") == "karpenter.sh/nodepool"
            and expression.get("operator") == "DoesNotExist"
            for expression in term.get("matchExpressions", [])
        )
        for term in required_affinity
    ):
        raise ToolError("Karpenter controller must exclude Karpenter EC2 nodes")
    containers = pod_spec.get("containers", [])
    controller = next(
        (item for item in containers if item.get("name") == "controller"), None
    )
    if controller is None:
        raise ToolError("Karpenter controller container was not rendered")
    expect(controller.get("image"), controller_lock["controllerImage"], "controller image")
    environment = {item.get("name"): item.get("value") for item in controller.get("env", [])}
    expect(environment.get("AWS_EC2_METADATA_DISABLED"), "true", "IMDS disable")
    expect(environment.get("AWS_REGION"), "us-east-1", "AWS region")
    if "AWS_ACCESS_KEY_ID" in environment or "AWS_SECRET_ACCESS_KEY" in environment:
        raise ToolError("Karpenter controller must not receive static AWS key variables")

    service_account = select_one(
        controller_documents, "ServiceAccount", "karpenter"
    )
    expect(
        service_account.get("metadata", {}).get("annotations", {}).get(
            "eks.amazonaws.com/role-arn"
        ),
        RUNTIME_VALUES["serviceAccount"]["annotations"][
            "eks.amazonaws.com/role-arn"
        ],
        "Karpenter IRSA annotation",
    )
    pdb = select_one(controller_documents, "PodDisruptionBudget", "karpenter")
    expect(pdb["spec"].get("maxUnavailable"), 1, "Karpenter PDB")
    if any(item.get("kind") == "DaemonSet" for item in controller_documents):
        raise ToolError("Karpenter controller chart must not render a DaemonSet")
    if any(item.get("kind") == "CustomResourceDefinition" for item in controller_documents):
        raise ToolError("controller chart must not own Karpenter CRDs")

    crd_names = {
        item.get("metadata", {}).get("name")
        for item in crd_documents
        if item.get("kind") == "CustomResourceDefinition"
    }
    expected_crds = {
        "capacitybuffers.autoscaling.x-k8s.io",
        "ec2nodeclasses.karpenter.k8s.aws",
        "nodeclaims.karpenter.sh",
        "nodeoverlays.karpenter.sh",
        "nodepools.karpenter.sh",
    }
    if crd_names != expected_crds:
        raise ToolError(f"unexpected Karpenter CRD inventory: {sorted(crd_names)}")

    return {
        "controllerChartSha256": controller_lock["contentSha256"],
        "controllerDocuments": len(controller_documents),
        "crdChartSha256": crd_lock["contentSha256"],
        "crds": len(crd_names),
        "fargateLabels": 2,
        "hostNetwork": False,
        "runtimeUAT": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-chart", type=Path)
    parser.add_argument("--crd-chart", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        print(
            json.dumps(
                audit(args.controller_chart, args.crd_chart),
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
