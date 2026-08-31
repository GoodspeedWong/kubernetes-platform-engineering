#!/usr/bin/env python3
"""Render and audit the digest-locked Cilium chart against the P7 values contract."""

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
from prepare_schemas import fetch_http


REPLACEMENTS = {
    "__INJECTED_CLUSTER_NAME__": "eks-dev-spot-cluster",
    "__INJECTED_ENVIRONMENT_NAME__": "eks-dev-spot",
    "__INJECTED_CILIUM_OPERATOR_ROLE_ARN__": "arn:aws:iam::000000000000:role/eks-dev-spot-cilium",
    "__INJECTED_EKS_API_HOST__": "test-only.eks.invalid",
    "__INJECTED_NATIVE_ROUTING_CIDR__": "10.40.0.0/16",
    "__INJECTED_AWS_REGION__": "us-east-1",
}


def replace_strings(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: replace_strings(child) for key, child in value.items()}
    if isinstance(value, list):
        return [replace_strings(child) for child in value]
    if isinstance(value, str):
        for old, new in REPLACEMENTS.items():
            value = value.replace(old, new)
    return value


def read_chart(path: Path | None, chart_lock: dict[str, Any]) -> bytes:
    expected = str(chart_lock["sha256"])
    payload = path.read_bytes() if path else fetch_http(str(chart_lock["url"]), expected)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise ToolError(f"Cilium chart digest mismatch: expected {expected}, got {actual}")
    return payload


def render_documents(chart_payload: bytes, values: dict[str, Any]) -> list[dict[str, Any]]:
    require_tool("helm")
    require_tool("yq")
    with tempfile.TemporaryDirectory(prefix="cilium-chart-audit-") as temporary:
        root = Path(temporary)
        chart_path = root / "cilium.tgz"
        values_path = root / "values.json"
        output_path = root / "rendered.yaml"
        chart_path.write_bytes(chart_payload)
        values_path.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n")
        rendered = subprocess.run(
            [
                "helm",
                "template",
                "cilium",
                str(chart_path),
                "--namespace",
                "kube-system",
                "--kube-version",
                "1.35.0",
                "--values",
                str(values_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if rendered.returncode != 0:
            raise ToolError(rendered.stderr.strip() or "Cilium Helm render failed")
        output_path.write_text(rendered.stdout)
        converted = subprocess.run(
            ["yq", "eval-all", "-o=json", "[.]", str(output_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if converted.returncode != 0:
            raise ToolError(converted.stderr.strip() or "Cilium render YAML parsing failed")
        try:
            documents = json.loads(converted.stdout)
        except json.JSONDecodeError as error:
            raise ToolError(f"Cilium render returned invalid JSON: {error}") from error
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


def audit(chart_path: Path | None = None) -> dict[str, Any]:
    lock = load_yaml(LOCK_FILE)
    chart_lock = lock["charts"]["cilium"]
    values = replace_strings(copy.deepcopy(load_yaml(EKS_ROOT / "values" / "cilium.yaml")))
    documents = render_documents(read_chart(chart_path, chart_lock), values)

    agent = select_one(documents, "DaemonSet", "cilium")
    operator = select_one(documents, "Deployment", "cilium-operator")
    config = select_one(documents, "ConfigMap", "cilium-config")
    service_account = select_one(documents, "ServiceAccount", "cilium-operator")

    expected_selector = {
        "karpenter.sh/nodepool": "spot-general",
        "kubernetes.io/os": "linux",
    }
    agent_spec = agent["spec"]["template"]["spec"]
    operator_spec = operator["spec"]["template"]["spec"]
    expect(agent_spec.get("hostNetwork"), True, "agent hostNetwork")
    expect(agent_spec.get("dnsPolicy"), "Default", "agent dnsPolicy")
    expect(agent_spec.get("nodeSelector"), expected_selector, "agent nodeSelector")
    expect(operator_spec.get("hostNetwork"), True, "operator hostNetwork")
    expect(operator_spec.get("dnsPolicy"), "Default", "operator dnsPolicy")
    expect(operator_spec.get("nodeSelector"), expected_selector, "operator nodeSelector")
    expect(operator_spec.get("serviceAccountName"), "cilium-operator", "operator service account")

    agent_tolerations = agent_spec.get("tolerations", [])
    operator_tolerations = operator_spec.get("tolerations", [])
    for label, tolerations in (("agent", agent_tolerations), ("operator", operator_tolerations)):
        if not any(
            item.get("key") == "node.cilium.io/agent-not-ready"
            and item.get("operator") == "Exists"
            for item in tolerations
        ):
            raise ToolError(f"{label} lacks startup-taint tolerance")

    agent_container = next(
        item for item in agent_spec["containers"] if item.get("name") == "cilium-agent"
    )
    operator_container = next(
        item for item in operator_spec["containers"] if item.get("name") == "cilium-operator"
    )
    expect(agent_container["image"], chart_lock["images"]["agent"], "agent image")
    expect(operator_container["image"], chart_lock["images"]["operatorAWS"], "operator image")
    expect(
        service_account.get("metadata", {}).get("annotations", {}).get(
            "eks.amazonaws.com/role-arn"
        ),
        REPLACEMENTS["__INJECTED_CILIUM_OPERATOR_ROLE_ARN__"],
        "operator IRSA annotation",
    )
    operator_env_names = {item.get("name") for item in operator_container.get("env", [])}
    for forbidden in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        if forbidden in operator_env_names:
            raise ToolError(f"operator rendered legacy credential variable {forbidden}")
    for required in ("KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT", "AWS_REGION"):
        if required not in operator_env_names:
            raise ToolError(f"operator lacks required environment variable {required}")

    config_data = config.get("data", {})
    expected_config = {
        "agent-not-ready-taint-key": "node.cilium.io/agent-not-ready",
        "eni-delete-on-termination": "true",
        "ipam": "eni",
        "ipv4-native-routing-cidr": "10.40.0.0/16",
        "kube-proxy-replacement": "true",
        "routing-mode": "native",
    }
    for key, expected_value in expected_config.items():
        expect(config_data.get(key), expected_value, f"cilium-config {key}")
    if "cni-chaining-mode" in config_data:
        raise ToolError("cni-chaining-mode must be absent for non-chained mode")
    expect(config_data.get("set-cilium-node-taints"), "true", "startup-taint management")
    expect(config_data.get("set-cilium-is-up-condition"), "true", "node network condition")

    forbidden_names = {"aws-node", "kube-proxy"}
    rendered_names = {
        item.get("metadata", {}).get("name")
        for item in documents
        if item.get("kind") in {"DaemonSet", "Deployment"}
    }
    if rendered_names & forbidden_names:
        raise ToolError(f"Cilium chart rendered forbidden workloads: {rendered_names & forbidden_names}")
    crds = [item for item in documents if item.get("kind") == "CustomResourceDefinition"]
    if crds:
        raise ToolError("locked Cilium chart unexpectedly rendered Helm-owned CRDs")

    return {
        "chartSha256": chart_lock["sha256"],
        "documents": len(documents),
        "agentHostNetwork": True,
        "operatorHostNetwork": True,
        "operatorIRSA": True,
        "legacyAWSKeyEnv": False,
        "runtimeUAT": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chart",
        type=Path,
        help="optional local cilium-1.20.1.tgz; its SHA-256 is still verified",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        print(json.dumps(audit(args.chart), indent=2, sort_keys=True))
        return 0
    except (OSError, ToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
