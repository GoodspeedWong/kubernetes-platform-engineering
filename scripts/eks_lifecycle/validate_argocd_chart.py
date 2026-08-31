#!/usr/bin/env python3
"""Render and audit the digest-locked Argo CD chart against the P8 values contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import EKS_ROOT, LOCK_FILE, ToolError, load_yaml, require_tool
from prepare_schemas import fetch_http


def read_chart(path: Path | None, chart_lock: dict[str, Any]) -> bytes:
    expected = str(chart_lock["sha256"])
    payload = path.read_bytes() if path else fetch_http(str(chart_lock["url"]), expected)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise ToolError(f"Argo CD chart digest mismatch: expected {expected}, got {actual}")
    return payload


def render_documents(chart_payload: bytes, values: dict[str, Any]) -> list[dict[str, Any]]:
    require_tool("helm")
    require_tool("yq")
    with tempfile.TemporaryDirectory(prefix="argocd-chart-audit-") as temporary:
        root = Path(temporary)
        chart_path = root / "argo-cd.tgz"
        values_path = root / "values.json"
        output_path = root / "rendered.yaml"
        chart_path.write_bytes(chart_payload)
        values_path.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n")
        rendered = subprocess.run(
            [
                "helm",
                "template",
                "argocd",
                str(chart_path),
                "--namespace",
                "argocd",
                "--kube-version",
                "1.35.0",
                "--include-crds",
                "--values",
                str(values_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if rendered.returncode != 0:
            raise ToolError(rendered.stderr.strip() or "Argo CD Helm render failed")
        output_path.write_text(rendered.stdout)
        converted = subprocess.run(
            ["yq", "eval-all", "-o=json", "[.]", str(output_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if converted.returncode != 0:
            raise ToolError(converted.stderr.strip() or "Argo CD render YAML parsing failed")
        try:
            documents = json.loads(converted.stdout)
        except json.JSONDecodeError as error:
            raise ToolError(f"Argo CD render returned invalid JSON: {error}") from error
    return [item for item in documents if isinstance(item, dict) and item.get("kind")]


def select_one(documents: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
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
    chart_lock = lock["charts"]["argoCD"]
    values = load_yaml(EKS_ROOT / "values" / "argocd.yaml")
    documents = render_documents(read_chart(chart_path, chart_lock), values)

    forbidden_cluster_rbac = [
        item
        for item in documents
        if item.get("kind") in {"ClusterRole", "ClusterRoleBinding"}
    ]
    if forbidden_cluster_rbac:
        names = [item.get("metadata", {}).get("name") for item in forbidden_cluster_rbac]
        raise ToolError(f"namespace-scoped Argo CD rendered cluster RBAC: {names}")

    expected_selector = {
        "karpenter.sh/nodepool": "spot-general",
        "kubernetes.io/os": "linux",
    }
    workload_refs = (
        ("StatefulSet", "argocd-application-controller"),
        ("Deployment", "argocd-repo-server"),
        ("Deployment", "argocd-server"),
        ("Deployment", "argocd-redis"),
        ("Deployment", "argocd-applicationset-controller"),
        ("Job", "argocd-redis-secret-init"),
    )
    expected_argocd_image = chart_lock["image"]
    expected_redis_image = chart_lock["redisImage"]
    for kind, name in workload_refs:
        workload = select_one(documents, kind, name)
        pod_spec = workload["spec"]["template"]["spec"]
        expect(pod_spec.get("nodeSelector"), expected_selector, f"{kind}/{name} nodeSelector")
        containers = pod_spec.get("initContainers", []) + pod_spec.get("containers", [])
        if not containers:
            raise ToolError(f"{kind}/{name} rendered no containers")
        for container in containers:
            image = container.get("image")
            expected = expected_redis_image if name == "argocd-redis" else expected_argocd_image
            expect(image, expected, f"{kind}/{name} container image")

    application_set = select_one(
        documents, "Deployment", "argocd-applicationset-controller"
    )
    expect(application_set["spec"].get("replicas"), 0, "ApplicationSet replicas")
    forbidden_workloads = {
        "argocd-dex-server",
        "argocd-notifications-controller",
        "argocd-commit-server",
    }
    rendered_workload_names = {
        item.get("metadata", {}).get("name")
        for item in documents
        if item.get("kind") in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
    }
    if rendered_workload_names & forbidden_workloads:
        raise ToolError(
            f"disabled Argo CD components were rendered: {rendered_workload_names & forbidden_workloads}"
        )

    for kind in ("Ingress", "PersistentVolumeClaim"):
        matches = [item for item in documents if item.get("kind") == kind]
        if matches:
            raise ToolError(f"Argo CD dev chart must not render {kind}")
    server_service = select_one(documents, "Service", "argocd-server")
    expect(server_service["spec"].get("type"), "ClusterIP", "Argo CD server Service type")

    expected_pdbs = {
        "argocd-application-controller",
        "argocd-repo-server",
        "argocd-server",
        "argocd-redis",
    }
    pdbs = {
        item.get("metadata", {}).get("name"): item
        for item in documents
        if item.get("kind") == "PodDisruptionBudget"
    }
    if set(pdbs) != expected_pdbs:
        raise ToolError(f"unexpected Argo CD PDB inventory: {sorted(pdbs)}")
    for name, pdb in pdbs.items():
        expect(pdb["spec"].get("maxUnavailable"), 1, f"PDB/{name} maxUnavailable")

    argocd_cm = select_one(documents, "ConfigMap", "argocd-cm")
    expect(argocd_cm.get("data", {}).get("admin.enabled"), "false", "local admin")
    exclusions = argocd_cm.get("data", {}).get("resource.exclusions", "")
    for required in (
        "platform.aws.goodnotes.io",
        "karpenter.sh",
        "karpenter.k8s.aws",
        "cilium.io",
        "ApplicationSet",
    ):
        if required not in exclusions:
            raise ToolError(f"argocd-cm resource exclusions lack {required}")

    crd_names = {
        item.get("metadata", {}).get("name")
        for item in documents
        if item.get("kind") == "CustomResourceDefinition"
    }
    expected_crds = {
        "applications.argoproj.io",
        "applicationsets.argoproj.io",
        "appprojects.argoproj.io",
    }
    if crd_names != expected_crds:
        raise ToolError(f"unexpected Argo CD CRD inventory: {sorted(crd_names)}")

    return {
        "chartSha256": chart_lock["sha256"],
        "clusterRoles": 0,
        "documents": len(documents),
        "pdbs": len(pdbs),
        "persistentClaims": 0,
        "spotScheduledWorkloads": len(workload_refs),
        "runtimeUAT": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chart",
        type=Path,
        help="optional local argo-cd-10.4.0.tgz; its SHA-256 is still verified",
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
