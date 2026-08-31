#!/usr/bin/env python3
"""Validate the static Cilium/EKS bootstrap contract without touching a cluster."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any

from common import LOCK_FILE, ToolError, load_yaml


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"


def require_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolError(f"{path} must be an object")
    return value


def resources_by_name(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    resources: dict[str, dict[str, Any]] = {}
    for item in document.get("items", []):
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            continue
        annotations = metadata.get("annotations")
        if not isinstance(annotations, dict):
            continue
        name = annotations.get(RESOURCE_NAME)
        if not isinstance(name, str):
            continue
        if name in resources:
            raise ToolError(f"duplicate composition resource name: {name}")
        resources[name] = item
    return resources


def expect_equal(actual: Any, expected: Any, path: str) -> None:
    if actual != expected:
        raise ToolError(f"{path} must be {expected!r}; got {actual!r}")


def validate_cilium_contract(
    foundation_render: dict[str, Any],
    cluster_render: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resources = resources_by_name(foundation_render)
    lock = load_yaml(LOCK_FILE)
    release = require_mapping(resources.get("cilium-release"), "cilium-release")
    release_labels = require_mapping(release.get("metadata", {}).get("labels"), "cilium labels")
    environment_name = release_labels.get("platform.aws.goodnotes.io/environment")
    cluster_name = release_labels.get("platform.aws.goodnotes.io/cluster")
    if not isinstance(environment_name, str) or not isinstance(cluster_name, str):
        raise ToolError("Cilium Release must carry environment and cluster ownership labels")
    provider = require_mapping(
        require_mapping(release.get("spec"), "cilium-release.spec").get("forProvider"),
        "cilium-release.spec.forProvider",
    )
    chart = require_mapping(provider.get("chart"), "cilium-release chart")
    expect_equal(chart.get("name"), "cilium", "cilium chart name")
    expect_equal(chart.get("repository"), "oci://quay.io/cilium/charts", "cilium chart repository")
    expect_equal(chart.get("digest"), lock["charts"]["cilium"]["manifestDigest"], "cilium chart digest")
    expect_equal(chart.get("version"), "1.20.1", "cilium chart version")
    expect_equal(provider.get("namespace"), "kube-system", "cilium namespace")
    expect_equal(provider.get("skipCreateNamespace"), True, "cilium skipCreateNamespace")
    expect_equal(provider.get("skipCRDs"), True, "cilium Helm CRD ownership")
    expect_equal(provider.get("wait"), True, "cilium Helm wait")
    expect_equal(
        provider.get("valuesFrom"),
        [{"secretKeyRef": {"key": "cilium-values", "name": f"{environment_name}-eks-access"}}],
        "cilium runtime values source",
    )

    values = require_mapping(provider.get("values"), "cilium values")
    expect_equal(values.get("ipam"), {"mode": "eni"}, "Cilium IPAM mode")
    expect_equal(values.get("routingMode"), "native", "Cilium routing mode")
    expect_equal(values.get("autoDirectNodeRoutes"), False, "Cilium autoDirectNodeRoutes")
    native_cidr = values.get("ipv4NativeRoutingCIDR")
    try:
        parsed_cidr = ipaddress.ip_network(native_cidr, strict=True)
    except (TypeError, ValueError) as error:
        raise ToolError(f"native routing CIDR must be a canonical network: {error}") from error
    if parsed_cidr.version != 4:
        raise ToolError("native routing CIDR must be IPv4 for Cilium ENI mode")
    expect_equal(values.get("kubeProxyReplacement"), True, "kube-proxy replacement")
    if "k8sServiceHost" in values or "k8sServicePort" in values:
        raise ToolError("EKS API host and port must come from cluster-owned runtime values")

    cni = require_mapping(values.get("cni"), "cilium values.cni")
    expect_equal(cni.get("chainingMode"), "none", "CNI chaining mode")
    expect_equal(cni.get("exclusive"), True, "CNI exclusive mode")
    expect_equal(cni.get("uninstall"), False, "CNI uninstall safety")
    expect_equal(cni.get("iptablesRemoveAWSRules"), True, "AWS CNI rule cleanup")

    eni = require_mapping(values.get("eni"), "cilium values.eni")
    expect_equal(eni.get("enabled"), True, "AWS ENI mode")
    expect_equal(eni.get("awsReleaseExcessIPs"), True, "excess IP release")
    node_spec = require_mapping(eni.get("nodeSpec"), "cilium values.eni.nodeSpec")
    expect_equal(node_spec.get("deleteOnTermination"), True, "ENI deletion policy")
    for path, entries in (
        ("instanceTagsFilter", eni.get("instanceTagsFilter")),
        ("subnetTagsFilter", eni.get("subnetTagsFilter")),
        ("nodeSpec.subnetTags", node_spec.get("subnetTags")),
        ("nodeSpec.securityGroupTags", node_spec.get("securityGroupTags")),
    ):
        if not isinstance(entries, list) or not entries:
            raise ToolError(f"cilium values.eni.{path} must be a non-empty tag filter")
        if not all(isinstance(item, str) and "=" in item for item in entries):
            raise ToolError(f"cilium values.eni.{path} must contain only k=v filters")
    required_eni_tags = {
        "io.cilium/cilium-managed": "true",
        "io.cilium/cluster-name": cluster_name,
        "platform.aws.goodnotes.io/environment": environment_name,
    }
    expect_equal(eni.get("eniTags"), required_eni_tags, "created ENI tags")
    expect_equal(eni.get("gcTags"), required_eni_tags, "ENI garbage-collection scope")

    expected_selector = {
        "karpenter.sh/nodepool": "spot-general",
        "kubernetes.io/os": "linux",
    }
    expect_equal(values.get("nodeSelector"), expected_selector, "Cilium agent node selector")
    operator = require_mapping(values.get("operator"), "cilium values.operator")
    expect_equal(operator.get("nodeSelector"), expected_selector, "Cilium operator node selector")
    expect_equal(operator.get("hostNetwork"), True, "Cilium operator host network")
    expect_equal(operator.get("dnsPolicy"), "Default", "Cilium operator DNS policy")
    expect_equal(values.get("dnsPolicy"), "Default", "Cilium agent DNS policy")
    expect_equal(operator.get("removeNodeTaints"), True, "Cilium startup-taint removal")
    expect_equal(operator.get("setNodeTaints"), True, "Cilium startup-taint management")
    expect_equal(operator.get("setNodeNetworkStatus"), True, "Cilium node network status")
    expect_equal(operator.get("skipCRDCreation"), False, "Cilium CRD owner")
    expect_equal(operator.get("replicas"), 2, "Cilium operator replicas")
    expect_equal(
        operator.get("affinity", {}).get("podAntiAffinity", {}).get(
            "requiredDuringSchedulingIgnoredDuringExecution"
        ),
        [],
        "Cilium operator hard anti-affinity override",
    )
    expect_equal(
        operator.get("topologySpreadConstraints", [{}])[0].get("whenUnsatisfiable"),
        "ScheduleAnyway",
        "Cilium operator zone spreading",
    )
    agent_tolerations = values.get("tolerations", [])
    if not any(
        item.get("key") == "node.cilium.io/agent-not-ready"
        and item.get("operator") == "Exists"
        for item in agent_tolerations
        if isinstance(item, dict)
    ):
        raise ToolError("Cilium agent must tolerate the NodePool startup taint")

    if cluster_render is not None:
        cluster_resources = resources_by_name(cluster_render)
        secret = require_mapping(
            cluster_resources.get("remote-kubeconfig-secret"),
            "cluster remote-kubeconfig-secret",
        )
        string_data = require_mapping(secret.get("stringData"), "connection Secret stringData")
        try:
            runtime_values = json.loads(string_data["cilium-values"])
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ToolError(f"invalid cilium-values runtime document: {error}") from error
        try:
            kubeconfig = json.loads(string_data["kubeconfig"])
            server = kubeconfig["clusters"][0]["cluster"]["server"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            raise ToolError(f"invalid token-free kubeconfig document: {error}") from error
        expected_host = server.removeprefix("https://")
        expect_equal(runtime_values.get("k8sServiceHost"), expected_host, "EKS API host")
        if "://" in expected_host:
            raise ToolError("EKS API server must use an HTTPS URL")
        expect_equal(runtime_values.get("k8sServicePort"), "443", "EKS API port")
        iam_role = runtime_values.get("eni", {}).get("iamRole")
        if not isinstance(iam_role, str) or not iam_role.endswith(
            f":role/{environment_name}-cilium"
        ):
            raise ToolError("Cilium operator IRSA role must be environment-scoped")
        serialized = json.dumps(runtime_values, sort_keys=True).lower()
        for forbidden in ("accesskey", "secretkey", "password", "token"):
            if forbidden in serialized:
                raise ToolError(f"cilium-values unexpectedly contains {forbidden}")

        fargate = require_mapping(
            cluster_resources.get("karpenter-fargate-profile"),
            "karpenter Fargate profile",
        )
        selectors = fargate["spec"]["forProvider"]["selector"]
        if any(item.get("namespace") == "kube-system" for item in selectors):
            raise ToolError("Fargate profile must not match Cilium or CoreDNS in kube-system")

        control_plane = cluster_resources["eks-control-plane"]
        expect_equal(
            control_plane["spec"]["forProvider"].get("bootstrapSelfManagedAddons"),
            False,
            "EKS self-managed addon bootstrap",
        )
        addons = [
            item["spec"]["forProvider"].get("addonName")
            for item in cluster_resources.values()
            if item.get("kind") == "Addon"
        ]
        expect_equal(addons, ["coredns"], "EKS addon owner inventory")
        expect_equal(
            cluster_resources["coredns-addon"]["spec"]["forProvider"].get("addonVersion"),
            "v1.14.3-eksbuild.3",
            "CoreDNS addon version",
        )

    return {
        "chartVersion": chart["version"],
        "cniOwner": "cilium",
        "ec2Only": True,
        "ipam": "eni",
        "kubeProxyReplacement": True,
        "runtimeUAT": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--foundation-render", type=Path, required=True)
    parser.add_argument("--cluster-render", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = validate_cilium_contract(
            load_yaml(args.foundation_render),
            load_yaml(args.cluster_render) if args.cluster_render else None,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
