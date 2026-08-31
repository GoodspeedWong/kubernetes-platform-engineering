#!/usr/bin/env python3
"""Validate a P2 XEKSEnvironment contract without contacting Kubernetes or AWS."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

from common import LOCK_FILE, ToolError, load_yaml


RETIREMENT_STAGES = (
    "Active",
    "DrainWorkloads",
    "RemoveGitOps",
    "DrainCapacity",
    "RemoveFoundation",
    "DeleteReady",
)
CPU_LIMITS = {"4", "8", "16", "32", "64"}
MEMORY_LIMITS = {"16Gi", "32Gi", "64Gi", "128Gi", "256Gi"}
FORBIDDEN_FIELDS = {
    "amiId",
    "capacityType",
    "helmValues",
    "instanceTypes",
    "routeTableIds",
    "securityGroupIds",
    "subnetIds",
    "vpcId",
}
REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
ARN_RE = re.compile(
    r"^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$"
)
NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
AMI_RE = re.compile(r"^ami-[0-9a-f]{17}$")
GIT_REPOSITORY_RE = re.compile(
    r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9._~/-]+\.git$"
)
GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
GIT_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def require_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolError(f"{path} must be an object")
    return value


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolError(f"{path} must be a non-empty string")
    return value


def assert_no_forbidden_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_FIELDS:
                raise ToolError(f"forbidden implementation field at {path}.{key}")
            assert_no_forbidden_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_forbidden_fields(child, f"{path}[{index}]")


def validate_ref(value: Any, path: str, expected_kind: str) -> dict[str, Any]:
    reference = require_mapping(value, path)
    if set(reference) != {"kind", "name"}:
        raise ToolError(f"{path} must contain exactly kind and name")
    if reference.get("kind") != expected_kind:
        raise ToolError(f"{path}.kind must be {expected_kind}")
    name = require_string(reference.get("name"), f"{path}.name")
    if len(name) > 253 or not NAME_RE.fullmatch(name):
        raise ToolError(f"{path}.name is not a valid catalog or provider name")
    return reference


def validate_evidence_ref(value: Any, path: str) -> dict[str, Any]:
    reference = require_mapping(value, path)
    if set(reference) != {"kind", "name", "namespace"}:
        raise ToolError(f"{path} must contain exactly kind, name, and namespace")
    if reference.get("kind") != "ConfigMap":
        raise ToolError(f"{path}.kind must be ConfigMap")
    if reference.get("namespace") != "crossplane-system":
        raise ToolError(f"{path}.namespace must be crossplane-system")
    name = require_string(reference.get("name"), f"{path}.name")
    if len(name) > 63 or not DNS_LABEL_RE.fullmatch(name):
        raise ToolError(f"{path}.name must be a DNS label of at most 63 characters")
    return reference


def validate_retirement_transition(old_stage: str | None, new_stage: str) -> None:
    if new_stage not in RETIREMENT_STAGES:
        raise ToolError(f"unsupported retirementStage: {new_stage}")
    if old_stage is None:
        if new_stage != "Active":
            raise ToolError("new environments must start at retirementStage Active")
        return
    if old_stage not in RETIREMENT_STAGES:
        raise ToolError(f"unsupported previous retirementStage: {old_stage}")
    old_index = RETIREMENT_STAGES.index(old_stage)
    new_index = RETIREMENT_STAGES.index(new_stage)
    if new_index not in {old_index, old_index + 1}:
        raise ToolError(
            f"retirementStage may stay at {old_stage} or advance exactly one stage"
        )


def validate_network(parameters: dict[str, Any]) -> None:
    region = require_string(parameters.get("region"), "spec.parameters.region")
    if not REGION_RE.fullmatch(region):
        raise ToolError("spec.parameters.region is not a valid AWS region shape")
    network = require_mapping(parameters.get("network"), "spec.parameters.network")
    if set(network) != {"cidrBlock", "publicSubnets", "privateSubnets"}:
        raise ToolError(
            "spec.parameters.network must contain exactly cidrBlock, publicSubnets, and privateSubnets"
        )
    try:
        vpc = ipaddress.ip_network(
            require_string(network.get("cidrBlock"), "spec.parameters.network.cidrBlock"),
            strict=True,
        )
    except ValueError as error:
        raise ToolError(f"invalid VPC CIDR: {error}") from error
    if vpc.version != 4 or not 16 <= vpc.prefixlen <= 24:
        raise ToolError("VPC CIDR must be IPv4 with a /16 through /24 prefix")

    parsed_subnets: list[ipaddress.IPv4Network] = []
    zones: dict[str, dict[str, str]] = {}
    for scope in ("publicSubnets", "privateSubnets"):
        subnets = require_mapping(network.get(scope), f"spec.parameters.network.{scope}")
        if set(subnets) != {"a", "b"}:
            raise ToolError(f"spec.parameters.network.{scope} must contain exactly a and b")
        zones[scope] = {}
        for slot in ("a", "b"):
            subnet = require_mapping(
                subnets.get(slot), f"spec.parameters.network.{scope}.{slot}"
            )
            if set(subnet) != {"availabilityZone", "cidrBlock"}:
                raise ToolError(
                    f"spec.parameters.network.{scope}.{slot} must contain exactly availabilityZone and cidrBlock"
                )
            zone = require_string(
                subnet.get("availabilityZone"),
                f"spec.parameters.network.{scope}.{slot}.availabilityZone",
            )
            if not zone.startswith(region) or zone == region:
                raise ToolError(f"availability zone {zone} does not belong to region {region}")
            zones[scope][slot] = zone
            try:
                parsed = ipaddress.ip_network(
                    require_string(
                        subnet.get("cidrBlock"),
                        f"spec.parameters.network.{scope}.{slot}.cidrBlock",
                    ),
                    strict=True,
                )
            except ValueError as error:
                raise ToolError(f"invalid subnet CIDR: {error}") from error
            if parsed.version != 4 or not 20 <= parsed.prefixlen <= 28:
                raise ToolError("subnet CIDRs must be IPv4 with a /20 through /28 prefix")
            if not parsed.subnet_of(vpc):
                raise ToolError(f"subnet {parsed} is outside VPC {vpc}")
            parsed_subnets.append(parsed)
        if zones[scope]["a"] == zones[scope]["b"]:
            raise ToolError(f"{scope} must span two availability zones")

    if zones["publicSubnets"] != zones["privateSubnets"]:
        raise ToolError("public/private subnet slots must use the same two availability zones")
    for index, left in enumerate(parsed_subnets):
        for right in parsed_subnets[index + 1 :]:
            if left.overlaps(right):
                raise ToolError(f"subnet CIDRs overlap: {left} and {right}")


def validate_access(parameters: dict[str, Any]) -> None:
    access = require_mapping(parameters.get("access"), "spec.parameters.access")
    expected_fields = {
        "adminPrincipalArn",
        "deploymentPrincipalArn",
        "publicAccessCidrs",
    }
    if set(access) != expected_fields:
        raise ToolError(
            "spec.parameters.access must contain exactly adminPrincipalArn, "
            "deploymentPrincipalArn, and publicAccessCidrs"
        )
    principals: dict[str, str] = {}
    for field in ("adminPrincipalArn", "deploymentPrincipalArn"):
        principal = require_string(
            access.get(field), f"spec.parameters.access.{field}"
        )
        if not ARN_RE.fullmatch(principal):
            raise ToolError(f"{field} must be an IAM role ARN")
        principals[field] = principal
    if principals["adminPrincipalArn"] == principals["deploymentPrincipalArn"]:
        raise ToolError(
            "administrator and deployment principals must be distinct IAM roles"
        )
    cidrs = access.get("publicAccessCidrs")
    if not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 8:
        raise ToolError("publicAccessCidrs must contain 1 through 8 IPv4 CIDRs")
    if len(set(cidrs)) != len(cidrs):
        raise ToolError("publicAccessCidrs must not contain duplicates")
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(require_string(cidr, "publicAccessCidrs[]"))
        except ValueError as error:
            raise ToolError(f"invalid public access CIDR: {error}") from error
        if network.version != 4 or network.prefixlen == 0:
            raise ToolError("unrestricted or non-IPv4 public endpoint access is forbidden")


def validate_compute(parameters: dict[str, Any]) -> None:
    compute = require_mapping(parameters.get("compute"), "spec.parameters.compute")
    if set(compute) != {"class", "limits"}:
        raise ToolError("spec.parameters.compute must contain exactly class and limits")
    if compute.get("class") != "spot-general":
        raise ToolError("compute.class must be spot-general; no fallback is supported")
    limits = require_mapping(compute.get("limits"), "spec.parameters.compute.limits")
    if set(limits) != {"cpu", "memory"}:
        raise ToolError("compute.limits must contain finite cpu and memory values")
    if limits.get("cpu") not in CPU_LIMITS:
        raise ToolError("compute.limits.cpu is not one of the bounded platform values")
    if limits.get("memory") not in MEMORY_LIMITS:
        raise ToolError("compute.limits.memory is not one of the bounded platform values")


def validate_gitops(
    parameters: dict[str, Any], old_parameters: dict[str, Any] | None = None
) -> None:
    value = parameters.get("gitOps")
    old_value = old_parameters.get("gitOps") if old_parameters else None
    if value is None:
        if old_value is not None:
            raise ToolError(
                "gitOps cannot be removed directly; use lifecycle.retirementStage"
            )
        return
    gitops = require_mapping(value, "spec.parameters.gitOps")
    expected = {
        "credentialsSecretRef",
        "destinationNamespace",
        "path",
        "repositoryURL",
        "revision",
    }
    if set(gitops) != expected:
        raise ToolError(f"spec.parameters.gitOps must contain exactly {sorted(expected)}")
    repository = require_string(
        gitops.get("repositoryURL"), "spec.parameters.gitOps.repositoryURL"
    )
    if not GIT_REPOSITORY_RE.fullmatch(repository):
        raise ToolError("gitOps.repositoryURL must be an HTTPS .git URL without credentials")
    revision = require_string(gitops.get("revision"), "spec.parameters.gitOps.revision")
    if not GIT_REVISION_RE.fullmatch(revision):
        raise ToolError("gitOps.revision must be an exact lowercase 40-character commit SHA")
    path = require_string(gitops.get("path"), "spec.parameters.gitOps.path")
    if (
        len(path) > 253
        or not GIT_PATH_RE.fullmatch(path)
        or any(segment in {"", ".", ".."} for segment in path.split("/"))
    ):
        raise ToolError("gitOps.path must be a normalized relative Git path")
    secret_ref = require_mapping(
        gitops.get("credentialsSecretRef"),
        "spec.parameters.gitOps.credentialsSecretRef",
    )
    if set(secret_ref) != {"name"}:
        raise ToolError("gitOps.credentialsSecretRef must contain exactly name")
    secret_name = require_string(
        secret_ref.get("name"), "spec.parameters.gitOps.credentialsSecretRef.name"
    )
    if len(secret_name) > 63 or not DNS_LABEL_RE.fullmatch(secret_name):
        raise ToolError("gitOps credentials Secret name must be a DNS label")
    if gitops.get("destinationNamespace") != "apps":
        raise ToolError("gitOps.destinationNamespace must be apps")
    if old_value is not None:
        old_gitops = require_mapping(old_value, "old.spec.parameters.gitOps")
        for field in (
            "repositoryURL",
            "credentialsSecretRef",
            "destinationNamespace",
        ):
            if gitops.get(field) != old_gitops.get(field):
                raise ToolError(f"spec.parameters.gitOps.{field} is immutable")


def validate_catalog_compatibility(
    parameters: dict[str, Any],
    platform_release: dict[str, Any],
    node_image: dict[str, Any],
    lock: dict[str, Any],
) -> None:
    release_ref = validate_ref(
        parameters.get("platformReleaseRef"),
        "spec.parameters.platformReleaseRef",
        "EnvironmentConfig",
    )
    image_ref = validate_ref(
        parameters.get("nodeImageRef"),
        "spec.parameters.nodeImageRef",
        "EnvironmentConfig",
    )
    for document, reference, label in (
        (platform_release, release_ref, "platform release"),
        (node_image, image_ref, "node image"),
    ):
        if document.get("apiVersion") != "apiextensions.crossplane.io/v1beta1":
            raise ToolError(f"{label} must use EnvironmentConfig v1beta1")
        if document.get("kind") != "EnvironmentConfig":
            raise ToolError(f"{label} must be an EnvironmentConfig")
        name = require_mapping(document.get("metadata"), f"{label}.metadata").get("name")
        if name != reference["name"]:
            raise ToolError(f"{label} name does not match its reference")

    version = parameters["kubernetesVersion"]
    release_data = require_mapping(
        require_mapping(platform_release.get("spec"), "platform release.spec").get("data"),
        "platform release.spec.data",
    )
    image_data = require_mapping(
        require_mapping(node_image.get("spec"), "node image.spec").get("data"),
        "node image.spec.data",
    )
    if str(release_data.get("kubernetes")) != version:
        raise ToolError("platform release is incompatible with kubernetesVersion")
    if str(image_data.get("kubernetes")) != version:
        raise ToolError("node image is incompatible with kubernetesVersion")
    if image_data.get("region") != parameters["region"]:
        raise ToolError("node image is incompatible with region")

    charts = require_mapping(lock.get("charts"), "versions.lock.charts")
    addons = require_mapping(lock.get("eksAddons"), "versions.lock.eksAddons")
    expected = {
        "cilium": require_mapping(charts.get("cilium"), "charts.cilium").get("version"),
        "karpenter": require_mapping(charts.get("karpenter"), "charts.karpenter").get("version"),
        "argoCDChart": require_mapping(charts.get("argoCD"), "charts.argoCD").get("chartVersion"),
        "argoCDApp": require_mapping(charts.get("argoCD"), "charts.argoCD").get("appVersion"),
        "coreDNSAddon": require_mapping(addons.get("coreDNS"), "eksAddons.coreDNS").get("version"),
    }
    release_cilium = require_mapping(release_data.get("cilium"), "release.cilium")
    release_karpenter = require_mapping(release_data.get("karpenter"), "release.karpenter")
    release_argocd = require_mapping(release_data.get("argoCD"), "release.argoCD")
    actual = {
        "cilium": release_cilium.get("chart"),
        "karpenter": release_karpenter.get("controllerChart"),
        "argoCDChart": release_argocd.get("chart"),
        "argoCDApp": release_argocd.get("app"),
        "coreDNSAddon": release_data.get("coreDNSAddon"),
    }
    if actual != expected:
        raise ToolError("platform release versions do not match versions.lock.yaml")
    if release_karpenter.get("crdChart") != expected["karpenter"]:
        raise ToolError("Karpenter CRD and controller chart versions must match")

    images = require_mapping(image_data.get("images"), "node image.images")
    amd64 = require_mapping(images.get("amd64"), "node image.images.amd64")
    locked_image = require_mapping(
        require_mapping(lock.get("nodeImages"), "versions.lock.nodeImages").get("al2023"),
        "versions.lock.nodeImages.al2023",
    )
    if amd64.get("family") != "AL2023":
        raise ToolError("node image family must be AL2023")
    if amd64.get("release") != locked_image.get("release"):
        raise ToolError("node image release does not match versions.lock.yaml")
    if amd64.get("alias") != locked_image.get("alias"):
        raise ToolError("node image alias does not match versions.lock.yaml")
    if not AMI_RE.fullmatch(str(amd64.get("amiId", ""))):
        raise ToolError("node image amiId must have the AWS AMI identifier shape")


def validate_environment(
    instance: dict[str, Any],
    platform_release: dict[str, Any],
    node_image: dict[str, Any],
    lock: dict[str, Any],
    old_instance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    assert_no_forbidden_fields(instance)
    if instance.get("apiVersion") != "platform.aws.goodnotes.io/v1alpha1":
        raise ToolError("instance apiVersion must be platform.aws.goodnotes.io/v1alpha1")
    if instance.get("kind") != "XEKSEnvironment":
        raise ToolError("instance kind must be XEKSEnvironment")
    metadata = require_mapping(instance.get("metadata"), "metadata")
    name = require_string(metadata.get("name"), "metadata.name")
    if len(name) > 52 or not DNS_LABEL_RE.fullmatch(name):
        raise ToolError("metadata.name must be a DNS name of at most 52 characters")
    spec = require_mapping(instance.get("spec"), "spec")
    crossplane = require_mapping(spec.get("crossplane"), "spec.crossplane")
    if crossplane.get("compositionUpdatePolicy") != "Manual":
        raise ToolError("spec.crossplane.compositionUpdatePolicy must be Manual")
    parameters = require_mapping(spec.get("parameters"), "spec.parameters")
    if parameters.get("class") != "dev":
        raise ToolError("spec.parameters.class must be dev")
    validate_ref(
        parameters.get("providerConfigRef"),
        "spec.parameters.providerConfigRef",
        "ClusterProviderConfig",
    )
    if parameters.get("kubernetesVersion") != "1.35":
        raise ToolError("kubernetesVersion must be 1.35 for this API revision")
    validate_network(parameters)
    validate_compute(parameters)
    validate_access(parameters)

    lifecycle = require_mapping(parameters.get("lifecycle"), "spec.parameters.lifecycle")
    allowed_lifecycle_fields = {"retirementStage", "deletionProtection", "evidenceRef"}
    if not {"retirementStage", "deletionProtection"}.issubset(lifecycle) or not set(
        lifecycle
    ).issubset(allowed_lifecycle_fields):
        raise ToolError(
            "spec.parameters.lifecycle supports retirementStage, deletionProtection, and optional evidenceRef"
        )
    stage = require_string(
        lifecycle.get("retirementStage"), "spec.parameters.lifecycle.retirementStage"
    )
    old_parameters: dict[str, Any] | None = None
    old_stage: str | None = None
    if old_instance is not None:
        old_parameters = require_mapping(
            require_mapping(old_instance.get("spec"), "old.spec").get("parameters"),
            "old.spec.parameters",
        )
        old_stage = require_string(
            require_mapping(old_parameters.get("lifecycle"), "old.lifecycle").get(
                "retirementStage"
            ),
            "old.lifecycle.retirementStage",
        )
        for field in ("class", "region", "network", "providerConfigRef"):
            if parameters.get(field) != old_parameters.get(field):
                raise ToolError(f"spec.parameters.{field} is immutable")
        old_lifecycle = require_mapping(
            old_parameters.get("lifecycle"), "old.spec.parameters.lifecycle"
        )
        if old_lifecycle.get("evidenceRef") is not None and lifecycle.get(
            "evidenceRef"
        ) != old_lifecycle.get("evidenceRef"):
            raise ToolError("lifecycle.evidenceRef cannot be changed or removed")
    validate_gitops(parameters, old_parameters)
    validate_retirement_transition(old_stage, stage)
    deletion_protection = lifecycle.get("deletionProtection")
    if not isinstance(deletion_protection, bool):
        raise ToolError("lifecycle.deletionProtection must be boolean")
    if not deletion_protection and stage != "DeleteReady":
        raise ToolError("deletionProtection may be false only at DeleteReady")
    if old_instance is None and not deletion_protection:
        raise ToolError("new environments must enable deletionProtection")
    evidence_ref = lifecycle.get("evidenceRef")
    if stage != "Active" and evidence_ref is None:
        raise ToolError("non-Active retirement stages require lifecycle.evidenceRef")
    if evidence_ref is not None:
        validate_evidence_ref(evidence_ref, "spec.parameters.lifecycle.evidenceRef")

    validate_catalog_compatibility(parameters, platform_release, node_image, lock)
    return {
        "environment": name,
        "class": "dev",
        "kubernetesVersion": "1.35",
        "capacityClass": "spot-general",
        "gitOpsConfigured": parameters.get("gitOps") is not None,
        "retirementStage": stage,
        "awsMutation": False,
        "kubernetesMutation": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate one XEKSEnvironment and its catalog references without applying resources."
    )
    parser.add_argument("--instance", type=Path, required=True)
    parser.add_argument("--platform-release", type=Path, required=True)
    parser.add_argument("--node-image", type=Path, required=True)
    parser.add_argument("--old-instance", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        report = validate_environment(
            load_yaml(args.instance),
            load_yaml(args.platform_release),
            load_yaml(args.node_image),
            load_yaml(LOCK_FILE),
            load_yaml(args.old_instance) if args.old_instance else None,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, ToolError, TypeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
