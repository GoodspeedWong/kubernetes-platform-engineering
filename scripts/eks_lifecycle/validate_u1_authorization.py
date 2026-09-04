#!/usr/bin/env python3
"""Validate one private, single-use U1 bootstrap-create authorization pack."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from common import ToolError, find_placeholders, load_yaml
import validate_u0_authorization as u0_authorization


SCHEMA_VERSION = 1
AUTHORIZATION_TYPE = "u1-bootstrap-create-window"
PENDING_STATUS = "PENDING_OPERATOR_APPROVAL"
APPROVED_STATUS = "APPROVED_FOR_ONE_U1_BOOTSTRAP_CREATE_WINDOW"
MAX_SESSION_SECONDS = 3600
MAX_EXECUTION_SECONDS = 3000
APPROVAL_MAX_AGE_SECONDS = 86400
SNAPSHOT_MAX_AGE_SECONDS = 86400
CLAIM_SCHEMA_VERSION = 1
CLAIM_STATUS = "CLAIMED_FOR_U1_BOOTSTRAP_CREATE"
CLAIM_ACKNOWLEDGEMENT = "I-CLAIM-ONE-U1-BOOTSTRAP-CREATE-WINDOW"
CLAIM_ROOT = Path.home() / ".local/share/eks-platform/u1-authorizations"
BUNDLE_RE = re.compile(
    r"^u1-bootstrap-[0-9]{4}-[0-9]{2}-[0-9]{2}(?:-[0-9]{2})?$"
)
WINDOW_RE = re.compile(r"^u1b-[0-9]{8}-[0-9]{2}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IPV4_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")

EXPECTED_KUBERNETES_VERSION = "1.35"
EXPECTED_COREDNS_ADDON_VERSION = "v1.14.3-eksbuild.3"
EXPECTED_PLATFORM_RELEASE_DATA = {
    "schemaVersion": 1,
    "kubernetes": EXPECTED_KUBERNETES_VERSION,
    "crossplane": {"core": "v2.2.1", "cli": "v2.3.0"},
    "cilium": {"chart": "1.20.1", "app": "1.20.1"},
    "karpenter": {
        "crdChart": "1.14.1",
        "controllerChart": "1.14.1",
        "app": "1.14.1",
    },
    "argoCD": {"chart": "10.4.0", "app": "v3.5.1"},
    "coreDNSAddon": EXPECTED_COREDNS_ADDON_VERSION,
}

TARGET_CONFLICT_KEYS = {
    "eksClusters",
    "vpcs",
    "subnets",
    "routeTables",
    "internetGateways",
    "natGateways",
    "elasticIps",
    "securityGroups",
    "networkInterfaces",
    "instances",
    "sqsQueues",
    "eventRules",
    "environmentIamRoles",
    "environmentIamInstanceProfiles",
}

SERVICE_LINKED_ROLES = {
    "AWSServiceRoleForAmazonEKS": True,
    "AWSServiceRoleForAmazonEKSForFargate": True,
    "AWSServiceRoleForEC2Spot": True,
}

PROVIDER_BOOTSTRAP_ROLES = {
    "upstream": True,
    "source": True,
    "execution": True,
    "deployment": True,
}

REQUIRED_FILES = {
    "REVIEW_SUMMARY.md",
    "authorization-contract.json",
    "aws-readonly-snapshot.json",
    "cost-and-cleanup-plan.json",
    "environment.approved.yaml",
    "expected-resource-contract.json",
    "node-image.approved.yaml",
    "platform-release.approved.yaml",
}

DECISION_KEYS = {
    "U0EvidenceAcceptedAndClaimsNotReusable",
    "ExactAccountRegionEnvironmentAndSingleOwnerRoot",
    "CurrentHostAndKindEgressSlash32sMustMatchAtExecution",
    "CrossplaneControllersAreTheOnlyAwsMutationPath",
    "PersistentBillableResourcesContinueAfterControllersPark",
    "SevenDaySeventyUsdSoftBudgetHasNoAutomaticHardStop",
    "FailurePreservesRootAndRequiresExplicitRetirement",
    "SpotOnlyEc2WithFargateControllerExceptionAccepted",
    "CiliumOwnsOnlyEc2DataPlaneNetworking",
    "BusinessGitBootstrapRemainsDisabled",
    "NoAutomaticRetryContinuationUpgradeDisruptionOrDeletion",
    "U1BootstrapCreateWindow",
}

PREPARATION_EVIDENCE_KEYS = {
    "u0ManagementStatus",
    "u0AdmissionStatus",
    "u0AdmissionWindowId",
    "u0AdmissionResultSha256",
    "accountReadinessPassed",
    "accountReadinessTotal",
    "deferredAccountItem",
    "projectDoneTasks",
    "projectTotalTasks",
    "awsResourceMutation",
}

KUBERNETES_MUTATION_SCOPE = (
    "protect and later restore exactly three reviewed shared XRs and 73 owned Objects",
    "create or replace, then scrub and delete crossplane-system/eks-platform-aws-session",
    "patch only the 14 reviewed controller Deployments for bounded startup and final zero-replica restore",
    "create exactly one reviewed XEKSEnvironment and allow its three stable owner child XRs",
    "allow reviewed Crossplane managed resources and remote bootstrap objects derived from that owner hierarchy",
)

AWS_MUTATION_SCOPE = (
    "Crossplane AWS Provider controllers may create or reconcile only resources derived from the reviewed XEKSEnvironment",
    "Karpenter may create only Spot EC2 capacity within the reviewed NodePool limits and environment discovery tags",
    "Cilium operator may create and reconcile only EC2 data-plane ENIs and IPAM allocations for the reviewed environment",
)

ALLOWED_ACTIONS = (
    "perform exact read-only AWS, EKS/CoreDNS release, and public-egress preflight after the single-use claim",
    "protect and later restore the existing shared management-plane objects",
    "publish the separately reviewed on-demand session Secret for at most 60 minutes",
    "start only the locked Crossplane, Function, and reviewed Provider controllers",
    "server-side dry-run and then create exactly one reviewed XEKSEnvironment",
    "allow the reviewed owner hierarchy to create and reconcile its bounded AWS and remote Kubernetes resources",
    "allow Karpenter Spot capacity and Cilium EC2 ENIs within the reviewed tags and limits",
    "collect read-only Kubernetes and AWS bootstrap evidence",
    "scrub and delete the session Secret, restore all 14 controllers to zero, restore shared protection, and preserve the environment",
)

FORBIDDEN_ACTIONS = (
    "run any direct AWS create, update, delete, tag, pass-role, or policy mutation command",
    "create a second environment or modify, unprotect, retire, or delete the reviewed environment",
    "create a managed node group, EKS Auto Mode capacity, or On-Demand or reserved EC2 fallback",
    "install aws-node or kube-proxy on the EC2 data plane or install Cilium on Fargate",
    "create network UAT approval, enable Argo CD business Git bootstrap, or publish Git credentials",
    "perform U1 network probes, token-expiry acceptance, U2 disruption, upgrade, or retirement",
    "automatically retry or continue reconciliation after the reviewed window",
    "delete partially created AWS resources as automatic failure cleanup",
    "print, log, export, or retain credential Secret values outside the approved in-memory verifier",
    "push commits, create a pull request, create a public Issue, or publish private bundle data",
)

CREDENTIAL_HANDLING = {
    "publishOwnedSessionSecret": True,
    "hostVerifierMayReadOwnedSecretValuesInMemory": True,
    "printCredentialValues": False,
    "persistCredentialValuesOutsideOwnedSecret": False,
    "automaticRenewal": False,
}

CLEANUP_BEHAVIOR = {
    "controllersRestoredToZero": True,
    "sessionSecretScrubbedAndDeleted": True,
    "sharedProtectionRestored": True,
    "environmentAndCloudResourcesPreserved": True,
    "automaticCloudDeletion": False,
    "explicitRetirementRequired": True,
}

EXPECTED_RESOURCE_CONTRACT = {
    "schemaVersion": 1,
    "ownerHierarchy": {
        "XEKSEnvironment": ["XNetwork", "XEKSCluster", "XClusterFoundation"],
        "XNetwork": ["VPC", "Subnets", "Routes", "NATGateway", "EIP"],
        "XEKSCluster": [
            "EKSControlPlane",
            "FargateProfile",
            "AccessAPI",
            "DedicatedIAMAndOIDC",
            "CoreDNSAddon",
            "InterruptionQueueAndEvents",
        ],
        "XClusterFoundation": [
            "RemoteProviderConfigs",
            "Karpenter",
            "Cilium",
            "SpotNodePool",
            "NetworkGatedArgoCD",
        ],
    },
    "stableChildren": [
        {"kind": "XNetwork", "suffix": "-network"},
        {"kind": "XEKSCluster", "suffix": "-cluster"},
        {"kind": "XClusterFoundation", "suffix": "-foundation"},
    ],
    "awsApiGroups": [
        "cloudwatchevents.aws.m.upbound.io",
        "ec2.aws.m.upbound.io",
        "eks.aws.m.upbound.io",
        "iam.aws.m.upbound.io",
        "sqs.aws.m.upbound.io",
    ],
    "controllerDerivedOwners": {
        "Karpenter": ["NodeClaim", "Node", "SpotEC2", "LaunchTemplate"],
        "CiliumOperator": ["EC2ENI", "IPAMAllocation"],
    },
    "requiredCapacityType": "spot",
    "fargateScope": "karpenter-controller-only",
    "ciliumScope": "ec2-data-plane-only",
    "gitBootstrapEnabled": False,
    "networkApprovalPresent": False,
    "forbiddenResourceClasses": [
        "ManagedNodeGroup",
        "EKSAutoMode",
        "OnDemandEC2",
        "ReservedEC2",
        "VpcCniAddon",
        "KubeProxyAddon",
        "SecondEnvironment",
    ],
}


def _read_private(path: Path, maximum_size: int = 2 * 1024 * 1024) -> bytes:
    return u0_authorization._read_private(path, maximum_size)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_read_private(path))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid private U1 JSON; output suppressed") from error
    if not isinstance(value, dict):
        raise ToolError("private U1 JSON must be an object")
    return value


def _timestamp(value: Any, label: str, *, allow_future: bool = False) -> datetime:
    return u0_authorization._timestamp(value, label, allow_future=allow_future)


def execution_code_state() -> dict[str, Any]:
    return u0_authorization.execution_code_state()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(_read_private(path)).hexdigest()


def _strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _strict_equal(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


def _account_from_role_arn(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ToolError(f"{label} must be a stable IAM role ARN")
    match = re.fullmatch(
        r"arn:aws[a-zA-Z-]*:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+",
        value,
    )
    if match is None or ":assumed-role/" in value:
        raise ToolError(f"{label} must be a stable IAM role ARN")
    return match.group(1)


def expected_public_access_cidrs(snapshot: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for key in ("hostPublicEgressIp", "kindPublicEgressIp"):
        cidr = f"{snapshot.get(key)}/32"
        if cidr not in result:
            result.append(cidr)
    return result


def _validate_catalog(document: Any, label: str) -> str:
    u0_authorization.validate_catalog_candidate(document, label)
    if find_placeholders(document):
        raise ToolError(f"{label} contains a placeholder")
    return document["metadata"]["name"]


def _validate_platform_release(document: Any) -> str:
    name = _validate_catalog(document, "platform release")
    if not _strict_equal(document.get("data"), EXPECTED_PLATFORM_RELEASE_DATA):
        raise ToolError("U1 platform release data differs from the locked contract")
    return name


def _validate_environment(directory: Path, bundle: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    document = load_yaml(directory / "environment.approved.yaml")
    if not isinstance(document, dict) or set(document) != {
        "apiVersion",
        "kind",
        "metadata",
        "spec",
    }:
        raise ToolError("U1 environment manifest shape differs")
    if (
        document.get("apiVersion") != "platform.aws.goodnotes.io/v1alpha1"
        or document.get("kind") != "XEKSEnvironment"
        or find_placeholders(document)
    ):
        raise ToolError("U1 environment manifest is invalid")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != {
        "name",
        "labels",
        "annotations",
    }:
        raise ToolError("U1 environment metadata differs")
    name = metadata.get("name")
    if not isinstance(name, str) or not re.fullmatch(
        r"[a-z][a-z0-9-]{1,50}[a-z0-9]", name
    ):
        raise ToolError("U1 environment name is invalid")
    if not _strict_equal(metadata.get("labels"), {
        "platform.aws.goodnotes.io/environment": name,
        "platform.aws.goodnotes.io/managed-by": "crossplane",
    }):
        raise ToolError("U1 environment labels differ")
    if not _strict_equal(metadata.get("annotations"), {
        "platform.aws.goodnotes.io/authorization-bundle": bundle,
        "platform.aws.goodnotes.io/do-not-apply-outside-runner": "true",
    }):
        raise ToolError("U1 environment annotations differ")
    spec = document.get("spec")
    if not isinstance(spec, dict) or set(spec) != {"crossplane", "parameters"}:
        raise ToolError("U1 environment spec differs")
    if not _strict_equal(
        spec.get("crossplane"), {"compositionUpdatePolicy": "Manual"}
    ):
        raise ToolError("U1 environment must pin manual Composition updates")
    parameters = spec.get("parameters")
    if not isinstance(parameters, dict) or set(parameters) != {
        "class",
        "region",
        "providerConfigRef",
        "kubernetesVersion",
        "platformReleaseRef",
        "nodeImageRef",
        "network",
        "compute",
        "access",
        "lifecycle",
    }:
        raise ToolError("U1 environment parameters differ or Git bootstrap is enabled")
    if (
        parameters.get("class") != "dev"
        or parameters.get("region") != snapshot.get("region")
        or parameters.get("kubernetesVersion") != EXPECTED_KUBERNETES_VERSION
        or not _strict_equal(
            parameters.get("providerConfigRef"),
            {"kind": "ClusterProviderConfig", "name": name},
        )
        or not _strict_equal(
            parameters.get("compute"),
            {"class": "spot-general", "limits": {"cpu": "16", "memory": "64Gi"}},
        )
        or not _strict_equal(
            parameters.get("lifecycle"),
            {"retirementStage": "Active", "deletionProtection": True},
        )
    ):
        raise ToolError("U1 environment intent differs from the reviewed bootstrap")
    access = parameters.get("access")
    if not isinstance(access, dict) or set(access) != {
        "adminPrincipalArn",
        "deploymentPrincipalArn",
        "publicAccessCidrs",
    }:
        raise ToolError("U1 access intent differs")
    account_ids = {
        _account_from_role_arn(access.get("adminPrincipalArn"), "adminPrincipalArn"),
        _account_from_role_arn(
            access.get("deploymentPrincipalArn"), "deploymentPrincipalArn"
        ),
    }
    if account_ids != {snapshot.get("accountId")}:
        raise ToolError("U1 principal account differs from the snapshot")
    expected_cidrs = expected_public_access_cidrs(snapshot)
    if not _strict_equal(access.get("publicAccessCidrs"), expected_cidrs):
        raise ToolError(
            "U1 public endpoint CIDRs differ from the observed host and KinD /32s"
        )
    network = parameters.get("network")
    if not isinstance(network, dict) or set(network) != {
        "cidrBlock",
        "publicSubnets",
        "privateSubnets",
    }:
        raise ToolError("U1 network intent differs")
    try:
        vpc = ipaddress.ip_network(network["cidrBlock"], strict=True)
        subnets = []
        zones = []
        for visibility, prefix in (("publicSubnets", 24), ("privateSubnets", 20)):
            slots = network[visibility]
            if not isinstance(slots, dict) or set(slots) != {"a", "b"}:
                raise ToolError("U1 subnet slots differ")
            for slot in ("a", "b"):
                item = slots[slot]
                if not isinstance(item, dict) or set(item) != {
                    "availabilityZone",
                    "cidrBlock",
                }:
                    raise ToolError("U1 subnet shape differs")
                subnet = ipaddress.ip_network(item["cidrBlock"], strict=True)
                if subnet.prefixlen != prefix or not subnet.subnet_of(vpc):
                    raise ToolError("U1 subnet is outside the reviewed VPC")
                subnets.append(subnet)
                zones.append(item["availabilityZone"])
        if vpc.prefixlen != 16 or any(
            left.overlaps(right)
            for index, left in enumerate(subnets)
            for right in subnets[index + 1 :]
        ):
            raise ToolError("U1 VPC/subnet CIDRs overlap or differ from /16")
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ToolError):
            raise
        raise ToolError("U1 network CIDR is invalid") from error
    if sorted(set(zones)) != sorted(snapshot.get("availabilityZones", [])):
        raise ToolError("U1 availability zones differ from the snapshot")
    platform_document = load_yaml(directory / "platform-release.approved.yaml")
    node_document = load_yaml(directory / "node-image.approved.yaml")
    platform_name = _validate_platform_release(platform_document)
    node_name = _validate_catalog(node_document, "node image")
    if not _strict_equal(
        parameters.get("platformReleaseRef"),
        {"kind": "EnvironmentConfig", "name": platform_name},
    ) or not _strict_equal(
        parameters.get("nodeImageRef"),
        {"kind": "EnvironmentConfig", "name": node_name},
    ):
        raise ToolError("U1 catalog references differ from the reviewed files")
    try:
        node_data = node_document["data"]
        amd64 = node_data["images"]["amd64"]
    except (KeyError, TypeError) as error:
        raise ToolError("U1 node image catalog shape differs") from error
    if (
        platform_document.get("data", {}).get("kubernetes")
        != parameters.get("kubernetesVersion")
        or platform_document.get("data", {}).get("coreDNSAddon")
        != snapshot.get("eksRelease", {}).get("coreDNSAddonVersion")
    ):
        raise ToolError("U1 platform release differs from the AWS snapshot")
    if (
        node_data.get("region") != snapshot.get("region")
        or node_data.get("kubernetes") != parameters.get("kubernetesVersion")
        or amd64.get("amiId") != snapshot.get("nodeImage", {}).get("imageId")
    ):
        raise ToolError("U1 node image catalog differs from the AWS snapshot")
    return {"name": name, "region": parameters["region"], "document": document}


def _validate_snapshot(document: dict[str, Any], *, allow_stale: bool) -> datetime:
    expected_keys = {
        "schemaVersion",
        "observedAt",
        "profile",
        "accountId",
        "partition",
        "region",
        "environment",
        "hostPublicEgressIp",
        "kindPublicEgressIp",
        "availabilityZones",
        "targetNameConflicts",
        "serviceLinkedRoles",
        "providerBootstrapRoles",
        "spotQuota",
        "nodeImage",
        "eksRelease",
        "awsMutation",
        "kubernetesMutation",
    }
    if set(document) != expected_keys or document.get("schemaVersion") != 1:
        raise ToolError("U1 AWS snapshot schema differs")
    observed_at = _timestamp(document.get("observedAt"), "snapshot observedAt")
    if (
        not allow_stale
        and (datetime.now(timezone.utc) - observed_at).total_seconds()
        > SNAPSHOT_MAX_AGE_SECONDS
    ):
        raise ToolError("U1 AWS snapshot is stale; regenerate and re-review")
    try:
        host_ip = ipaddress.ip_address(document.get("hostPublicEgressIp"))
        kind_ip = ipaddress.ip_address(document.get("kindPublicEgressIp"))
    except (TypeError, ValueError) as error:
        raise ToolError("U1 public egress snapshot is invalid") from error
    if (
        document.get("profile") != "warlock-cli-codex-admin"
        or not isinstance(document.get("accountId"), str)
        or not re.fullmatch(r"[0-9]{12}", document["accountId"])
        or document.get("partition") != "aws"
        or document.get("region") != "us-east-1"
        or document.get("environment") != "eks-dev-spot"
        or host_ip.version != 4
        or kind_ip.version != 4
        or document.get("availabilityZones") != ["us-east-1a", "us-east-1b"]
        or not _strict_equal(
            document.get("targetNameConflicts"),
            {key: 0 for key in sorted(TARGET_CONFLICT_KEYS)},
        )
        or not _strict_equal(document.get("serviceLinkedRoles"), SERVICE_LINKED_ROLES)
        or not _strict_equal(
            document.get("providerBootstrapRoles"), PROVIDER_BOOTSTRAP_ROLES
        )
        or document.get("awsMutation") is not False
        or document.get("kubernetesMutation") is not False
    ):
        raise ToolError("U1 AWS snapshot does not prove the reviewed zero-conflict baseline")
    quota = document.get("spotQuota")
    if (
        not isinstance(quota, dict)
        or quota.get("quotaCode") != "L-1216C47A"
        or isinstance(quota.get("value"), bool)
        or not isinstance(quota.get("value"), (int, float))
        or not math.isfinite(float(quota["value"]))
        or quota["value"] < 16
    ):
        raise ToolError("U1 Spot vCPU quota is below the reviewed NodePool limit")
    image = document.get("nodeImage")
    if (
        not isinstance(image, dict)
        or not re.fullmatch(r"ami-[0-9a-f]{17}", str(image.get("imageId", "")))
        or image.get("state") != "available"
        or image.get("architecture") != "x86_64"
        or image.get("rootDeviceType") != "ebs"
    ):
        raise ToolError("U1 reviewed node image is unavailable or incompatible")
    release = document.get("eksRelease")
    architectures = (
        release.get("coreDNSArchitectures") if isinstance(release, dict) else None
    )
    compute_types = (
        release.get("coreDNSComputeTypes") if isinstance(release, dict) else None
    )
    platform_versions = (
        release.get("coreDNSPlatformVersions") if isinstance(release, dict) else None
    )
    if (
        not isinstance(release, dict)
        or set(release)
        != {
            "clusterVersion",
            "clusterType",
            "status",
            "defaultPlatformVersion",
            "kubernetesPatchVersion",
            "coreDNSAddonVersion",
            "coreDNSArchitectures",
            "coreDNSComputeTypes",
            "coreDNSPlatformVersions",
            "coreDNSRequiresConfiguration",
            "coreDNSRequiresIamPermissions",
        }
        or release.get("clusterVersion") != EXPECTED_KUBERNETES_VERSION
        or release.get("clusterType") != "eks"
        or release.get("status") != "STANDARD_SUPPORT"
        or not re.fullmatch(
            r"eks\.[0-9]+", str(release.get("defaultPlatformVersion", ""))
        )
        or not re.fullmatch(
            rf"{re.escape(EXPECTED_KUBERNETES_VERSION)}\.[0-9]+",
            str(release.get("kubernetesPatchVersion", "")),
        )
        or release.get("coreDNSAddonVersion") != EXPECTED_COREDNS_ADDON_VERSION
        or not isinstance(architectures, list)
        or any(not isinstance(value, str) for value in architectures)
        or not {"amd64", "arm64"}.issubset(set(architectures))
        or not isinstance(compute_types, list)
        or any(not isinstance(value, str) for value in compute_types)
        or not {"ec2", "fargate"}.issubset(set(compute_types))
        or not isinstance(platform_versions, list)
        or any(not isinstance(value, str) for value in platform_versions)
        or "*" not in platform_versions
        or release.get("coreDNSRequiresConfiguration") is not False
        or release.get("coreDNSRequiresIamPermissions") is not False
    ):
        raise ToolError("U1 EKS/CoreDNS release snapshot is unavailable or incompatible")
    return observed_at


def _validate_cost_plan(document: dict[str, Any]) -> None:
    expected = {
        "schemaVersion": 1,
        "currency": "USD",
        "maximumEnvironmentAgeDays": 7,
        "warningThresholdUsd": 50,
        "softStopThresholdUsd": 70,
        "hardStop": False,
        "automaticBudgetAction": False,
        "billingOwner": "GoodspeedWong",
        "cleanupOwner": "GoodspeedWong",
        "resourcesRemainBillableAfterWindow": True,
        "failureAction": "park controllers, remove the session, preserve the environment, and require explicit retirement",
        "budgetEnforcement": "manual observation; AWS billing data may be delayed",
    }
    if not _strict_equal(document, expected):
        raise ToolError("U1 cost and cleanup plan differs from the reviewed contract")


def _verify_checksums(directory: Path) -> int:
    # U0's parser is intentionally not reused because its required-file set differs.
    if {entry.name for entry in directory.iterdir()} != REQUIRED_FILES | {"SHA256SUMS"}:
        raise ToolError("U1 bundle contains an unreviewed file")
    try:
        lines = _read_private(directory / "SHA256SUMS").decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ToolError("U1 checksum manifest must be ASCII") from error
    checksums: dict[str, str] = {}
    for line in lines:
        match = u0_authorization.CHECKSUM_RE.fullmatch(line)
        if match is None or match.group(2) in checksums:
            raise ToolError("U1 checksum manifest is malformed or duplicated")
        checksums[match.group(2)] = match.group(1)
    if set(checksums) != REQUIRED_FILES:
        raise ToolError("U1 checksum manifest file inventory differs")
    for name, expected in checksums.items():
        if _file_sha256(directory / name) != expected:
            raise ToolError("U1 bundle checksum differs; re-review is required")
    return len(checksums)


def validate_authorization(
    path: Path,
    require_approved: bool,
    *,
    allow_stale_approved: bool = False,
) -> dict[str, Any]:
    path = Path(os.path.abspath(path.expanduser()))
    if path.name != "authorization-contract.json":
        raise ToolError("explicit U1 authorization-contract.json path required")
    try:
        payload = _read_private(path)
        document = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid private U1 authorization; output suppressed") from error
    if not isinstance(document, dict):
        raise ToolError("private U1 authorization must be an object")
    authorization_digest = hashlib.sha256(payload).hexdigest()
    expected_keys = {
        "schemaVersion",
        "bundle",
        "windowId",
        "singleUse",
        "generatedAt",
        "reviewStatus",
        "approvedBy",
        "approvedAt",
        "authorizationType",
        "requiresSeparateApprovedManagementSessionReview",
        "preparationEvidence",
        "requestedU1Window",
        "decisions",
        "reviewedInputs",
        "executionCode",
    }
    if set(document) != expected_keys or document.get("schemaVersion") != SCHEMA_VERSION:
        raise ToolError("U1 authorization fields differ from schema v1")
    bundle = document.get("bundle")
    window_id = document.get("windowId")
    if (
        not isinstance(bundle, str)
        or BUNDLE_RE.fullmatch(bundle) is None
        or path.parent.name != bundle
        or not isinstance(window_id, str)
        or WINDOW_RE.fullmatch(window_id) is None
        or document.get("singleUse") is not True
        or document.get("authorizationType") != AUTHORIZATION_TYPE
        or document.get("requiresSeparateApprovedManagementSessionReview") is not True
    ):
        raise ToolError("U1 bundle identity or authorization boundary differs")
    generated_at = _timestamp(document.get("generatedAt"), "generatedAt")
    execution_code = execution_code_state()
    if not _strict_equal(document.get("executionCode"), execution_code):
        raise ToolError("U1 reviewed execution code differs from the current checkout")
    preparation = document.get("preparationEvidence")
    if (
        not isinstance(preparation, dict)
        or set(preparation) != PREPARATION_EVIDENCE_KEYS
        or preparation.get("u0ManagementStatus") != "U0_MANAGEMENT_PREFLIGHT_PASS"
        or preparation.get("u0AdmissionStatus") != "U0_ADMISSION_PREFLIGHT_PASS"
        or preparation.get("u0AdmissionWindowId") != "u0a-20260904-02"
        or not SHA256_RE.fullmatch(str(preparation.get("u0AdmissionResultSha256", "")))
        or preparation.get("accountReadinessPassed") != 19
        or preparation.get("accountReadinessTotal") != 20
        or preparation.get("deferredAccountItem") != "A15TargetPrivateNodePathInU1"
        or preparation.get("projectDoneTasks") != 122
        or preparation.get("projectTotalTasks") != 153
        or preparation.get("awsResourceMutation") is not False
    ):
        raise ToolError("U1 prerequisite evidence differs")
    requested = document.get("requestedU1Window")
    if not isinstance(requested, dict) or set(requested) != {
        "purpose",
        "maximumSessionSeconds",
        "maximumExecutionSeconds",
        "stsSessionIssuanceAllowed",
        "directAwsCliMutationAllowed",
        "crossplaneAwsResourceMutationAllowed",
        "kubernetesMutationAllowed",
        "persistentEnvironmentAllowed",
        "automaticRetryAllowed",
        "u1TasksWithPossibleSideEffects",
        "kubernetesMutationScope",
        "awsMutationScope",
        "credentialHandling",
        "cleanupBehavior",
        "allowed",
        "forbidden",
    }:
        raise ToolError("U1 requested window shape differs")
    if (
        requested.get("purpose")
        != "Create exactly one reviewed EKS environment and stop at the first U1 bootstrap checkpoint"
        or requested.get("maximumSessionSeconds") != MAX_SESSION_SECONDS
        or requested.get("maximumExecutionSeconds") != MAX_EXECUTION_SECONDS
        or requested.get("stsSessionIssuanceAllowed") is not True
        or requested.get("directAwsCliMutationAllowed") is not False
        or requested.get("crossplaneAwsResourceMutationAllowed") is not True
        or requested.get("kubernetesMutationAllowed") is not True
        or requested.get("persistentEnvironmentAllowed") is not True
        or requested.get("automaticRetryAllowed") is not False
        or not _strict_equal(
            requested.get("u1TasksWithPossibleSideEffects"),
            ["U1-01", "U1-02", "U1-03", "U1-04", "U1-05"],
        )
        or not _strict_equal(
            requested.get("kubernetesMutationScope"), list(KUBERNETES_MUTATION_SCOPE)
        )
        or not _strict_equal(
            requested.get("awsMutationScope"), list(AWS_MUTATION_SCOPE)
        )
        or not _strict_equal(
            requested.get("credentialHandling"), CREDENTIAL_HANDLING
        )
        or not _strict_equal(requested.get("cleanupBehavior"), CLEANUP_BEHAVIOR)
        or not _strict_equal(requested.get("allowed"), list(ALLOWED_ACTIONS))
        or not _strict_equal(requested.get("forbidden"), list(FORBIDDEN_ACTIONS))
    ):
        raise ToolError("U1 requested actions differ from the reviewed allowlist")
    snapshot = _load_json(path.parent / "aws-readonly-snapshot.json")
    snapshot_time = _validate_snapshot(snapshot, allow_stale=allow_stale_approved)
    environment = _validate_environment(path.parent, bundle, snapshot)
    if snapshot.get("environment") != environment["name"]:
        raise ToolError("U1 environment differs from the AWS snapshot")
    _validate_cost_plan(_load_json(path.parent / "cost-and-cleanup-plan.json"))
    if not _strict_equal(
        _load_json(path.parent / "expected-resource-contract.json"),
        EXPECTED_RESOURCE_CONTRACT,
    ):
        raise ToolError("U1 expected resource contract differs")
    reviewed_inputs = document.get("reviewedInputs")
    expected_input_names = REQUIRED_FILES - {
        "REVIEW_SUMMARY.md",
        "authorization-contract.json",
    }
    if not isinstance(reviewed_inputs, dict) or set(reviewed_inputs) != expected_input_names:
        raise ToolError("U1 reviewed input inventory differs")
    for name, expected in reviewed_inputs.items():
        if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
            raise ToolError("U1 reviewed input digest is invalid")
        if _file_sha256(path.parent / name) != expected:
            raise ToolError("U1 reviewed input changed")
    decisions = document.get("decisions")
    if not isinstance(decisions, dict) or set(decisions) != DECISION_KEYS:
        raise ToolError("U1 decision inventory differs")
    status = document.get("reviewStatus")
    approved = status == APPROVED_STATUS
    if status == PENDING_STATUS:
        if document.get("approvedBy") is not None or document.get("approvedAt") is not None:
            raise ToolError("pending U1 authorization cannot name an approval")
        if any(value is not None for value in decisions.values()):
            raise ToolError("pending U1 decisions must remain unset")
    elif approved:
        reviewer = document.get("approvedBy")
        if (
            not isinstance(reviewer, str)
            or not reviewer.strip()
            or any(marker in reviewer for marker in ("__REPLACE", "<", ">", "\n", "\r"))
        ):
            raise ToolError("approved U1 authorization must identify the reviewer")
        approved_at = _timestamp(document.get("approvedAt"), "approvedAt")
        age = (datetime.now(timezone.utc) - approved_at).total_seconds()
        if (
            approved_at < generated_at
            or approved_at < snapshot_time
            or (not allow_stale_approved and age > APPROVAL_MAX_AGE_SECONDS)
        ):
            raise ToolError("U1 approval or snapshot is stale; regenerate and re-review")
        if any(value is not True for value in decisions.values()):
            raise ToolError("every U1 decision must be explicitly accepted")
    else:
        raise ToolError("U1 reviewStatus is not pending or approved")
    if require_approved and not approved:
        raise ToolError("U1 bootstrap-create window is not approved")
    checksums = _verify_checksums(path.parent)
    if _file_sha256(path) != authorization_digest:
        raise ToolError("U1 authorization changed during validation")
    return {
        "bundle": bundle,
        "windowId": window_id,
        "reviewStatus": status,
        "approved": approved,
        "singleUse": True,
        "maximumSessionSeconds": MAX_SESSION_SECONDS,
        "maximumExecutionSeconds": MAX_EXECUTION_SECONDS,
        "environment": environment["name"],
        "region": environment["region"],
        "accountId": snapshot["accountId"],
        "auditProfile": snapshot["profile"],
        "hostPublicEgressIp": snapshot["hostPublicEgressIp"],
        "kindPublicEgressIp": snapshot["kindPublicEgressIp"],
        "directAwsCliMutationAllowed": False,
        "crossplaneAwsResourceMutationAllowed": True,
        "persistentEnvironmentAllowed": True,
        "checksumsVerified": checksums,
        "reviewedGitCommit": execution_code["gitCommit"],
        "executionCodeSha256": execution_code["aggregateSha256"],
        "executionCodeFiles": execution_code["trackedNonMarkdownFiles"],
        "markdownDriftExcluded": execution_code["markdownDriftExcluded"],
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
        "mutationPerformed": False,
        "_authorizationSha256": authorization_digest,
    }


def _claim_path(root: Path, window_id: str) -> Path:
    if WINDOW_RE.fullmatch(window_id) is None:
        raise ToolError("U1 windowId is invalid")
    return root / f"{window_id}.json"


def claim_authorization(
    path: Path,
    acknowledgement: str,
    *,
    claim_root: Path = CLAIM_ROOT,
    now: datetime | None = None,
) -> dict[str, Any]:
    if acknowledgement != CLAIM_ACKNOWLEDGEMENT:
        raise ToolError("explicit single-use U1 claim acknowledgement required")
    authorization = validate_authorization(path, require_approved=True)
    digest = authorization.pop("_authorizationSha256")
    wall_clock = datetime.now(timezone.utc)
    claimed_at = now or wall_clock
    if claimed_at.tzinfo is None or abs((wall_clock - claimed_at).total_seconds()) > 1:
        raise ToolError("U1 claim time must be current and timezone-qualified")
    deadline = claimed_at + timedelta(seconds=MAX_SESSION_SECONDS)
    root = u0_authorization._claim_root(claim_root, create=True)
    receipt_path = _claim_path(root, authorization["windowId"])
    receipt = {
        "claimSchemaVersion": CLAIM_SCHEMA_VERSION,
        "status": CLAIM_STATUS,
        "bundle": authorization["bundle"],
        "windowId": authorization["windowId"],
        "authorizationSha256": digest,
        "executionGitCommit": authorization["reviewedGitCommit"],
        "executionCodeSha256": authorization["executionCodeSha256"],
        "claimedAt": claimed_at.isoformat(),
        "deadline": deadline.isoformat(),
    }
    u0_authorization._write_claim(receipt_path, receipt)
    return authorization | {
        "mode": "claim",
        "claimed": True,
        "claimStatus": CLAIM_STATUS,
        "claimedAt": receipt["claimedAt"],
        "deadline": receipt["deadline"],
        "localAuthorizationStateMutation": True,
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
    }


def verify_claim(
    path: Path,
    *,
    claim_root: Path = CLAIM_ROOT,
    require_active: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    authorization = validate_authorization(
        path,
        require_approved=True,
        allow_stale_approved=not require_active,
    )
    digest = authorization.pop("_authorizationSha256")
    root = u0_authorization._claim_root(claim_root, create=False)
    receipt = _load_json(_claim_path(root, authorization["windowId"]))
    expected_keys = {
        "claimSchemaVersion",
        "status",
        "bundle",
        "windowId",
        "authorizationSha256",
        "executionGitCommit",
        "executionCodeSha256",
        "claimedAt",
        "deadline",
    }
    if set(receipt) != expected_keys or (
        receipt.get("claimSchemaVersion") != CLAIM_SCHEMA_VERSION
        or receipt.get("status") != CLAIM_STATUS
        or receipt.get("bundle") != authorization["bundle"]
        or receipt.get("windowId") != authorization["windowId"]
        or receipt.get("authorizationSha256") != digest
        or receipt.get("executionGitCommit") != authorization["reviewedGitCommit"]
        or receipt.get("executionCodeSha256") != authorization["executionCodeSha256"]
    ):
        raise ToolError("U1 claim does not match the approved authorization")
    claimed_at = _timestamp(receipt.get("claimedAt"), "claimedAt")
    deadline = _timestamp(receipt.get("deadline"), "deadline", allow_future=True)
    if deadline != claimed_at + timedelta(seconds=MAX_SESSION_SECONDS):
        raise ToolError("U1 claim deadline differs from the reviewed window")
    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None or checked_at < claimed_at:
        raise ToolError("U1 claim verification time is invalid")
    if require_active and checked_at >= deadline:
        raise ToolError("U1 claim expired; only park/recovery is allowed")
    return authorization | {
        "mode": "verify-claim",
        "claimed": True,
        "claimStatus": CLAIM_STATUS,
        "claimedAt": receipt["claimedAt"],
        "deadline": receipt["deadline"],
        "claimActive": checked_at < deadline,
        "localAuthorizationStateMutation": False,
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("plan", "validate-approved", "claim", "verify-claim")
    )
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args(argv)
    try:
        if args.mode == "claim":
            result = claim_authorization(args.authorization, args.acknowledge)
        elif args.mode == "verify-claim":
            if args.acknowledge:
                raise ToolError("verify-claim does not accept acknowledgement")
            result = verify_claim(args.authorization)
        else:
            if args.acknowledge:
                raise ToolError(f"{args.mode} does not accept acknowledgement")
            result = validate_authorization(
                args.authorization,
                require_approved=args.mode == "validate-approved",
            )
            result.pop("_authorizationSha256", None)
            result["mode"] = args.mode
            result["claimed"] = False
            result["localAuthorizationStateMutation"] = False
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ToolError, OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "U1 authorization validation failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
