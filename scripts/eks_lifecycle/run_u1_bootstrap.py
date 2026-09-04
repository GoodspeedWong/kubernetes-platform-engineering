#!/usr/bin/env python3
"""Run or park one reviewed U1 bootstrap-create window.

Plan mode is local-only. Run mode atomically claims one private authorization,
verifies a zero-conflict baseline, protects unrelated shared management-plane
objects, opens the separately approved on-demand session, starts exactly the
locked 14 controllers, and creates exactly one reviewed XEKSEnvironment. AWS
mutation is performed only by those reviewed controllers. The runner parks the
controllers and removes the session at the end while deliberately preserving
the protected environment and any billable cloud resources. It never performs
automatic cloud deletion, retry, continuation, network approval, or U2 work.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import REPO_ROOT, ToolError, load_yaml
import renew_management_credentials as credentials
import run_u0_management_preflight as u0_runner
import validate_u1_authorization as authorization_tool


RUN_ACKNOWLEDGEMENT = "I-APPROVE-EXECUTE-ONE-U1-BOOTSTRAP-CREATE-WINDOW"
RECOVER_ACKNOWLEDGEMENT = "I-APPROVE-U1-PARK-RECOVERY-ONLY"
RESULT_ROOT = Path.home() / ".local/share/eks-platform/u1-results"
NAMESPACE = credentials.SOURCE_NAMESPACE
EXPECTED_NON_AWS_MANAGED_BASELINE = 73
AWS_MANAGED_MARKERS = (".aws.upbound.io/", ".aws.m.upbound.io/")
CHECKPOINT_WAIT_SECONDS = 2400
POLL_SECONDS = 10

READ_ONLY_AWS_OPERATIONS = {
    ("sts", "get-caller-identity"),
    ("eks", "list-clusters"),
    ("eks", "describe-cluster"),
    ("eks", "list-fargate-profiles"),
    ("eks", "describe-fargate-profile"),
    ("eks", "list-nodegroups"),
    ("eks", "list-addons"),
    ("ec2", "describe-vpcs"),
    ("ec2", "describe-subnets"),
    ("ec2", "describe-route-tables"),
    ("ec2", "describe-internet-gateways"),
    ("ec2", "describe-nat-gateways"),
    ("ec2", "describe-addresses"),
    ("ec2", "describe-security-groups"),
    ("ec2", "describe-network-interfaces"),
    ("ec2", "describe-instances"),
    ("ec2", "describe-images"),
    ("sqs", "list-queues"),
    ("events", "list-rules"),
    ("iam", "get-role"),
    ("service-quotas", "get-service-quota"),
}

ENVIRONMENT_IAM_ROLE_SUFFIXES = (
    "eks-cluster",
    "fargate-pod",
    "karpenter-controller",
    "cilium-operator",
    "ec2-node",
)

JOURNAL_EVENTS = {
    "CLAIMED",
    "BASELINE_REJECTED_NO_MUTATION",
    "BASELINE_VERIFIED",
    "PROTECTION_STARTED",
    "PROTECTED",
    "SESSION_STARTED",
    *credentials.SESSION_PROGRESS_STAGES,
    "SESSION_OPENED",
    "CONTROLLERS_STARTED",
    "ENVIRONMENT_DRY_RUN_VERIFIED",
    "ENVIRONMENT_CREATED",
    "CHILDREN_OBSERVED",
    "INFRASTRUCTURE_READY",
    "MONITOR_WINDOW_ENDED",
    "EVIDENCE_CAPTURED",
    "CLEANUP_STARTED",
    "CLEANUP_COMPLETE",
    "FAILED_CLEANUP_COMPLETE",
    "RECOVERY_STARTED",
    "RECOVERY_COMPLETE",
    "RECOVERY_REQUIRED",
}


@dataclass(frozen=True)
class U1Contract:
    authorization_path: Path
    session_review_path: Path
    authorization: dict[str, Any] = field(repr=False)
    session_review: dict[str, Any] = field(repr=False)
    bootstrap: credentials.BootstrapContract = field(repr=False)
    bundle_directory: Path = field(repr=False)
    environment_document: dict[str, Any] = field(repr=False)
    expected_resources: dict[str, Any] = field(repr=False)
    environment: str
    region: str
    account_id: str
    audit_profile: str
    expected_public_ip: str
    node_image_id: str
    controller_names: tuple[str, ...]
    run_id: str


def _session_contract(
    path: Path,
    *,
    recovery_only: bool = False,
) -> tuple[dict[str, Any], credentials.BootstrapContract]:
    review = credentials.load_private_review(path)
    try:
        contract = credentials.BootstrapContract(**review["contract"])
    except (KeyError, TypeError) as error:
        raise ToolError("A05 session review contract is malformed") from error
    credentials.validate_contract(contract)
    if not recovery_only:
        credentials.verify_review_approval(contract, review)
    if review.get("sessionMode") != credentials.SESSION_MODE:
        raise ToolError("A05 review does not approve the on-demand-60m session")
    return review, contract


def load_contract(
    authorization_path: Path,
    session_review_path: Path,
    *,
    require_approved: bool,
    allow_stale_approved: bool = False,
    recovery_only: bool = False,
) -> U1Contract:
    authorization_path = Path(os.path.abspath(authorization_path.expanduser()))
    session_review_path = Path(os.path.abspath(session_review_path.expanduser()))
    authorization = authorization_tool.validate_authorization(
        authorization_path,
        require_approved=require_approved,
        allow_stale_approved=allow_stale_approved,
    )
    authorization.pop("_authorizationSha256", None)
    session_review, bootstrap = _session_contract(
        session_review_path,
        recovery_only=recovery_only,
    )
    bundle_directory = authorization_path.parent
    environment_document = load_yaml(bundle_directory / "environment.approved.yaml")
    expected_resources = authorization_tool._load_json(
        bundle_directory / "expected-resource-contract.json"
    )
    metadata = environment_document.get("metadata", {})
    parameters = environment_document.get("spec", {}).get("parameters", {})
    environment = metadata.get("name")
    region = parameters.get("region")
    if environment != authorization["environment"] or environment != bootstrap.environment:
        raise ToolError("U1 environment differs from the authorization or A05 review")
    if region != authorization["region"] or region != bootstrap.region:
        raise ToolError("U1 region differs from the authorization or A05 review")
    if {
        bootstrap.source_role_arn.split(":")[4],
        bootstrap.provider_role_arn.split(":")[4],
        bootstrap.deployment_role_arn.split(":")[4],
    } != {authorization["accountId"]}:
        raise ToolError("U1 account differs from the A05 review")
    node_catalog = load_yaml(bundle_directory / "node-image.approved.yaml")
    try:
        node_image_id = node_catalog["data"]["images"]["amd64"]["amiId"]
    except (KeyError, TypeError) as error:
        raise ToolError("U1 node image catalog lacks the reviewed amd64 AMI") from error
    if not re.fullmatch(r"ami-[0-9a-f]{17}", str(node_image_id)):
        raise ToolError("U1 node image catalog AMI is invalid")
    match = re.fullmatch(r"u1b-([0-9]{8})-([0-9]{2})", authorization["windowId"])
    if match is None:
        raise ToolError("U1 window identity is invalid")
    return U1Contract(
        authorization_path=authorization_path,
        session_review_path=session_review_path,
        authorization=authorization,
        session_review=session_review,
        bootstrap=bootstrap,
        bundle_directory=bundle_directory,
        environment_document=environment_document,
        expected_resources=expected_resources,
        environment=environment,
        region=region,
        account_id=authorization["accountId"],
        audit_profile=authorization["auditProfile"],
        expected_public_ip=authorization["hostPublicEgressIp"],
        node_image_id=node_image_id,
        controller_names=u0_runner.controller_inventory(),
        run_id=f"a05-{match.group(1)}-u1-{match.group(2)}",
    )


def public_plan(contract: U1Contract) -> dict[str, Any]:
    return {
        "mode": "plan",
        "bundle": contract.authorization["bundle"],
        "windowId": contract.authorization["windowId"],
        "reviewStatus": contract.authorization["reviewStatus"],
        "approved": contract.authorization["approved"],
        "environment": contract.environment,
        "region": contract.region,
        "singleEnvironmentCreate": True,
        "controllerDeployments": len(contract.controller_names),
        "sharedXRsToProtect": 3,
        "ownedObjectsToProtect": EXPECTED_NON_AWS_MANAGED_BASELINE,
        "maximumSessionSeconds": authorization_tool.MAX_SESSION_SECONDS,
        "maximumExecutionSeconds": authorization_tool.MAX_EXECUTION_SECONDS,
        "directAwsCliMutationAllowed": False,
        "crossplaneAwsResourceMutationAllowed": True,
        "persistentEnvironmentAfterWindow": True,
        "automaticRetry": False,
        "automaticCloudDeletion": False,
        "networkApprovalOrGitBootstrap": False,
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
        "localClaimCreated": False,
        "mutationPerformed": False,
    }


class Journal:
    def __init__(self, path: Path):
        self.path = path

    @classmethod
    def create(cls, window_id: str) -> "Journal":
        root = u0_runner.authorization_tool._claim_root(
            authorization_tool.CLAIM_ROOT, create=False
        )
        path = root / f"{window_id}.state.jsonl"
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError as error:
            raise ToolError("U1 execution journal already exists; reuse is forbidden") from error
        except OSError as error:
            raise ToolError("U1 execution journal could not be created safely") from error
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.flush()
            os.fsync(stream.fileno())
        directory_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return cls(path)

    @classmethod
    def existing(cls, window_id: str) -> "Journal | None":
        root = u0_runner.authorization_tool._claim_root(
            authorization_tool.CLAIM_ROOT, create=False
        )
        path = root / f"{window_id}.state.jsonl"
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ToolError("U1 execution journal is unsafe")
        return cls(path)

    def append(self, event: str) -> None:
        if event not in JOURNAL_EVENTS:
            raise ToolError("unreviewed U1 journal event")
        payload = (
            json.dumps(
                {"event": event, "recordedAt": datetime.now(timezone.utc).isoformat()},
                sort_keys=True,
            )
            + "\n"
        ).encode()
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "ab") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ToolError("U1 execution journal ownership or mode changed")
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())


def _clean_env() -> dict[str, str]:
    return credentials._clean_env()


def _run_text(command: list[str], *, timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=_clean_env(),
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolError(f"{command[0]} unavailable or timed out; output suppressed") from error
    if result.returncode:
        raise ToolError(f"{command[0]} failed ({result.returncode}); output suppressed")
    return result.stdout.strip()


def _write_private_json(path: Path, document: dict[str, Any]) -> Path:
    root = u0_runner.authorization_tool._claim_root(path.parent, create=True)
    target = root / path.name
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as error:
        raise ToolError("U1 result already exists; reuse is forbidden") from error
    except OSError as error:
        raise ToolError("U1 result could not be created safely") from error
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    directory_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return target


def _condition(document: dict[str, Any], condition_type: str) -> dict[str, Any] | None:
    for item in document.get("status", {}).get("conditions", []) or []:
        if item.get("type") == condition_type:
            return item
    return None


class RealOperations(u0_runner.RealOperations):
    checkpoint_wait_seconds = CHECKPOINT_WAIT_SECONDS
    poll_seconds = POLL_SECONDS

    def __init__(self) -> None:
        self._baseline_non_aws_identities: set[tuple[str, str, str, str]] = set()

    def _verify_claim(self, contract: U1Contract) -> None:
        authorization_tool.verify_claim(contract.authorization_path)

    def _aws_json(
        self,
        contract: U1Contract,
        profile: str,
        service: str,
        operation: str,
        *args: str,
        allow_no_such_entity: bool = False,
    ) -> dict[str, Any] | None:
        if profile != contract.audit_profile:
            raise ToolError("U1 read-only AWS profile differs from the reviewed snapshot")
        if (service, operation) not in READ_ONLY_AWS_OPERATIONS:
            raise ToolError("U1 direct AWS operation is not in the read-only allowlist")
        command = [
            "aws",
            "--profile",
            profile,
            "--region",
            contract.region,
            "--no-cli-pager",
            service,
            operation,
            *args,
            "--output",
            "json",
        ]
        try:
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
                env=_clean_env(),
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise ToolError("U1 read-only AWS command unavailable; output suppressed") from error
        if result.returncode:
            if (
                allow_no_such_entity
                and service == "iam"
                and operation == "get-role"
                and "NoSuchEntity" in result.stderr
            ):
                return None
            raise ToolError("U1 read-only AWS command failed; output suppressed")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ToolError("U1 read-only AWS response is invalid; output suppressed") from error
        if not isinstance(value, dict):
            raise ToolError("U1 read-only AWS response shape differs")
        return value

    def _public_ip(self, command: list[str]) -> str:
        value = _run_text(command, timeout=20).strip()
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as error:
            raise ToolError("U1 public egress lookup returned an invalid address") from error
        if parsed.version != 4:
            raise ToolError("U1 bootstrap requires the reviewed IPv4 /32")
        return str(parsed)

    def public_egress(self, contract: U1Contract) -> dict[str, str]:
        host = self._public_ip(
            ["curl", "-fsS", "--max-time", "15", "https://checkip.amazonaws.com"]
        )
        cluster_name = contract.bootstrap.context.removeprefix("kind-")
        nodes = _run_text(["kind", "get", "nodes", "--name", cluster_name]).splitlines()
        control_planes = sorted(name for name in nodes if name.endswith("control-plane"))
        if len(control_planes) != 1:
            raise ToolError("U1 management KinD control-plane identity differs")
        node = control_planes[0]
        try:
            kind_ip = self._public_ip(
                [
                    "docker",
                    "exec",
                    node,
                    "curl",
                    "-fsS",
                    "--max-time",
                    "15",
                    "https://checkip.amazonaws.com",
                ]
            )
        except ToolError:
            kind_ip = self._public_ip(
                [
                    "docker",
                    "exec",
                    node,
                    "wget",
                    "-qO-",
                    "https://checkip.amazonaws.com",
                ]
            )
        if host != contract.expected_public_ip or kind_ip != contract.expected_public_ip:
            raise ToolError("U1 host or KinD egress IP differs from the approved /32")
        return {"host": host, "kind": kind_ip}

    def _tagged_count(
        self,
        contract: U1Contract,
        profile: str,
        service: str,
        operation: str,
        response_key: str,
        *,
        filters: tuple[str, ...] = (),
    ) -> int:
        response = self._aws_json(
            contract,
            profile,
            service,
            operation,
            *filters,
        )
        value = response.get(response_key, []) if response else []
        if not isinstance(value, list):
            raise ToolError("U1 AWS conflict inventory response differs")
        return len(value)

    def aws_conflicts(self, contract: U1Contract, profile: str) -> dict[str, int]:
        tag_filter = (
            "--filters",
            f"Name=tag:platform.aws.goodnotes.io/environment,Values={contract.environment}",
        )
        clusters = self._aws_json(contract, profile, "eks", "list-clusters") or {}
        cluster_names = clusters.get("clusters", [])
        if not isinstance(cluster_names, list):
            raise ToolError("U1 EKS inventory response differs")
        sqs = self._aws_json(
            contract,
            profile,
            "sqs",
            "list-queues",
            "--queue-name-prefix",
            f"{contract.environment}-",
        ) or {}
        rules = self._aws_json(
            contract,
            profile,
            "events",
            "list-rules",
            "--name-prefix",
            f"{contract.environment}-",
        ) or {}
        iam_count = 0
        for suffix in ENVIRONMENT_IAM_ROLE_SUFFIXES:
            role = self._aws_json(
                contract,
                profile,
                "iam",
                "get-role",
                "--role-name",
                f"{contract.environment}-{suffix}",
                allow_no_such_entity=True,
            )
            iam_count += int(role is not None)
        reservations = self._aws_json(
            contract,
            profile,
            "ec2",
            "describe-instances",
            *tag_filter,
        ) or {}
        instances = sum(
            len(item.get("Instances", []))
            for item in reservations.get("Reservations", [])
            if isinstance(item, dict)
        )
        return {
            "eksClusters": int(f"{contract.environment}-cluster" in cluster_names),
            "vpcs": self._tagged_count(contract, profile, "ec2", "describe-vpcs", "Vpcs", filters=tag_filter),
            "subnets": self._tagged_count(contract, profile, "ec2", "describe-subnets", "Subnets", filters=tag_filter),
            "routeTables": self._tagged_count(contract, profile, "ec2", "describe-route-tables", "RouteTables", filters=tag_filter),
            "internetGateways": self._tagged_count(contract, profile, "ec2", "describe-internet-gateways", "InternetGateways", filters=tag_filter),
            "natGateways": self._tagged_count(contract, profile, "ec2", "describe-nat-gateways", "NatGateways", filters=tag_filter),
            "elasticIps": self._tagged_count(contract, profile, "ec2", "describe-addresses", "Addresses", filters=tag_filter),
            "securityGroups": self._tagged_count(contract, profile, "ec2", "describe-security-groups", "SecurityGroups", filters=tag_filter),
            "networkInterfaces": self._tagged_count(contract, profile, "ec2", "describe-network-interfaces", "NetworkInterfaces", filters=tag_filter),
            "instances": instances,
            "sqsQueues": len(sqs.get("QueueUrls", []) or []),
            "eventRules": len(rules.get("Rules", []) or []),
            "environmentIamRoles": iam_count,
        }

    def _assert_catalogs(self, contract: U1Contract) -> None:
        for filename in ("platform-release.approved.yaml", "node-image.approved.yaml"):
            expected = load_yaml(contract.bundle_directory / filename)
            name = expected["metadata"]["name"]
            live = self._kube(contract, "get", "environmentconfig", name)
            live_metadata = live.get("metadata", {})
            expected_metadata = expected.get("metadata", {})
            expected_annotations = expected_metadata.get("annotations", {})
            live_annotations = live_metadata.get("annotations", {})
            expected_labels = expected_metadata.get("labels", {})
            live_labels = live_metadata.get("labels", {})
            if (
                live.get("apiVersion") != expected.get("apiVersion")
                or live.get("kind") != expected.get("kind")
                or live_metadata.get("name") != name
                or live.get("data") != expected.get("data")
                or any(
                    live_annotations.get(key) != value
                    for key, value in expected_annotations.items()
                )
                or any(
                    live_labels.get(key) != value
                    for key, value in expected_labels.items()
                )
            ):
                raise ToolError("live U1 catalog differs from the reviewed package")

    def _lifecycle_inventory(self, contract: U1Contract) -> tuple[list[str], list[str]]:
        base = ["kubectl", "--context", contract.bootstrap.context]
        xrs: list[str] = []
        for resource in u0_runner.XR_RESOURCES:
            xrs.extend(u0_runner._run_names(base + ["get", resource, "-o", "name"]))
        managed = u0_runner._run_names(
            base + ["get", "managed", "--all-namespaces", "-o", "name"]
        )
        return xrs, managed

    @staticmethod
    def _managed_identity(item: dict[str, Any]) -> tuple[str, str, str, str]:
        metadata = item.get("metadata", {})
        return (
            str(item.get("apiVersion", "")),
            str(item.get("kind", "")),
            str(metadata.get("namespace", "")),
            str(metadata.get("name", "")),
        )

    def _record_non_aws_baseline(self, contract: U1Contract) -> None:
        document = self._kube(contract, "get", "managed", "--all-namespaces")
        items = document.get("items", [])
        if not isinstance(items, list):
            raise ToolError("U1 non-AWS managed baseline response differs")
        identities: set[tuple[str, str, str, str]] = set()
        for item in items:
            if not isinstance(item, dict):
                raise ToolError("U1 non-AWS managed baseline item differs")
            group = str(item.get("apiVersion", "")).split("/", 1)[0]
            marker = f"{group}/"
            if any(value in marker for value in AWS_MANAGED_MARKERS):
                raise ToolError("U1 create window found an existing AWS managed resource")
            identity = self._managed_identity(item)
            if not all((identity[0], identity[1], identity[3])) or identity in identities:
                raise ToolError("U1 non-AWS managed baseline identity differs")
            identities.add(identity)
        if len(identities) != EXPECTED_NON_AWS_MANAGED_BASELINE:
            raise ToolError("U1 non-AWS managed baseline differs")
        self._baseline_non_aws_identities = identities

    def baseline(self, contract: U1Contract, audit_profile: str) -> dict[str, Any]:
        self._assert_stopped(contract, allow_tagged_functions=False)
        if credentials.session_metadata(contract.bootstrap.context) is not None:
            raise ToolError("U1 baseline contains a published session Secret")
        xrs, managed = self._lifecycle_inventory(contract)
        if xrs:
            raise ToolError("U1 create window requires an empty lifecycle XR inventory")
        if any(marker in name for name in managed for marker in AWS_MANAGED_MARKERS):
            raise ToolError("U1 create window found an existing AWS managed resource")
        if len(managed) != EXPECTED_NON_AWS_MANAGED_BASELINE:
            raise ToolError("U1 non-AWS managed baseline differs")
        self._record_non_aws_baseline(contract)
        self._assert_catalogs(contract)
        egress = self.public_egress(contract)
        caller = self._aws_json(contract, audit_profile, "sts", "get-caller-identity") or {}
        if caller.get("Account") != contract.account_id:
            raise ToolError("U1 audit profile account differs from the authorization")
        conflicts = self.aws_conflicts(contract, audit_profile)
        if set(conflicts) != authorization_tool.TARGET_CONFLICT_KEYS or any(conflicts.values()):
            raise ToolError("U1 target environment already has conflicting AWS resources")
        quota = self._aws_json(
            contract,
            audit_profile,
            "service-quotas",
            "get-service-quota",
            "--service-code",
            "ec2",
            "--quota-code",
            "L-1216C47A",
        ) or {}
        value = quota.get("Quota", {}).get("Value")
        if not isinstance(value, (int, float)) or value < 16:
            raise ToolError("U1 Spot vCPU quota fell below the reviewed limit")
        images = self._aws_json(
            contract,
            audit_profile,
            "ec2",
            "describe-images",
            "--image-ids",
            contract.node_image_id,
        ) or {}
        image_items = images.get("Images", [])
        if (
            len(image_items) != 1
            or image_items[0].get("State") != "available"
            or image_items[0].get("Architecture") != "x86_64"
            or image_items[0].get("RootDeviceType") != "ebs"
        ):
            raise ToolError("U1 reviewed node image is no longer available")
        return {
            "controllersStopped": 14,
            "sessionSecretAbsent": True,
            "lifecycleXRs": 0,
            "awsManagedResources": 0,
            "nonAwsManagedResources": len(managed),
            "targetConflicts": conflicts,
            "egressMatched": egress["host"] == egress["kind"] == contract.expected_public_ip,
            "accountMatched": True,
            "spotQuotaAtLeastNodePoolLimit": True,
            "nodeImageAvailable": True,
        }

    def _optional(
        self, contract: U1Contract, resource: str, name: str
    ) -> dict[str, Any] | None:
        command = [
            "kubectl",
            "--context",
            contract.bootstrap.context,
            "get",
            resource,
            name,
            "--ignore-not-found",
            "-o",
            "json",
        ]
        try:
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
                env=_clean_env(),
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise ToolError("U1 optional Kubernetes lookup unavailable") from error
        if result.returncode:
            raise ToolError("U1 optional Kubernetes lookup failed; output suppressed")
        if not result.stdout.strip():
            return None
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ToolError("U1 optional Kubernetes response is invalid") from error
        if not isinstance(value, dict):
            raise ToolError("U1 optional Kubernetes response shape differs")
        return value

    def dry_run_environment(self, contract: U1Contract) -> None:
        self._verify_claim(contract)
        if self._optional(contract, "xeksenvironment.platform.aws.goodnotes.io", contract.environment) is not None:
            raise ToolError("reviewed U1 environment already exists; create window cannot resume")
        dry_run = self._kube(
            contract,
            "create",
            "--dry-run=server",
            "-f",
            "-",
            body=contract.environment_document,
        )
        if dry_run.get("metadata", {}).get("name") != contract.environment:
            raise ToolError("U1 server-side dry-run returned another environment")
        if self._optional(contract, "xeksenvironment.platform.aws.goodnotes.io", contract.environment) is not None:
            raise ToolError("U1 server-side dry-run unexpectedly persisted the environment")

    def create_environment(self, contract: U1Contract) -> dict[str, Any]:
        self._verify_claim(contract)
        if self._optional(
            contract,
            "xeksenvironment.platform.aws.goodnotes.io",
            contract.environment,
        ) is not None:
            raise ToolError("reviewed U1 environment appeared before create")
        created = self._kube(
            contract,
            "create",
            "-f",
            "-",
            body=contract.environment_document,
        )
        metadata = created.get("metadata", {})
        expected_metadata = contract.environment_document["metadata"]
        if (
            metadata.get("name") != contract.environment
            or not metadata.get("uid")
            or metadata.get("generation") != 1
            or not authorization_tool._strict_equal(
                metadata.get("labels"), expected_metadata["labels"]
            )
            or any(
                metadata.get("annotations", {}).get(key) != value
                for key, value in expected_metadata["annotations"].items()
            )
            or not authorization_tool._strict_equal(
                created.get("spec"), contract.environment_document.get("spec")
            )
        ):
            raise ToolError("persisted U1 environment differs from the reviewed manifest")
        return {
            "name": contract.environment,
            "uid": metadata["uid"],
            "generation": metadata["generation"],
        }

    def _assert_environment_identity(
        self,
        contract: U1Contract,
        root: dict[str, Any],
        *,
        expected_uid: str | None,
    ) -> dict[str, Any]:
        metadata = root.get("metadata", {})
        expected_metadata = contract.environment_document["metadata"]
        if (
            metadata.get("name") != contract.environment
            or (expected_uid is not None and metadata.get("uid") != expected_uid)
            or not metadata.get("uid")
            or not authorization_tool._strict_equal(
                metadata.get("labels"), expected_metadata["labels"]
            )
            or any(
                metadata.get("annotations", {}).get(key) != value
                for key, value in expected_metadata["annotations"].items()
            )
            or not authorization_tool._strict_equal(
                root.get("spec"), contract.environment_document.get("spec")
            )
        ):
            raise ToolError("U1 environment identity or reviewed intent changed")
        return metadata

    def _environment_snapshot(
        self, contract: U1Contract, expected_uid: str
    ) -> dict[str, Any]:
        root = self._kube(
            contract,
            "get",
            "xeksenvironment.platform.aws.goodnotes.io",
            contract.environment,
        )
        metadata = self._assert_environment_identity(
            contract,
            root,
            expected_uid=expected_uid,
        )
        child_specs = (
            ("XNetwork", "xnetwork.platform.aws.goodnotes.io", "-network"),
            ("XEKSCluster", "xekscluster.platform.aws.goodnotes.io", "-cluster"),
            (
                "XClusterFoundation",
                "xclusterfoundation.platform.aws.goodnotes.io",
                "-foundation",
            ),
        )
        children: dict[str, dict[str, Any]] = {}
        for kind, resource, suffix in child_specs:
            name = f"{contract.environment}{suffix}"
            child = self._optional(contract, resource, name)
            if child is not None:
                child_meta = child.get("metadata", {})
                owner_references = child_meta.get("ownerReferences", []) or []
                if (
                    child_meta.get("name") != name
                    or child_meta.get("labels", {}).get(
                        "platform.aws.goodnotes.io/environment"
                    )
                    != contract.environment
                    or not any(
                        item.get("kind") == "XEKSEnvironment"
                        and item.get("uid") == expected_uid
                        and item.get("controller") is True
                        for item in owner_references
                        if isinstance(item, dict)
                    )
                ):
                    raise ToolError("U1 child XR owner identity differs")
                children[kind] = {
                    "name": name,
                    "uid": child_meta.get("uid"),
                    "generation": child_meta.get("generation"),
                    "ready": (_condition(child, "Ready") or {}).get("status") == "True",
                    "infrastructureReady": (
                        _condition(child, "InfrastructureReady") or {}
                    ).get("status")
                    == "True",
                }
        root_infrastructure = (_condition(root, "InfrastructureReady") or {}).get("status") == "True"
        cluster_infrastructure = children.get("XEKSCluster", {}).get(
            "infrastructureReady", False
        )
        return {
            "root": {
                "name": contract.environment,
                "uid": expected_uid,
                "generation": metadata.get("generation"),
                "infrastructureReady": root_infrastructure,
            },
            "children": children,
            "allChildrenObserved": len(children) == 3,
            "infrastructureReady": bool(
                root_infrastructure and cluster_infrastructure
            ),
        }

    def wait_checkpoint(self, contract: U1Contract, environment: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + self.checkpoint_wait_seconds
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            self._verify_claim(contract)
            last = self._environment_snapshot(contract, environment["uid"])
            if last["allChildrenObserved"] and last["infrastructureReady"]:
                return last | {"checkpointReached": True}
            time.sleep(self.poll_seconds)
        if not last:
            last = self._environment_snapshot(contract, environment["uid"])
        return last | {"checkpointReached": False}

    def _managed_inventory(self, contract: U1Contract) -> dict[str, Any]:
        document = self._kube(contract, "get", "managed", "--all-namespaces")
        allowed_groups = set(contract.expected_resources["awsApiGroups"])
        aws_counts: dict[str, int] = {}
        non_aws = 0
        for item in document.get("items", []):
            api_version = item.get("apiVersion", "")
            group = api_version.split("/", 1)[0]
            marker = f"{group}/"
            is_aws = any(value in marker for value in AWS_MANAGED_MARKERS)
            if not is_aws:
                identity = self._managed_identity(item)
                labels = item.get("metadata", {}).get("labels", {})
                if (
                    identity not in self._baseline_non_aws_identities
                    and labels.get("platform.aws.goodnotes.io/environment")
                    != contract.environment
                ):
                    raise ToolError(
                        "U1 produced a non-AWS managed resource without the reviewed owner label"
                    )
                non_aws += 1
                continue
            if group not in allowed_groups:
                raise ToolError("U1 produced an AWS managed resource outside the reviewed API groups")
            labels = item.get("metadata", {}).get("labels", {})
            if labels.get("platform.aws.goodnotes.io/environment") != contract.environment:
                raise ToolError("U1 AWS managed resource lacks the exact environment owner label")
            kind = item.get("kind", "")
            if kind in {"NodeGroup", "Nodegroup"}:
                raise ToolError("U1 created a forbidden managed node group")
            if kind == "Addon" and item.get("spec", {}).get("forProvider", {}).get(
                "addonName"
            ) in {"vpc-cni", "kube-proxy"}:
                raise ToolError("U1 created a forbidden VPC CNI or kube-proxy add-on")
            aws_counts[f"{group}/{kind}"] = aws_counts.get(f"{group}/{kind}", 0) + 1
        return {
            "awsManagedResources": sum(aws_counts.values()),
            "nonAwsManagedResources": non_aws,
            "awsKinds": dict(sorted(aws_counts.items())),
        }

    @staticmethod
    def _tags(items: list[dict[str, Any]]) -> dict[str, str]:
        return {
            item.get("Key", ""): item.get("Value", "")
            for item in items or []
            if isinstance(item, dict)
        }

    def verify_spot_instances(
        self, contract: U1Contract, audit_profile: str
    ) -> dict[str, Any]:
        instances = self._aws_json(
            contract,
            audit_profile,
            "ec2",
            "describe-instances",
            "--filters",
            f"Name=tag:platform.aws.goodnotes.io/environment,Values={contract.environment}",
            "Name=instance-state-name,Values=pending,running,stopping,stopped",
        ) or {}
        active_instances = [
            item
            for reservation in instances.get("Reservations", [])
            if isinstance(reservation, dict)
            for item in reservation.get("Instances", [])
            if isinstance(item, dict)
        ]
        if any(item.get("InstanceLifecycle") != "spot" for item in active_instances):
            raise ToolError("U1 observed a non-Spot EC2 instance")
        return {
            "activeEc2Instances": len(active_instances),
            "allObservedEc2Spot": True,
        }

    def verify_aws_checkpoint(
        self, contract: U1Contract, audit_profile: str
    ) -> dict[str, Any]:
        cluster_name = f"{contract.environment}-cluster"
        response = self._aws_json(
            contract,
            audit_profile,
            "eks",
            "describe-cluster",
            "--name",
            cluster_name,
        ) or {}
        cluster = response.get("cluster", {})
        vpc_config = cluster.get("resourcesVpcConfig", {})
        access = cluster.get("accessConfig", {})
        if (
            cluster.get("name") != cluster_name
            or cluster.get("status") != "ACTIVE"
            or cluster.get("version") != "1.35"
            or cluster.get("deletionProtection") is not True
            or access.get("authenticationMode") != "API"
            or access.get("bootstrapClusterCreatorAdminPermissions") is not False
            or vpc_config.get("endpointPrivateAccess") is not True
            or vpc_config.get("endpointPublicAccess") is not True
            or vpc_config.get("publicAccessCidrs")
            != [f"{contract.expected_public_ip}/32"]
            or (cluster.get("computeConfig") or {}).get("enabled") is True
        ):
            raise ToolError("U1 EKS control plane differs from the reviewed contract")
        profiles = self._aws_json(
            contract,
            audit_profile,
            "eks",
            "list-fargate-profiles",
            "--cluster-name",
            cluster_name,
        ) or {}
        if profiles.get("fargateProfileNames") != ["karpenter"]:
            raise ToolError("U1 Fargate profile inventory differs")
        profile = self._aws_json(
            contract,
            audit_profile,
            "eks",
            "describe-fargate-profile",
            "--cluster-name",
            cluster_name,
            "--fargate-profile-name",
            "karpenter",
        ) or {}
        fargate = profile.get("fargateProfile", {})
        if (
            fargate.get("status") != "ACTIVE"
            or fargate.get("selectors")
            != [
                {
                    "namespace": "karpenter",
                    "labels": {
                        "app.kubernetes.io/instance": "karpenter",
                        "app.kubernetes.io/name": "karpenter",
                    },
                }
            ]
        ):
            raise ToolError("U1 Karpenter Fargate profile differs")
        nodegroups = self._aws_json(
            contract,
            audit_profile,
            "eks",
            "list-nodegroups",
            "--cluster-name",
            cluster_name,
        ) or {}
        if nodegroups.get("nodegroups", []) != []:
            raise ToolError("U1 unexpectedly created an EKS managed node group")
        addons = self._aws_json(
            contract,
            audit_profile,
            "eks",
            "list-addons",
            "--cluster-name",
            cluster_name,
        ) or {}
        addon_names = addons.get("addons", [])
        if any(name in {"vpc-cni", "kube-proxy"} for name in addon_names):
            raise ToolError("U1 unexpectedly installed VPC CNI or kube-proxy add-on")
        spot = self.verify_spot_instances(contract, audit_profile)
        return {
            "clusterActive": True,
            "deletionProtection": True,
            "authenticationMode": "API",
            "fargateProfileActive": True,
            "managedNodeGroups": 0,
            "forbiddenAddons": 0,
            **spot,
        }

    def capture_evidence(
        self,
        contract: U1Contract,
        environment: dict[str, Any],
        checkpoint: dict[str, Any],
        audit_profile: str,
    ) -> dict[str, Any]:
        inventory = self._managed_inventory(contract)
        aws = self.verify_spot_instances(contract, audit_profile)
        if checkpoint.get("checkpointReached"):
            aws = self.verify_aws_checkpoint(contract, audit_profile)
        else:
            aws |= {
                "clusterActive": False,
                "checkpointReadOnlyAwsVerificationDeferred": True,
            }
        return {
            "environment": environment,
            "checkpoint": checkpoint,
            "managedInventory": inventory,
            "aws": aws,
        }

    def cleanup(
        self,
        contract: U1Contract,
        *,
        expected_environment_uid: str | None,
    ) -> dict[str, Any]:
        result = super().cleanup(contract)
        current = self._optional(
            contract,
            "xeksenvironment.platform.aws.goodnotes.io",
            contract.environment,
        )
        environment_present = current is not None
        if current is not None:
            self._assert_environment_identity(
                contract,
                current,
                expected_uid=expected_environment_uid,
            )
        elif expected_environment_uid is not None:
            raise ToolError("U1 environment disappeared during park cleanup")
        return result | {
            "environmentPresent": environment_present,
            "environmentDeleted": False,
            "awsDeletionAttempted": False,
        }


def execute(
    contract: U1Contract,
    profile: str,
    audit_profile: str,
    acknowledgement: str,
    *,
    operations: RealOperations | None = None,
) -> dict[str, Any]:
    if acknowledgement != RUN_ACKNOWLEDGEMENT:
        raise ToolError("explicit U1 bootstrap execution acknowledgement required")
    if not profile or not audit_profile or profile == audit_profile:
        raise ToolError("distinct explicit source and reviewed audit profiles are required")
    contract = load_contract(
        contract.authorization_path,
        contract.session_review_path,
        require_approved=True,
    )
    if audit_profile != contract.audit_profile:
        raise ToolError("U1 audit profile differs from the reviewed AWS snapshot")
    authorization_tool.claim_authorization(
        contract.authorization_path,
        authorization_tool.CLAIM_ACKNOWLEDGEMENT,
    )
    journal = Journal.create(contract.authorization["windowId"])
    journal.append("CLAIMED")
    ops = operations or RealOperations()
    protection_attempted = False
    session_attempted = False
    controllers_attempted = False
    environment_created: dict[str, Any] | None = None
    baseline: dict[str, Any] = {}
    checkpoint: dict[str, Any] = {}
    evidence: dict[str, Any] = {}
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None
    cleanup: dict[str, Any] = {}
    try:
        authorization_tool.verify_claim(contract.authorization_path)
        baseline = ops.baseline(contract, audit_profile)
        journal.append("BASELINE_VERIFIED")

        protection_attempted = True
        journal.append("PROTECTION_STARTED")
        ops.protect(contract)
        journal.append("PROTECTED")

        session_attempted = True
        journal.append("SESSION_STARTED")
        ops.open_session(
            contract,
            profile,
            audit_profile,
            progress=journal.append,
        )
        journal.append("SESSION_OPENED")

        controllers_attempted = True
        ops.start_controllers(contract)
        ops.wait_ready(contract)
        journal.append("CONTROLLERS_STARTED")

        ops.dry_run_environment(contract)
        journal.append("ENVIRONMENT_DRY_RUN_VERIFIED")
        environment_created = ops.create_environment(contract)
        journal.append("ENVIRONMENT_CREATED")
        checkpoint = ops.wait_checkpoint(contract, environment_created)
        if checkpoint.get("allChildrenObserved"):
            journal.append("CHILDREN_OBSERVED")
        if checkpoint.get("checkpointReached"):
            journal.append("INFRASTRUCTURE_READY")
        else:
            journal.append("MONITOR_WINDOW_ENDED")
        evidence = ops.capture_evidence(
            contract,
            environment_created,
            checkpoint,
            audit_profile,
        )
        journal.append("EVIDENCE_CAPTURED")
    except BaseException as error:
        failure = error
    finally:
        if protection_attempted or session_attempted or controllers_attempted:
            try:
                journal.append("CLEANUP_STARTED")
                cleanup = ops.cleanup(
                    contract,
                    expected_environment_uid=(environment_created or {}).get("uid"),
                )
                journal.append(
                    "FAILED_CLEANUP_COMPLETE" if failure else "CLEANUP_COMPLETE"
                )
            except BaseException as error:
                cleanup_failure = error
                try:
                    journal.append("RECOVERY_REQUIRED")
                except BaseException:
                    pass
        elif failure is not None:
            try:
                journal.append("BASELINE_REJECTED_NO_MUTATION")
            except BaseException:
                pass

    status = (
        "U1_BOOTSTRAP_RECOVERY_REQUIRED"
        if cleanup_failure is not None
        else "U1_BOOTSTRAP_FAILED_SAFE"
        if failure is not None
        else "U1_01_PASS"
        if checkpoint.get("checkpointReached")
        else "U1_BOOTSTRAP_PENDING_CONTINUATION"
    )
    report = {
        "schemaVersion": 1,
        "status": status,
        "bundle": contract.authorization["bundle"],
        "windowId": contract.authorization["windowId"],
        "recordedAt": datetime.now(timezone.utc).isoformat(),
        "reviewedGitCommit": contract.authorization["reviewedGitCommit"],
        "executionCodeSha256": contract.authorization["executionCodeSha256"],
        "baseline": baseline,
        "environment": environment_created,
        "checkpoint": checkpoint,
        "evidence": evidence,
        "cleanup": cleanup,
        "failureSha256": hashlib.sha256(str(failure).encode()).hexdigest()
        if failure is not None
        else None,
        "cleanupFailureSha256": hashlib.sha256(str(cleanup_failure).encode()).hexdigest()
        if cleanup_failure is not None
        else None,
        "singleUseClaimConsumed": True,
        "directAwsCliMutation": False,
        "crossplaneAwsResourceMutationAuthorized": True,
        "environmentDeletionAttempted": False,
        "automaticRetry": False,
        "networkApprovalCreated": False,
        "gitBootstrapEnabled": False,
        "u2Entered": False,
    }
    result_path = _write_private_json(
        RESULT_ROOT / f"{contract.authorization['windowId']}.json",
        report,
    )
    if cleanup_failure is not None:
        raise ToolError(
            "U1 park cleanup is incomplete; use recovery-only and do not retry"
        ) from cleanup_failure
    if failure is not None:
        if isinstance(failure, KeyboardInterrupt):
            raise failure
        if not (protection_attempted or session_attempted or controllers_attempted):
            raise ToolError(
                "U1 baseline failed after claim; no Kubernetes or AWS mutation was attempted"
            ) from failure
        raise ToolError(
            "U1 bootstrap failed; controllers were parked and the environment was preserved"
        ) from failure
    return {
        "status": status,
        "windowId": contract.authorization["windowId"],
        "singleUseClaimConsumed": True,
        "environmentPersisted": environment_created is not None,
        "infrastructureReady": bool(checkpoint.get("checkpointReached")),
        "controllersRestoredToZero": cleanup.get("controllersStopped") == 14,
        "sessionSecretAbsent": cleanup.get("sessionSecretAbsent") is True,
        "sharedProtectionRestored": cleanup.get("sharedProtectionRestored") is True,
        "environmentDeletionAttempted": False,
        "directAwsCliMutation": False,
        "resultPath": str(result_path),
    }


def recover(
    contract: U1Contract,
    acknowledgement: str,
    *,
    operations: RealOperations | None = None,
) -> dict[str, Any]:
    if acknowledgement != RECOVER_ACKNOWLEDGEMENT:
        raise ToolError("explicit U1 park recovery acknowledgement required")
    authorization_tool.verify_claim(
        contract.authorization_path,
        require_active=False,
    )
    journal = Journal.existing(contract.authorization["windowId"])
    if journal is not None:
        journal.append("RECOVERY_STARTED")
    result = (operations or RealOperations()).cleanup(
        contract,
        expected_environment_uid=None,
    )
    if journal is not None:
        journal.append("RECOVERY_COMPLETE")
    return {
        "status": "U1_PARK_RECOVERY_COMPLETE",
        "windowId": contract.authorization["windowId"],
        "controllersRestoredToZero": result["controllersStopped"] == 14,
        "sessionSecretAbsent": result["sessionSecretAbsent"],
        "environmentDeletionAttempted": False,
        "directAwsApiCalls": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run", "recover"))
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--session-review", type=Path, required=True)
    parser.add_argument("--profile")
    parser.add_argument("--audit-profile")
    parser.add_argument("--acknowledge", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.mode == "plan":
            if args.profile or args.audit_profile or args.acknowledge:
                raise ToolError("plan does not accept profiles or acknowledgement")
            contract = load_contract(
                args.authorization,
                args.session_review,
                require_approved=False,
            )
            result = public_plan(contract)
        elif args.mode == "run":
            if not args.profile or not args.audit_profile:
                raise ToolError("run requires source and audit profiles")
            contract = load_contract(
                args.authorization,
                args.session_review,
                require_approved=True,
            )
            result = execute(
                contract,
                args.profile,
                args.audit_profile,
                args.acknowledge,
            )
        else:
            if args.profile or args.audit_profile:
                raise ToolError("recovery does not accept AWS profiles")
            contract = load_contract(
                args.authorization,
                args.session_review,
                require_approved=True,
                allow_stale_approved=True,
                recovery_only=True,
            )
            result = recover(contract, args.acknowledge)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print(
            "U1 command interrupted; park cleanup was attempted; inspect recovery state",
            file=sys.stderr,
        )
        return 130
    except (ToolError, OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "U1 bootstrap command failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
