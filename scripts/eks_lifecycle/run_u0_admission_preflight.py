#!/usr/bin/env python3
"""Run or recover one reviewed U0-06 Kubernetes admission-test window.

Plan mode is local-only. Run mode atomically consumes one private authorization,
keeps every reviewed controller stopped, creates only an exact paused test XR
and resourceName-scoped temporary RBAC, executes synthetic-identity admission
checks, records sanitized evidence, and always attempts cleanup. No AWS command,
management session, credential Secret access, or persistent platform resource is
part of this runner.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import ToolError, load_yaml
import run_u0_management_preflight as management_preflight
import validate_u0_admission_authorization as authorization_tool
import validate_u0_authorization as u0_authorization


RUN_ACKNOWLEDGEMENT = "I-APPROVE-EXECUTE-ONE-U0-ADMISSION-PREFLIGHT"
RECOVER_ACKNOWLEDGEMENT = "I-APPROVE-U0-ADMISSION-RECOVERY-ONLY"
NAMESPACE = "crossplane-system"
EXPECTED_NON_AWS_MANAGED = 73
RESULT_ROOT = Path.home() / ".local/share/eks-platform/u0-admission-results"

POLICY_NAME = "eks-lifecycle-stage-approvers.platform.aws.goodnotes.io"
STAGE_EDITOR_NAME = "eks-lifecycle-stage-editor"
EVIDENCE_WRITER_NAME = "eks-lifecycle-evidence-writer"
XR_RESOURCES = management_preflight.XR_RESOURCES
AWS_MANAGED_MARKERS = management_preflight.AWS_MANAGED_MARKERS

JOURNAL_EVENTS = {
    "CLAIMED",
    "BASELINE_VERIFIED",
    "SETUP_STARTED",
    "FIXTURE_CREATED",
    "TEMPORARY_RBAC_CREATED",
    "TESTS_STARTED",
    "TESTS_VERIFIED",
    "CLEANUP_STARTED",
    "CLEANUP_COMPLETE",
    "FAILED_CLEANUP_COMPLETE",
    "RECOVERY_STARTED",
    "RECOVERY_COMPLETE",
    "RECOVERY_REQUIRED",
}


@dataclass(frozen=True)
class AdmissionContract:
    authorization_path: Path
    authorization: dict[str, Any] = field(repr=False)
    bundle_directory: Path = field(repr=False)
    context: str
    fixture: dict[str, Any] = field(repr=False)
    temporary_rbac: tuple[dict[str, Any], ...] = field(repr=False)
    test_plan: dict[str, Any] = field(repr=False)


def load_contract(
    authorization_path: Path,
    *,
    require_approved: bool,
    allow_stale_approved: bool = False,
) -> AdmissionContract:
    authorization_path = Path(os.path.abspath(authorization_path.expanduser()))
    authorization = authorization_tool.validate_authorization(
        authorization_path,
        require_approved=require_approved,
        allow_stale_approved=allow_stale_approved,
    )
    authorization.pop("_authorizationSha256", None)
    bundle = authorization_path.parent
    try:
        test_plan = json.loads(
            u0_authorization._read_private(bundle / "admission-test-plan.json")
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid U0 admission test plan; output suppressed") from error
    fixture = load_yaml(bundle / "environment-fixture.yaml")
    rbac_list = load_yaml(bundle / "temporary-rbac.yaml")
    items = rbac_list.get("items", []) if isinstance(rbac_list, dict) else []
    if len(items) != 2:
        raise ToolError("U0 admission temporary RBAC inventory differs")
    return AdmissionContract(
        authorization_path=authorization_path,
        authorization=authorization,
        bundle_directory=bundle,
        context=test_plan["context"],
        fixture=fixture,
        temporary_rbac=tuple(items),
        test_plan=test_plan,
    )


def public_plan(contract: AdmissionContract) -> dict[str, Any]:
    matrix = contract.test_plan["ordinaryOwnerWriteMatrix"]
    return {
        "mode": "plan",
        "bundle": contract.authorization["bundle"],
        "windowId": contract.authorization["windowId"],
        "reviewStatus": contract.authorization["reviewStatus"],
        "approved": contract.authorization["approved"],
        "context": contract.context,
        "maximumWindowSeconds": authorization_tool.MAX_WINDOW_SECONDS,
        "ordinaryAuthorizationChecks": len(matrix["verbs"])
        * len(matrix["targets"]),
        "dryRunAdmissionChecks": len(contract.test_plan["dryRunCases"]),
        "temporaryKubernetesResources": 3,
        "controllersExpectedStopped": 14,
        "managementSessionRequired": False,
        "awsProfilesAccepted": False,
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
        root = u0_authorization._claim_root(authorization_tool.CLAIM_ROOT, create=False)
        path = root / f"{window_id}.state.jsonl"
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError as error:
            raise ToolError("U0 admission journal already exists; use recovery") from error
        except OSError as error:
            raise ToolError("U0 admission journal could not be created safely") from error
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.flush()
            os.fsync(stream.fileno())
        return cls(path)

    @classmethod
    def existing(cls, window_id: str) -> "Journal | None":
        root = u0_authorization._claim_root(authorization_tool.CLAIM_ROOT, create=False)
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
            raise ToolError("U0 admission journal is unsafe")
        return cls(path)

    def append(self, event: str) -> None:
        if event not in JOURNAL_EVENTS:
            raise ToolError("unreviewed U0 admission journal event")
        payload = (
            json.dumps(
                {"event": event, "recordedAt": datetime.now(timezone.utc).isoformat()},
                sort_keys=True,
            )
            + "\n"
        ).encode()
        try:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        except OSError as error:
            raise ToolError("U0 admission journal is unavailable") from error
        with os.fdopen(descriptor, "ab") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ToolError("U0 admission journal ownership or mode changed")
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())


def _response_sha256(result: subprocess.CompletedProcess[str]) -> str:
    return hashlib.sha256(
        (result.stdout + "\0" + result.stderr).encode("utf-8", errors="replace")
    ).hexdigest()


def _clean_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}


def _write_result(window_id: str, document: dict[str, Any]) -> Path:
    root = u0_authorization._claim_root(RESULT_ROOT, create=True)
    path = root / f"{window_id}.json"
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as error:
        raise ToolError("U0 admission result already exists; reuse is forbidden") from error
    except OSError as error:
        raise ToolError("U0 admission result could not be created safely") from error
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    directory_descriptor = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return path


class RealOperations:
    def __init__(self) -> None:
        self.evidence: dict[str, Any] = {
            "ordinaryOwnerWriteMatrix": [],
            "dryRunCases": [],
        }

    def _kubectl(
        self,
        contract: AdmissionContract,
        *args: str,
        input_text: str | None = None,
        timeout: int = 45,
    ) -> subprocess.CompletedProcess[str]:
        command = ["kubectl", "--context", contract.context, *args]
        try:
            return subprocess.run(
                command,
                input=input_text,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
                env=_clean_env(),
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise ToolError("kubectl unavailable or timed out; output suppressed") from error

    def _json(
        self,
        contract: AdmissionContract,
        *args: str,
        input_document: Any | None = None,
    ) -> Any:
        result = self._kubectl(
            contract,
            *args,
            input_text=(
                json.dumps(input_document) if input_document is not None else None
            ),
        )
        if result.returncode:
            raise ToolError("kubectl request failed; output suppressed")
        try:
            return json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError) as error:
            raise ToolError("kubectl returned invalid JSON; output suppressed") from error

    def _text(self, contract: AdmissionContract, *args: str) -> str:
        result = self._kubectl(contract, *args)
        if result.returncode:
            raise ToolError("kubectl read failed; output suppressed")
        return result.stdout.strip()

    def _optional(
        self, contract: AdmissionContract, resource: str, name: str, *extra: str
    ) -> dict[str, Any] | None:
        result = self._kubectl(
            contract,
            "get",
            resource,
            name,
            *extra,
            "--ignore-not-found",
            "-o",
            "json",
        )
        if result.returncode:
            raise ToolError("kubectl optional read failed; output suppressed")
        if not result.stdout.strip():
            return None
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ToolError("kubectl optional read returned invalid JSON") from error
        if not isinstance(value, dict):
            raise ToolError("kubectl optional read returned an invalid object")
        return value

    @staticmethod
    def _owned_labels(window_id: str) -> dict[str, str]:
        return {
            "platform.aws.goodnotes.io/managed-by": "u0-admission-preflight",
            "platform.aws.goodnotes.io/window-id": window_id,
        }

    def _assert_reviewed_policy(self, contract: AdmissionContract) -> dict[str, str]:
        policy = self._json(
            contract,
            "get",
            "validatingadmissionpolicy.admissionregistration.k8s.io",
            POLICY_NAME,
            "-o",
            "json",
        )
        spec = policy.get("spec", {})
        rules = spec.get("matchConstraints", {}).get("resourceRules", [])
        conditions = spec.get("matchConditions", [])
        validations = spec.get("validations", [])
        expected_validations = {
            (
                "request.userInfo.groups.exists(group, group == 'platform-eks-lifecycle-approvers')",
                "lifecycle changes require the platform-eks-lifecycle-approvers group",
                "Forbidden",
            ),
            (
                "object.spec.parameters.lifecycle.retirementStage == 'Active' || has(object.spec.parameters.lifecycle.evidenceRef)",
                "non-Active lifecycle stages require an immutable evidenceRef",
                "Invalid",
            ),
        }
        if (
            spec.get("failurePolicy") != "Fail"
            or len(rules) != 1
            or rules[0].get("apiGroups") != ["platform.aws.goodnotes.io"]
            or rules[0].get("apiVersions") != ["v1alpha1"]
            or rules[0].get("operations") != ["UPDATE"]
            or rules[0].get("resources") != ["xeksenvironments"]
            or conditions
            != [
                {
                    "name": "lifecycle-change",
                    "expression": "object.spec.parameters.lifecycle != oldObject.spec.parameters.lifecycle",
                }
            ]
            or {
                (
                    item.get("expression"),
                    item.get("message"),
                    item.get("reason"),
                )
                for item in validations
            }
            != expected_validations
            or policy.get("status", {}).get("typeChecking", {}).get(
                "expressionWarnings", []
            )
        ):
            raise ToolError("live lifecycle admission policy differs from the review")
        binding = self._json(
            contract,
            "get",
            "validatingadmissionpolicybinding.admissionregistration.k8s.io",
            POLICY_NAME,
            "-o",
            "json",
        )
        if binding.get("spec", {}) != {
            "policyName": POLICY_NAME,
            "validationActions": ["Deny"],
        }:
            raise ToolError("live lifecycle admission binding differs from the review")
        return {
            "policyUid": policy.get("metadata", {}).get("uid", ""),
            "policyResourceVersion": policy.get("metadata", {}).get(
                "resourceVersion", ""
            ),
            "bindingUid": binding.get("metadata", {}).get("uid", ""),
        }

    def _assert_reviewed_rbac(self, contract: AdmissionContract) -> None:
        stage_role = self._json(
            contract, "get", "clusterrole", STAGE_EDITOR_NAME, "-o", "json"
        )
        stage_binding = self._json(
            contract, "get", "clusterrolebinding", STAGE_EDITOR_NAME, "-o", "json"
        )
        expected_stage_rules = [
            {
                "apiGroups": ["platform.aws.goodnotes.io"],
                "resources": ["xeksenvironments"],
                "verbs": ["get", "list", "patch", "update", "watch"],
            }
        ]
        expected_subject = [
            {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Group",
                "name": authorization_tool.APPROVER_GROUP,
            }
        ]
        if (
            stage_role.get("rules") != expected_stage_rules
            or stage_binding.get("subjects") != expected_subject
            or stage_binding.get("roleRef")
            != {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": STAGE_EDITOR_NAME,
            }
        ):
            raise ToolError("live lifecycle stage RBAC differs from the review")
        writer = self._json(
            contract,
            "--namespace",
            NAMESPACE,
            "get",
            "role",
            EVIDENCE_WRITER_NAME,
            "-o",
            "json",
        )
        writer_binding = self._json(
            contract,
            "--namespace",
            NAMESPACE,
            "get",
            "rolebinding",
            EVIDENCE_WRITER_NAME,
            "-o",
            "json",
        )
        if (
            writer.get("rules")
            != [
                {
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "verbs": ["create", "get", "patch", "update"],
                }
            ]
            or writer_binding.get("subjects") != expected_subject
            or writer_binding.get("roleRef")
            != {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": EVIDENCE_WRITER_NAME,
            }
        ):
            raise ToolError("live lifecycle evidence RBAC differs from the review")

    def _assert_controllers_stopped(self, contract: AdmissionContract) -> None:
        expected = set(management_preflight.controller_inventory())
        deployments = self._json(
            contract,
            "--namespace",
            NAMESPACE,
            "get",
            "deployments",
            "-o",
            "json",
        )
        by_name = {
            item.get("metadata", {}).get("name", ""): item
            for item in deployments.get("items", [])
            if item.get("metadata", {}).get("name")
        }
        if set(by_name) != expected:
            raise ToolError("live controller inventory differs from the reviewed 14")
        if any(
            item.get("spec", {}).get("replicas", 1) != 0
            or item.get("status", {}).get("replicas", 0) != 0
            for item in by_name.values()
        ):
            raise ToolError("a reviewed controller is not fully stopped")

    def _assert_resource_inventory(
        self, contract: AdmissionContract, *, allow_fixture: bool
    ) -> int:
        for resource in XR_RESOURCES:
            document = self._json(contract, "get", resource, "-o", "json")
            names = [
                item.get("metadata", {}).get("name")
                for item in document.get("items", [])
            ]
            expected = (
                [authorization_tool.FIXTURE_NAME]
                if allow_fixture
                and resource == "xeksenvironments.platform.aws.goodnotes.io"
                else []
            )
            if names != expected:
                raise ToolError("lifecycle XR inventory differs from the reviewed window")
        managed = self._text(
            contract, "get", "managed", "--all-namespaces", "-o", "name"
        ).splitlines()
        managed = [item for item in managed if item]
        if any(marker in name for name in managed for marker in AWS_MANAGED_MARKERS):
            raise ToolError("an AWS managed resource exists during U0 admission testing")
        if len(managed) != EXPECTED_NON_AWS_MANAGED:
            raise ToolError("non-AWS managed inventory differs from the reviewed baseline")
        return len(managed)

    def _assert_temporary_absent(self, contract: AdmissionContract) -> None:
        if self._optional(
            contract,
            "xeksenvironment.platform.aws.goodnotes.io",
            authorization_tool.FIXTURE_NAME,
        ) is not None:
            raise ToolError("U0 admission fixture already exists")
        for resource in ("clusterrole", "clusterrolebinding"):
            if self._optional(
                contract, resource, authorization_tool.TEMPORARY_ROLE_NAME
            ) is not None:
                raise ToolError("temporary U0 admission RBAC already exists")
        if self._optional(
            contract,
            "configmap",
            authorization_tool.EVIDENCE_NAME,
            "--namespace",
            NAMESPACE,
        ) is not None:
            raise ToolError("U0 admission evidence probe unexpectedly persisted")

    def baseline(self, contract: AdmissionContract) -> dict[str, Any]:
        self._assert_controllers_stopped(contract)
        policy = self._assert_reviewed_policy(contract)
        self._assert_reviewed_rbac(contract)
        managed = self._assert_resource_inventory(contract, allow_fixture=False)
        self._assert_temporary_absent(contract)
        return {
            "controllersStopped": 14,
            "managementSessionSecretAccessed": False,
            "awsManagedResources": 0,
            "nonAwsManagedResources": managed,
            **policy,
        }

    def _create_document(
        self, contract: AdmissionContract, document: dict[str, Any]
    ) -> dict[str, Any]:
        authorization_tool.verify_claim(contract.authorization_path)
        return self._json(
            contract,
            "create",
            "-f",
            "-",
            "-o",
            "json",
            input_document=document,
        )

    def _assert_fixture_unchanged(self, contract: AdmissionContract) -> dict[str, Any]:
        fixture = self._optional(
            contract,
            "xeksenvironment.platform.aws.goodnotes.io",
            authorization_tool.FIXTURE_NAME,
        )
        if fixture is None:
            raise ToolError("paused U0 admission fixture disappeared")
        metadata = fixture.get("metadata", {})
        lifecycle = fixture.get("spec", {}).get("parameters", {}).get("lifecycle", {})
        if (
            metadata.get("labels") != self._owned_labels(
                contract.authorization["windowId"]
            )
            or metadata.get("annotations", {}).get("crossplane.io/paused") != "true"
            or lifecycle
            != {"deletionProtection": True, "retirementStage": "Active"}
        ):
            raise ToolError("paused U0 admission fixture was changed or unprotected")
        return fixture

    def setup(self, contract: AdmissionContract, progress: Any = None) -> dict[str, str]:
        fixture = self._create_document(contract, contract.fixture)
        if progress is not None:
            progress("FIXTURE_CREATED")
        for document in contract.temporary_rbac:
            self._create_document(contract, document)
        if progress is not None:
            progress("TEMPORARY_RBAC_CREATED")
        self._assert_controllers_stopped(contract)
        self._assert_resource_inventory(contract, allow_fixture=True)
        observed = self._assert_fixture_unchanged(contract)
        labels = self._owned_labels(contract.authorization["windowId"])
        for resource in ("clusterrole", "clusterrolebinding"):
            item = self._optional(
                contract, resource, authorization_tool.TEMPORARY_ROLE_NAME
            )
            if item is None or item.get("metadata", {}).get("labels") != labels:
                raise ToolError("temporary U0 admission RBAC is missing or changed")
        if fixture.get("metadata", {}).get("uid") != observed.get("metadata", {}).get(
            "uid"
        ):
            raise ToolError("U0 admission fixture identity changed during setup")
        return {
            "fixtureUid": observed.get("metadata", {}).get("uid", ""),
            "fixtureResourceVersion": observed.get("metadata", {}).get(
                "resourceVersion", ""
            ),
        }

    @staticmethod
    def _actor_args(plan: dict[str, Any], actor: str) -> list[str]:
        identity = plan["actors"][actor]
        result = ["--as", identity["user"]]
        for group in identity["groups"]:
            result.extend(("--as-group", group))
        return result

    def _authorization_check(
        self,
        contract: AdmissionContract,
        actor_args: list[str],
        verb: str,
        target: dict[str, str],
    ) -> dict[str, Any]:
        args = [*actor_args, "auth", "can-i", verb, target["resource"]]
        if target["scope"] == "namespaced":
            args.extend(("--namespace", target["namespace"]))
        result = self._kubectl(contract, *args)
        evidence = {
            "verb": verb,
            "resource": target["resource"],
            "scope": target["scope"],
            "allowed": result.stdout.strip() == "yes",
            "responseSha256": _response_sha256(result),
        }
        self.evidence["ordinaryOwnerWriteMatrix"].append(evidence)
        if result.returncode != 1 or result.stdout.strip() != "no":
            raise ToolError("ordinary identity received an owner write permission")
        return evidence

    @staticmethod
    def _evidence_document(window_id: str) -> dict[str, Any]:
        return {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": authorization_tool.EVIDENCE_NAME,
                "namespace": NAMESPACE,
                "labels": {
                    "platform.aws.goodnotes.io/managed-by": "u0-admission-preflight",
                    "platform.aws.goodnotes.io/window-id": window_id,
                },
            },
            "data": {"test-only": "server-side-dry-run"},
        }

    @staticmethod
    def _replacement(request: str, fixture: dict[str, Any]) -> dict[str, Any]:
        metadata = fixture["metadata"]
        replacement = {
            "apiVersion": fixture["apiVersion"],
            "kind": fixture["kind"],
            "metadata": {
                "name": metadata["name"],
                "uid": metadata["uid"],
                "resourceVersion": metadata["resourceVersion"],
                "labels": copy.deepcopy(metadata["labels"]),
                "annotations": copy.deepcopy(metadata["annotations"]),
            },
            "spec": copy.deepcopy(fixture["spec"]),
        }
        lifecycle = replacement["spec"]["parameters"]["lifecycle"]
        if request in {"valid-transition", "stage-skip"}:
            lifecycle["evidenceRef"] = {
                "kind": "ConfigMap",
                "name": authorization_tool.EVIDENCE_NAME,
                "namespace": NAMESPACE,
            }
            lifecycle["retirementStage"] = (
                "DrainWorkloads"
                if request == "valid-transition"
                else "RemoveGitOps"
            )
        elif request == "unprotect":
            lifecycle["deletionProtection"] = False
        else:
            raise ToolError("unreviewed U0 admission replacement request")
        return replacement

    def _dry_run_case(
        self,
        contract: AdmissionContract,
        case: dict[str, Any],
        fixture: dict[str, Any],
    ) -> dict[str, Any]:
        actor_args = self._actor_args(contract.test_plan, case["actor"])
        if case["request"] == "evidence-create":
            result = self._kubectl(
                contract,
                *actor_args,
                "create",
                "-f",
                "-",
                "--dry-run=server",
                "-o",
                "json",
                input_text=json.dumps(
                    self._evidence_document(contract.authorization["windowId"])
                ),
            )
        else:
            result = self._kubectl(
                contract,
                *actor_args,
                "replace",
                "-f",
                "-",
                "--dry-run=server",
                "-o",
                "json",
                input_text=json.dumps(
                    self._replacement(case["request"], fixture)
                ),
            )
        allowed = result.returncode == 0
        combined = result.stdout + "\n" + result.stderr
        marker = case["expectedMarker"]
        evidence = {
            "id": case["id"],
            "actor": case["actor"],
            "request": case["request"],
            "expectedAllowed": case["expectedAllowed"],
            "observedAllowed": allowed,
            "enforcement": case["enforcement"],
            "expectedMarkerMatched": marker is None or marker in combined,
            "responseSha256": _response_sha256(result),
        }
        self.evidence["dryRunCases"].append(evidence)
        if allowed != case["expectedAllowed"] or not evidence["expectedMarkerMatched"]:
            raise ToolError("U0 admission outcome differs from the reviewed expectation")
        if allowed:
            try:
                response = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise ToolError("successful admission dry-run returned invalid JSON") from error
            expected_name = (
                authorization_tool.EVIDENCE_NAME
                if case["request"] == "evidence-create"
                else authorization_tool.FIXTURE_NAME
            )
            if response.get("metadata", {}).get("name") != expected_name:
                raise ToolError("admission dry-run response identity differs")
        self._assert_fixture_unchanged(contract)
        return evidence

    def run_tests(self, contract: AdmissionContract) -> dict[str, Any]:
        authorization_tool.verify_claim(contract.authorization_path)
        matrix = contract.test_plan["ordinaryOwnerWriteMatrix"]
        ordinary_args = self._actor_args(contract.test_plan, "ordinary")
        for target in matrix["targets"]:
            for verb in matrix["verbs"]:
                self._authorization_check(
                    contract, ordinary_args, verb, target
                )
        fixture = self._assert_fixture_unchanged(contract)
        for case in contract.test_plan["dryRunCases"]:
            authorization_tool.verify_claim(contract.authorization_path)
            self._dry_run_case(contract, case, fixture)
        if self._optional(
            contract,
            "configmap",
            authorization_tool.EVIDENCE_NAME,
            "--namespace",
            NAMESPACE,
        ) is not None:
            raise ToolError("server-side dry-run evidence unexpectedly persisted")
        self._assert_controllers_stopped(contract)
        self._assert_resource_inventory(contract, allow_fixture=True)
        if len(self.evidence["ordinaryOwnerWriteMatrix"]) != (
            len(matrix["targets"]) * len(matrix["verbs"])
        ) or len(self.evidence["dryRunCases"]) != len(
            contract.test_plan["dryRunCases"]
        ):
            raise ToolError("U0 admission evidence inventory is incomplete")
        return {
            "ordinaryOwnerWriteMatrix": list(
                self.evidence["ordinaryOwnerWriteMatrix"]
            ),
            "dryRunCases": list(self.evidence["dryRunCases"]),
        }

    def _delete_owned(
        self,
        contract: AdmissionContract,
        resource: str,
        name: str,
        *,
        require_paused: bool = False,
    ) -> bool:
        item = self._optional(contract, resource, name)
        if item is None:
            return False
        metadata = item.get("metadata", {})
        if metadata.get("labels") != self._owned_labels(
            contract.authorization["windowId"]
        ) or (
            require_paused
            and metadata.get("annotations", {}).get("crossplane.io/paused") != "true"
        ):
            raise ToolError("refusing to delete an object not owned by this U0 window")
        result = self._kubectl(
            contract,
            "delete",
            resource,
            name,
            "--wait=true",
            "--timeout=30s",
            "-o",
            "name",
        )
        if result.returncode:
            raise ToolError("temporary U0 admission cleanup failed; output suppressed")
        if self._optional(contract, resource, name) is not None:
            raise ToolError("temporary U0 admission object remains after deletion")
        return True

    def cleanup(self, contract: AdmissionContract) -> dict[str, Any]:
        deleted = 0
        deleted += self._delete_owned(
            contract,
            "clusterrolebinding",
            authorization_tool.TEMPORARY_ROLE_NAME,
        )
        deleted += self._delete_owned(
            contract, "clusterrole", authorization_tool.TEMPORARY_ROLE_NAME
        )
        deleted += self._delete_owned(
            contract,
            "xeksenvironment.platform.aws.goodnotes.io",
            authorization_tool.FIXTURE_NAME,
            require_paused=True,
        )
        baseline = self.baseline(contract)
        return {
            "temporaryResourcesDeleted": deleted,
            "baselineRestored": True,
            "controllersStopped": baseline["controllersStopped"],
            "managementSessionSecretAccessed": False,
            "awsManagedResources": baseline["awsManagedResources"],
            "nonAwsManagedResources": baseline["nonAwsManagedResources"],
        }


def execute(
    contract: AdmissionContract,
    acknowledgement: str,
    *,
    operations: RealOperations | None = None,
) -> dict[str, Any]:
    if acknowledgement != RUN_ACKNOWLEDGEMENT:
        raise ToolError("explicit U0 admission execution acknowledgement required")
    contract = load_contract(contract.authorization_path, require_approved=True)
    claim = authorization_tool.claim_authorization(
        contract.authorization_path,
        authorization_tool.CLAIM_ACKNOWLEDGEMENT,
    )
    journal = Journal.create(contract.authorization["windowId"])
    journal.append("CLAIMED")
    ops = operations or RealOperations()
    setup_attempted = False
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None
    baseline: dict[str, Any] = {}
    setup: dict[str, Any] = {}
    tests: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}
    try:
        authorization_tool.verify_claim(contract.authorization_path)
        baseline = ops.baseline(contract)
        journal.append("BASELINE_VERIFIED")
        setup_attempted = True
        journal.append("SETUP_STARTED")
        setup = ops.setup(contract, progress=journal.append)
        journal.append("TESTS_STARTED")
        tests = ops.run_tests(contract)
        journal.append("TESTS_VERIFIED")
    except BaseException as error:
        failure = error
    finally:
        if setup_attempted:
            try:
                journal.append("CLEANUP_STARTED")
                cleanup = ops.cleanup(contract)
                journal.append(
                    "FAILED_CLEANUP_COMPLETE" if failure else "CLEANUP_COMPLETE"
                )
            except BaseException as error:
                cleanup_failure = error
                try:
                    journal.append("RECOVERY_REQUIRED")
                except BaseException:
                    pass
    evidence = tests or getattr(ops, "evidence", {})
    report = {
        "schemaVersion": 1,
        "status": (
            "U0_ADMISSION_PREFLIGHT_PASS"
            if failure is None and cleanup_failure is None
            else "U0_ADMISSION_PREFLIGHT_FAILED_CLOSED"
        ),
        "bundle": contract.authorization["bundle"],
        "windowId": contract.authorization["windowId"],
        "recordedAt": datetime.now(timezone.utc).isoformat(),
        "reviewedGitCommit": claim["reviewedGitCommit"],
        "executionCodeSha256": claim["executionCodeSha256"],
        "baseline": baseline,
        "fixture": {
            "name": authorization_tool.FIXTURE_NAME,
            "uid": setup.get("fixtureUid", ""),
            "paused": True,
        },
        "evidence": evidence,
        "cleanup": cleanup,
        "awsApiCalls": False,
        "awsResourceMutation": False,
        "stsSessionIssued": False,
        "managementSessionSecretAccessed": False,
        "controllersStarted": False,
    }
    result_path = _write_result(contract.authorization["windowId"], report)
    if cleanup_failure is not None:
        raise ToolError(
            "U0 admission cleanup failed; run the reviewed recovery-only entry"
        ) from cleanup_failure
    if failure is not None:
        if setup_attempted:
            raise ToolError(
                "U0 admission test failed closed and bounded cleanup completed"
            ) from failure
        raise ToolError(
            "U0 admission baseline failed before mutation; claim remains consumed"
        ) from failure
    matrix_count = len(evidence.get("ordinaryOwnerWriteMatrix", []))
    dry_run_count = len(evidence.get("dryRunCases", []))
    if (
        matrix_count
        != len(authorization_tool.OWNER_WRITE_TARGETS)
        * len(authorization_tool.WRITE_VERBS)
        or dry_run_count
        != len(
            authorization_tool.expected_test_plan(
                contract.authorization["windowId"]
            )["dryRunCases"]
        )
        or cleanup.get("baselineRestored") is not True
    ):
        raise ToolError("U0 admission result is incomplete")
    return {
        "status": "U0_ADMISSION_PREFLIGHT_PASS",
        "windowId": contract.authorization["windowId"],
        "ordinaryAuthorizationChecks": matrix_count,
        "dryRunAdmissionChecks": dry_run_count,
        "temporaryResourcesDeleted": cleanup["temporaryResourcesDeleted"],
        "baselineRestored": True,
        "controllersStopped": 14,
        "managementSessionSecretUntouched": True,
        "awsApiCalls": False,
        "awsResourceMutation": False,
        "resultPath": str(result_path),
    }


def recover(
    contract: AdmissionContract,
    acknowledgement: str,
    *,
    operations: RealOperations | None = None,
) -> dict[str, Any]:
    if acknowledgement != RECOVER_ACKNOWLEDGEMENT:
        raise ToolError("explicit U0 admission recovery acknowledgement required")
    authorization_tool.verify_claim(
        contract.authorization_path,
        require_active=False,
    )
    journal = Journal.existing(contract.authorization["windowId"])
    if journal is not None:
        journal.append("RECOVERY_STARTED")
    result = (operations or RealOperations()).cleanup(contract)
    if journal is not None:
        journal.append("RECOVERY_COMPLETE")
    return {
        "status": "U0_ADMISSION_RECOVERY_COMPLETE",
        "windowId": contract.authorization["windowId"],
        "baselineRestored": result["baselineRestored"],
        "controllersStopped": result["controllersStopped"],
        "managementSessionSecretUntouched": True,
        "awsApiCalls": False,
        "awsResourceMutation": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run", "recover"))
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--acknowledge", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.mode == "plan":
            if args.acknowledge:
                raise ToolError("plan does not accept an acknowledgement")
            contract = load_contract(args.authorization, require_approved=False)
            result = public_plan(contract)
        elif args.mode == "run":
            contract = load_contract(args.authorization, require_approved=True)
            result = execute(contract, args.acknowledge)
        else:
            contract = load_contract(
                args.authorization,
                require_approved=True,
                allow_stale_approved=True,
            )
            result = recover(contract, args.acknowledge)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print(
            "U0 admission command interrupted; use the reviewed recovery-only entry",
            file=sys.stderr,
        )
        return 130
    except (ToolError, OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "U0 admission command failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
