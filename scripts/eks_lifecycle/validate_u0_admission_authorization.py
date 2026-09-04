#!/usr/bin/env python3
"""Validate one private, single-use U0 admission-test authorization pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from common import ToolError, find_placeholders, load_yaml
import validate_u0_authorization as u0_authorization


SCHEMA_VERSION = 1
AUTHORIZATION_TYPE = "u0-admission-negative-test-window"
PENDING_STATUS = "PENDING_OPERATOR_APPROVAL"
APPROVED_STATUS = "APPROVED_FOR_ONE_U0_ADMISSION_WINDOW"
MAX_WINDOW_SECONDS = 900
APPROVAL_MAX_AGE_SECONDS = 86400
CLAIM_SCHEMA_VERSION = 1
CLAIM_STATUS = "CLAIMED_FOR_U0_ADMISSION_EXECUTION"
CLAIM_ACKNOWLEDGEMENT = "I-CLAIM-ONE-U0-ADMISSION-PREFLIGHT-WINDOW"
CLAIM_ROOT = Path.home() / ".local/share/eks-platform/u0-admission-authorizations"

BUNDLE_RE = re.compile(
    r"^u0-admission-(20[0-9]{2})-([0-9]{2})-([0-9]{2})-([0-9]{2})$"
)
WINDOW_RE = re.compile(r"^u0a-20[0-9]{6}-[0-9]{2}$")
CHECKSUM_RE = u0_authorization.CHECKSUM_RE

CONTEXT = "kind-kube-nebula-a"
FIXTURE_NAME = "u0-admission-probe"
EVIDENCE_NAME = "u0-admission-evidence-probe"
TEMPORARY_ROLE_NAME = "u0-admission-probe-editor"
ORDINARY_USER = "u0-ordinary.platform.aws.goodnotes.io"
DELEGATED_EDITOR_USER = "u0-delegated-editor.platform.aws.goodnotes.io"
APPROVER_USER = "u0-lifecycle-approver.platform.aws.goodnotes.io"
APPROVER_GROUP = "platform-eks-lifecycle-approvers"

REQUIRED_FILES = {
    "REVIEW_SUMMARY.md",
    "authorization-contract.json",
    "admission-test-plan.json",
    "environment-fixture.yaml",
    "temporary-rbac.yaml",
}

PREPARATION_EVIDENCE = {
    "awsApiCalls": False,
    "awsResourceMutation": False,
    "kubernetesApiCalls": False,
    "kubernetesMutation": False,
    "sessionIssued": False,
    "controllersStarted": False,
}

ALLOWED_ACTIONS = (
    "read the reviewed management-cluster admission, RBAC, controller, XR, and managed-resource baseline without accessing Secrets",
    "persist exactly one paused XEKSEnvironment fixture named u0-admission-probe while all reviewed controllers remain stopped",
    "persist one exact resourceName-scoped temporary ClusterRole and ClusterRoleBinding for the synthetic delegated editor",
    "impersonate only the three reviewed synthetic users and the reviewed lifecycle approver group",
    "submit the exact reviewed SubjectAccessReview-equivalent can-i checks and server-side dry-run admission requests",
    "write an owner-only result containing outcomes, matched public policy messages, and response hashes but no credentials",
    "delete the temporary binding, role, and paused fixture, then prove the pre-window baseline is restored",
)

FORBIDDEN_ACTIONS = (
    "call any AWS API or issue any STS session",
    "publish, read, modify, or delete the management-session Secret",
    "start or otherwise modify any Crossplane, Function, or Provider controller",
    "create any AWS managed resource or any lifecycle XR other than the exact paused u0-admission-probe fixture",
    "modify permanent RBAC, admission policies, XRDs, Compositions, Providers, Functions, catalogs, shared XRs, or existing managed Objects",
    "persist lifecycle evidence or use any real human, workload, or controller identity as a test subject",
    "advance to U1 or interpret this window as AWS create, update, delete, disruption, upgrade, or retirement authorization",
    "retry a claimed window or use the normal run path for cleanup after an interruption",
    "push commits, create a pull request, or publish private bundle or result data",
)

DECISION_KEYS = {
    "U006AdmissionNegativeTests",
    "TemporaryPausedFixture",
    "TemporaryResourceNameScopedRbac",
    "SyntheticImpersonationOnly",
    "NoAwsSessionOrControllerStart",
    "CleanupOnlyRecovery",
}

OWNER_WRITE_TARGETS: tuple[dict[str, str], ...] = (
    {"resource": "xnetworks.platform.aws.goodnotes.io", "scope": "cluster"},
    {"resource": "xeksclusters.platform.aws.goodnotes.io", "scope": "cluster"},
    {
        "resource": "xclusterfoundations.platform.aws.goodnotes.io",
        "scope": "cluster",
    },
    {
        "resource": "xeksenvironments.platform.aws.goodnotes.io",
        "scope": "cluster",
    },
    {
        "resource": "compositeresourcedefinitions.apiextensions.crossplane.io",
        "scope": "cluster",
    },
    {
        "resource": "compositions.apiextensions.crossplane.io",
        "scope": "cluster",
    },
    {
        "resource": "environmentconfigs.apiextensions.crossplane.io",
        "scope": "cluster",
    },
    {"resource": "providers.pkg.crossplane.io", "scope": "cluster"},
    {"resource": "functions.pkg.crossplane.io", "scope": "cluster"},
    {
        "resource": "deploymentruntimeconfigs.pkg.crossplane.io",
        "scope": "cluster",
    },
    {
        "resource": "validatingadmissionpolicies.admissionregistration.k8s.io",
        "scope": "cluster",
    },
    {
        "resource": "clusterroles.rbac.authorization.k8s.io",
        "scope": "cluster",
    },
    {
        "resource": "configmaps",
        "scope": "namespaced",
        "namespace": "crossplane-system",
    },
)

WRITE_VERBS = ("create", "update", "patch", "delete")


def expected_test_plan(window_id: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "windowId": window_id,
        "context": CONTEXT,
        "fixture": {
            "resource": "xeksenvironments.platform.aws.goodnotes.io",
            "name": FIXTURE_NAME,
            "paused": True,
        },
        "actors": {
            "ordinary": {
                "user": ORDINARY_USER,
                "groups": ["system:authenticated"],
            },
            "delegatedEditor": {
                "user": DELEGATED_EDITOR_USER,
                "groups": ["system:authenticated"],
            },
            "approver": {
                "user": APPROVER_USER,
                "groups": ["system:authenticated", APPROVER_GROUP],
            },
        },
        "ordinaryOwnerWriteMatrix": {
            "verbs": list(WRITE_VERBS),
            "targets": [dict(item) for item in OWNER_WRITE_TARGETS],
            "expectedAllowed": False,
        },
        "dryRunCases": [
            {
                "id": "ordinary-valid-transition-rbac-deny",
                "actor": "ordinary",
                "request": "valid-transition",
                "expectedAllowed": False,
                "expectedMarker": 'cannot patch resource "xeksenvironments"',
                "enforcement": "RBAC",
            },
            {
                "id": "ordinary-stage-skip-rbac-deny",
                "actor": "ordinary",
                "request": "stage-skip",
                "expectedAllowed": False,
                "expectedMarker": 'cannot patch resource "xeksenvironments"',
                "enforcement": "RBAC",
            },
            {
                "id": "ordinary-unprotect-rbac-deny",
                "actor": "ordinary",
                "request": "unprotect",
                "expectedAllowed": False,
                "expectedMarker": 'cannot patch resource "xeksenvironments"',
                "enforcement": "RBAC",
            },
            {
                "id": "delegated-valid-transition-policy-deny",
                "actor": "delegatedEditor",
                "request": "valid-transition",
                "expectedAllowed": False,
                "expectedMarker": "lifecycle changes require the platform-eks-lifecycle-approvers group",
                "enforcement": "ValidatingAdmissionPolicy",
            },
            {
                "id": "approver-valid-transition-allow",
                "actor": "approver",
                "request": "valid-transition",
                "expectedAllowed": True,
                "expectedMarker": None,
                "enforcement": "ValidatingAdmissionPolicy",
            },
            {
                "id": "approver-stage-skip-schema-deny",
                "actor": "approver",
                "request": "stage-skip",
                "expectedAllowed": False,
                "expectedMarker": "advance retirement exactly one stage at a time",
                "enforcement": "XRD-CEL",
            },
            {
                "id": "approver-unprotect-schema-deny",
                "actor": "approver",
                "request": "unprotect",
                "expectedAllowed": False,
                "expectedMarker": "deletionProtection may be disabled only at DeleteReady",
                "enforcement": "XRD-CEL",
            },
            {
                "id": "ordinary-evidence-create-rbac-deny",
                "actor": "ordinary",
                "request": "evidence-create",
                "expectedAllowed": False,
                "expectedMarker": 'cannot create resource "configmaps"',
                "enforcement": "RBAC",
            },
            {
                "id": "approver-evidence-create-allow",
                "actor": "approver",
                "request": "evidence-create",
                "expectedAllowed": True,
                "expectedMarker": None,
                "enforcement": "RBAC",
            },
        ],
    }


def expected_temporary_rbac(window_id: str) -> dict[str, Any]:
    labels = {
        "platform.aws.goodnotes.io/managed-by": "u0-admission-preflight",
        "platform.aws.goodnotes.io/window-id": window_id,
    }
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {"name": TEMPORARY_ROLE_NAME, "labels": labels},
                "rules": [
                    {
                        "apiGroups": ["platform.aws.goodnotes.io"],
                        "resources": ["xeksenvironments"],
                        "resourceNames": [FIXTURE_NAME],
                        "verbs": ["get", "patch", "update"],
                    }
                ],
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {"name": TEMPORARY_ROLE_NAME, "labels": labels},
                "subjects": [
                    {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "User",
                        "name": DELEGATED_EDITOR_USER,
                    }
                ],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": TEMPORARY_ROLE_NAME,
                },
            },
        ],
    }


def requested_window() -> dict[str, Any]:
    return {
        "purpose": "Complete U0-06 management-plane admission negative tests only",
        "context": CONTEXT,
        "maximumWindowSeconds": MAX_WINDOW_SECONDS,
        "awsApiCallsAllowed": False,
        "awsResourceMutationAllowed": False,
        "stsSessionIssuanceAllowed": False,
        "managementSessionSecretAccessAllowed": False,
        "controllerMutationAllowed": False,
        "kubernetesMutationAllowed": True,
        "temporaryResources": [
            f"xeksenvironments.platform.aws.goodnotes.io/{FIXTURE_NAME}",
            f"clusterroles.rbac.authorization.k8s.io/{TEMPORARY_ROLE_NAME}",
            f"clusterrolebindings.rbac.authorization.k8s.io/{TEMPORARY_ROLE_NAME}",
        ],
        "allowed": list(ALLOWED_ACTIONS),
        "forbidden": list(FORBIDDEN_ACTIONS),
    }


def _claim_path(root: Path, window_id: str) -> Path:
    if not WINDOW_RE.fullmatch(window_id):
        raise ToolError("U0 admission windowId is invalid")
    return root / f"{window_id}.json"


def _window_for_bundle(bundle: str) -> str:
    match = BUNDLE_RE.fullmatch(bundle)
    if match is None:
        raise ToolError("U0 admission bundle identity is invalid")
    return f"u0a-{''.join(match.groups()[:3])}-{match.group(4)}"


def verify_checksums(directory: Path) -> int:
    if {entry.name for entry in directory.iterdir()} != REQUIRED_FILES | {"SHA256SUMS"}:
        raise ToolError("U0 admission bundle contains an unreviewed file")
    try:
        lines = u0_authorization._read_private(directory / "SHA256SUMS").decode(
            "ascii"
        ).splitlines()
    except UnicodeDecodeError as error:
        raise ToolError("U0 admission checksum manifest must be ASCII") from error
    checksums: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_RE.fullmatch(line)
        if match is None or match.group(2) in checksums:
            raise ToolError("U0 admission checksum manifest is malformed or duplicated")
        checksums[match.group(2)] = match.group(1)
    if set(checksums) != REQUIRED_FILES:
        raise ToolError("U0 admission checksum inventory differs")
    for name, expected in checksums.items():
        actual = hashlib.sha256(
            u0_authorization._read_private(directory / name)
        ).hexdigest()
        if actual != expected:
            raise ToolError("U0 admission bundle checksum differs; re-review is required")
    return len(checksums)


def _validate_fixture(directory: Path, window_id: str) -> None:
    document = load_yaml(directory / "environment-fixture.yaml")
    if find_placeholders(document):
        raise ToolError("U0 admission fixture contains a placeholder")
    expected_labels = {
        "platform.aws.goodnotes.io/managed-by": "u0-admission-preflight",
        "platform.aws.goodnotes.io/window-id": window_id,
    }
    metadata = document.get("metadata", {})
    lifecycle = document.get("spec", {}).get("parameters", {}).get("lifecycle", {})
    if (
        document.get("apiVersion") != "platform.aws.goodnotes.io/v1alpha1"
        or document.get("kind") != "XEKSEnvironment"
        or metadata.get("name") != FIXTURE_NAME
        or metadata.get("labels") != expected_labels
        or metadata.get("annotations") != {"crossplane.io/paused": "true"}
        or "status" in document
        or lifecycle
        != {"retirementStage": "Active", "deletionProtection": True}
        or document.get("spec", {}).get("crossplane", {}).get(
            "compositionUpdatePolicy"
        )
        != "Manual"
    ):
        raise ToolError("U0 admission fixture differs from the fail-closed contract")


def _validate_bundle_inputs(directory: Path, window_id: str) -> None:
    _validate_fixture(directory, window_id)
    try:
        plan = json.loads(
            u0_authorization._read_private(directory / "admission-test-plan.json")
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid U0 admission test plan; output suppressed") from error
    if plan != expected_test_plan(window_id):
        raise ToolError("U0 admission test plan differs from the executable contract")
    rbac = load_yaml(directory / "temporary-rbac.yaml")
    if rbac != expected_temporary_rbac(window_id):
        raise ToolError("temporary admission-test RBAC differs from the executable contract")


def validate_authorization(
    path: Path,
    require_approved: bool,
    *,
    allow_stale_approved: bool = False,
) -> dict[str, Any]:
    path = Path(os.path.abspath(path.expanduser()))
    if path.name != "authorization-contract.json":
        raise ToolError("explicit U0 admission authorization-contract.json path required")
    try:
        payload = u0_authorization._read_private(path)
        document = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid private U0 admission JSON; output suppressed") from error
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
        "preparationEvidence",
        "requestedWindow",
        "decisions",
        "executionCode",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ToolError("U0 admission authorization fields differ from the schema")
    authorization_digest = hashlib.sha256(payload).hexdigest()
    if document.get("schemaVersion") != SCHEMA_VERSION:
        raise ToolError("unsupported U0 admission authorization schema")
    bundle = document.get("bundle")
    if (
        not isinstance(bundle, str)
        or not BUNDLE_RE.fullmatch(bundle)
        or path.parent.name != bundle
    ):
        raise ToolError("U0 admission bundle identity differs from its directory")
    window_id = document.get("windowId")
    if not isinstance(window_id, str) or not WINDOW_RE.fullmatch(window_id):
        raise ToolError("U0 admission windowId is invalid")
    if window_id != _window_for_bundle(bundle):
        raise ToolError("U0 admission bundle and window identities differ")
    if document.get("singleUse") is not True:
        raise ToolError("U0 admission authorization must be single-use")
    generated_at = u0_authorization._timestamp(document.get("generatedAt"), "generatedAt")
    if (
        document.get("authorizationType") != AUTHORIZATION_TYPE
        or document.get("preparationEvidence") != PREPARATION_EVIDENCE
        or document.get("requestedWindow") != requested_window()
    ):
        raise ToolError("U0 admission authorization boundary differs")
    actual_execution_code = u0_authorization.execution_code_state()
    if document.get("executionCode") != actual_execution_code:
        raise ToolError("U0 admission execution code differs from the reviewed checkout")
    decisions = document.get("decisions")
    if not isinstance(decisions, dict) or set(decisions) != DECISION_KEYS:
        raise ToolError("U0 admission decision inventory differs")
    status = document.get("reviewStatus")
    approved = status == APPROVED_STATUS
    if status == PENDING_STATUS:
        if document.get("approvedBy") is not None or document.get("approvedAt") is not None:
            raise ToolError("pending U0 admission authorization cannot name an approval")
        if any(value is not None for value in decisions.values()):
            raise ToolError("pending U0 admission decisions must remain unset")
    elif approved:
        reviewer = document.get("approvedBy")
        if (
            not isinstance(reviewer, str)
            or not reviewer.strip()
            or any(marker in reviewer for marker in ("__REPLACE", "<", ">", "\n", "\r"))
        ):
            raise ToolError("approved U0 admission authorization must name the reviewer")
        approved_at = u0_authorization._timestamp(document.get("approvedAt"), "approvedAt")
        age = (datetime.now(timezone.utc) - approved_at).total_seconds()
        if approved_at < generated_at or (
            not allow_stale_approved and age > APPROVAL_MAX_AGE_SECONDS
        ):
            raise ToolError("U0 admission approval must be fresh and after generation")
        if any(value is not True for value in decisions.values()):
            raise ToolError("every U0 admission decision must be explicitly accepted")
    else:
        raise ToolError("U0 admission reviewStatus is not pending or approved")
    if require_approved and not approved:
        raise ToolError("U0 admission window is not approved")
    checksums = verify_checksums(path.parent)
    _validate_bundle_inputs(path.parent, window_id)
    if hashlib.sha256(u0_authorization._read_private(path)).hexdigest() != authorization_digest:
        raise ToolError("U0 admission authorization changed during validation")
    return {
        "bundle": bundle,
        "windowId": window_id,
        "reviewStatus": status,
        "approved": approved,
        "singleUse": True,
        "maximumWindowSeconds": MAX_WINDOW_SECONDS,
        "awsApiCallsAllowed": False,
        "stsSessionIssuanceAllowed": False,
        "controllerMutationAllowed": False,
        "temporaryKubernetesResources": 3,
        "ordinaryAuthorizationChecks": len(OWNER_WRITE_TARGETS) * len(WRITE_VERBS),
        "dryRunAdmissionChecks": len(expected_test_plan(window_id)["dryRunCases"]),
        "checksumsVerified": checksums,
        "reviewedGitCommit": actual_execution_code["gitCommit"],
        "executionCodeSha256": actual_execution_code["aggregateSha256"],
        "executionCodeFiles": actual_execution_code["trackedNonMarkdownFiles"],
        "markdownDriftExcluded": actual_execution_code["markdownDriftExcluded"],
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
        "mutationPerformed": False,
        "_authorizationSha256": authorization_digest,
    }


def claim_authorization(
    path: Path,
    acknowledgement: str,
    *,
    claim_root: Path = CLAIM_ROOT,
    now: datetime | None = None,
) -> dict[str, Any]:
    if acknowledgement != CLAIM_ACKNOWLEDGEMENT:
        raise ToolError("explicit single-use U0 admission claim acknowledgement required")
    authorization = validate_authorization(path, require_approved=True)
    authorization_digest = authorization.pop("_authorizationSha256")
    wall_clock = datetime.now(timezone.utc)
    claimed_at = now or wall_clock
    if claimed_at.tzinfo is None or abs((wall_clock - claimed_at).total_seconds()) > 1:
        raise ToolError("U0 admission claim time must be current and timezone-qualified")
    deadline = claimed_at + timedelta(seconds=MAX_WINDOW_SECONDS)
    root = u0_authorization._claim_root(claim_root, create=True)
    receipt_path = _claim_path(root, authorization["windowId"])
    receipt = {
        "claimSchemaVersion": CLAIM_SCHEMA_VERSION,
        "status": CLAIM_STATUS,
        "bundle": authorization["bundle"],
        "windowId": authorization["windowId"],
        "authorizationSha256": authorization_digest,
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
    authorization_digest = authorization.pop("_authorizationSha256")
    root = u0_authorization._claim_root(claim_root, create=False)
    receipt_path = _claim_path(root, authorization["windowId"])
    try:
        receipt = json.loads(u0_authorization._read_private(receipt_path))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid U0 admission claim receipt; output suppressed") from error
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
    if not isinstance(receipt, dict) or set(receipt) != expected_keys:
        raise ToolError("U0 admission claim receipt fields differ")
    if (
        receipt.get("claimSchemaVersion") != CLAIM_SCHEMA_VERSION
        or receipt.get("status") != CLAIM_STATUS
        or receipt.get("bundle") != authorization["bundle"]
        or receipt.get("windowId") != authorization["windowId"]
        or receipt.get("authorizationSha256") != authorization_digest
        or receipt.get("executionGitCommit") != authorization["reviewedGitCommit"]
        or receipt.get("executionCodeSha256") != authorization["executionCodeSha256"]
    ):
        raise ToolError("U0 admission claim does not match the authorization")
    claimed_at = u0_authorization._timestamp(receipt.get("claimedAt"), "claimedAt")
    deadline = u0_authorization._timestamp(
        receipt.get("deadline"), "deadline", allow_future=True
    )
    if deadline != claimed_at + timedelta(seconds=MAX_WINDOW_SECONDS):
        raise ToolError("U0 admission claim deadline differs from the reviewed window")
    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None or checked_at < claimed_at:
        raise ToolError("U0 admission claim verification time is invalid")
    if require_active and checked_at >= deadline:
        raise ToolError("U0 admission claim expired; only recovery is allowed")
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
    args = parser.parse_args(argv or sys.argv[1:])
    try:
        if args.mode == "claim":
            result = claim_authorization(args.authorization, args.acknowledge)
        elif args.mode == "verify-claim":
            if args.acknowledge:
                raise ToolError("verify-claim does not accept an acknowledgement")
            result = verify_claim(args.authorization)
        else:
            if args.acknowledge:
                raise ToolError(f"{args.mode} does not accept an acknowledgement")
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
    except (ToolError, OSError, ValueError, KeyError, TypeError):
        print(
            "U0 admission authorization validation failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
