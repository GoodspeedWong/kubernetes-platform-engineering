#!/usr/bin/env python3
"""Validate one private, single-use U0 management-preflight authorization pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import ToolError, find_placeholders, load_yaml


SCHEMA_VERSION = 2
AUTHORIZATION_TYPE = "u0-management-preflight-window"
PENDING_STATUS = "PENDING_OPERATOR_APPROVAL"
APPROVED_STATUS = "APPROVED_FOR_ONE_U0_WINDOW"
MAX_SESSION_SECONDS = 3600
APPROVAL_MAX_AGE_SECONDS = 86400
BUNDLE_RE = re.compile(r"^u0-preflight-[0-9]{4}-[0-9]{2}-[0-9]{2}$")
WINDOW_RE = re.compile(r"^u0-[0-9]{8}-[0-9]{2}$")
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")

REQUIRED_FILES = {
    "REVIEW_SUMMARY.md",
    "authorization-contract.json",
    "aws-readonly-snapshot.json",
    "environment.candidate.yaml",
    "node-image.candidate.yaml",
    "platform-release.candidate.yaml",
    "u0-inputs.json",
}

DECISION_KEYS = {
    "A01AccountPurposeBillingAndOwners",
    "A02RootMfaRecovery",
    "A06HumanAdminPrincipal",
    "A08PolicyVersusRuntimePhaseSplit",
    "A13NetworkCidrsAndExternalConflict",
    "A14DynamicPublicEgressResponsibility",
    "A16ExplicitEbsEncryptionUsingAwsManagedKey",
    "A17SevenDaySeventyUsdSoftBudget",
    "A18EventHistoryForFirstUat",
    "A19BusinessGitBootstrapDisabled",
    "U0ManagementPreflightWindow",
}

PREPARATION_EVIDENCE = {
    "awsResourceMutation": False,
    "kubernetesMutation": False,
    "sessionIssued": False,
    "controllersStarted": False,
}

KUBERNETES_MUTATION_SCOPE = (
    "pause and later restore exactly three reviewed shared XRs and 73 owned Objects",
    "create or replace, then scrub and delete crossplane-system/eks-platform-aws-session",
    "apply only reviewed management definitions, dependencies, explicit RBAC, and the two approved catalogs",
    "patch only the 14 reviewed controller Deployments for bounded startup and final zero-replica restore",
    "submit server-side dry-run admission requests that persist no objects",
)

ALLOWED_ACTIONS = (
    "protect and later restore the existing shared management-plane objects",
    "publish the already reviewed on-demand session Secret for at most 60 minutes",
    "apply only the reviewed management definitions, dependencies, explicit RBAC, and approved platform/node catalogs",
    "start only the locked Crossplane, Function, and reviewed Provider controllers",
    "perform server-side dry-run admission checks without persisting test resources",
    "perform STS AssumeRole and read-only AWS/Kubernetes checks",
    "verify actual Provider Pod egress and online preflight",
    "scrub and delete the session Secret and restore all 14 controller Deployments to zero replicas",
)

FORBIDDEN_ACTIONS = (
    "create, update, or delete any AWS resource",
    "apply environment.candidate.yaml or create any persistent XR or managed resource",
    "advance to U1",
    "change IAM, EBS default encryption, CloudTrail, Budget, or Git credentials",
    "print, log, export, or retain credential Secret values outside the approved in-memory verifier",
    "push commits, create a pull request, or publish private bundle data",
)

CREDENTIAL_HANDLING = {
    "publishOwnedSessionSecret": True,
    "hostVerifierMayReadOwnedSecretValuesInMemory": True,
    "printCredentialValues": False,
    "persistCredentialValuesOutsideOwnedSecret": False,
    "automaticRenewal": False,
}


def _read_private(path: Path, maximum_size: int = 2 * 1024 * 1024) -> bytes:
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise ToolError("U0 bundle directory must be owner-only")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ToolError("U0 bundle file is missing or unsafe") from error
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > maximum_size
        ):
            raise ToolError("U0 bundle files must be owner-only regular files")
        return stream.read(maximum_size + 1)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_read_private(path))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid private U0 JSON; output suppressed") from error
    if not isinstance(value, dict):
        raise ToolError("private U0 JSON must be an object")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ToolError(f"{label} must be timezone-qualified")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ToolError(f"{label} must be timezone-qualified") from error
    if parsed.tzinfo is None or parsed > datetime.now(timezone.utc):
        raise ToolError(f"{label} must be a non-future timezone-qualified time")
    return parsed


def verify_checksums(directory: Path) -> int:
    if {entry.name for entry in directory.iterdir()} != REQUIRED_FILES | {"SHA256SUMS"}:
        raise ToolError("U0 bundle contains an unreviewed file")
    try:
        lines = _read_private(directory / "SHA256SUMS").decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ToolError("U0 checksum manifest must be ASCII") from error
    checksums: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_RE.fullmatch(line)
        if match is None or match.group(2) in checksums:
            raise ToolError("U0 checksum manifest is malformed or duplicated")
        checksums[match.group(2)] = match.group(1)
    if set(checksums) != REQUIRED_FILES:
        raise ToolError("U0 checksum manifest file inventory differs")
    for name, expected in checksums.items():
        actual = hashlib.sha256(_read_private(directory / name)).hexdigest()
        if actual != expected:
            raise ToolError("U0 bundle checksum differs; re-review is required")
    return len(checksums)


def _validate_candidate_inputs(directory: Path) -> None:
    for name in (
        "environment.candidate.yaml",
        "platform-release.candidate.yaml",
        "node-image.candidate.yaml",
    ):
        document = load_yaml(directory / name)
        if find_placeholders(document):
            raise ToolError("U0 candidate contains a test placeholder")
    for name in ("u0-inputs.json", "aws-readonly-snapshot.json"):
        if find_placeholders(_load_json(directory / name)):
            raise ToolError("U0 private input contains a test placeholder")


def validate_authorization(path: Path, require_approved: bool) -> dict[str, Any]:
    path = Path(os.path.abspath(path.expanduser()))
    if path.name != "authorization-contract.json":
        raise ToolError("explicit authorization-contract.json path required")
    document = _load_json(path)
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
        "notAManagementSessionReview",
        "requiresSeparateApprovedManagementSessionReview",
        "preparationEvidence",
        "requestedU0Window",
        "decisions",
    }
    if set(document) != expected_keys:
        raise ToolError("U0 authorization fields differ from the reviewed schema")
    if document["schemaVersion"] != SCHEMA_VERSION:
        raise ToolError("unsupported U0 authorization schema")
    bundle = document.get("bundle")
    if not isinstance(bundle, str) or not BUNDLE_RE.fullmatch(bundle) or path.parent.name != bundle:
        raise ToolError("U0 bundle identity differs from its private directory")
    if not isinstance(document.get("windowId"), str) or not WINDOW_RE.fullmatch(document["windowId"]):
        raise ToolError("U0 windowId is invalid")
    if document.get("singleUse") is not True:
        raise ToolError("U0 authorization must be single-use")
    generated_at = _timestamp(document.get("generatedAt"), "generatedAt")
    if (
        document.get("authorizationType") != AUTHORIZATION_TYPE
        or document.get("notAManagementSessionReview") is not True
        or document.get("requiresSeparateApprovedManagementSessionReview") is not True
        or document.get("preparationEvidence") != PREPARATION_EVIDENCE
    ):
        raise ToolError("U0 authorization boundary differs from the reviewed contract")

    requested = document.get("requestedU0Window")
    if not isinstance(requested, dict) or set(requested) != {
        "purpose",
        "maximumSessionSeconds",
        "stsSessionIssuanceAllowed",
        "awsResourceMutationAllowed",
        "kubernetesMutationAllowed",
        "kubernetesMutationScope",
        "credentialHandling",
        "allowed",
        "forbidden",
    }:
        raise ToolError("U0 requested window shape differs from the reviewed contract")
    if (
        requested.get("purpose") != "Complete U0 management-plane preflight only"
        or requested.get("maximumSessionSeconds") != MAX_SESSION_SECONDS
        or requested.get("stsSessionIssuanceAllowed") is not True
        or requested.get("awsResourceMutationAllowed") is not False
        or requested.get("kubernetesMutationAllowed") is not True
        or requested.get("kubernetesMutationScope") != list(KUBERNETES_MUTATION_SCOPE)
        or requested.get("credentialHandling") != CREDENTIAL_HANDLING
        or requested.get("allowed") != list(ALLOWED_ACTIONS)
        or requested.get("forbidden") != list(FORBIDDEN_ACTIONS)
    ):
        raise ToolError("U0 requested actions differ from the reviewed allowlist")

    decisions = document.get("decisions")
    if not isinstance(decisions, dict) or set(decisions) != DECISION_KEYS:
        raise ToolError("U0 decision inventory differs")
    status = document.get("reviewStatus")
    approved = status == APPROVED_STATUS
    if status == PENDING_STATUS:
        if document.get("approvedBy") is not None or document.get("approvedAt") is not None:
            raise ToolError("pending U0 authorization cannot name an approval")
        if any(value is not None for value in decisions.values()):
            raise ToolError("pending U0 decisions must remain unset")
    elif approved:
        reviewer = document.get("approvedBy")
        if (
            not isinstance(reviewer, str)
            or not reviewer.strip()
            or any(marker in reviewer for marker in ("__REPLACE", "<", ">", "\n", "\r"))
        ):
            raise ToolError("approved U0 authorization must identify the reviewer")
        approved_at = _timestamp(document.get("approvedAt"), "approvedAt")
        age = (datetime.now(timezone.utc) - approved_at).total_seconds()
        if approved_at < generated_at or age > APPROVAL_MAX_AGE_SECONDS:
            raise ToolError("U0 approval must be fresh and no earlier than bundle generation")
        if any(value is not True for value in decisions.values()):
            raise ToolError("every U0 decision must be explicitly accepted")
    else:
        raise ToolError("U0 reviewStatus is not pending or approved")
    if require_approved and not approved:
        raise ToolError("U0 management-preflight window is not approved")

    checksums = verify_checksums(path.parent)
    _validate_candidate_inputs(path.parent)
    return {
        "bundle": bundle,
        "windowId": document["windowId"],
        "reviewStatus": status,
        "approved": approved,
        "decisionsComplete": approved,
        "singleUse": True,
        "maximumSessionSeconds": MAX_SESSION_SECONDS,
        "separateManagementSessionReviewRequired": True,
        "awsResourceMutationAllowed": False,
        "kubernetesMutationActions": len(KUBERNETES_MUTATION_SCOPE),
        "checksumsVerified": checksums,
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
        "mutationPerformed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "validate-approved"))
    parser.add_argument("--authorization", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_authorization(
            args.authorization,
            require_approved=args.mode == "validate-approved",
        )
        result["mode"] = args.mode
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ToolError, OSError, ValueError, KeyError, TypeError):
        print(
            "U0 authorization validation failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
