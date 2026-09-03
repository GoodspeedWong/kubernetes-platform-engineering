#!/usr/bin/env python3
"""Validate one private, single-use U0 management-preflight authorization pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from common import REPO_ROOT, ToolError, find_placeholders, load_yaml


SCHEMA_VERSION = 3
AUTHORIZATION_TYPE = "u0-management-preflight-window"
PENDING_STATUS = "PENDING_OPERATOR_APPROVAL"
APPROVED_STATUS = "APPROVED_FOR_ONE_U0_WINDOW"
MAX_SESSION_SECONDS = 3600
APPROVAL_MAX_AGE_SECONDS = 86400
CLAIM_SCHEMA_VERSION = 2
CLAIM_STATUS = "CLAIMED_FOR_EXECUTION"
CLAIM_ACKNOWLEDGEMENT = "I-CLAIM-ONE-U0-MANAGEMENT-PREFLIGHT-WINDOW"
CLAIM_ROOT = Path.home() / ".local/share/eks-platform/u0-authorizations"
BUNDLE_RE = re.compile(r"^u0-preflight-[0-9]{4}-[0-9]{2}-[0-9]{2}$")
WINDOW_RE = re.compile(r"^u0-[0-9]{8}-[0-9]{2}$")
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

EXECUTION_ROOTS = (
    "scripts/eks_lifecycle",
    "kind-goodnotes-k8s-demo/crossplane-platform-aws-eks",
    "kind-goodnotes-k8s-demo/crossplane-platform-aws-network",
)

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
    "pin exactly three reviewed Crossplane Function package references from their locked tags to immutable digests",
    "patch only the 14 reviewed controller Deployments for bounded startup and final zero-replica restore",
    "submit server-side dry-run admission requests that persist no objects",
)

ALLOWED_ACTIONS = (
    "protect and later restore the existing shared management-plane objects",
    "publish the already reviewed on-demand session Secret for at most 60 minutes",
    "apply only the reviewed management definitions, dependencies, explicit RBAC, and approved platform/node catalogs",
    "pin the three existing Crossplane Functions to their reviewed immutable package digests before starting Crossplane core",
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


def _timestamp(value: Any, label: str, *, allow_future: bool = False) -> datetime:
    if not isinstance(value, str):
        raise ToolError(f"{label} must be timezone-qualified")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ToolError(f"{label} must be timezone-qualified") from error
    if parsed.tzinfo is None or (not allow_future and parsed > datetime.now(timezone.utc)):
        raise ToolError(f"{label} must be a non-future timezone-qualified time")
    return parsed


def _git(*args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            timeout=15,
            env={
                "PATH": os.environ.get("PATH", ""),
                "LANG": "C",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
            },
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolError("local Git execution-code check was unavailable") from error
    if result.returncode:
        raise ToolError("local Git execution-code check failed; output suppressed")
    return result.stdout


def execution_code_state() -> dict[str, Any]:
    try:
        commit = _git("rev-parse", "--verify", "HEAD").decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ToolError("local Git commit identity is invalid") from error
    if not GIT_COMMIT_RE.fullmatch(commit):
        raise ToolError("local Git commit identity is invalid")

    tracked = [
        entry
        for entry in _git("ls-files", "-z", "--", *EXECUTION_ROOTS).split(b"\0")
        if entry and not entry.lower().endswith(b".md")
    ]
    if not tracked or tracked != sorted(set(tracked)):
        raise ToolError("execution-code tracked file inventory is empty or ambiguous")
    untracked = [
        entry
        for entry in _git(
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *EXECUTION_ROOTS,
        ).split(b"\0")
        if entry and not entry.lower().endswith(b".md")
    ]
    if untracked:
        raise ToolError("unreviewed non-Markdown execution file is present")

    aggregate = hashlib.sha256()
    for raw_path in tracked:
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise ToolError("execution-code path escaped the repository")
        path = REPO_ROOT / relative
        try:
            info = path.lstat()
        except OSError as error:
            raise ToolError("reviewed execution file is missing") from error
        if not stat.S_ISREG(info.st_mode):
            raise ToolError("reviewed execution path must be a regular file")
        payload = path.read_bytes()
        aggregate.update(raw_path)
        aggregate.update(b"\0")
        aggregate.update(str(len(payload)).encode("ascii"))
        aggregate.update(b"\0")
        aggregate.update(hashlib.sha256(payload).digest())
    return {
        "gitCommit": commit,
        "roots": list(EXECUTION_ROOTS),
        "trackedNonMarkdownFiles": len(tracked),
        "aggregateSha256": aggregate.hexdigest(),
        "untrackedNonMarkdownFiles": 0,
        "markdownDriftExcluded": True,
    }


def _claim_root(path: Path, *, create: bool) -> Path:
    root = Path(os.path.abspath(path.expanduser()))
    for candidate in (root, *root.parents):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ToolError("U0 claim state path contains a symlink")
    if create:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = root.lstat()
    except FileNotFoundError as error:
        raise ToolError("U0 claim state directory is missing") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ToolError("U0 claim state directory must be owner-only mode 0700")
    return root


def _claim_path(root: Path, window_id: str) -> Path:
    if not WINDOW_RE.fullmatch(window_id):
        raise ToolError("U0 windowId is invalid")
    return root / f"{window_id}.json"


def _write_claim(path: Path, receipt: dict[str, Any]) -> None:
    payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as error:
        raise ToolError("U0 window was already claimed; reuse is forbidden") from error
    except OSError as error:
        raise ToolError("U0 claim receipt could not be created safely") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        # A partial receipt deliberately remains and blocks an unsafe retry.
        raise ToolError("U0 claim receipt durability is uncertain; reuse is forbidden") from error


def claim_authorization(
    path: Path,
    acknowledgement: str,
    *,
    claim_root: Path = CLAIM_ROOT,
    now: datetime | None = None,
) -> dict[str, Any]:
    if acknowledgement != CLAIM_ACKNOWLEDGEMENT:
        raise ToolError("explicit single-use U0 claim acknowledgement required")
    authorization = validate_authorization(path, require_approved=True)
    authorization_digest = authorization.pop("_authorizationSha256")
    wall_clock = datetime.now(timezone.utc)
    claimed_at = now or wall_clock
    if (
        claimed_at.tzinfo is None
        or abs((wall_clock - claimed_at).total_seconds()) > 1
    ):
        raise ToolError("U0 claim time must be current and timezone-qualified")
    deadline = claimed_at + timedelta(seconds=MAX_SESSION_SECONDS)
    root = _claim_root(claim_root, create=True)
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
    _write_claim(receipt_path, receipt)
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
    root = _claim_root(claim_root, create=False)
    receipt_path = _claim_path(root, authorization["windowId"])
    try:
        receipt = json.loads(_read_private(receipt_path))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid U0 claim receipt; output suppressed") from error
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
        raise ToolError("U0 claim receipt fields differ")
    if (
        receipt.get("claimSchemaVersion") != CLAIM_SCHEMA_VERSION
        or receipt.get("status") != CLAIM_STATUS
        or receipt.get("bundle") != authorization["bundle"]
        or receipt.get("windowId") != authorization["windowId"]
        or receipt.get("authorizationSha256") != authorization_digest
        or receipt.get("executionGitCommit") != authorization["reviewedGitCommit"]
        or receipt.get("executionCodeSha256") != authorization["executionCodeSha256"]
    ):
        raise ToolError("U0 claim receipt does not match the approved authorization")
    claimed_at = _timestamp(receipt.get("claimedAt"), "claimedAt")
    deadline = _timestamp(receipt.get("deadline"), "deadline", allow_future=True)
    if deadline != claimed_at + timedelta(seconds=MAX_SESSION_SECONDS):
        raise ToolError("U0 claim deadline differs from the reviewed window")
    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None:
        raise ToolError("U0 claim verification time must be timezone-qualified")
    if checked_at < claimed_at:
        raise ToolError("U0 claim verification time precedes the claim")
    if require_active and checked_at >= deadline:
        raise ToolError("U0 claim window has expired; only recovery is allowed")
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


def validate_authorization(
    path: Path,
    require_approved: bool,
    *,
    allow_stale_approved: bool = False,
) -> dict[str, Any]:
    path = Path(os.path.abspath(path.expanduser()))
    if path.name != "authorization-contract.json":
        raise ToolError("explicit authorization-contract.json path required")
    try:
        authorization_payload = _read_private(path)
        document = json.loads(authorization_payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ToolError("invalid private U0 JSON; output suppressed") from error
    if not isinstance(document, dict):
        raise ToolError("private U0 JSON must be an object")
    authorization_digest = hashlib.sha256(authorization_payload).hexdigest()
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
        "executionCode",
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
    actual_execution_code = execution_code_state()
    if document.get("executionCode") != actual_execution_code:
        raise ToolError("U0 reviewed execution code differs from the current checkout")

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
        if approved_at < generated_at or (
            not allow_stale_approved and age > APPROVAL_MAX_AGE_SECONDS
        ):
            raise ToolError("U0 approval must be fresh and no earlier than bundle generation")
        if any(value is not True for value in decisions.values()):
            raise ToolError("every U0 decision must be explicitly accepted")
    else:
        raise ToolError("U0 reviewStatus is not pending or approved")
    if require_approved and not approved:
        raise ToolError("U0 management-preflight window is not approved")

    checksums = verify_checksums(path.parent)
    _validate_candidate_inputs(path.parent)
    if hashlib.sha256(_read_private(path)).hexdigest() != authorization_digest:
        raise ToolError("U0 authorization changed during validation")
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
        "reviewedGitCommit": actual_execution_code["gitCommit"],
        "executionCodeSha256": actual_execution_code["aggregateSha256"],
        "executionCodeFiles": actual_execution_code["trackedNonMarkdownFiles"],
        "untrackedExecutionFiles": actual_execution_code[
            "untrackedNonMarkdownFiles"
        ],
        "markdownDriftExcluded": actual_execution_code["markdownDriftExcluded"],
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
        "mutationPerformed": False,
        "_authorizationSha256": authorization_digest,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        choices=("plan", "validate-approved", "claim", "verify-claim"),
    )
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args(argv)
    try:
        if args.mode == "claim":
            result = claim_authorization(
                args.authorization,
                args.acknowledge,
            )
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
            "U0 authorization validation failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
