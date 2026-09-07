#!/usr/bin/env python3
"""Local-only validation and distinct, durable claims for same-root U1 continuation.

Historical create receipts are evidence, never authority for this entry point.
Drafts may omit a fresh AWS snapshot; approval and claim may not. No cloud or
Kubernetes commands are issued by this module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common import EKS_ROOT, ToolError, load_yaml
import u1_environment_identity as identity
import validate_u1_authorization as create

AUTHORIZATION_TYPE = "u1-existing-root-continuation"
PENDING = "DRAFT_NOT_AUTHORIZED"
APPROVED = "APPROVED_FOR_ONE_SAME_ROOT_CONTINUATION"
CLAIM_STATUS = "CLAIMED_FOR_U1_SAME_ROOT_CONTINUATION"
CLAIM_ACKNOWLEDGEMENT = "I-CLAIM-ONE-U1-SAME-ROOT-CONTINUATION"
CLAIM_ROOT = Path.home() / ".local/share/eks-platform/u1-continuation-authorizations"
WINDOW_RE = re.compile(r"^u1c-([0-9]{8})-([0-9]{2})$")
BUNDLE_RE = re.compile(r"^u1-continuation-([0-9]{4})-([0-9]{2})-([0-9]{2})-([0-9]{2})$")
FILES = {"REVIEW_SUMMARY.md", "authorization-contract.json", "sources.json"}
REFRESH_FILES = {
    "REVIEW_SUMMARY.md",
    "business-workload-evidence.json",
    "core-readonly-evidence.json",
    "managed-inventory-evidence.json",
    "permanent-definitions-evidence.json",
    "refresh-result.json",
    "runtime-and-final-checks.json",
    "shared-object-evidence.json",
    "source-inputs.json",
    "SHA256SUMS",
}
SCOPE = {
    "rootOperation": "observe-only; never create/apply/replace/patch/delete root",
    "sameUidRequired": True,
    "immutableCompositionPinRequired": True,
    "startingInventory": {
        "root": 1,
        "children": 0,
        "awsManaged": 0,
        "nonAwsObjects": 73,
    },
    "controllers": 14,
    "sharedObjects": 76,
    "businessWorkloads": 89,
    "maximumExecutionSeconds": 3000,
    "maximumSessionSeconds": 3600,
    "separateA05ReviewRequired": True,
    "directAwsCliMutationAllowed": False,
    "controllerAwsReconciliationAllowed": True,
    "permanentDefinitionsMutationAllowed": False,
    "automaticRetryAllowed": False,
    "automaticDeletionAllowed": False,
    "networkApprovalAllowed": False,
    "gitBootstrapAllowed": False,
    "stopAt": "first U1 bootstrap checkpoint; no U1-06/U1-07/U2/U3/U4/U5",
    "failureAction": "park 14; remove session; restore shared objects; preserve root and cloud",
    "budget": {
        "days": 7,
        "usd": 70,
        "softOnly": True,
        "billingContinuesAfterParking": True,
    },
}


def digest(path: Path) -> str:
    return create._file_sha256(path)


def verify_files(directory: Path, expected: dict, names: set[str]) -> None:
    if set(expected) != names or {p.name for p in directory.iterdir()} != names:
        raise ToolError("continuation source file inventory differs")
    for name, value in expected.items():
        if (
            not create.SHA256_RE.fullmatch(str(value))
            or digest(directory / name) != value
        ):
            raise ToolError("continuation source file changed")


def reference(ref: dict) -> Path:
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
        raise ToolError("continuation source reference shape differs")
    path = Path(ref["path"])
    if not path.is_absolute() or digest(path) != ref["sha256"]:
        raise ToolError("continuation private source reference changed")
    return path


def source_evidence(sources: dict) -> dict:
    """Verify archived bytes and derive identity from full documents, not labels."""
    if set(sources) != {
        "createBundle",
        "createClaim",
        "createResult",
        "createJournal",
        "refreshBundle",
        "sessionReview",
        "coreRbacSource",
    }:
        raise ToolError("continuation source inventory differs")
    directories = {}
    for key, names in (
        ("createBundle", create.REQUIRED_FILES | {"SHA256SUMS"}),
        ("refreshBundle", REFRESH_FILES),
    ):
        item = sources[key]
        if set(item) != {"path", "files"} or not Path(item["path"]).is_absolute():
            raise ToolError("continuation source directory shape differs")
        directory = Path(item["path"])
        verify_files(directory, item["files"], names)
        directories[key] = directory
    archive, refresh = directories["createBundle"], directories["refreshBundle"]
    create._verify_checksums(archive)  # Integrity only: never re-authorize old code.
    old = create._load_json(archive / "authorization-contract.json")
    receipt = create._load_json(reference(sources["createClaim"]))
    result = create._load_json(reference(sources["createResult"]))
    reference(sources["createJournal"])
    reference(sources["sessionReview"])
    core_source = sources["coreRbacSource"]
    expected_core_path = EKS_ROOT.parent / "crossplane/manifest.yaml"
    if (
        set(core_source) != {"path", "sha256"}
        or core_source["path"] != str(expected_core_path)
        or hashlib.sha256(expected_core_path.read_bytes()).hexdigest()
        != core_source["sha256"]
    ):
        raise ToolError("separately bound core RBAC source changed")
    if (
        old.get("authorizationType") != create.AUTHORIZATION_TYPE
        or old.get("reviewStatus") != create.APPROVED_STATUS
        or receipt.get("status") != create.CLAIM_STATUS
        or receipt.get("authorizationSha256")
        != digest(archive / "authorization-contract.json")
        or result.get("status") != "U1_BOOTSTRAP_RECOVERY_REQUIRED"
        or result.get("singleUseClaimConsumed") is not True
        or result.get("environment", {}).get("generation") != 1
        or any(
            item.get("windowId") != old["windowId"]
            or item.get("bundle") != old["bundle"]
            for item in (receipt, result)
        )
        or receipt.get("executionGitCommit") != old["executionCode"]["gitCommit"]
        or result.get("executionCodeSha256") != old["executionCode"]["aggregateSha256"]
    ):
        raise ToolError("archived create receipt/result binding differs")
    snapshot = create._load_json(archive / "aws-readonly-snapshot.json")
    create._validate_snapshot(snapshot, allow_stale=True)
    create._validate_environment(archive, old["bundle"], snapshot)
    create._validate_cost_plan(
        create._load_json(archive / "cost-and-cleanup-plan.json")
    )
    if not identity.strict_equal(
        create._load_json(archive / "expected-resource-contract.json"),
        create.EXPECTED_RESOURCE_CONTRACT,
    ):
        raise ToolError("archived resource contract differs")
    env = load_yaml(archive / "environment.approved.yaml")
    proof = {
        name.removesuffix(".json"): create._load_json(refresh / name)
        for name in REFRESH_FILES
        if name.endswith(".json")
    }
    final = proof["refresh-result"]
    required = {
        "controllersStopped": 14,
        "sessionSecretAbsent": True,
        "sameRootUidAndReviewedIntent": True,
        "lockedCompositionAndRevisionContent": True,
        "sharedObjectsUidAndProtectionRestored": 76,
        "businessWorkloadStatesUnchanged": 89,
        "lifecycleXRs": 1,
        "childXRs": 0,
        "awsManagedResources": 0,
        "nonAwsManagedObjects": 73,
        "permanentDefinitionsCompared": 63,
        "unclassifiedDefinitionDifferences": 0,
        "providers": 10,
        "functions": 3,
        "ownedRuntimeDeployments": 13,
        "retiredAutomaticRbacTargetsAbsent": 25,
        "generatedLifecycleCrdSchemasAndOwners": 4,
        "admissionExpressionWarnings": 0,
        "sameRootAndRevisionBinding": True,
    }
    if final.get("status") != "KUBERNETES_READ_ONLY_REFRESH_PASS" or any(
        not identity.strict_equal(final.get("checks", {}).get(k), v)
        for k, v in required.items()
    ):
        raise ToolError("independent parked-baseline confirmation is incomplete")
    docs = proof["core-readonly-evidence"]["documents"]
    uid = result["environment"]["uid"]
    refs = identity.validate_root(docs["root"], env, expected_uid=uid)
    pin = identity.validate_binding(
        docs["composition"],
        docs["compositionRevision"],
        load_yaml(EKS_ROOT / "environment/composition.yaml")["spec"],
        revision_name=refs.revision,
    )
    if not identity.strict_equal(
        proof["runtime-and-final-checks"]["runtimePin"], asdict(pin)
    ):
        raise ToolError("independent runtime pin differs")
    from u1_continuation_definitions import verify_local

    definitions = verify_local(
        archive, proof["permanent-definitions-evidence"]["documents"]
    )
    return {
        "archive": archive,
        "proof": proof,
        "environment": env,
        "snapshot": snapshot,
        "rootUid": uid,
        "pin": pin,
        "sourceWindow": old["windowId"],
        "definitions": definitions,
    }


def verify_bundle(path: Path) -> None:
    expected = {}
    for line in (
        create._read_private(path.parent / "SHA256SUMS").decode("ascii").splitlines()
    ):
        match = create.u0_authorization.CHECKSUM_RE.fullmatch(line)
        if match is None or match[2] in expected:
            raise ToolError("continuation checksum manifest malformed")
        expected[match[2]] = match[1]
    if set(expected) != FILES:
        raise ToolError("continuation bundle inventory differs")
    verify_files(
        path.parent,
        expected | {"SHA256SUMS": digest(path.parent / "SHA256SUMS")},
        FILES | {"SHA256SUMS"},
    )


def validate(
    path: Path, *, require_approved: bool, recovery_only: bool = False
) -> dict:
    path = Path(os.path.abspath(path.expanduser()))
    if path.name != "authorization-contract.json":
        raise ToolError("explicit continuation authorization-contract.json required")
    before = digest(path)
    verify_bundle(path)
    doc = create._load_json(path)
    if (
        set(doc)
        != {
            "schemaVersion",
            "authorizationType",
            "bundle",
            "windowId",
            "generatedAt",
            "reviewStatus",
            "approvedBy",
            "approvedAt",
            "scope",
            "executionCode",
            "sourcesSha256",
            "rootUid",
            "compositionPin",
            "sourceCreateWindow",
            "awsReadOnlySnapshot",
        }
        or type(doc["schemaVersion"]) is not int
        or doc["schemaVersion"] != 1
    ):
        raise ToolError("continuation schema differs")
    bundle = BUNDLE_RE.fullmatch(str(doc["bundle"]))
    window = WINDOW_RE.fullmatch(str(doc["windowId"]))
    if (
        doc["authorizationType"] != AUTHORIZATION_TYPE
        or bundle is None
        or window is None
        or doc["bundle"] != path.parent.name
        or window[1] != "".join(bundle.groups()[:3])
        or window[2] != bundle[4]
        or not identity.strict_equal(doc["scope"], SCOPE)
    ):
        raise ToolError(
            "continuation identity or scope differs; create claims are forbidden"
        )
    generated = create._timestamp(doc["generatedAt"], "generatedAt")
    if not identity.strict_equal(doc["executionCode"], create.execution_code_state()):
        raise ToolError("continuation execution code differs from reviewed checkout")
    if doc["sourcesSha256"] != digest(path.parent / "sources.json"):
        raise ToolError("continuation source manifest changed")
    sources = create._load_json(path.parent / "sources.json")
    evidence = source_evidence(sources)
    if (
        doc["rootUid"] != evidence["rootUid"]
        or doc["sourceCreateWindow"] != evidence["sourceWindow"]
        or not identity.strict_equal(doc["compositionPin"], asdict(evidence["pin"]))
    ):
        raise ToolError("continuation root or immutable revision binding differs")
    blockers = []
    snapshot = doc["awsReadOnlySnapshot"]
    if snapshot is None:
        blockers.append("fresh AWS/release/AMI/quota/dual-egress snapshot missing")
    else:
        create._validate_snapshot(
            snapshot, allow_stale=recovery_only or not require_approved
        )
        create._validate_environment(
            evidence["archive"], evidence["archive"].name, snapshot
        )
    approved = doc["reviewStatus"] == APPROVED
    if doc["reviewStatus"] == PENDING:
        if doc["approvedBy"] is not None or doc["approvedAt"] is not None:
            raise ToolError("pending continuation cannot record an approval")
        blockers.append("independent same-root active-window approval missing")
    elif approved:
        if (
            blockers
            or not isinstance(doc["approvedBy"], str)
            or not doc["approvedBy"].strip()
        ):
            raise ToolError(
                "continuation approval lacks required fresh evidence/reviewer"
            )
        at = create._timestamp(doc["approvedAt"], "approvedAt")
        observed = create._timestamp(snapshot["observedAt"], "observedAt")
        if at < max(generated, observed) or (
            not recovery_only
            and (datetime.now(timezone.utc) - at).total_seconds() > 86400
        ):
            raise ToolError("continuation approval is stale or precedes its evidence")
        # Separate A05 approval is verified locally; IAM is audited live before STS.
        import run_u1_bootstrap as runtime

        _, bootstrap = runtime._session_contract(
            reference(sources["sessionReview"]), recovery_only=recovery_only
        )
        if (
            bootstrap.environment != snapshot["environment"]
            or bootstrap.region != snapshot["region"]
            or bootstrap.context != "kind-kube-nebula-a"
            or {
                arn.split(":")[4]
                for arn in (
                    bootstrap.source_role_arn,
                    bootstrap.provider_role_arn,
                    bootstrap.deployment_role_arn,
                )
            }
            != {snapshot["accountId"]}
        ):
            raise ToolError("continuation A05 scope differs")
    else:
        raise ToolError("continuation review status differs")
    if require_approved and (not approved or blockers):
        raise ToolError("same-root continuation is not approved/ready")
    if digest(path) != before:
        raise ToolError("continuation authorization changed during validation")
    return {
        "document": doc,
        "sources": sources,
        "evidence": evidence,
        "blockers": blockers,
        "authorizationSha256": before,
        "approved": approved,
    }


def claim(path: Path, acknowledgement: str, *, root: Path = CLAIM_ROOT) -> dict:
    if acknowledgement != CLAIM_ACKNOWLEDGEMENT:
        raise ToolError("distinct continuation claim acknowledgement required")
    result = validate(path, require_approved=True)
    doc = result["document"]
    at = datetime.now(timezone.utc)
    receipt = {
        "status": CLAIM_STATUS,
        "windowId": doc["windowId"],
        "bundle": doc["bundle"],
        "authorizationSha256": result["authorizationSha256"],
        "rootUid": doc["rootUid"],
        "executionCode": doc["executionCode"],
        "claimedAt": at.isoformat(),
        "deadline": (at + timedelta(seconds=3600)).isoformat(),
    }
    directory = create.u0_authorization._claim_root(root, create=True)
    create.u0_authorization._write_claim(directory / f"{doc['windowId']}.json", receipt)
    return receipt


def verify_claim(
    path: Path, *, root: Path = CLAIM_ROOT, require_active: bool = True
) -> dict:
    result = validate(path, require_approved=True, recovery_only=not require_active)
    doc = result["document"]
    directory = create.u0_authorization._claim_root(root, create=False)
    receipt = create._load_json(directory / f"{doc['windowId']}.json")
    expected = {
        "status": CLAIM_STATUS,
        "windowId": doc["windowId"],
        "bundle": doc["bundle"],
        "authorizationSha256": result["authorizationSha256"],
        "rootUid": doc["rootUid"],
        "executionCode": doc["executionCode"],
        "claimedAt": receipt.get("claimedAt"),
        "deadline": receipt.get("deadline"),
    }
    if not identity.strict_equal(receipt, expected):
        raise ToolError("continuation claim differs from approved same-root contract")
    at = create._timestamp(receipt["claimedAt"], "claimedAt")
    end = create._timestamp(receipt["deadline"], "deadline", allow_future=True)
    if end != at + timedelta(seconds=3600) or (
        require_active and datetime.now(timezone.utc) >= end
    ):
        raise ToolError("continuation claim expired; recovery-only required")
    return receipt


def public_plan(result: dict) -> dict:
    doc = result["document"]
    return {
        "mode": "plan",
        "bundle": doc["bundle"],
        "windowId": doc["windowId"],
        "reviewStatus": doc["reviewStatus"],
        "approved": result["approved"],
        "blockers": result["blockers"],
        "sameRootBindingVerified": True,
        "scope": doc["scope"],
        "oldClaimReusable": False,
        "localClaimCreated": False,
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
        "reviewedGitCommit": doc["executionCode"]["gitCommit"],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "validate-approved"))
    parser.add_argument("--authorization", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(
            json.dumps(
                public_plan(
                    validate(
                        args.authorization,
                        require_approved=args.mode == "validate-approved",
                    )
                ),
                indent=2,
            )
        )
        return 0
    except (ToolError, OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "continuation validation failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
