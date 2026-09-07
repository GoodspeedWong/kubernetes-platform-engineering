#!/usr/bin/env python3
"""Local CIDR authorization and append-only receipt checks; never calls an API.

Historical verification is receipt evidence ONLY, never a claim/run capability.
Owner-only files and hashes provide local audit integrity, not a remote signature
or protection against the workstation owner rewriting the entire evidence chain.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common import ToolError
import u1_cidr_amendment as amendment
import u1_environment_identity as identity
import validate_u1_continuation as continuation

create = continuation.create
TYPE = "u1-root-cidr-amendment"
PENDING = "DRAFT_NOT_AUTHORIZED"
APPROVED = "APPROVED_FOR_ONE_ROOT_CIDR_AMENDMENT"
CLAIM_STATUS = "CLAIMED_FOR_ONE_ROOT_CIDR_AMENDMENT"
PASS = "U1_ROOT_CIDR_AMENDMENT_VERIFIED"
ACK = "I-APPROVE-ONE-KUBERNETES-ONLY-ROOT-CIDR-AMENDMENT"
BUNDLE_RE = re.compile(
    r"^u1-root-cidr-change-([0-9]{4})-([0-9]{2})-([0-9]{2})-([0-9]{2})$"
)
WINDOW_RE = re.compile(r"^u1ip-([0-9]{8})-([0-9]{2})$")
STATE_ROOT = Path.home() / ".local/share/eks-platform/u1-cidr-amendments"
SCOPE = {
    "context": "kind-kube-nebula-a",
    "root": "XEKSEnvironment/eks-dev-spot",
    "field": amendment.FIELD,
    "maximumExecutionSeconds": 900,
    "maximumPersistentPatchRequests": 1,
    "freshUidResourceVersionAndFullSpecTests": True,
    "awsApiCallsAllowed": False,
    "sessionAccessAllowed": "metadata-only absence check; no data, STS or publication",
    "controllerWritesAllowed": False,
    "permanentDefinitionWritesAllowed": False,
    "publicEgressProbesAllowed": "host proxy and KinD process-proxy-unset, separately",
    "operatorMustExcludeConcurrentMaintenanceAndScheduledStarts": True,
    "automaticRetryRollbackOrDeletionAllowed": False,
    "failureAction": "read-only diagnosis under separate authority; never patch again",
    "continuationAuthorized": False,
}
DOC_KEYS = {
    "schemaVersion",
    "authorizationType",
    "bundle",
    "windowId",
    "generatedAt",
    "reviewStatus",
    "approvedBy",
    "approvedAt",
    "executionCode",
    "scope",
    "sourcesSha256",
    "rootUid",
    "compositionPin",
    "sourceCreateWindow",
    "beforeIntentSha256",
    "afterIntentSha256",
    "candidateCidrs",
    "egressObservation",
    "actor",
    "exclusiveMaintenanceAcknowledged",
}


def reference(path):
    path = Path(os.path.abspath(path))
    return {"path": str(path), "sha256": continuation.digest(path)}


def read_reference(ref):
    return create._load_json(continuation.reference(ref))


def validate(path, *, require_approved, historical=False):
    path = Path(os.path.abspath(path))
    if path.name != "authorization-contract.json":
        raise ToolError("explicit CIDR authorization-contract.json required")
    digest = continuation.digest(path)
    continuation.verify_bundle(path)
    doc = create._load_json(path)
    if set(doc) != DOC_KEYS or not identity.strict_equal(doc.get("schemaVersion"), 1):
        raise ToolError("CIDR authorization schema differs")
    bundle = BUNDLE_RE.fullmatch(str(doc["bundle"]))
    window = WINDOW_RE.fullmatch(str(doc["windowId"]))
    if (
        doc["authorizationType"] != TYPE
        or bundle is None
        or window is None
        or doc["bundle"] != path.parent.name
        or window[1] != "".join(bundle.groups()[:3])
        or window[2] != bundle[4]
        or not identity.strict_equal(doc["scope"], SCOPE)
    ):
        raise ToolError("CIDR authorization identity or scope differs")
    generated = create._timestamp(doc["generatedAt"], "generatedAt")
    code = doc["executionCode"]
    if (
        not isinstance(code, dict)
        or set(code)
        != {
            "gitCommit",
            "roots",
            "trackedNonMarkdownFiles",
            "aggregateSha256",
            "untrackedNonMarkdownFiles",
            "markdownDriftExcluded",
        }
        or not create.u0_authorization.GIT_COMMIT_RE.fullmatch(str(code["gitCommit"]))
        or not create.SHA256_RE.fullmatch(str(code["aggregateSha256"]))
        or not identity.strict_equal(
            code["roots"], list(create.u0_authorization.EXECUTION_ROOTS)
        )
        or type(code["trackedNonMarkdownFiles"]) is not int
        or code["trackedNonMarkdownFiles"] < 1
        or not identity.strict_equal(code["untrackedNonMarkdownFiles"], 0)
        or code["markdownDriftExcluded"] is not True
    ):
        raise ToolError("CIDR execution code evidence has an invalid shape")
    if not historical and not identity.strict_equal(
        code, create.execution_code_state()
    ):
        raise ToolError("CIDR execution checkout differs from the reviewed code")
    if doc["sourcesSha256"] != continuation.digest(path.parent / "sources.json"):
        raise ToolError("CIDR sources changed")
    sources = create._load_json(path.parent / "sources.json")
    if "cidrAmendment" in sources:
        raise ToolError("only one amendment from the original intent is supported")
    evidence = continuation.source_evidence(sources)
    before = evidence["environment"]
    after = amendment.candidate(before, doc["candidateCidrs"])
    if (
        before["metadata"]["name"] != "eks-dev-spot"
        or doc["rootUid"] != evidence["rootUid"]
        or not identity.strict_equal(doc["compositionPin"], asdict(evidence["pin"]))
        or doc["sourceCreateWindow"] != evidence["sourceWindow"]
        or doc["beforeIntentSha256"] != identity.spec_digest(before)
        or doc["afterIntentSha256"] != identity.spec_digest(after)
    ):
        raise ToolError("CIDR original intent, root UID or pin binding differs")
    approved = doc["reviewStatus"] == APPROVED
    if not approved:
        if (
            doc["reviewStatus"] != PENDING
            or doc["approvedBy"] is not None
            or doc["approvedAt"] is not None
            or doc["exclusiveMaintenanceAcknowledged"] is not False
        ):
            raise ToolError(
                "CIDR draft cannot contain approval or maintenance acceptance"
            )
    else:
        observation = doc["egressObservation"]
        if not isinstance(observation, dict) or set(observation) != {
            "observedAt",
            "host",
            "kind",
        }:
            raise ToolError(
                "CIDR approval requires both separately observed egress paths"
            )
        observed = create._timestamp(observation["observedAt"], "observedAt")
        addresses = sorted({observation["host"] + "/32", observation["kind"] + "/32"})
        if amendment.cidrs(addresses) != doc["candidateCidrs"]:
            raise ToolError("CIDR candidate does not match both reviewed egress paths")
        actor = doc["actor"]
        if (
            not identity.strict_equal(actor, amendment.actor_identity(actor))
            or doc["exclusiveMaintenanceAcknowledged"] is not True
            or not isinstance(doc["approvedBy"], str)
            or not doc["approvedBy"].strip()
        ):
            raise ToolError(
                "CIDR approval lacks exact actor and exclusive maintenance acceptance"
            )
        at = create._timestamp(doc["approvedAt"], "approvedAt")
        if at < max(generated, observed) or at - observed > timedelta(minutes=30):
            raise ToolError("CIDR approval predates evidence or reviewed stale egress")
        if not historical and datetime.now(timezone.utc) - observed > timedelta(
            minutes=30
        ):
            raise ToolError(
                "CIDR reviewed egress is stale; new evidence and review required"
            )
    if require_approved and not approved:
        raise ToolError("CIDR change needs independent execution approval")
    if continuation.digest(path) != digest:
        raise ToolError("CIDR authorization changed during validation")
    return {
        "document": doc,
        "sources": sources,
        "evidence": evidence,
        "before": before,
        "after": after,
        "approved": approved,
        "authorizationSha256": digest,
    }


def claim(path, acknowledgement, *, root=None):
    if acknowledgement != ACK:
        raise ToolError("CIDR-specific execution acknowledgement required")
    reviewed = validate(path, require_approved=True)
    doc = reviewed["document"]
    now = datetime.now(timezone.utc)
    value = {
        "status": CLAIM_STATUS,
        "windowId": doc["windowId"],
        "authorizationSha256": reviewed["authorizationSha256"],
        "executionCode": doc["executionCode"],
        "rootUid": doc["rootUid"],
        "claimedAt": now.isoformat(),
        "deadline": (now + timedelta(seconds=900)).isoformat(),
    }
    directory = create.u0_authorization._claim_root(root or STATE_ROOT, create=True)
    create.u0_authorization._write_claim(
        directory / (doc["windowId"] + ".claim.json"), value
    )
    return reviewed, value


def verify_claim(value, reviewed, *, active=False):
    doc = reviewed["document"]
    expected = {
        "status": CLAIM_STATUS,
        "windowId": doc["windowId"],
        "authorizationSha256": reviewed["authorizationSha256"],
        "executionCode": doc["executionCode"],
        "rootUid": doc["rootUid"],
        "claimedAt": value.get("claimedAt"),
        "deadline": value.get("deadline"),
    }
    if not identity.strict_equal(value, expected):
        raise ToolError("CIDR claim binding differs")
    at = create._timestamp(value["claimedAt"], "claimedAt")
    end = create._timestamp(value["deadline"], "deadline", allow_future=True)
    if (
        end != at + timedelta(seconds=900)
        or at < create._timestamp(doc["approvedAt"], "approvedAt")
        or at - create._timestamp(doc["egressObservation"]["observedAt"], "observedAt")
        > timedelta(minutes=30)
        or (active and datetime.now(timezone.utc) >= end)
    ):
        raise ToolError("CIDR claim expired or timestamps differ")
    return at, end


def write_intent(reviewed, patch, at):
    return {
        "windowId": reviewed["document"]["windowId"],
        "authorizationSha256": reviewed["authorizationSha256"],
        "patchSha256": identity.spec_digest(patch),
        "recordedAt": at,
    }


def verify_receipt(ref, sources, evidence):
    """Verify the whole immutable chain before deriving amended continuation intent."""
    receipt = read_reference(ref)
    if set(receipt) != {
        "schemaVersion",
        "status",
        "windowId",
        "authorization",
        "claim",
        "before",
        "dryRun",
        "preWrite",
        "writeIntent",
        "after",
        "recordedAt",
    }:
        raise ToolError("CIDR receipt schema differs")
    if (
        not identity.strict_equal(receipt["schemaVersion"], 1)
        or receipt["status"] != PASS
    ):
        raise ToolError("CIDR receipt is not a verified successful amendment")
    auth_path = continuation.reference(receipt["authorization"])
    reviewed = validate(auth_path, require_approved=True, historical=True)
    if not identity.strict_equal(reviewed["sources"], sources):
        raise ToolError("CIDR receipt belongs to different original evidence")
    if (
        not identity.strict_equal(reviewed["before"], evidence["environment"])
        or reviewed["document"]["rootUid"] != evidence["rootUid"]
        or reviewed["evidence"]["pin"] != evidence["pin"]
    ):
        raise ToolError("CIDR receipt original owner or intent differs")
    doc = reviewed["document"]
    if receipt["windowId"] != doc["windowId"]:
        raise ToolError("CIDR receipt window differs")
    # Fixed names in ONE owner-only state directory prevent mixing run fragments.
    directory = Path(ref["path"]).parent
    if Path(ref["path"]).name != doc["windowId"] + ".receipt.json":
        raise ToolError("CIDR receipt filename differs")
    chain = {}
    for field, suffix in (
        ("claim", "claim"),
        ("before", "before"),
        ("dryRun", "dry-run"),
        ("preWrite", "pre-write"),
        ("writeIntent", "write-intent"),
        ("after", "after"),
    ):
        if receipt[field].get("path") != str(
            directory / f"{doc['windowId']}.{suffix}.json"
        ):
            raise ToolError("CIDR receipt fragments do not belong to one run")
        chain[field] = read_reference(receipt[field])
    if (directory / (doc["windowId"] + ".failure.json")).exists():
        raise ToolError("CIDR failed/ambiguous run cannot authorize continuation")
    start, end = verify_claim(chain["claim"], reviewed)
    egress = {k: doc["egressObservation"][k] for k in ("host", "kind")}
    times = [start]
    for field, intent in (
        ("before", reviewed["before"]),
        ("preWrite", reviewed["before"]),
        ("after", reviewed["after"]),
    ):
        amendment.verify_observation(
            chain[field],
            intent,
            evidence["rootUid"],
            evidence["pin"],
            egress,
            doc["actor"],
        )
    for key in ("metadata", "spec"):
        if not identity.strict_equal(
            chain["preWrite"]["root"][key], chain["before"]["root"][key]
        ):
            raise ToolError("CIDR pre-write root changed after dry-run")
    for field, dry_run in (("dryRun", True), ("after", False)):
        amendment.verify_readback(
            chain["before"]["root"],
            chain[field]["root"],
            reviewed["before"],
            reviewed["after"],
            evidence["rootUid"],
            evidence["pin"],
            dry_run=dry_run,
        )
    if set(chain["dryRun"]) != {"root", "observedAt"}:
        raise ToolError("CIDR dry-run evidence schema differs")
    patch = amendment.patch_for(
        chain["before"]["root"],
        reviewed["before"],
        reviewed["after"],
        evidence["rootUid"],
        evidence["pin"],
    )
    if not identity.strict_equal(
        chain["writeIntent"],
        write_intent(reviewed, patch, chain["writeIntent"].get("recordedAt")),
    ):
        raise ToolError("CIDR durable write-intent differs from the tested patch")
    for field, time_key in (
        ("before", "observedAt"),
        ("dryRun", "observedAt"),
        ("preWrite", "observedAt"),
        ("writeIntent", "recordedAt"),
        ("after", "observedAt"),
    ):
        times.append(create._timestamp(chain[field][time_key], time_key))
    times.append(create._timestamp(receipt["recordedAt"], "recordedAt"))
    if times != sorted(times) or times[-1] > end:
        raise ToolError(
            "CIDR receipt events are unordered or outside the claimed window"
        )
    return copy.deepcopy(reviewed["after"])


def public_plan(reviewed):
    return {
        "mode": "plan",
        "reviewStatus": reviewed["document"]["reviewStatus"],
        "approved": reviewed["approved"],
        "scope": SCOPE,
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
        "claimCreated": False,
        "singleFieldDeltaVerified": True,
        "continuationAuthorized": False,
    }


def main(argv=None):
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
            "CIDR validation failed closed; private values suppressed", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
