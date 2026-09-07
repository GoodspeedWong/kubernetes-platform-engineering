#!/usr/bin/env python3
"""Plan locally, or execute ONE independently approved existing-root window.

No root writes, definition applies, old claims, automatic retry or cloud delete.
Every active path consumes a new claim before any API call. Every failure after
protection starts parks outside the active timer using the contract's root UID.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from common import ToolError
import run_u1_bootstrap as base
import validate_u1_continuation as auth

RUN_ACK = "I-APPROVE-ONE-U1-SAME-ROOT-CONTINUATION"
RECOVER_ACK = "I-APPROVE-U1-CONTINUATION-RECOVERY-ONLY"
RESULT_ROOT = Path.home() / ".local/share/eks-platform/u1-continuation-results"


def runtime_contract(path: Path, reviewed: dict, *, recovery_only: bool = False):
    doc, evidence = reviewed["document"], reviewed["evidence"]
    session_path = auth.reference(reviewed["sources"]["sessionReview"])
    session, bootstrap = base._session_contract(
        session_path, recovery_only=recovery_only
    )
    snapshot = doc["awsReadOnlySnapshot"]
    archive = evidence["archive"]
    match = auth.WINDOW_RE.fullmatch(doc["windowId"])
    return base.U1Contract(
        authorization_path=path,
        session_review_path=session_path,
        authorization={
            "bundle": doc["bundle"],
            "windowId": doc["windowId"],
            "reviewStatus": doc["reviewStatus"],
            "approved": reviewed["approved"],
            "reviewedGitCommit": doc["executionCode"]["gitCommit"],
            "executionCodeSha256": doc["executionCode"]["aggregateSha256"],
        },
        session_review=session,
        bootstrap=bootstrap,
        bundle_directory=archive,
        environment_document=evidence["environment"],
        expected_resources=auth.create._load_json(
            archive / "expected-resource-contract.json"
        ),
        environment=snapshot["environment"],
        region=snapshot["region"],
        account_id=snapshot["accountId"],
        audit_profile=snapshot["profile"],
        expected_host_public_ip=snapshot["hostPublicEgressIp"],
        expected_kind_public_ip=snapshot["kindPublicEgressIp"],
        node_image_id=snapshot["nodeImage"]["imageId"],
        kubernetes_version=auth.create.EXPECTED_KUBERNETES_VERSION,
        coredns_addon_version=auth.create.EXPECTED_COREDNS_ADDON_VERSION,
        controller_names=base.u0_runner.controller_inventory(),
        run_id=f"a05-{match[1]}-u1c-{match[2]}",
    )


class Journal(base.Journal):
    """Reuse the durable, fixed-event writer, never the create-window directory."""

    @classmethod
    def create(cls, window: str):
        if auth.WINDOW_RE.fullmatch(window) is None:
            raise ToolError("continuation journal rejects create-window identity")
        root = auth.create.u0_authorization._claim_root(auth.CLAIM_ROOT, create=False)
        path = root / f"{window}.state.jsonl"
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(
                (
                    json.dumps({"windowId": window, "type": auth.AUTHORIZATION_TYPE})
                    + "\n"
                ).encode()
            )
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return cls(path)


def execute(
    path: Path,
    profile: str,
    audit_profile: str,
    acknowledgement: str,
    *,
    operations=None,
) -> dict:
    if acknowledgement != RUN_ACK:
        raise ToolError("distinct same-root execution acknowledgement required")
    reviewed = auth.validate(path, require_approved=True)
    contract = runtime_contract(path, reviewed)
    if (
        not profile
        or profile == audit_profile
        or audit_profile != contract.audit_profile
    ):
        raise ToolError("distinct explicit source and reviewed audit profiles required")
    receipt = auth.claim(path, auth.CLAIM_ACKNOWLEDGEMENT)
    journal = Journal.create(receipt["windowId"])
    journal.append("CLAIMED")
    if operations is None:
        from u1_continuation_operations import RealOperations

        operations = RealOperations(reviewed)
    root_uid = reviewed["document"][
        "rootUid"
    ]  # Known before any live action; never inferred by name.
    attempted = False
    failure = cleanup_failure = None
    baseline, observed, checkpoint, evidence, cleanup = {}, {}, {}, {}, {}
    try:
        with base._bounded_execution_window(3000):
            journal.append("EXECUTION_DEADLINE_ARMED")
            auth.verify_claim(path)
            baseline = operations.baseline(contract, audit_profile)
            journal.append("BASELINE_VERIFIED")
            observed = operations.observe_root(contract)
            if observed.get("uid") != root_uid:
                raise ToolError("continuation baseline root UID differs")
            attempted = True  # Set BEFORE a possibly partial first mutation.
            journal.append("PROTECTION_STARTED")
            operations.protect(contract)
            journal.append("PROTECTED")
            auth.verify_claim(path)
            journal.append("SESSION_STARTED")
            operations.open_session(
                contract, profile, audit_profile, progress=journal.append
            )
            journal.append("SESSION_OPENED")
            # Existing root may reconcile as soon as core starts. Recheck its
            # full identity and immutable pin before enabling any controller.
            operations.observe_root(contract)
            auth.verify_claim(path)
            operations.start_controllers(contract)
            operations.wait_ready(contract)
            journal.append("CONTROLLERS_STARTED")
            checkpoint = operations.wait_checkpoint(contract, observed)
            journal.append(
                "INFRASTRUCTURE_READY"
                if checkpoint.get("checkpointReached")
                else "MONITOR_WINDOW_ENDED"
            )
            evidence = operations.capture_evidence(
                contract, observed, checkpoint, audit_profile
            )
            journal.append("EVIDENCE_CAPTURED")
    except BaseException as error:
        failure = error
    finally:
        # Timer has already been disarmed. No more active operations are allowed.
        if attempted:
            try:
                # Journal I/O must never prevent mandatory safety cleanup.
                try:
                    journal.append("CLEANUP_STARTED")
                except BaseException:
                    pass
                cleanup = operations.cleanup(
                    contract, expected_environment_uid=root_uid
                )
                verify_parked_report(cleanup)
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
        "U1_CONTINUATION_RECOVERY_REQUIRED"
        if cleanup_failure
        else (
            "U1_CONTINUATION_FAILED_SAFE"
            if failure
            else (
                "U1_01_PASS"
                if checkpoint.get("checkpointReached")
                else "U1_CONTINUATION_PENDING_NEW_REVIEW"
            )
        )
    )
    report = {
        "schemaVersion": 1,
        "status": status,
        "windowId": receipt["windowId"],
        "bundle": contract.authorization["bundle"],
        "rootUid": root_uid,
        "authorizationSha256": receipt["authorizationSha256"],
        "recordedAt": datetime.now(timezone.utc).isoformat(),
        "executionCode": reviewed["document"]["executionCode"],
        "baseline": baseline,
        "observedRoot": observed,
        "checkpoint": checkpoint,
        "evidence": evidence,
        "cleanup": cleanup,
        "failureSha256": (
            hashlib.sha256(str(failure).encode()).hexdigest() if failure else None
        ),
        "cleanupFailureSha256": (
            hashlib.sha256(str(cleanup_failure).encode()).hexdigest()
            if cleanup_failure
            else None
        ),
        "singleUseClaimConsumed": True,
        "rootWriteAttempted": False,
        "oldClaimReused": False,
        "directAwsCliMutation": False,
        "automaticRetry": False,
        "cloudDeletionAttempted": False,
        "cleanupOutsideActiveDeadline": True,
        "executionDeadlineExceeded": isinstance(
            failure, base.ExecutionDeadlineExceeded
        ),
    }
    result = base._write_private_json(
        RESULT_ROOT / f"{receipt['windowId']}.json", report
    )
    if cleanup_failure:
        raise ToolError(
            "continuation parking incomplete; recovery-only required, no retry"
        ) from cleanup_failure
    if failure:
        raise ToolError(
            "continuation failed closed; claim consumed, no retry"
        ) from failure
    return {
        "status": status,
        "windowId": receipt["windowId"],
        "rootWriteAttempted": False,
        "controllersRestoredToZero": cleanup.get("controllersStopped") == 14,
        "sessionSecretAbsent": cleanup.get("sessionSecretAbsent") is True,
        "resultPath": str(result),
    }


def recover(path: Path, acknowledgement: str, *, operations=None) -> dict:
    if acknowledgement != RECOVER_ACK:
        raise ToolError("distinct continuation recovery-only acknowledgement required")
    reviewed = auth.validate(path, require_approved=True, recovery_only=True)
    receipt = auth.verify_claim(path, require_active=False)
    assert_recovery_eligible(receipt)
    # A claim alone does not authorize cleanup of somebody else's session. There
    # must be a durable record that this exact window attempted protection.
    journal_path = auth.CLAIM_ROOT / f"{receipt['windowId']}.state.jsonl"
    raw = auth.create._read_private(journal_path).decode()
    lines = [json.loads(line) for line in raw.splitlines()]
    if (
        not lines
        or lines[0]
        != {"windowId": receipt["windowId"], "type": auth.AUTHORIZATION_TYPE}
        or not any(line.get("event") == "PROTECTION_STARTED" for line in lines[1:])
    ):
        raise ToolError(
            "continuation has no recorded protection attempt; recovery writes forbidden"
        )
    contract = runtime_contract(path, reviewed, recovery_only=True)
    if operations is None:
        from u1_continuation_operations import RealOperations

        operations = RealOperations(reviewed)
    cleanup = operations.cleanup(
        contract, expected_environment_uid=reviewed["document"]["rootUid"]
    )
    verify_parked_report(cleanup)
    result = {
        "status": "U1_CONTINUATION_RECOVERY_COMPLETE",
        "windowId": receipt["windowId"],
        "rootUid": reviewed["document"]["rootUid"],
        "cleanup": cleanup,
        "authorizationSha256": receipt["authorizationSha256"],
        "activeOperations": False,
        "awsApiCalls": False,
        "oldWindowResultRewritten": False,
    }
    base._write_private_json(
        RESULT_ROOT / f"{receipt['windowId']}.recovery.json", result
    )
    return {"status": result["status"], "windowId": receipt["windowId"]}


def verify_parked_report(cleanup: dict) -> None:
    required = {
        "controllersStopped": 14,
        "sessionSecretAbsent": True,
        "sharedProtectionRestored": True,
        "environmentPresent": True,
        "environmentDeleted": False,
        "awsDeletionAttempted": False,
    }
    if any(
        not auth.identity.strict_equal(cleanup.get(k), v) for k, v in required.items()
    ):
        raise ToolError(
            "continuation cleanup did not prove the complete parked baseline"
        )


def assert_recovery_eligible(receipt: dict) -> None:
    """Never re-clean a successful window, or interrupt a still-active window."""
    window = receipt["windowId"]
    if (RESULT_ROOT / f"{window}.recovery.json").exists():
        raise ToolError("continuation recovery already completed; do not repeat")
    path = RESULT_ROOT / f"{window}.json"
    if path.exists():
        result = auth.create._load_json(path)
        if (
            result.get("windowId") != window
            or result.get("authorizationSha256") != receipt["authorizationSha256"]
            or result.get("rootUid") != receipt["rootUid"]
            or result.get("status") != "U1_CONTINUATION_RECOVERY_REQUIRED"
        ):
            raise ToolError(
                "continuation result does not authorize recovery-only writes"
            )
    elif datetime.now(timezone.utc) < auth.create._timestamp(
        receipt["deadline"], "deadline", allow_future=True
    ):
        raise ToolError(
            "continuation may still be active; recovery-only must wait for claim expiry"
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run", "recover"))
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--profile", default="")
    parser.add_argument("--audit-profile", default="")
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args(argv)
    try:
        if args.mode == "plan":
            if args.acknowledge or args.profile or args.audit_profile:
                raise ToolError("local plan accepts no execution options")
            result = auth.public_plan(
                auth.validate(args.authorization, require_approved=False)
            )
        elif args.mode == "recover":
            if args.profile or args.audit_profile:
                raise ToolError("recovery-only takes no AWS profiles")
            result = recover(args.authorization, args.acknowledge)
        else:
            result = execute(
                args.authorization, args.profile, args.audit_profile, args.acknowledge
            )
        print(json.dumps(result, indent=2))
        return 0
    except (ToolError, OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "U1 continuation failed closed; private values suppressed", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
