#!/usr/bin/env python3
"""Local plan, or ONE separately approved Kubernetes-only root CIDR patch.

Never call this run mode under a local-code-only approval. No AWS API, STS,
session publication, controller write, apply, rollback or automatic retry exists
in this workflow. Unknown write outcomes need separately authorized read-only
diagnosis; a failed window never produces a continuation receipt.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import json
import os
import stat
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from common import ToolError
import run_u1_bootstrap as base
import u1_cidr_amendment as amendment
import u1_continuation_operations as continuation_ops
import u1_environment_identity as identity
import validate_u1_cidr_authorization as auth
from u1_readonly_metadata import ReadOnlyMetadata

RESOURCE = "xeksenvironment.platform.aws.goodnotes.io"


def now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def exclusive_run(root):
    """Serialize this entry point; operator approval must also exclude other tools."""
    root = auth.create.u0_authorization._claim_root(root, create=True)
    descriptor = os.open(
        root / "execution.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ToolError("CIDR execution lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ToolError("another CIDR window is active") from error
        yield
    finally:
        os.close(descriptor)


class RealOperations(continuation_ops.RealOperations):
    """Reuse ONLY audited read assertions; deny inherited mutation/AWS dispatch."""

    def __init__(self, reviewed):
        super().__init__(reviewed)
        self.contract = SimpleNamespace(
            bootstrap=SimpleNamespace(context=auth.SCOPE["context"]),
            environment="eks-dev-spot",
            bundle_directory=self.evidence["archive"],
            environment_document=reviewed["before"],
            controller_names=base.u0_runner.controller_inventory(),
        )
        self.write_attempted = False
        self.dry_run_attempted = False

    def _aws_json(self, *_args, **_kwargs):
        raise ToolError("CIDR-only window forbids every AWS API including reads")

    def _assert_stopped(self, contract, **kwargs):
        deployments = self._assert_controller_identity(contract, **kwargs)
        if len(deployments) != 14:
            raise ToolError("CIDR window requires exactly fourteen locked controllers")
        for document in deployments.values():
            if not all(
                identity.strict_equal(value, 0)
                for value in (
                    document.get("spec", {}).get("replicas", 1),
                    document.get("status", {}).get("replicas", 0),
                )
            ):
                raise ToolError("CIDR controller replicas must be integer zero")

    def _verify_claim(self, _contract):
        # Inherited active workflows must not be usable through this adapter.
        raise ToolError(
            "CIDR adapter cannot enter inherited session/controller workflows"
        )

    def _kube(self, contract, *args, body=None):
        read = args[2:] if args[:1] == ("--namespace",) else args
        if (
            not read
            or read[0] != "get"
            or body is not None
            or len(read) not in (2, 3)
            or any(x.startswith("-") for x in read[1:])
            or any(
                x in read[1].lower()
                for x in ("secret", "object.kubernetes", "objects.kubernetes")
            )
        ):
            raise ToolError("CIDR adapter permits only bounded non-secret GETs")
        return super()._kube(contract, *args, body=None)

    def actor(self):
        command = ["kubectl", "--context", auth.SCOPE["context"]]
        # These are non-persistent identity/authorization review API requests.
        result = json.loads(base._run_text(command + ["auth", "whoami", "-o", "json"]))
        actor = amendment.actor_identity(result["status"]["userInfo"])
        if not identity.strict_equal(actor, self.reviewed["document"]["actor"]):
            raise ToolError("CIDR effective actor changed")
        for verb in ("get", "patch"):
            if (
                base._run_text(
                    command + ["auth", "can-i", verb, RESOURCE + "/eks-dev-spot"]
                )
                != "yes"
            ):
                raise ToolError("CIDR effective actor lacks exact root permission")
        return actor

    def egress(self):
        curl = ["curl", "-fsS", "--max-time", "15", "https://checkip.amazonaws.com"]
        host = base._run_text(curl, timeout=20)
        nodes = base._run_text(
            ["kind", "get", "nodes", "--name", "kube-nebula-a"]
        ).splitlines()
        planes = [n for n in nodes if n.endswith("control-plane")]
        if planes != ["kube-nebula-a-control-plane"]:
            raise ToolError("CIDR KinD egress source node differs")
        unset = ["env"]
        for variable in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            unset.extend(["-u", variable])
        kind = base._run_text(["docker", "exec", planes[0], *unset, *curl], timeout=20)
        observed = {"host": host, "kind": kind}
        expected = {
            k: self.reviewed["document"]["egressObservation"][k] for k in observed
        }
        if not identity.strict_equal(observed, expected):
            raise ToolError("CIDR live dual egress differs; window cannot retry")
        return observed

    def observation(self, intent):
        self.contract.environment_document = intent
        # Entering the metadata reader first rejects exec/auth-provider contexts.
        with ReadOnlyMetadata(auth.SCOPE["context"]) as reader:
            self._assert_stopped(self.contract)
            pods = reader.get("/api/v1/namespaces/crossplane-system/pods", many=True)
            if pods or self._session_present(self.contract, reader):
                raise ToolError("CIDR window requires zero runtime Pods and no session")
            xrs = []
            for resource in base.u0_runner.XR_RESOURCES:
                plural, group = resource.split(".", 1)
                xrs.extend(
                    (resource, x["metadata"]["name"], x["metadata"]["uid"])
                    for x in reader.get(f"/apis/{group}/v1alpha1/{plural}", many=True)
                )
            if xrs != [
                (
                    "xeksenvironments.platform.aws.goodnotes.io",
                    "eks-dev-spot",
                    self.evidence["rootUid"],
                )
            ]:
                raise ToolError("CIDR window requires the sole reviewed childless root")
            self._assert_shared(self.contract, reader)
            self._assert_managed(self.contract, reader)
            self._assert_permanent(self.contract)
            self._assert_catalogs(self.contract)
            actor, egress = self.actor(), self.egress()
            root = self._kube(self.contract, "get", RESOURCE, "eks-dev-spot")
            self._assert_environment_identity(
                self.contract, root, expected_uid=self.evidence["rootUid"]
            )
            # Repeat the fast stopping gates after the slower inventory/egress reads.
            self._assert_stopped(self.contract)
            if reader.get(
                "/api/v1/namespaces/crossplane-system/pods", many=True
            ) or self._session_present(self.contract, reader):
                raise ToolError("CIDR parked state changed during observation")
        result = {
            "observedAt": now(),
            "root": root,
            "compositionPin": asdict(self.evidence["pin"]),
            "checks": copy.deepcopy(amendment.CHECKS),
            "egress": egress,
            "actor": actor,
        }
        amendment.verify_observation(
            result,
            intent,
            self.evidence["rootUid"],
            self.evidence["pin"],
            egress,
            actor,
        )
        return result

    def patch(self, patch, before_root, *, dry_run):
        expected = amendment.patch_for(
            before_root,
            self.reviewed["before"],
            self.reviewed["after"],
            self.evidence["rootUid"],
            self.evidence["pin"],
        )
        if not identity.strict_equal(patch, expected):
            raise ToolError(
                "CIDR patch differs from exact UID/RV/spec-tested single-field request"
            )
        if type(dry_run) is not bool:
            raise ToolError("explicit dry-run boolean required")
        flag = "dry_run_attempted" if dry_run else "write_attempted"
        if getattr(self, flag) or (not dry_run and not self.dry_run_attempted):
            raise ToolError(
                "CIDR adapter forbids repeat requests or writes before dry-run"
            )
        setattr(self, flag, True)  # Includes unknown transport outcomes: never retry.
        command = [
            "kubectl",
            "--context",
            auth.SCOPE["context"],
            "--request-timeout=30s",
            "patch",
            RESOURCE,
            "eks-dev-spot",
            "--type=json",
            "--patch-file=/dev/stdin",
            "-o",
            "json",
        ]
        if dry_run:
            command.append("--dry-run=server")
        try:
            result = subprocess.run(
                command,
                input=json.dumps(patch),
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
                env=base._clean_env(),
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise ToolError("CIDR patch transport outcome unknown; no retry") from error
        if result.returncode:
            raise ToolError("CIDR patch rejected or outcome unknown; output suppressed")
        return json.loads(result.stdout)


def execute(path, acknowledgement, *, operations=None, state_root=None):
    if acknowledgement != auth.ACK:
        raise ToolError("CIDR-specific execution acknowledgement required")
    # Validate before even creating a local lock or claim directory.
    auth.validate(path, require_approved=True)
    directory = state_root or auth.STATE_ROOT
    with exclusive_run(directory):
        reviewed, claim = auth.claim(path, acknowledgement, root=directory)
        window = reviewed["document"]["windowId"]
        directory = auth.create.u0_authorization._claim_root(directory, create=False)
        stage, write_attempted = "CLAIMED", False

        def write(suffix, document):
            return base._write_private_json(
                directory / f"{window}.{suffix}.json", document
            )

        def active():
            current = auth.validate(path, require_approved=True)
            if current["authorizationSha256"] != reviewed["authorizationSha256"]:
                raise ToolError("CIDR authorization changed after claim")
            saved = auth.create._load_json(directory / f"{window}.claim.json")
            if not identity.strict_equal(saved, claim):
                raise ToolError("CIDR claim changed after consumption")
            auth.verify_claim(claim, reviewed, active=True)

        def verify(observation, intent):
            doc = reviewed["document"]
            egress = {k: doc["egressObservation"][k] for k in ("host", "kind")}
            amendment.verify_observation(
                observation,
                intent,
                doc["rootUid"],
                reviewed["evidence"]["pin"],
                egress,
                doc["actor"],
            )
            stamp = auth.create._timestamp(observation["observedAt"], "observedAt")
            if stamp < auth.create._timestamp(claim["claimedAt"], "claimedAt"):
                raise ToolError("CIDR observation predates this execution window")

        try:
            remaining = (
                auth.create._timestamp(claim["deadline"], "deadline", allow_future=True)
                - datetime.now(timezone.utc)
            ).total_seconds()
            with base._bounded_execution_window(remaining):
                for suffix in (
                    "before",
                    "dry-run",
                    "pre-write",
                    "write-intent",
                    "after",
                    "receipt",
                    "failure",
                ):
                    if (directory / f"{window}.{suffix}.json").exists():
                        raise ToolError(
                            "CIDR state artifacts already exist; no API calls allowed"
                        )
                ops = operations if operations is not None else RealOperations(reviewed)
                active()
                before = ops.observation(reviewed["before"])
                verify(before, reviewed["before"])
                before_path = write("before", before)
                stage = "BASELINE_VERIFIED"
                patch = amendment.patch_for(
                    before["root"],
                    reviewed["before"],
                    reviewed["after"],
                    reviewed["document"]["rootUid"],
                    reviewed["evidence"]["pin"],
                )
                active()
                dry = ops.patch(patch, before["root"], dry_run=True)
                amendment.verify_readback(
                    before["root"],
                    dry,
                    reviewed["before"],
                    reviewed["after"],
                    reviewed["document"]["rootUid"],
                    reviewed["evidence"]["pin"],
                    dry_run=True,
                )
                dry_path = write("dry-run", {"root": dry, "observedAt": now()})
                stage = "DRY_RUN_VERIFIED"
                fresh = ops.observation(reviewed["before"])
                verify(fresh, reviewed["before"])
                if not identity.strict_equal(
                    fresh["root"]["metadata"], before["root"]["metadata"]
                ) or not identity.strict_equal(
                    fresh["root"]["spec"], before["root"]["spec"]
                ):
                    raise ToolError(
                        "CIDR root changed after dry-run; no new patch or retry"
                    )
                pre_write_path = write("pre-write", fresh)
                active()
                intent_path = write(
                    "write-intent", auth.write_intent(reviewed, patch, now())
                )
                stage, write_attempted = "WRITE_MAY_HAVE_OCCURRED", True
                actual = ops.patch(patch, before["root"], dry_run=False)
                amendment.verify_readback(
                    before["root"],
                    actual,
                    reviewed["before"],
                    reviewed["after"],
                    reviewed["document"]["rootUid"],
                    reviewed["evidence"]["pin"],
                )
                after = ops.observation(reviewed["after"])
                verify(after, reviewed["after"])
                amendment.verify_readback(
                    before["root"],
                    after["root"],
                    reviewed["before"],
                    reviewed["after"],
                    reviewed["document"]["rootUid"],
                    reviewed["evidence"]["pin"],
                )
                after_path = write("after", after)
                active()
                receipt = {
                    "schemaVersion": 1,
                    "status": auth.PASS,
                    "windowId": window,
                    "authorization": auth.reference(path),
                    "claim": auth.reference(directory / f"{window}.claim.json"),
                    "before": auth.reference(before_path),
                    "dryRun": auth.reference(dry_path),
                    "preWrite": auth.reference(pre_write_path),
                    "writeIntent": auth.reference(intent_path),
                    "after": auth.reference(after_path),
                    "recordedAt": now(),
                }
                receipt_path = write("receipt", receipt)
                # The same consumer check is the completion gate. A failure marker
                # makes even a partially recorded receipt unusable for continuation.
                auth.verify_receipt(
                    auth.reference(receipt_path),
                    reviewed["sources"],
                    reviewed["evidence"],
                )
                return {
                    "status": auth.PASS,
                    "receipt": str(receipt_path),
                    "awsApiCalls": False,
                    "persistentPatchRequests": 1,
                    "continuationAuthorized": False,
                }
        except BaseException:
            write(
                "failure",
                {
                    "windowId": window,
                    "stage": stage,
                    "writeMayHaveOccurred": write_attempted,
                    "status": (
                        "READ_ONLY_DIAGNOSIS_REQUIRED"
                        if write_attempted
                        else "FAILED_BEFORE_PERSISTENT_PATCH"
                    ),
                    "automaticRetryAllowed": False,
                    "recordedAt": now(),
                },
            )
            raise ToolError(
                "CIDR window failed closed; claim consumed, no retry/rollback; inspect private evidence"
            ) from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run"))
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--acknowledge")
    args = parser.parse_args(argv)
    try:
        result = (
            auth.public_plan(auth.validate(args.authorization, require_approved=False))
            if args.mode == "plan"
            else execute(args.authorization, args.acknowledge)
        )
        print(json.dumps(result, indent=2))
        return 0
    except (ToolError, OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "CIDR entry point failed closed; private values suppressed", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
