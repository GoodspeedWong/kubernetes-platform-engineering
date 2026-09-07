from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))

from common import ToolError, load_yaml
import run_u1_cidr_amendment as runner
import u1_cidr_amendment as amendment
import u1_environment_identity as identity
import validate_u1_cidr_authorization as auth
import validate_u1_continuation as continuation
from test_u1_authorization import CODE_STATE, environment, snapshot
from test_u1_continuation import PIN


def intent_fixture():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "environment.yaml"
        path.write_bytes(environment())
        return load_yaml(path)


def root_for(intent):
    root = copy.deepcopy(intent)
    root["metadata"].update(uid="root-uid", resourceVersion="123", generation=3)
    root["metadata"]["labels"][identity.COMPOSITE_LABEL] = "eks-dev-spot"
    root["spec"]["crossplane"].update(
        compositionRef={"name": PIN.composition_name},
        compositionRevisionRef={"name": PIN.revision_name},
    )
    return root


class PureAmendmentTests(unittest.TestCase):
    def setUp(self):
        self.before = intent_fixture()
        self.after = amendment.candidate(self.before, ["8.8.8.8/32", "9.9.9.9/32"])
        self.root = root_for(self.before)

    def test_only_cidr_changes_and_inputs_are_not_modified(self):
        before = copy.deepcopy(self.before)
        root = copy.deepcopy(self.root)
        amendment.verify_delta(self.before, self.after)
        value = amendment.patch_for(self.root, self.before, self.after, "root-uid", PIN)
        self.assertEqual(["test"] * 4 + ["replace"], [x["op"] for x in value])
        self.assertEqual(amendment.FIELD, value[-1]["path"])
        self.assertEqual(before, self.before)
        self.assertEqual(root, self.root)

    def test_invalid_cidrs_rejected(self):
        for value in (
            [],
            ["0.0.0.0/0"],
            ["8.8.8.0/24"],
            ["10.1.1.1/32"],
            ["127.0.0.1/32"],
            ["224.1.1.1/32"],
            ["::1/128"],
            [True],
            ["8.8.8.8/32", "8.8.8.8/32"],
            ["9.9.9.9/32", "8.8.8.8/32"],
            ["1.1.1.1/32", "8.8.8.8/32", "9.9.9.9/32"],
            "8.8.8.8/32",
        ):
            with self.subTest(value=value), self.assertRaises(ToolError):
                amendment.candidate(self.before, value)

    def test_noop_rejected(self):
        with self.assertRaises(ToolError):
            amendment.candidate(
                self.after,
                self.after["spec"]["parameters"]["access"]["publicAccessCidrs"],
            )

    def test_other_intent_and_metadata_changes_rejected(self):
        for mutate in (
            lambda x: x["spec"]["parameters"].update(region="us-west-2"),
            lambda x: x["spec"]["parameters"]["compute"]["limits"].update(cpu="32"),
            lambda x: x["spec"]["parameters"]["lifecycle"].update(
                deletionProtection=False
            ),
            lambda x: x["spec"]["crossplane"].update(
                compositionUpdatePolicy="Automatic"
            ),
            lambda x: x["metadata"].update(annotations={}),
        ):
            value = copy.deepcopy(self.after)
            mutate(value)
            with self.assertRaises(ToolError):
                amendment.verify_delta(self.before, value)

    def test_root_uid_rv_pin_children_and_bool_generation_rejected(self):
        for mutate in (
            lambda x: x["metadata"].update(uid="replacement"),
            lambda x: x["metadata"].update(resourceVersion=""),
            lambda x: x["metadata"].update(generation=True),
            lambda x: x["metadata"].update(deletionTimestamp="now"),
            lambda x: x["spec"]["crossplane"].update(
                compositionRevisionRef={"name": "wrong"}
            ),
            lambda x: x["spec"]["crossplane"].update(
                resourceRefs=[{"kind": "XNetwork"}]
            ),
        ):
            value = copy.deepcopy(self.root)
            mutate(value)
            with self.assertRaises(ToolError):
                amendment.patch_for(value, self.before, self.after, "root-uid", PIN)

    def changed_root(self):
        value = root_for(self.after)
        value["metadata"].update(generation=4, resourceVersion="124")
        return value

    def test_readback_rejects_rv_generation_and_additional_metadata_mutation(self):
        value = self.changed_root()
        amendment.verify_readback(
            self.root, value, self.before, self.after, "root-uid", PIN
        )
        for mutate in (
            lambda x: x["metadata"].update(resourceVersion="123"),
            lambda x: x["metadata"].update(generation=5),
            lambda x: x["metadata"].update(
                finalizers=["composite.apiextensions.crossplane.io"]
            ),
            lambda x: x["spec"]["parameters"]["access"].update(
                adminPrincipalArn="changed"
            ),
        ):
            value = self.changed_root()
            mutate(value)
            with self.assertRaises(ToolError):
                amendment.verify_readback(
                    self.root, value, self.before, self.after, "root-uid", PIN
                )

    def test_dry_run_can_keep_rv_but_must_preserve_all_other_intent(self):
        value = self.changed_root()
        value["metadata"]["resourceVersion"] = "123"
        amendment.verify_readback(
            self.root, value, self.before, self.after, "root-uid", PIN, dry_run=True
        )


class FakeOperations:
    def __init__(self, reviewed):
        self.reviewed = reviewed
        self.calls = []
        self.fail = None
        self.drift_before_write = False
        self.drift_after = False

    def observation(self, intent):
        phase = "after" if intent == self.reviewed["after"] else "before"
        self.calls.append(phase)
        if self.fail == phase:
            raise ToolError("synthetic observation failure")
        root = root_for(intent)
        if phase == "after":
            root["metadata"].update(generation=4, resourceVersion="124")
        if self.drift_before_write and self.calls.count("before") == 2:
            root["metadata"]["resourceVersion"] = "999"
        checks = copy.deepcopy(amendment.CHECKS)
        if self.drift_after and phase == "after":
            checks["controllerPods"] = 1
        return {
            "observedAt": runner.now(),
            "root": root,
            "compositionPin": asdict(PIN),
            "checks": checks,
            "egress": {"host": "8.8.8.8", "kind": "9.9.9.9"},
            "actor": self.reviewed["document"]["actor"],
        }

    def patch(self, value, before_root, *, dry_run):
        phase = "dry-run" if dry_run else "patch"
        self.calls.append(phase)
        if self.fail == phase:
            raise subprocess.TimeoutExpired("synthetic", 1)
        root = root_for(self.reviewed["after"])
        root["metadata"].update(
            generation=4, resourceVersion="123" if dry_run else "124"
        )
        return root


class AuthorizationAndExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.directory = self.root / "u1-root-cidr-change-2026-09-07-01"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "authorization-contract.json"
        self.state = self.root / "state"
        self.before = intent_fixture()
        self.after = amendment.candidate(self.before, ["8.8.8.8/32", "9.9.9.9/32"])
        self.sources = {"synthetic": "source evidence is mocked, no APIs"}
        self.evidence = {
            "environment": self.before,
            "rootUid": "root-uid",
            "pin": PIN,
            "sourceWindow": "u1b-20260905-01",
            "archive": self.directory,
            "proof": {"core-readonly-evidence": {"controllers": []}},
        }
        self.doc = {
            "schemaVersion": 1,
            "authorizationType": auth.TYPE,
            "bundle": self.directory.name,
            "windowId": "u1ip-20260907-01",
            "generatedAt": (
                datetime.now(timezone.utc) - timedelta(minutes=20)
            ).isoformat(),
            "reviewStatus": auth.PENDING,
            "approvedBy": None,
            "approvedAt": None,
            "executionCode": copy.deepcopy(CODE_STATE),
            "scope": copy.deepcopy(auth.SCOPE),
            "sourcesSha256": "",
            "rootUid": "root-uid",
            "compositionPin": asdict(PIN),
            "sourceCreateWindow": "u1b-20260905-01",
            "beforeIntentSha256": identity.spec_digest(self.before),
            "afterIntentSha256": identity.spec_digest(self.after),
            "candidateCidrs": ["8.8.8.8/32", "9.9.9.9/32"],
            "egressObservation": None,
            "actor": None,
            "exclusiveMaintenanceAcknowledged": False,
        }
        for owner, name, value in (
            (continuation, "source_evidence", self.evidence),
            (auth.create, "execution_code_state", CODE_STATE),
            (runner.base.u0_runner, "controller_inventory", ["crossplane"]),
        ):
            patcher = patch.object(owner, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        blocker = patch.object(
            subprocess,
            "run",
            side_effect=AssertionError("offline test attempted a command/API"),
        )
        blocker.start()
        self.addCleanup(blocker.stop)
        self.save()

    def save_json(self, path, data):
        path.write_text(json.dumps(data))
        path.chmod(0o600)

    def save(self):
        self.save_json(self.directory / "sources.json", self.sources)
        self.save_json(self.directory / "REVIEW_SUMMARY.md", "synthetic private review")
        self.doc["sourcesSha256"] = continuation.digest(self.directory / "sources.json")
        self.save_json(self.path, self.doc)
        manifest = self.directory / "SHA256SUMS"
        manifest.write_text(
            "".join(
                f"{continuation.digest(self.directory / n)}  {n}\n"
                for n in sorted(continuation.FILES)
            )
        )
        manifest.chmod(0o600)

    def approve(self):
        self.doc.update(
            reviewStatus=auth.APPROVED,
            approvedBy="synthetic reviewer",
            approvedAt=runner.now(),
            exclusiveMaintenanceAcknowledged=True,
            actor={
                "username": "test-owner",
                "groups": ["system:authenticated", "test-approvers"],
            },
            egressObservation={
                "observedAt": (
                    datetime.now(timezone.utc) - timedelta(minutes=5)
                ).isoformat(),
                "host": "8.8.8.8",
                "kind": "9.9.9.9",
            },
        )
        self.save()

    def reviewed(self):
        return auth.validate(self.path, require_approved=True)

    def invoke(self, ops=None):
        return runner.execute(
            self.path,
            auth.ACK,
            operations=ops or FakeOperations(self.reviewed()),
            state_root=self.state,
        )

    def success(self):
        self.approve()
        ops = FakeOperations(self.reviewed())
        result = self.invoke(ops)
        return result, ops

    def test_plan_is_inert_and_draft_cannot_claim_or_run(self):
        plan = auth.public_plan(auth.validate(self.path, require_approved=False))
        self.assertFalse(plan["approved"])
        self.assertFalse(plan["claimCreated"])
        for call in (
            lambda: auth.claim(self.path, auth.ACK, root=self.state),
            lambda: runner.execute(self.path, auth.ACK, state_root=self.state),
        ):
            with self.assertRaises(ToolError):
                call()
        self.assertFalse(self.state.exists())

    def test_old_ack_and_window_namespace_rejected(self):
        with self.assertRaises(ToolError):
            runner.execute(
                self.path, continuation.CLAIM_ACKNOWLEDGEMENT, state_root=self.state
            )
        self.doc["windowId"] = "u1c-20260907-01"
        self.save()
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)

    def test_binding_scope_and_strict_types_rejected(self):
        original = copy.deepcopy(self.doc)
        for key, value in (
            ("rootUid", "new"),
            ("schemaVersion", True),
            ("beforeIntentSha256", "a" * 64),
            ("afterIntentSha256", "b" * 64),
            ("sourceCreateWindow", "new"),
            ("compositionPin", asdict(replace(PIN, revision_uid="new"))),
            ("scope", auth.SCOPE | {"awsApiCallsAllowed": True}),
            ("executionCode", CODE_STATE | {"gitCommit": "9" * 40}),
        ):
            self.doc = original | {key: value}
            self.save()
            with self.subTest(key=key), self.assertRaises(ToolError):
                auth.validate(self.path, require_approved=False)

    def test_approval_requires_fresh_both_paths_actor_and_maintenance(self):
        self.approve()
        original = copy.deepcopy(self.doc)
        for key, value in (
            ("egressObservation", None),
            ("actor", None),
            ("exclusiveMaintenanceAcknowledged", 1),
            ("egressObservation", self.doc["egressObservation"] | {"kind": "1.1.1.1"}),
            (
                "egressObservation",
                self.doc["egressObservation"]
                | {
                    "observedAt": (
                        datetime.now(timezone.utc) - timedelta(hours=1)
                    ).isoformat()
                },
            ),
            (
                "approvedAt",
                (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            ),
        ):
            self.doc = original | {key: value}
            self.save()
            with self.subTest(key=key), self.assertRaises(ToolError):
                self.reviewed()

    def test_second_amendment_is_not_accepted(self):
        self.sources["cidrAmendment"] = {}
        self.save()
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)

    def test_claim_is_exclusive_private_and_not_old_create_authority(self):
        self.approve()
        reviewed, claim = auth.claim(self.path, auth.ACK, root=self.state)
        auth.verify_claim(claim, reviewed, active=True)
        self.assertEqual(
            0o600,
            (self.state / (self.doc["windowId"] + ".claim.json")).stat().st_mode
            & 0o777,
        )
        with self.assertRaises(ToolError):
            auth.claim(self.path, auth.ACK, root=self.state)
        for changed in (
            claim | {"rootUid": "new"},
            claim | {"status": continuation.CLAIM_STATUS},
            claim
            | {
                "deadline": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).isoformat()
            },
        ):
            with self.assertRaises(ToolError):
                auth.verify_claim(changed, reviewed, active=True)

    def test_private_files_symlinks_and_extra_files_rejected(self):
        self.path.chmod(0o644)
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)
        self.path.chmod(0o600)
        extra = self.directory / "extra"
        extra.write_text("no")
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)
        extra.unlink()
        saved = self.path.read_bytes()
        self.path.unlink()
        target = self.root / "target"
        target.write_bytes(saved)
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)

    def test_success_one_patch_and_full_receipt_roundtrip(self):
        result, ops = self.success()
        self.assertEqual(auth.PASS, result["status"])
        self.assertEqual(["before", "dry-run", "before", "patch", "after"], ops.calls)
        self.assertFalse(result["awsApiCalls"])
        self.assertFalse(result["continuationAuthorized"])
        self.assertEqual(
            self.after,
            auth.verify_receipt(
                auth.reference(result["receipt"]), self.sources, self.evidence
            ),
        )
        self.assertFalse(list(self.state.glob("*.failure.json")))
        with self.assertRaises(ToolError):
            self.invoke()

    def test_failures_never_retry_rollback_or_issue_receipt(self):
        self.approve()
        for stage in ("before", "dry-run", "patch", "after"):
            with self.subTest(stage=stage):
                self.state = self.root / ("state-" + stage)
                ops = FakeOperations(self.reviewed())
                ops.fail = stage
                with self.assertRaises(ToolError):
                    self.invoke(ops)
                self.assertLessEqual(ops.calls.count("patch"), 1)
                self.assertFalse(list(self.state.glob("*.receipt.json")))
                failure = auth.create._load_json(
                    next(self.state.glob("*.failure.json"))
                )
                self.assertIs(
                    failure["writeMayHaveOccurred"], stage in ("patch", "after")
                )

    def test_rv_drift_after_dry_run_stops_before_write(self):
        self.approve()
        ops = FakeOperations(self.reviewed())
        ops.drift_before_write = True
        with self.assertRaises(ToolError):
            self.invoke(ops)
        self.assertNotIn("patch", ops.calls)

    def test_post_write_controller_drift_is_not_success(self):
        self.approve()
        ops = FakeOperations(self.reviewed())
        ops.drift_after = True
        with self.assertRaises(ToolError):
            self.invoke(ops)
        self.assertFalse(list(self.state.glob("*.receipt.json")))

    def test_prewrite_durability_failure_prevents_patch(self):
        self.approve()
        ops = FakeOperations(self.reviewed())
        original = runner.base._write_private_json

        def write(path, document):
            if path.name.endswith(".write-intent.json"):
                raise OSError("synthetic fsync failure")
            return original(path, document)

        with (
            patch.object(runner.base, "_write_private_json", side_effect=write),
            self.assertRaises(ToolError),
        ):
            self.invoke(ops)
        self.assertNotIn("patch", ops.calls)

    def test_deadline_interrupt_does_not_clean_up_or_mutate(self):
        self.approve()
        ops = FakeOperations(self.reviewed())
        ops.observation = Mock(
            side_effect=runner.base.ExecutionDeadlineExceeded("synthetic")
        )
        with self.assertRaises(ToolError):
            self.invoke(ops)
        self.assertEqual([], ops.calls)

    def test_receipt_tampering_and_incomplete_checks_rejected_even_rehashed(self):
        result, _ = self.success()
        receipt_path = Path(result["receipt"])
        receipt = auth.create._load_json(receipt_path)
        after_path = Path(receipt["after"]["path"])
        original = auth.create._load_json(after_path)
        for mutate in (
            lambda x: x["checks"].update(controllerPods=1),
            lambda x: x["checks"].update(roots=True),
            lambda x: x["root"]["spec"]["parameters"]["compute"]["limits"].update(
                cpu="32"
            ),
            lambda x: x["root"]["metadata"].update(uid="replacement"),
            lambda x: x["egress"].update(host="1.1.1.1"),
            lambda x: x["actor"].update(username="different"),
            lambda x: x.update(observedAt=self.doc["generatedAt"]),
        ):
            changed = copy.deepcopy(original)
            mutate(changed)
            self.save_json(after_path, changed)
            receipt["after"] = auth.reference(after_path)
            self.save_json(receipt_path, receipt)
            with self.assertRaises(ToolError):
                auth.verify_receipt(
                    auth.reference(receipt_path), self.sources, self.evidence
                )

    def test_receipt_unknown_outcome_marker_rejects_otherwise_valid_chain(self):
        result, _ = self.success()
        self.save_json(
            self.state / (self.doc["windowId"] + ".failure.json"),
            {"status": "ambiguous"},
        )
        with self.assertRaises(ToolError):
            auth.verify_receipt(
                auth.reference(result["receipt"]), self.sources, self.evidence
            )

    def test_receipt_cannot_mix_claim_fragments_or_original_sources(self):
        result, _ = self.success()
        ref = auth.reference(result["receipt"])
        for source in ({}, self.sources | {"other": "source"}):
            with self.assertRaises(ToolError):
                auth.verify_receipt(ref, source, self.evidence)
        receipt = auth.create._load_json(Path(result["receipt"]))
        receipt["claim"] = receipt["before"]
        self.save_json(Path(result["receipt"]), receipt)
        with self.assertRaises(ToolError):
            auth.verify_receipt(
                auth.reference(result["receipt"]), self.sources, self.evidence
            )

    def test_receipt_does_not_reauthorize_stale_code_for_new_run(self):
        result, _ = self.success()
        with patch.object(
            auth.create,
            "execution_code_state",
            return_value=CODE_STATE | {"gitCommit": "9" * 40},
        ):
            auth.verify_receipt(
                auth.reference(result["receipt"]), self.sources, self.evidence
            )
            with self.assertRaises(ToolError):
                self.reviewed()

    def test_continuation_derives_only_receipted_intent_without_editing_archive(self):
        result, _ = self.success()
        ref = auth.reference(result["receipt"])
        original = copy.deepcopy(self.evidence)
        amended = continuation.amended_evidence(
            self.evidence, self.sources | {"cidrAmendment": ref}, self.sources
        )
        self.assertIs(True, amended["cidrAmendmentVerified"])
        self.assertEqual(self.after, amended["environment"])
        self.assertEqual(original, self.evidence)
        self.assertIs(
            self.evidence,
            continuation.amended_evidence(self.evidence, self.sources, self.sources),
        )
        with self.assertRaises(ToolError):
            continuation.amended_evidence(
                self.evidence,
                self.sources | {"cidrAmendment": ref | {"sha256": "0" * 64}},
                self.sources,
            )

    def test_receipt_missing_prewrite_evidence_cannot_authorize_continuation(self):
        result, _ = self.success()
        receipt = auth.create._load_json(Path(result["receipt"]))
        Path(receipt["writeIntent"]["path"]).unlink()
        with self.assertRaises(ToolError):
            auth.verify_receipt(
                auth.reference(result["receipt"]), self.sources, self.evidence
            )

    def test_receipt_prewrite_rv_drift_is_rejected_even_if_rehashed(self):
        result, _ = self.success()
        receipt_path = Path(result["receipt"])
        receipt = auth.create._load_json(receipt_path)
        pre_write_path = Path(receipt["preWrite"]["path"])
        value = auth.create._load_json(pre_write_path)
        value["root"]["metadata"]["resourceVersion"] = "different"
        self.save_json(pre_write_path, value)
        receipt["preWrite"] = auth.reference(pre_write_path)
        self.save_json(receipt_path, receipt)
        with self.assertRaises(ToolError):
            auth.verify_receipt(
                auth.reference(receipt_path), self.sources, self.evidence
            )

    def test_receipt_extended_deadline_rejected_even_with_updated_hash(self):
        result, _ = self.success()
        receipt = auth.create._load_json(Path(result["receipt"]))
        claim_path = Path(receipt["claim"]["path"])
        value = auth.create._load_json(claim_path)
        value["deadline"] = (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).isoformat()
        self.save_json(claim_path, value)
        receipt["claim"] = auth.reference(claim_path)
        self.save_json(Path(result["receipt"]), receipt)
        with self.assertRaises(ToolError):
            auth.verify_receipt(
                auth.reference(result["receipt"]), self.sources, self.evidence
            )

    def test_partial_receipt_never_gets_overwritten(self):
        self.approve()
        self.state.mkdir(mode=0o700)
        target = self.state / (self.doc["windowId"] + ".receipt.json")
        self.save_json(target, {"incomplete": True})
        with self.assertRaises(ToolError):
            self.invoke()
        self.assertEqual({"incomplete": True}, auth.create._load_json(target))

    def test_advisory_lock_blocks_parallel_cidr_process(self):
        with runner.exclusive_run(self.state), self.assertRaises(ToolError):
            with runner.exclusive_run(self.state):
                self.fail("parallel lock acquired")

    def test_live_adapter_denies_inherited_writes_and_all_aws_apis(self):
        self.approve()
        ops = runner.RealOperations(self.reviewed())
        for arguments in (
            ("apply", "-f", "-"),
            ("patch", "deployment", "crossplane"),
            ("get", "secrets"),
            ("get", "objects.kubernetes.crossplane.io"),
        ):
            with self.assertRaises(ToolError):
                ops._kube(ops.contract, *arguments)
        with self.assertRaises(ToolError):
            ops._aws_json(None, "audit", "sts", "get-caller-identity")
        with self.assertRaises(ToolError):
            ops._verify_claim(ops.contract)

    def test_live_stop_gate_rejects_bool_replicas_and_wrong_inventory(self):
        self.approve()
        ops = runner.RealOperations(self.reviewed())
        values = {
            str(n): {"spec": {"replicas": 0}, "status": {"replicas": 0}}
            for n in range(14)
        }
        with patch.object(ops, "_assert_controller_identity", return_value=values):
            ops._assert_stopped(ops.contract)
            values["0"]["spec"]["replicas"] = False
            with self.assertRaises(ToolError):
                ops._assert_stopped(ops.contract)
            values.pop("0")
            with self.assertRaises(ToolError):
                ops._assert_stopped(ops.contract)

    def test_actor_exact_identity_and_permission_are_required(self):
        self.approve()
        ops = runner.RealOperations(self.reviewed())
        info = {"status": {"userInfo": self.doc["actor"]}}
        with patch.object(
            runner.base, "_run_text", side_effect=[json.dumps(info), "yes", "yes"]
        ):
            self.assertEqual(self.doc["actor"], ops.actor())
        for values in (
            [json.dumps(info), "no"],
            [
                json.dumps(
                    {"status": {"userInfo": self.doc["actor"] | {"username": "other"}}}
                )
            ],
        ):
            with (
                patch.object(runner.base, "_run_text", side_effect=values),
                self.assertRaises(ToolError),
            ):
                ops.actor()

    def test_live_egress_paths_are_independent_and_proxy_unset(self):
        self.approve()
        ops = runner.RealOperations(self.reviewed())
        with patch.object(
            runner.base,
            "_run_text",
            side_effect=["8.8.8.8", "kube-nebula-a-control-plane", "9.9.9.9"],
        ) as command:
            ops.egress()
            calls = command.call_args_list
            self.assertEqual("curl", calls[0].args[0][0])
            self.assertEqual(
                ["docker", "exec", "kube-nebula-a-control-plane", "env"],
                calls[2].args[0][:4],
            )
            self.assertIn("HTTPS_PROXY", calls[2].args[0])
            self.assertIn("https_proxy", calls[2].args[0])
        with (
            patch.object(
                runner.base,
                "_run_text",
                side_effect=["8.8.8.8", "kube-nebula-a-control-plane", "1.1.1.1"],
            ),
            self.assertRaises(ToolError),
        ):
            ops.egress()

    def test_observation_uses_readonly_assertions_and_rejects_pods_or_session(self):
        self.approve()
        ops = runner.RealOperations(self.reviewed())
        reader = Mock()
        root = root_for(self.before)

        def get(path, **kwargs):
            if "xeksenvironments" in path:
                return [{"metadata": root["metadata"]}]
            return []

        reader.get.side_effect = get
        with (
            patch.object(runner, "ReadOnlyMetadata") as transport,
            patch.object(ops, "_assert_stopped"),
            patch.object(ops, "_session_present", return_value=False) as session,
            patch.object(ops, "_assert_shared"),
            patch.object(ops, "_assert_managed"),
            patch.object(ops, "_assert_permanent"),
            patch.object(ops, "_assert_catalogs"),
            patch.object(ops, "_assert_environment_identity"),
            patch.object(ops, "actor", return_value=self.doc["actor"]),
            patch.object(
                ops, "egress", return_value={"host": "8.8.8.8", "kind": "9.9.9.9"}
            ),
            patch.object(ops, "_kube", return_value=root),
        ):
            transport.return_value.__enter__.return_value = reader
            self.assertEqual(amendment.CHECKS, ops.observation(self.before)["checks"])
            session.return_value = True
            with self.assertRaises(ToolError):
                ops.observation(self.before)
            session.return_value = False
            reader.get.side_effect = lambda path, **kwargs: (
                [{}] if path.endswith("/pods") else get(path, **kwargs)
            )
            with self.assertRaises(ToolError):
                ops.observation(self.before)

    def test_transport_has_only_one_patch_with_stdin_and_bounded_timeout(self):
        self.approve()
        reviewed = self.reviewed()
        ops = runner.RealOperations(reviewed)
        root = root_for(self.before)
        value = amendment.patch_for(root, self.before, self.after, "root-uid", PIN)
        response = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")
        with patch.object(runner.subprocess, "run", return_value=response) as command:
            ops.patch(value, root, dry_run=True)
            self.assertIn("--dry-run=server", command.call_args.args[0])
            ops.patch(value, root, dry_run=False)
            self.assertNotIn("--dry-run=server", command.call_args.args[0])
            self.assertIn("--patch-file=/dev/stdin", command.call_args.args[0])
            self.assertEqual(45, command.call_args.kwargs["timeout"])
            self.assertEqual(value, json.loads(command.call_args.kwargs["input"]))
            with self.assertRaises(ToolError):
                ops.patch(value, root, dry_run=False)
            self.assertEqual(2, command.call_count)

    def test_transport_rejects_widened_patch_before_subprocess(self):
        self.approve()
        ops = runner.RealOperations(self.reviewed())
        root = root_for(self.before)
        value = amendment.patch_for(root, self.before, self.after, "root-uid", PIN)
        value.append({"op": "replace", "path": "/spec/replicas", "value": 1})
        with self.assertRaises(ToolError):
            ops.patch(value, root, dry_run=True)

    def test_transport_unknown_outcome_cannot_be_retried(self):
        self.approve()
        ops = runner.RealOperations(self.reviewed())
        root = root_for(self.before)
        value = amendment.patch_for(root, self.before, self.after, "root-uid", PIN)
        ops.dry_run_attempted = True
        with patch.object(
            runner.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("synthetic", 1),
        ) as command:
            for _ in range(2):
                with self.assertRaises(ToolError):
                    ops.patch(value, root, dry_run=False)
            self.assertEqual(1, command.call_count)


if __name__ == "__main__":
    unittest.main()
