from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))

from common import ToolError
import prepare_u1_continuation as prepare
import run_u1_continuation as runner
import u1_continuation_definitions as definitions
import u1_continuation_operations as operations
import u1_environment_identity as identity
import u1_readonly_metadata as metadata
import validate_u1_continuation as auth
from test_u1_authorization import CODE_STATE, snapshot
from test_u1_bootstrap import contract, FakeJournal, FakeOperations

PIN = identity.CompositionPin(
    identity.COMPOSITION_NAME,
    "composition-uid",
    identity.COMPOSITION_NAME + "-abc",
    "revision-uid",
    "3" * 64,
)


class ContinuationAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve() / "u1-continuation-2026-09-07-01"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "authorization-contract.json"
        self.sources = {
            "sessionReview": {
                "path": str(self.directory / "a05.json"),
                "sha256": "0" * 64,
            }
        }
        self.evidence = {
            "rootUid": "existing-root-uid",
            "pin": PIN,
            "sourceWindow": "u1b-20260905-01",
            "archive": Path("old-archive"),
            "archivedSpotQuotaVerified": False,
        }
        self.doc = {
            "schemaVersion": 1,
            "authorizationType": auth.AUTHORIZATION_TYPE,
            "bundle": self.directory.name,
            "windowId": "u1c-20260907-01",
            "generatedAt": (
                datetime.now(timezone.utc) - timedelta(minutes=15)
            ).isoformat(),
            "reviewStatus": auth.PENDING,
            "approvedAt": None,
            "approvedBy": None,
            "scope": copy.deepcopy(auth.SCOPE),
            "executionCode": copy.deepcopy(CODE_STATE),
            "sourcesSha256": "",
            "rootUid": "existing-root-uid",
            "compositionPin": asdict(PIN),
            "sourceCreateWindow": "u1b-20260905-01",
            "awsReadOnlySnapshot": None,
        }
        for target, value in (("source_evidence", self.evidence),):
            started = patch.object(auth, target, return_value=value)
            started.start()
            self.addCleanup(started.stop)
        for owner, target, value in (
            (auth.create, "execution_code_state", CODE_STATE),
            (auth.create, "_validate_environment", {}),
            (runner.base, "_session_contract", ({}, contract().bootstrap)),
            (auth, "reference", Path("session-review.json")),
        ):
            started = patch.object(owner, target, return_value=value)
            started.start()
            self.addCleanup(started.stop)
        self.save()

    def save(self):
        for name, doc in (
            ("sources.json", self.sources),
            ("REVIEW_SUMMARY.md", "private draft"),
        ):
            path = self.directory / name
            path.write_text(json.dumps(doc))
            path.chmod(0o600)
        self.doc["sourcesSha256"] = auth.digest(self.directory / "sources.json")
        self.path.write_text(json.dumps(self.doc))
        self.path.chmod(0o600)
        manifest = self.directory / "SHA256SUMS"
        manifest.write_text(
            "".join(
                f"{auth.digest(self.directory / n)}  {n}\n" for n in sorted(auth.FILES)
            )
        )
        manifest.chmod(0o600)

    def approve(self):
        self.doc.update(
            reviewStatus=auth.APPROVED,
            approvedBy="test-reviewer",
            approvedAt=datetime.now(timezone.utc).isoformat(),
            awsReadOnlySnapshot=snapshot(),
        )
        self.save()

    def test_pending_plan_is_local_and_not_authority(self):
        with patch.object(auth, "claim") as claim:
            plan = auth.public_plan(auth.validate(self.path, require_approved=False))
        self.assertFalse(plan["approved"])
        self.assertFalse(plan["oldClaimReusable"])
        self.assertFalse(plan["awsApiCalls"])
        self.assertFalse(plan["kubernetesApiCalls"])
        self.assertFalse(plan["archivedSpotQuotaVerified"])
        self.assertEqual(2, len(plan["blockers"]))
        claim.assert_not_called()

    def test_draft_cannot_claim_or_create_claim_directory(self):
        claim_root = Path(self.tmp.name).resolve() / "claims"
        with self.assertRaises(ToolError):
            auth.claim(self.path, auth.CLAIM_ACKNOWLEDGEMENT, root=claim_root)
        self.assertFalse(claim_root.exists())

    def test_old_create_namespace_and_ack_are_rejected(self):
        for field, value in (
            ("authorizationType", auth.create.AUTHORIZATION_TYPE),
            ("windowId", "u1b-20260907-01"),
        ):
            with self.subTest(field=field):
                before = self.doc[field]
                self.doc[field] = value
                self.save()
                with self.assertRaises(ToolError):
                    auth.validate(self.path, require_approved=False)
                self.doc[field] = before
        with self.assertRaises(ToolError):
            auth.claim(self.path, auth.create.CLAIM_ACKNOWLEDGEMENT)

    def test_same_uid_pin_and_source_window_must_all_match(self):
        for field, value in (
            ("rootUid", "replacement"),
            ("sourceCreateWindow", "u1b-20260905-02"),
            ("compositionPin", asdict(replace(PIN, revision_uid="new-uid"))),
        ):
            with self.subTest(field=field):
                before = self.doc[field]
                self.doc[field] = value
                self.save()
                with self.assertRaises(ToolError):
                    auth.validate(self.path, require_approved=False)
                self.doc[field] = before

    def test_exact_scope_and_types_not_bool_int_equivalence(self):
        for field, value in (
            ("controllers", 15),
            ("sameUidRequired", 1),
            ("automaticRetryAllowed", True),
            ("rootOperation", "apply"),
            ("maximumExecutionSeconds", 3600),
        ):
            with self.subTest(field=field):
                before = self.doc["scope"][field]
                self.doc["scope"][field] = value
                self.save()
                with self.assertRaises(ToolError):
                    auth.validate(self.path, require_approved=False)
                self.doc["scope"][field] = before

    def test_code_or_source_checksum_drift_rejects(self):
        self.doc["executionCode"]["aggregateSha256"] = "f" * 64
        self.save()
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)
        self.doc["executionCode"] = copy.deepcopy(CODE_STATE)
        self.save()
        (self.directory / "sources.json").write_text("{}")
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)

    def test_missing_snapshot_cannot_be_approved_even_for_plan(self):
        self.doc.update(
            reviewStatus=auth.APPROVED,
            approvedBy="test",
            approvedAt=datetime.now(timezone.utc).isoformat(),
        )
        self.save()
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)

    def test_legacy_snapshot_never_authorizes_continuation_or_claim(self):
        self.approve()
        self.doc["awsReadOnlySnapshot"]["schemaVersion"] = 1
        self.doc["awsReadOnlySnapshot"]["spotQuota"] = {
            "quotaCode": "L-1216C47A",
            "value": 32.0,
        }
        self.save()
        root = Path(self.tmp.name) / "legacy-rejected-claims"
        for recovery_only in (False, True):
            with (
                self.subTest(recovery_only=recovery_only),
                self.assertRaises(ToolError),
            ):
                auth.validate(
                    self.path, require_approved=True, recovery_only=recovery_only
                )
        with self.assertRaises(ToolError):
            auth.claim(self.path, auth.CLAIM_ACKNOWLEDGEMENT, root=root)
        self.assertFalse(root.exists())

    def test_wrong_quota_identity_never_authorizes_continuation_claim(self):
        self.approve()
        self.doc["awsReadOnlySnapshot"]["spotQuota"]["usageClass"] = "Standard/OnDemand"
        self.save()
        root = Path(self.tmp.name) / "wrong-quota-claims"
        with self.assertRaises(ToolError):
            auth.claim(self.path, auth.CLAIM_ACKNOWLEDGEMENT, root=root)
        self.assertFalse(root.exists())

    def test_stale_snapshot_or_release_drift_rejected(self):
        self.approve()
        for change in (
            lambda s: s.update(
                observedAt=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
            ),
            lambda s: s["eksRelease"].update(status="EXTENDED_SUPPORT"),
            lambda s: s["targetNameConflicts"].update(environmentIamRoles=1),
        ):
            self.doc["awsReadOnlySnapshot"] = snapshot()
            change(self.doc["awsReadOnlySnapshot"])
            self.save()
            with self.assertRaises(ToolError):
                auth.validate(self.path, require_approved=True)

    def test_a05_scope_is_independent(self):
        self.approve()
        with (
            patch.object(
                runner.base,
                "_session_contract",
                side_effect=ToolError("A05 unapproved"),
            ),
            self.assertRaises(ToolError),
        ):
            auth.validate(self.path, require_approved=True)
        other = replace(contract().bootstrap, context="other-context")
        with (
            patch.object(runner.base, "_session_contract", return_value=({}, other)),
            self.assertRaises(ToolError),
        ):
            auth.validate(self.path, require_approved=True)

    def test_single_use_receipt_is_durable_owner_only_and_separate(self):
        self.approve()
        root = Path(self.tmp.name).resolve() / "claims"
        receipt = auth.claim(self.path, auth.CLAIM_ACKNOWLEDGEMENT, root=root)
        self.assertEqual(auth.CLAIM_STATUS, receipt["status"])
        self.assertEqual("existing-root-uid", receipt["rootUid"])
        self.assertEqual(
            0o600, (root / (self.doc["windowId"] + ".json")).stat().st_mode & 0o777
        )
        auth.verify_claim(self.path, root=root)
        with self.assertRaises(ToolError):
            auth.claim(self.path, auth.CLAIM_ACKNOWLEDGEMENT, root=root)
        self.assertNotEqual(auth.CLAIM_ROOT, auth.create.CLAIM_ROOT)

    def test_expired_claim_only_verifies_for_recovery(self):
        self.approve()
        root = Path(self.tmp.name).resolve() / "claims"
        receipt = auth.claim(self.path, auth.CLAIM_ACKNOWLEDGEMENT, root=root)
        at = datetime.now(timezone.utc) - timedelta(hours=2)
        receipt.update(
            claimedAt=at.isoformat(),
            deadline=(at + timedelta(seconds=3600)).isoformat(),
        )
        (root / (self.doc["windowId"] + ".json")).write_text(json.dumps(receipt))
        with self.assertRaises(ToolError):
            auth.verify_claim(self.path, root=root)
        auth.verify_claim(self.path, root=root, require_active=False)

    def test_claim_uid_swap_and_extended_deadline_rejected(self):
        self.approve()
        root = Path(self.tmp.name).resolve() / "claims"
        receipt = auth.claim(self.path, auth.CLAIM_ACKNOWLEDGEMENT, root=root)
        path = root / (self.doc["windowId"] + ".json")
        for key, value in (
            ("rootUid", "replacement"),
            ("deadline", (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()),
        ):
            altered = receipt | {key: value}
            path.write_text(json.dumps(altered))
            with self.assertRaises(ToolError):
                auth.verify_claim(self.path, root=root)

    def test_public_file_symlink_and_extra_file_rejected(self):
        self.path.chmod(0o644)
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)
        self.path.chmod(0o600)
        extra = self.directory / "extra"
        extra.write_text("unreviewed")
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)
        extra.unlink()
        original = self.path.read_bytes()
        self.path.unlink()
        target = Path(self.tmp.name) / "other.json"
        target.write_bytes(original)
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(ToolError):
            auth.validate(self.path, require_approved=False)

    def test_prepare_never_overwrites_existing_bundle(self):
        with self.assertRaises(ToolError):
            prepare.prepare(self.directory, self.sources)

    def test_verified_amendment_uses_effective_intent_for_fresh_snapshot(self):
        self.evidence.update(
            cidrAmendmentVerified=True, environment={"test": "amended intent"}
        )
        self.approve()
        with patch.object(auth.create, "_validate_environment_document") as check:
            result = auth.validate(self.path, require_approved=True)
        check.assert_called_once_with(
            self.evidence["archive"],
            self.evidence["archive"].name,
            self.doc["awsReadOnlySnapshot"],
            self.evidence["environment"],
        )
        self.assertTrue(auth.public_plan(result)["cidrAmendmentVerified"])

    def test_effective_intent_is_passed_to_observe_only_runtime(self):
        self.approve()
        self.evidence.update(
            cidrAmendmentVerified=True, environment={"test": "amended intent"}
        )
        reviewed = {
            "document": self.doc,
            "sources": self.sources,
            "evidence": self.evidence,
            "approved": True,
        }
        with (
            patch.object(auth.create, "_load_json", return_value={}),
            patch.object(
                runner.base.u0_runner, "controller_inventory", return_value=[]
            ),
        ):
            runtime = runner.runtime_contract(self.path, reviewed)
        self.assertEqual(self.evidence["environment"], runtime.environment_document)
        self.assertEqual(self.evidence["archive"], runtime.bundle_directory)
        self.assertEqual(
            "observe-only; never create/apply/replace/patch/delete root",
            auth.SCOPE["rootOperation"],
        )


class ContinuationFakeOperations(FakeOperations):
    def observe_root(self, _contract):
        self._call("observe")
        return {"name": "eks-dev-spot", "uid": "existing-root-uid", "generation": 3}


class ContinuationExecutionTests(unittest.TestCase):
    def invoke(self, ops, *, fail_event=None):
        reviewed = {
            "document": {"rootUid": "existing-root-uid", "executionCode": CODE_STATE}
        }
        original = contract()
        runtime = replace(
            original,
            authorization=original.authorization | {"windowId": "u1c-20260907-01"},
        )
        journal = FakeJournal()
        if fail_event:
            append = journal.append

            def wrapped(event):
                if event == fail_event:
                    raise OSError("journal failure")
                append(event)

            journal.append = wrapped
        reports = []
        with (
            patch.object(auth, "validate", return_value=reviewed),
            patch.object(runner, "runtime_contract", return_value=runtime),
            patch.object(
                auth,
                "claim",
                return_value={
                    "windowId": "u1c-20260907-01",
                    "authorizationSha256": "a" * 64,
                },
            ) as claim,
            patch.object(auth, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(
                runner.base,
                "_write_private_json",
                side_effect=lambda path, doc: reports.append(doc) or path,
            ),
        ):
            try:
                result = runner.execute(
                    Path("authorization-contract.json"),
                    "source",
                    "warlock-cli-codex-admin",
                    runner.RUN_ACK,
                    operations=ops,
                )
            except ToolError:
                result = None
        return result, reports, journal, claim.call_count

    def test_success_observes_existing_root_never_creates_or_dryruns(self):
        ops = ContinuationFakeOperations()
        result, reports, _, claims = self.invoke(ops)
        self.assertEqual("U1_01_PASS", result["status"])
        self.assertNotIn("create", ops.calls)
        self.assertNotIn("dry-run", ops.calls)
        self.assertEqual("existing-root-uid", ops.cleanup_uid)
        self.assertFalse(reports[0]["rootWriteAttempted"])
        self.assertEqual(1, claims)

    def test_baseline_failure_has_no_mutations_or_cleanup(self):
        ops = ContinuationFakeOperations(fail_at="baseline")
        _, reports, journal, _ = self.invoke(ops)
        self.assertEqual(["baseline"], ops.calls)
        self.assertIn("BASELINE_REJECTED_NO_MUTATION", journal.events)
        self.assertEqual("U1_CONTINUATION_FAILED_SAFE", reports[0]["status"])

    def test_every_active_failure_parks_contract_uid_without_retry(self):
        for stage in ("protect", "open", "start", "wait", "checkpoint", "evidence"):
            with self.subTest(stage=stage):
                ops = ContinuationFakeOperations(fail_at=stage)
                _, reports, _, claims = self.invoke(ops)
                self.assertEqual("cleanup", ops.calls[-1])
                self.assertEqual("existing-root-uid", ops.cleanup_uid)
                self.assertEqual("U1_CONTINUATION_FAILED_SAFE", reports[0]["status"])
                self.assertEqual(1, claims)

    def test_cleanup_failure_requires_recovery_not_success(self):
        _, reports, journal, _ = self.invoke(
            ContinuationFakeOperations(fail_at="cleanup")
        )
        self.assertEqual("U1_CONTINUATION_RECOVERY_REQUIRED", reports[0]["status"])
        self.assertIn("RECOVERY_REQUIRED", journal.events)

    def test_checkpoint_not_reached_is_not_u1_pass(self):
        result, _, _, _ = self.invoke(
            ContinuationFakeOperations(checkpoint_reached=False)
        )
        self.assertEqual("U1_CONTINUATION_PENDING_NEW_REVIEW", result["status"])

    def test_deadline_exception_disarms_before_cleanup(self):
        ops = ContinuationFakeOperations()
        ops.wait_checkpoint = Mock(
            side_effect=runner.base.ExecutionDeadlineExceeded("expired")
        )
        _, reports, _, _ = self.invoke(ops)
        self.assertTrue(reports[0]["executionDeadlineExceeded"])
        self.assertTrue(reports[0]["cleanupOutsideActiveDeadline"])
        self.assertEqual("cleanup", ops.calls[-1])

    def test_journal_failure_cannot_prevent_cleanup(self):
        ops = ContinuationFakeOperations()
        self.invoke(ops, fail_event="CLEANUP_STARTED")
        self.assertEqual("cleanup", ops.calls[-1])

    def test_incomplete_cleanup_report_is_never_a_pass(self):
        ops = ContinuationFakeOperations()
        ops.cleanup = Mock(return_value={"controllersStopped": 13})
        _, reports, _, _ = self.invoke(ops)
        self.assertEqual("U1_CONTINUATION_RECOVERY_REQUIRED", reports[0]["status"])

    def test_root_swap_before_mutation_is_rejected(self):
        ops = ContinuationFakeOperations()
        ops.observe_root = Mock(return_value={"uid": "replacement"})
        _, reports, _, _ = self.invoke(ops)
        self.assertNotIn("protect", ops.calls)
        self.assertFalse(reports[0]["rootWriteAttempted"])

    def test_run_wrong_ack_does_not_validate_or_claim(self):
        with patch.object(auth, "validate") as validate, self.assertRaises(ToolError):
            runner.execute(
                Path("unused"), "source", "audit", runner.base.RUN_ACKNOWLEDGEMENT
            )
        validate.assert_not_called()


class ContinuationAdapterTests(unittest.TestCase):
    def setUp(self):
        self.reviewed = {
            "evidence": {
                "pin": PIN,
                "rootUid": "existing-root-uid",
                "proof": {
                    "core-readonly-evidence": {
                        "controllers": [{"name": "crossplane", "uid": "core-uid"}]
                    }
                },
            }
        }
        self.ops = operations.RealOperations(self.reviewed)

    def test_root_write_paths_including_dry_run_disabled(self):
        for method in (self.ops.create_environment, self.ops.dry_run_environment):
            with self.assertRaises(ToolError):
                method(contract())
        for args in (
            ("apply", "-f", "-"),
            ("delete", "xeksenvironment", "eks-dev-spot"),
            ("replace", "-f", "-", "--dry-run=server"),
            ("patch", "xeksenvironment", "get"),
        ):
            with self.subTest(args=args), self.assertRaises(ToolError):
                self.ops._kube(contract(), *args)

    def test_controller_patch_requires_original_uid_and_only_replica_field(self):
        patch_ops = [
            {"op": "test", "path": "/metadata/uid", "value": "core-uid"},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "1"},
            {"op": "replace", "path": "/spec/replicas", "value": 1},
        ]

        def invoke():
            return self.ops._kube(
                contract(),
                "--namespace",
                runner.base.NAMESPACE,
                "patch",
                "deployment",
                "crossplane",
                "--type=json",
                "-p",
                json.dumps(patch_ops),
            )

        with patch.object(
            runner.base.u0_runner.RealOperations, "_kube", return_value={}
        ) as call:
            invoke()
            call.assert_called_once()
            patch_ops[0]["value"] = "new-uid"
            with self.assertRaises(ToolError):
                invoke()
            patch_ops[0]["value"] = "core-uid"
            patch_ops[2]["value"] = True
            with self.assertRaises(ToolError):
                invoke()

    def test_aws_write_allowlist_cannot_be_bypassed(self):
        with (
            patch.object(runner.base.subprocess, "run") as run,
            self.assertRaises(ToolError),
        ):
            self.ops._aws_json(
                contract(), "warlock-cli-codex-admin", "ec2", "create-vpc"
            )
        run.assert_not_called()

    def test_cleanup_rejects_unbound_uid(self):
        with (
            patch.object(runner.base.RealOperations, "cleanup") as cleanup,
            self.assertRaises(ToolError),
        ):
            self.ops.cleanup(contract(), expected_environment_uid=None)
        cleanup.assert_not_called()

    def test_definition_permissions_uid_or_default_drift_rejected(self):
        document = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "test", "uid": "uid"},
            "rules": [],
        }
        saved = {
            "apiVersion": document["apiVersion"],
            "kind": "ClusterRole",
            "name": "test",
            "namespace": "",
            "uid": "uid",
            "actualPayloadSha256": definitions.payload_digest(document),
        }
        operations.verify_definition(document, saved)
        for mutate in (
            lambda d: d.update(rules=[{"verbs": ["*"]}]),
            lambda d: d["metadata"].update(uid="new"),
            lambda d: d.update(aggregationRule={}),
            lambda d: d["metadata"].update(ownerReferences=[{}]),
        ):
            altered = copy.deepcopy(document)
            mutate(altered)
            with self.assertRaises(ToolError):
                operations.verify_definition(altered, saved)

    def test_shared_identity_or_protection_marker_change_rejected(self):
        saved = {"name": "shared", "uid": "same", "ownerReferences": []}
        actual = {"metadata": saved.copy()}
        operations.verify_shared(actual, saved)
        for mutate in (
            lambda d: d["metadata"].update(uid="new"),
            lambda d: d["metadata"].update(deletionTimestamp="now"),
            lambda d: d["metadata"].update(
                annotations={"crossplane.io/paused": "false"}
            ),
        ):
            altered = copy.deepcopy(actual)
            mutate(altered)
            with self.assertRaises(ToolError):
                operations.verify_shared(altered, saved)

    def test_default_normalization_is_narrow_and_nonmutating(self):
        document = {
            "kind": "Provider",
            "spec": {"package": "digest", "skipDependencyResolution": True},
        }
        normal = definitions.with_server_defaults(document)
        self.assertTrue(normal["spec"]["skipDependencyResolution"])
        self.assertIs(False, normal["spec"]["ignoreCrossplaneConstraints"])
        self.assertNotIn("ignoreCrossplaneConstraints", document["spec"])
        unknown = {"kind": "Other", "spec": {}}
        self.assertEqual(unknown, definitions.with_server_defaults(unknown))


class RevisionImagePinTests(unittest.TestCase):
    def setUp(self):
        # Saved runtime evidence has Parent.spec.package but Revision.spec.image
        # (neither spec.package nor spec.source). All identities here are synthetic.
        self.saved = []
        self.documents = {}
        for kind in ("Provider", "Function"):
            name = "test-" + kind.lower()
            revision_name = name + "-revision"
            image = "registry.example.test/" + name + "@sha256:" + "a" * 64
            saved = {
                "kind": kind,
                "name": name,
                "uid": name + "-uid",
                "package": image,
                "revision": revision_name,
                "revisionUid": revision_name + "-uid",
                "deploymentUid": name + "-deployment-uid",
            }

            def owner(owner_kind, owner_name, owner_uid):
                return [
                    {
                        "apiVersion": "pkg.crossplane.io/v1",
                        "kind": owner_kind,
                        "name": owner_name,
                        "uid": owner_uid,
                        "controller": True,
                    }
                ]

            package = {
                "apiVersion": "pkg.crossplane.io/v1",
                "kind": kind,
                "metadata": {"name": name, "uid": saved["uid"]},
                "spec": {"package": image},
                "status": {"currentRevision": revision_name},
            }
            revision = {
                "apiVersion": "pkg.crossplane.io/v1",
                "kind": kind + "Revision",
                "metadata": {
                    "name": revision_name,
                    "uid": saved["revisionUid"],
                    "ownerReferences": owner(kind, name, saved["uid"]),
                },
                "spec": {
                    "desiredState": "Active",
                    "image": image,
                    "ignoreCrossplaneConstraints": False,
                    "packagePullPolicy": "IfNotPresent",
                    "revision": 1,
                    "runtimeConfigRef": {"name": "test-runtime"},
                    "skipDependencyResolution": False,
                    "tlsServerSecretName": "test-server-tls",
                },
            }
            if kind == "Provider":
                revision["spec"]["tlsClientSecretName"] = "test-client-tls"
            deployment = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": revision_name,
                    "uid": saved["deploymentUid"],
                    "ownerReferences": owner(
                        kind + "Revision", revision_name, saved["revisionUid"]
                    ),
                },
                "spec": {
                    "replicas": 0,
                    "template": {"spec": {"serviceAccountName": revision_name}},
                },
            }
            self.saved.append(saved)
            self.documents[("get", kind.lower() + ".pkg.crossplane.io", name)] = package
            self.documents[
                ("get", kind.lower() + "revision.pkg.crossplane.io", revision_name)
            ] = revision
            self.documents[
                (
                    "--namespace",
                    runner.base.NAMESPACE,
                    "get",
                    "deployment",
                    revision_name,
                )
            ] = deployment
        self.documents[("get", "clusterrole", "crossplane")] = {
            "metadata": {"uid": "core-uid"},
            "rules": [],
        }
        self.ops = operations.RealOperations(
            {
                "evidence": {
                    "pin": PIN,
                    "definitions": {},
                    "proof": {
                        "core-readonly-evidence": {"controllers": []},
                        "permanent-definitions-evidence": {"documents": []},
                        "runtime-and-final-checks": {
                            "coreRbac": {
                                "uid": "core-uid",
                                "rulesSha256": identity.spec_digest([]),
                            },
                            "packageRuntimePins": self.saved,
                            "generatedCrdBindings": [],
                        },
                    },
                }
            }
        )
        for patcher in (
            patch.object(
                runner.base.subprocess,
                "run",
                side_effect=AssertionError("offline test attempted a command/API"),
            ),
            patch.object(
                runner.base.u0_runner.provider_rbac, "inventory", return_value={}
            ),
            patch.object(runner.base.u0_runner.provider_rbac, "audit"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(self.ops, "_kube", side_effect=self.get_document)
        self.kube = patcher.start()
        self.addCleanup(patcher.stop)

    def get_document(self, _contract, *args):
        if args not in self.documents:
            raise AssertionError("unexpected offline Kubernetes request shape")
        return copy.deepcopy(self.documents[args])

    def resource_keys(self, saved):
        return (
            ("get", saved["kind"].lower() + ".pkg.crossplane.io", saved["name"]),
            (
                "get",
                saved["kind"].lower() + "revision.pkg.crossplane.io",
                saved["revision"],
            ),
            (
                "--namespace",
                runner.base.NAMESPACE,
                "get",
                "deployment",
                saved["revision"],
            ),
        )

    def test_provider_and_function_image_only_revisions_pass_full_runtime_chain(self):
        before = copy.deepcopy(self.documents)
        self.ops._assert_permanent(contract())
        self.assertEqual(before, self.documents)
        self.assertEqual(7, self.kube.call_count)
        for saved in self.saved:
            _, revision_key, _ = self.resource_keys(saved)
            spec = self.documents[revision_key]["spec"]
            self.assertNotIn("package", spec)
            self.assertNotIn("source", spec)
            self.assertEqual(saved["package"], spec["image"])

    def test_image_must_match_exact_digest_no_package_or_source_fallback(self):
        before = copy.deepcopy(self.documents)
        for saved in self.saved:
            _, revision_key, _ = self.resource_keys(saved)
            for change in (
                "missing",
                "wrong-digest",
                "tag",
                "package",
                "source",
                "null",
                "bool",
            ):
                self.documents = copy.deepcopy(before)
                spec = self.documents[revision_key]["spec"]
                spec.pop("image")
                if change in ("package", "source"):
                    spec[change] = saved["package"]
                elif change != "missing":
                    spec["image"] = {
                        "wrong-digest": saved["package"].replace("a" * 64, "b" * 64),
                        "tag": saved["package"].split("@")[0] + ":v1.0.0",
                        "null": None,
                        "bool": True,
                    }[change]
                with (
                    self.subTest(kind=saved["kind"], change=change),
                    self.assertRaisesRegex(
                        ToolError, "package/runtime owner chain drift"
                    ),
                ):
                    self.ops._assert_permanent(contract())

    def test_parent_revision_and_deployment_identity_gates_remain_enforced(self):
        before = copy.deepcopy(self.documents)
        changes = (
            (0, lambda x: x["metadata"].update(uid="other")),
            (0, lambda x: x["spec"].update(package="different")),
            (0, lambda x: x["status"].update(currentRevision="other")),
            (1, lambda x: x["metadata"].update(uid="other")),
            (1, lambda x: x["spec"].update(desiredState="Inactive")),
            (1, lambda x: x["metadata"]["ownerReferences"][0].update(uid="other")),
            (1, lambda x: x["metadata"]["ownerReferences"][0].update(controller=1)),
            (
                1,
                lambda x: x["metadata"]["ownerReferences"][0].update(
                    apiVersion="wrong/v1"
                ),
            ),
            (1, lambda x: x["metadata"]["ownerReferences"].append({})),
            (2, lambda x: x["metadata"].update(uid="other")),
            (
                2,
                lambda x: x["spec"]["template"]["spec"].update(
                    serviceAccountName="other"
                ),
            ),
            (2, lambda x: x["metadata"]["ownerReferences"][0].update(uid="other")),
            (2, lambda x: x["metadata"]["ownerReferences"][0].update(kind="wrong")),
            (2, lambda x: x["metadata"].update(ownerReferences=[])),
        )
        for saved in self.saved:
            keys = self.resource_keys(saved)
            for index, (resource, mutate) in enumerate(changes):
                self.documents = copy.deepcopy(before)
                mutate(self.documents[keys[resource]])
                with (
                    self.subTest(kind=saved["kind"], index=index),
                    self.assertRaisesRegex(
                        ToolError, "package/runtime owner chain drift"
                    ),
                ):
                    self.ops._assert_permanent(contract())


class MetadataTransportTests(unittest.TestCase):
    def request(self, document, *, status=200, many=False, optional=False):
        client = metadata.ReadOnlyMetadata("kind-kube-nebula-a")
        client.path = Path("unused.sock")
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = status
        response.read.return_value = json.dumps(document).encode()
        with patch.object(metadata, "UnixConnection", return_value=connection):
            result = client.get(
                "/api/v1/namespaces/crossplane-system/secrets/session",
                many=many,
                optional=optional,
            )
        self.assertEqual("GET", connection.request.call_args.args[0])
        self.assertIn(
            "as=PartialObjectMetadata",
            connection.request.call_args.kwargs["headers"]["Accept"],
        )
        connection.close.assert_called_once()
        return result

    def test_metadata_404_absence_without_secret_data(self):
        self.assertIsNone(self.request({}, status=404, optional=True))

    def test_full_secret_response_is_never_accepted(self):
        with self.assertRaises(ToolError):
            self.request(
                {"apiVersion": "v1", "kind": "Secret", "data": {"test": "masked"}}
            )

    def test_metadata_shape_cannot_contain_secret_data(self):
        with self.assertRaises(ToolError):
            self.request(
                {
                    "apiVersion": "meta.k8s.io/v1",
                    "kind": "PartialObjectMetadata",
                    "data": {},
                }
            )

    def test_null_empty_metadata_list_is_explicitly_supported(self):
        self.assertEqual(
            [],
            self.request(
                {
                    "apiVersion": "meta.k8s.io/v1",
                    "kind": "PartialObjectMetadataList",
                    "items": None,
                },
                many=True,
            ),
        )

    def test_403_is_not_treated_as_absence(self):
        with self.assertRaises(ToolError):
            self.request({}, status=403, optional=True)

    def test_constructing_reader_does_not_start_proxy(self):
        with patch.object(metadata.subprocess, "Popen") as popen:
            metadata.ReadOnlyMetadata("kind-kube-nebula-a")
        popen.assert_not_called()


class ContinuationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        patcher = patch.object(runner, "RESULT_ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.receipt = {
            "windowId": "u1c-20260907-01",
            "rootUid": "same-root",
            "authorizationSha256": "a" * 64,
            "deadline": (
                datetime.now(timezone.utc) + timedelta(minutes=20)
            ).isoformat(),
        }

    def save(self, document, suffix=".json"):
        path = self.root / (self.receipt["windowId"] + suffix)
        path.write_text(json.dumps(document))
        path.chmod(0o600)

    def test_recovery_cannot_interrupt_unfinished_active_window(self):
        with self.assertRaises(ToolError):
            runner.assert_recovery_eligible(self.receipt)

    def test_crashed_expired_window_requires_no_active_result(self):
        self.receipt["deadline"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()
        runner.assert_recovery_eligible(self.receipt)

    def test_only_matching_recovery_required_result_is_eligible(self):
        result = {
            k: self.receipt[k] for k in ("windowId", "rootUid", "authorizationSha256")
        }
        for status in (
            "U1_01_PASS",
            "U1_CONTINUATION_FAILED_SAFE",
            "U1_CONTINUATION_PENDING_NEW_REVIEW",
        ):
            self.save(result | {"status": status})
            with self.assertRaises(ToolError):
                runner.assert_recovery_eligible(self.receipt)
        self.save(result | {"status": "U1_CONTINUATION_RECOVERY_REQUIRED"})
        runner.assert_recovery_eligible(self.receipt)
        self.save(
            result
            | {"status": "U1_CONTINUATION_RECOVERY_REQUIRED", "rootUid": "different"}
        )
        with self.assertRaises(ToolError):
            runner.assert_recovery_eligible(self.receipt)

    def test_completed_recovery_is_not_repeatable(self):
        self.save(
            {"status": "U1_CONTINUATION_RECOVERY_COMPLETE"}, suffix=".recovery.json"
        )
        with self.assertRaises(ToolError):
            runner.assert_recovery_eligible(self.receipt)

    def test_exec_plugin_context_rejected_before_proxy_start(self):
        config = {
            "users": [{"user": {"exec": {"command": "aws"}}}],
            "clusters": [{"cluster": {"server": "https://127.0.0.1:12345"}}],
        }
        with (
            patch.object(
                metadata.bootstrap, "_run_text", return_value=json.dumps(config)
            ),
            patch.object(metadata.subprocess, "Popen") as popen,
            self.assertRaises(ToolError),
        ):
            with metadata.ReadOnlyMetadata("kind-kube-nebula-a"):
                pass
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
