from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts/eks_lifecycle"))
from common import ToolError
import run_u1_bootstrap as runner
import u1_environment_identity as identity
from test_u1_bootstrap import FakeJournal, FakeOperations, contract


def documents():
    reviewed = contract()
    root = copy.deepcopy(reviewed.environment_document)
    root["metadata"].update(uid="root-uid", generation=3)
    root["metadata"]["labels"][identity.COMPOSITE_LABEL] = reviewed.environment
    root["metadata"]["finalizers"] = ["composite.apiextensions.crossplane.io"]
    revision_name = identity.COMPOSITION_NAME + "-abc1234"
    root["spec"]["crossplane"].update(
        compositionRef={"name": identity.COMPOSITION_NAME},
        compositionRevisionRef={"name": revision_name},
    )
    spec = {
        "compositeTypeRef": {"apiVersion": root["apiVersion"], "kind": root["kind"]},
        "mode": "Pipeline",
        "pipeline": [{"step": "render", "functionRef": {"name": "locked-function"}}],
    }
    composition = {
        "apiVersion": "apiextensions.crossplane.io/v1",
        "kind": "Composition",
        "metadata": {"name": identity.COMPOSITION_NAME, "uid": "composition-uid"},
        "spec": copy.deepcopy(spec),
    }
    revision = {
        "apiVersion": composition["apiVersion"],
        "kind": "CompositionRevision",
        "metadata": {
            "name": revision_name,
            "uid": "revision-uid",
            "ownerReferences": [
                {
                    "apiVersion": composition["apiVersion"],
                    "kind": "Composition",
                    "name": identity.COMPOSITION_NAME,
                    "uid": "composition-uid",
                    "controller": True,
                    "blockOwnerDeletion": True,
                }
            ],
        },
        "spec": {**copy.deepcopy(spec), "revision": 1},
    }
    return reviewed, root, composition, revision, spec


class U1EnvironmentIdentityTests(unittest.TestCase):
    def test_recovery_unreadable_result_still_parks_but_never_marks_complete(self):
        operations, journal = FakeOperations(), FakeJournal()
        with patch.object(runner.authorization_tool, "verify_claim"), patch.object(
            runner, "recovery_environment_uid", side_effect=ToolError("missing result")
        ), patch.object(
            runner.Journal, "existing", return_value=journal
        ), self.assertRaisesRegex(
            ToolError, "missing result"
        ):
            runner.recover(
                contract(), runner.RECOVER_ACKNOWLEDGEMENT, operations=operations
            )
        self.assertEqual(["cleanup"], operations.calls)
        self.assertIsNone(operations.cleanup_uid)
        self.assertEqual(["RECOVERY_STARTED"], journal.events)

    def test_recovery_uid_is_loaded_only_from_the_matching_recorded_window(self):
        reviewed = contract()
        report = {
            "schemaVersion": 1,
            "windowId": reviewed.authorization["windowId"],
            "bundle": reviewed.authorization["bundle"],
            "reviewedGitCommit": reviewed.authorization["reviewedGitCommit"],
            "executionCodeSha256": reviewed.authorization["executionCodeSha256"],
            "singleUseClaimConsumed": True,
            "environment": {
                "name": reviewed.environment,
                "uid": "original-uid",
                "generation": 1,
            },
        }
        with patch.object(runner.authorization_tool, "_load_json", return_value=report):
            self.assertEqual("original-uid", runner.recovery_environment_uid(reviewed))
        for key, value in [
            ("windowId", "other"),
            ("executionCodeSha256", "other"),
            ("singleUseClaimConsumed", 1),
            ("environment", {"name": reviewed.environment, "uid": "", "generation": 1}),
        ]:
            with self.subTest(key=key), patch.object(
                runner.authorization_tool,
                "_load_json",
                return_value={**report, key: value},
            ), self.assertRaises(ToolError):
                runner.recovery_environment_uid(reviewed)

    def test_unknown_root_uid_parks_but_cannot_report_recovery_complete(self):
        reviewed, root, _, _, _ = documents()
        operations = runner.RealOperations()
        with patch.object(
            runner.u0_runner.RealOperations,
            "cleanup",
            return_value={"controllersStopped": 14},
        ) as park, patch.object(
            operations, "_optional", return_value=root
        ), self.assertRaisesRegex(
            ToolError, "UID was not recorded"
        ):
            operations.cleanup(reviewed, expected_environment_uid=None)
        park.assert_called_once()

    def test_observed_runtime_additions_are_accepted_without_mutating_input(self):
        reviewed, root, _, _, _ = documents()
        before = copy.deepcopy(root)
        refs = identity.validate_root(
            root, reviewed.environment_document, expected_uid="root-uid"
        )
        self.assertEqual(identity.COMPOSITION_NAME, refs.composition)
        self.assertEqual(before, root)
        self.assertNotIn(
            identity.COMPOSITE_LABEL,
            reviewed.environment_document["metadata"]["labels"],
        )

    def test_create_phase_without_runtime_fields_is_still_valid(self):
        reviewed = contract()
        root = copy.deepcopy(reviewed.environment_document)
        root["metadata"].update(uid="root-uid", generation=1)
        self.assertIsNone(
            identity.validate_root(
                root, reviewed.environment_document, expected_uid="root-uid"
            ).revision
        )

    def test_reviewed_intent_identity_and_metadata_drift_are_rejected(self):
        changes = [
            lambda r: r["spec"]["parameters"].update(region="us-west-2"),
            lambda r: r["spec"]["parameters"]["lifecycle"].update(
                deletionProtection=False
            ),
            lambda r: r["spec"]["parameters"]["lifecycle"].update(deletionProtection=1),
            lambda r: r["spec"]["parameters"]["lifecycle"].update(
                retirementStage="DeleteReady"
            ),
            lambda r: r["spec"].update(unreviewed=True),
            lambda r: r["spec"]["crossplane"].update(
                compositionUpdatePolicy="Automatic"
            ),
            lambda r: r["spec"]["crossplane"].update(
                compositionSelector={"matchLabels": {}}
            ),
            lambda r: r["metadata"].update(uid="different"),
            lambda r: r["metadata"].update(generation=True),
            lambda r: r["metadata"].update(namespace="foreign"),
            lambda r: r["metadata"].update(deletionTimestamp="2026-01-01T00:00:00Z"),
            lambda r: r["metadata"].update(ownerReferences=[{"uid": "foreign"}]),
            lambda r: r["metadata"]["labels"].update(
                {identity.COMPOSITE_LABEL: "other"}
            ),
            lambda r: r["metadata"]["labels"].update({"unreviewed": "value"}),
            lambda r: r["metadata"]["annotations"].update(
                {"crossplane.io/paused": "true"}
            ),
            lambda r: r["metadata"]["annotations"].update(
                {"platform.aws.goodnotes.io/authorization-bundle": "other"}
            ),
            lambda r: r.update(kind="XEKSCluster"),
        ]
        for index, change in enumerate(changes):
            reviewed, root, _, _, _ = documents()
            change(root)
            with self.subTest(index=index), self.assertRaises(ToolError):
                identity.validate_root(
                    root, reviewed.environment_document, expected_uid="root-uid"
                )

    def test_references_only_allow_three_stable_cluster_scoped_children(self):
        reviewed, root, _, _, _ = documents()
        references = [
            {
                "apiVersion": root["apiVersion"],
                "kind": kind,
                "name": reviewed.environment + suffix,
            }
            for kind, suffix in identity.CHILDREN.items()
        ]
        for count in range(4):
            root["spec"]["crossplane"]["resourceRefs"] = references[:count]
            identity.validate_root(
                root, reviewed.environment_document, expected_uid="root-uid"
            )
        for refs in [
            None,
            {},
            references + references[:1],
            [dict(references[0], name="foreign")],
            [dict(references[0], namespace="foreign")],
            [dict(references[0], uid="unchecked")],
            [dict(references[0], kind="Object")],
            [dict(references[0], apiVersion="wrong/v1")],
        ]:
            root["spec"]["crossplane"]["resourceRefs"] = refs
            with self.subTest(refs=refs), self.assertRaises(ToolError):
                identity.validate_root(
                    root, reviewed.environment_document, expected_uid="root-uid"
                )

    def test_wrong_or_malformed_runtime_binding_is_rejected(self):
        for key, value in [
            ("compositionRef", None),
            ("compositionRevisionRef", None),
            ("compositionRef", {"name": "other"}),
            ("compositionRef", {"name": identity.COMPOSITION_NAME, "extra": 1}),
            ("compositionRevisionRef", {"name": "other-revision"}),
            ("compositionRevisionRef", {"name": True}),
            (
                "compositionRevisionRef",
                {"name": identity.COMPOSITION_NAME + "-abc", "extra": 1},
            ),
        ]:
            reviewed, root, _, _, _ = documents()
            root["spec"]["crossplane"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ToolError):
                identity.validate_root(
                    root, reviewed.environment_document, expected_uid="root-uid"
                )

    def test_full_revision_content_ownership_and_uid_are_pinned(self):
        _, _, composition, revision, spec = documents()
        revision_name = revision["metadata"]["name"]
        pin = identity.validate_binding(
            composition, revision, spec, revision_name=revision_name
        )
        self.assertEqual(identity.spec_digest(spec), pin.spec_sha256)
        # Revision counter itself is legitimately mutable in Crossplane; content is not.
        revision["spec"]["revision"] = 2
        self.assertEqual(
            pin,
            identity.validate_binding(
                composition, revision, spec, revision_name=revision_name, previous=pin
            ),
        )
        cases = [
            lambda c, r: r["spec"]["pipeline"][0]["functionRef"].update(
                name="unreviewed"
            ),
            lambda c, r: c["spec"].update(unreviewed=True),
            lambda c, r: r["metadata"]["ownerReferences"][0].update(uid="foreign"),
            lambda c, r: r["metadata"].update(uid="replacement"),
            lambda c, r: r["metadata"].update(namespace="foreign"),
            lambda c, r: c["metadata"].update(namespace="foreign"),
            lambda c, r: r["metadata"].update(deletionTimestamp="2026-01-01"),
            lambda c, r: r["spec"].update(revision=True),
            lambda c, r: r["spec"].update(revision=0),
        ]
        for index, change in enumerate(cases):
            c, r = copy.deepcopy(composition), copy.deepcopy(revision)
            change(c, r)
            with self.subTest(index=index), self.assertRaises(ToolError):
                identity.validate_binding(
                    c, r, spec, revision_name=revision_name, previous=pin
                )

    def test_replaced_composition_with_updated_owner_is_rejected_after_pin(self):
        _, _, composition, revision, spec = documents()
        revision_name = revision["metadata"]["name"]
        pin = identity.validate_binding(
            composition, revision, spec, revision_name=revision_name
        )
        composition["metadata"]["uid"] = "new-composition-uid"
        revision["metadata"]["ownerReferences"][0]["uid"] = "new-composition-uid"
        with self.assertRaisesRegex(ToolError, "identity changed"):
            identity.validate_binding(
                composition, revision, spec, revision_name=revision_name, previous=pin
            )

    def test_recovery_replacement_root_parks_without_accepting_new_uid(self):
        reviewed, root, _, _, _ = documents()
        operations = runner.RealOperations()
        with patch.object(
            runner.u0_runner.RealOperations,
            "cleanup",
            return_value={"controllersStopped": 14},
        ) as park, patch.object(
            operations, "_optional", return_value=root
        ), patch.object(
            operations, "_kube"
        ) as lookup, self.assertRaises(
            ToolError
        ):
            operations.cleanup(reviewed, expected_environment_uid="original-root-uid")
        park.assert_called_once()
        lookup.assert_not_called()

    def test_actual_runner_snapshot_and_park_accept_normal_completion_fields(self):
        reviewed, root, composition, revision, spec = documents()
        operations = runner.RealOperations()
        with patch.object(
            operations, "_kube", side_effect=[root, composition, revision]
        ), patch.object(operations, "_optional", return_value=None), patch.object(
            runner, "load_yaml", return_value={"spec": spec}
        ):
            snapshot = operations._environment_snapshot(reviewed, "root-uid")
        self.assertFalse(snapshot["allChildrenObserved"])
        self.assertEqual(3, snapshot["root"]["generation"])
        parked = {
            "controllersStopped": 14,
            "sessionSecretAbsent": True,
            "sharedProtectionRestored": True,
        }
        with patch.object(
            runner.u0_runner.RealOperations, "cleanup", return_value=parked
        ), patch.object(operations, "_optional", return_value=root), patch.object(
            operations, "_kube", side_effect=[composition, revision]
        ), patch.object(
            runner, "load_yaml", return_value={"spec": spec}
        ):
            result = operations.cleanup(reviewed, expected_environment_uid="root-uid")
        self.assertTrue(result["environmentPresent"])
        self.assertFalse(result["environmentDeleted"])
        self.assertFalse(result["awsDeletionAttempted"])

    def test_runner_rejects_disappeared_and_same_content_switched_revision(self):
        reviewed, root, composition, revision, spec = documents()
        operations = runner.RealOperations()
        with patch.object(
            operations, "_kube", side_effect=[composition, revision]
        ), patch.object(runner, "load_yaml", return_value={"spec": spec}):
            operations._assert_environment_identity(
                reviewed, root, expected_uid="root-uid"
            )
        missing = copy.deepcopy(root)
        missing["spec"]["crossplane"].pop("compositionRevisionRef")
        with self.assertRaisesRegex(ToolError, "disappeared"):
            operations._assert_environment_identity(
                reviewed, missing, expected_uid="root-uid"
            )
        changed = copy.deepcopy(root)
        new_revision = copy.deepcopy(revision)
        new_name = identity.COMPOSITION_NAME + "-other"
        changed["spec"]["crossplane"]["compositionRevisionRef"]["name"] = new_name
        new_revision["metadata"]["name"] = new_name
        with patch.object(
            operations, "_kube", side_effect=[composition, new_revision]
        ), patch.object(
            runner, "load_yaml", return_value={"spec": spec}
        ), self.assertRaises(
            ToolError
        ):
            operations._assert_environment_identity(
                reviewed, changed, expected_uid="root-uid"
            )


if __name__ == "__main__":
    unittest.main()
