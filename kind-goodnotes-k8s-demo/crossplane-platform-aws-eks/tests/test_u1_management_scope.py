from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))

from common import ToolError
import run_u1_bootstrap as bootstrap
import run_u1_cidr_amendment as cidr_runner
import u1_cidr_amendment as amendment
import u1_continuation_operations as continuation
import u1_shared_protection as protection
import validate_u1_cidr_authorization as cidr_auth
import validate_u1_continuation as continuation_auth
from u1_management_scope import EXISTING_WORKLOAD_BOUNDARY, SHARED_PROTECTION_POLICY
from test_u1_bootstrap import contract
from test_u1_continuation import PIN


def shared_fixture():
    documents = {}
    for (resource, name), kind in zip(
        protection.XR_NAMES.items(),
        ("XKeycloak", "XTradingDataStore", "XTradingWorkload"),
    ):
        group = resource.split(".", 1)[1]
        documents[(resource, name)] = {
            "apiVersion": group + "/v1alpha1",
            "kind": kind,
            "metadata": {"name": name, "uid": name + "-uid", "resourceVersion": "1"},
            "spec": {"parameters": {"test": "intent"}},
        }
    owners = list(documents.values())
    for i in range(73):
        owner = owners[i % 3]
        name = f"test-object-{i:02d}"
        documents[(protection.OBJECT_RESOURCE, name)] = {
            "apiVersion": "kubernetes.crossplane.io/v1alpha2",
            "kind": "Object",
            "metadata": {
                "name": name,
                "uid": name + "-uid",
                "resourceVersion": "1",
                "ownerReferences": [
                    {
                        "apiVersion": owner["apiVersion"],
                        "kind": owner["kind"],
                        "name": owner["metadata"]["name"],
                        "uid": owner["metadata"]["uid"],
                        "controller": True,
                    }
                ],
            },
            "spec": {
                "providerConfigRef": {"name": "crossplane-local"},
                "forProvider": {
                    "manifest": {"testOnly": "private-placeholder-do-not-persist"}
                },
            },
        }
    return documents


class SharedProtectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name).resolve() / "a05-20260907-u1c-99"
        self.documents = shared_fixture()
        self.original = copy.deepcopy(self.documents)
        self.writes = []
        self.fail_patch_at = None
        self.controllers = [
            {"spec": {"replicas": 0}, "status": {"replicas": 0}} for _ in range(14)
        ]
        self.business = {
            str(i): {"uid": f"business-{i}", "replicas": 0} for i in range(89)
        }
        for patcher in (
            patch.object(protection.legacy, "STATE", self.state),
            patch.object(protection.legacy, "kube", side_effect=self.kube),
            patch.object(
                protection.legacy,
                "workload_state",
                side_effect=AssertionError("existing business inventory forbidden"),
            ),
            patch.object(
                protection.legacy.subprocess,
                "run",
                side_effect=AssertionError("offline test attempted command/API"),
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def kube(self, args):
        if args == ["get", "deployment", "-n", "crossplane-system"]:
            return {"items": copy.deepcopy(self.controllers)}
        if (
            len(args) == 2
            and args[0] == "get"
            and args[1] in (*protection.XR_NAMES, protection.OBJECT_RESOURCE)
        ):
            return {
                "items": [
                    copy.deepcopy(d)
                    for (r, _), d in self.documents.items()
                    if r == args[1]
                ]
            }
        if len(args) == 3 and args[0] == "get" and (args[1], args[2]) in self.documents:
            return copy.deepcopy(self.documents[(args[1], args[2])])
        if len(args) != 6 or args[0] != "patch" or args[3:5] != ["--type=json", "-p"]:
            raise AssertionError("unexpected request outside shared-object protection")
        if self.fail_patch_at == len(self.writes):
            raise ToolError("synthetic partial patch failure")
        document = self.documents[(args[1], args[2])]
        for operation in json.loads(args[5]):
            path = operation["path"]
            self.assertIn(
                path,
                (
                    "/metadata/uid",
                    "/metadata/resourceVersion",
                    "/metadata/annotations",
                    "/metadata/annotations/crossplane.io~1paused",
                    "/metadata/annotations/platform.aws.goodnotes.io~1a05-maintenance",
                ),
            )
            target = document
            keys = [
                x.replace("~1", "/").replace("~0", "~") for x in path.split("/")[1:]
            ]
            for key in keys[:-1]:
                target = target[key]
            if operation["op"] == "test":
                self.assertEqual(operation["value"], target[keys[-1]])
            elif operation["op"] == "add":
                target[keys[-1]] = operation["value"]
            elif operation["op"] == "remove":
                del target[keys[-1]]
            else:
                raise AssertionError("non-protection mutation")
        document["metadata"]["resourceVersion"] = str(
            int(document["metadata"]["resourceVersion"]) + 1
        )
        self.writes.append((args[1], args[2]))
        return copy.deepcopy(document)

    def test_full_protect_verify_restore_ignores_75_business_changes(self):
        for i in range(75):
            self.business[str(i)]["replicas"] = 1
        baseline = copy.deepcopy(self.business)
        self.assertFalse(protection.protect()["existingKindWorkloadsAccessed"])
        self.assertEqual(76, protection.verify_protected()["protectedObjectsVerified"])
        raw = (self.state / "protection.json").read_text()
        self.assertNotIn("workloads", json.loads(raw))
        self.assertNotIn("private-placeholder", raw)
        # A different owner may legitimately change/recreate workloads during a window.
        self.business["0"] = {"uid": "new-business-uid", "replicas": 3}
        expected = copy.deepcopy(self.business)
        self.assertEqual(76, protection.restore()["restoredObjects"])
        self.assertEqual(expected, self.business)
        self.assertNotEqual(baseline, self.business)
        self.assertEqual(152, len(self.writes))
        self.assertEqual(76, protection.restore()["restoredObjects"])
        self.assertEqual(152, len(self.writes))
        for key in self.documents:
            self.assertEqual(
                protection.fingerprint(self.original[key]),
                protection.fingerprint(self.documents[key]),
            )
        self.assertEqual(0o600, (self.state / "protection.json").stat().st_mode & 0o777)

    def test_protection_snapshot_never_overwritten(self):
        protection.protect()
        raw = (self.state / "protection.json").read_bytes()
        protection.restore()
        with self.assertRaises(FileExistsError):
            protection.protect()
        self.assertEqual(raw, (self.state / "protection.json").read_bytes())

    def test_incomplete_parking_rejected_before_protection_state_or_write(self):
        original = copy.deepcopy(self.controllers)
        for field, value in (("spec", 1), ("status", 1), ("spec", False)):
            self.controllers = copy.deepcopy(original)
            self.controllers[0][field]["replicas"] = value
            with self.assertRaises(ToolError):
                protection.protect()
            self.assertFalse(self.state.exists())
        self.controllers = original[:-1]
        with self.assertRaises(ToolError):
            protection.protect()
        self.assertEqual([], self.writes)

    def test_initial_owner_target_count_or_pause_drift_rejected_before_write(self):
        key = (protection.OBJECT_RESOURCE, "test-object-00")
        for mutate in (
            lambda d: d["spec"]["providerConfigRef"].update(name="remote-eks"),
            lambda d: d["metadata"]["ownerReferences"][0].update(uid="other"),
            lambda d: d["metadata"]["ownerReferences"][0].update(controller=1),
            lambda d: d["metadata"].update(
                annotations={protection.legacy.PAUSE: "true"}
            ),
            lambda d: d["metadata"].update(deletionTimestamp="now"),
        ):
            self.documents = copy.deepcopy(self.original)
            mutate(self.documents[key])
            with self.assertRaises(ToolError):
                protection.protect()
            self.assertFalse(self.state.exists())
            self.assertEqual([], self.writes)
        self.documents = copy.deepcopy(self.original)
        self.documents.pop(key)
        with self.assertRaises(ToolError):
            protection.protect()
        self.assertEqual([], self.writes)

    def test_protected_uid_spec_owner_or_token_drift_still_blocks(self):
        protection.protect()
        protected = copy.deepcopy(self.documents)
        key = (protection.OBJECT_RESOURCE, "test-object-00")
        for mutate in (
            lambda d: d["metadata"].update(uid="replacement"),
            lambda d: d["spec"].update(forProvider={"manifest": {"changed": True}}),
            lambda d: d["metadata"]["ownerReferences"][0].update(uid="other"),
            lambda d: d["metadata"]["annotations"].update(
                {protection.legacy.MARKER: "someone-else"}
            ),
            lambda d: d["metadata"]["annotations"].clear(),
        ):
            self.documents = copy.deepcopy(protected)
            mutate(self.documents[key])
            with self.assertRaises(ToolError):
                protection.verify_protected()
        self.documents = copy.deepcopy(protected)
        self.documents[key]["spec"]["changed"] = True
        with self.assertRaises(ToolError):
            protection.restore()
        self.assertEqual(76, len(self.writes))

    def test_partial_protect_and_restore_are_recoverable_without_business_reads(self):
        self.fail_patch_at = 4
        with self.assertRaises(ToolError):
            protection.protect()
        self.assertTrue((self.state / "protection.json").exists())
        self.fail_patch_at = 6
        with self.assertRaises(ToolError):
            protection.restore()
        self.fail_patch_at = None
        self.assertEqual(76, protection.restore()["restoredObjects"])
        self.assertEqual(8, len(self.writes))
        self.assertTrue(
            all(
                protection.legacy.PAUSE not in d["metadata"].get("annotations", {})
                for d in self.documents.values()
            )
        )

    def test_foreign_state_or_legacy_workload_snapshot_cannot_be_adopted(self):
        protection.legacy.save_new(
            "protection.json",
            json.dumps(
                {"token": "old", "workloads": self.business, "objects": []}
            ).encode(),
        )
        with self.assertRaises(ToolError):
            protection.restore()
        self.assertEqual([], self.writes)

    def test_corrupt_protection_scope_or_target_cannot_restore(self):
        protection.protect()
        path = self.state / "protection.json"
        original = json.loads(path.read_text())
        for mutate in (
            lambda s: s.update(policy="legacy"),
            lambda s: s.update(schemaVersion=True),
            lambda s: s["objects"].pop(),
            lambda s: s["objects"][0].update(resource="secrets"),
            lambda s: s["objects"][0].update(uid="replacement"),
            lambda s: s["objects"][0].update(name="--all"),
            lambda s: s["objects"].__setitem__(1, s["objects"][0]),
        ):
            changed = copy.deepcopy(original)
            mutate(changed)
            path.write_text(json.dumps(changed))
            with self.assertRaises(ToolError):
                protection.restore()
            self.assertEqual(76, len(self.writes))

    def test_recovery_evidence_failure_prevents_first_patch(self):
        with patch.object(
            protection.legacy, "save_new", side_effect=OSError("synthetic disk error")
        ), self.assertRaises(OSError):
            protection.protect()
        self.assertEqual([], self.writes)

    def test_shared_validator_does_not_read_or_bind_business_archive(self):
        records = [
            {
                "resource": r,
                "name": d["metadata"]["name"],
                "uid": d["metadata"]["uid"],
                "ownerReferences": d["metadata"].get("ownerReferences", []),
            }
            for (r, _), d in self.documents.items()
        ]
        evidence = {
            "pin": PIN,
            "proof": {
                "core-readonly-evidence": {"controllers": []},
                "shared-object-evidence": {"sharedObjects": records},
                "business-workload-evidence": {"workloads": "historical unbound input"},
            },
        }
        ops = continuation.RealOperations({"evidence": evidence})
        reader = Mock()

        def get(path, **_kwargs):
            plural = path.rsplit("/", 1)[1]
            return [
                copy.deepcopy(d)
                for (r, _), d in self.documents.items()
                if r.split(".", 1)[0] == plural
            ]

        reader.get.side_effect = get
        ops._assert_shared(contract(), reader)
        self.documents[(protection.OBJECT_RESOURCE, "test-object-00")]["metadata"][
            "uid"
        ] = "changed"
        with self.assertRaises(ToolError):
            ops._assert_shared(contract(), reader)


class ScopeContractTests(unittest.TestCase):
    def test_cidr_and_continuation_explicitly_exclude_migration_and_global_state(self):
        for module in (cidr_auth, continuation_auth):
            self.assertEqual(2, module.SCHEMA_VERSION)
            self.assertEqual(
                EXISTING_WORKLOAD_BOUNDARY, module.SCOPE["existingKindWorkloads"]
            )
        self.assertNotIn("businessWorkloads", continuation_auth.SCOPE)
        self.assertNotIn("businessWorkloadsUnchanged", amendment.CHECKS)
        self.assertIs(True, amendment.CHECKS["existingKindWorkloadsExcluded"])
        self.assertEqual(
            SHARED_PROTECTION_POLICY,
            EXISTING_WORKLOAD_BOUNDARY["sharedControllerProtection"],
        )

    def test_u1_only_selects_new_protection_and_verifies_before_start(self):
        ops = bootstrap.RealOperations()
        with patch.object(bootstrap.u0_runner, "_run_suppressed") as run:
            for mode in ("protect", "verify", "restore"):
                ops._harden(contract(), mode)
                args = run.call_args.args[0]
                self.assertTrue(args[1].endswith("/u1_shared_protection.py"))
                self.assertIn(protection.ACK, args)
                self.assertNotIn("harden_management_kind.py", args[1])
            with self.assertRaises(ToolError):
                ops._harden(contract(), "encrypt")
        events = []
        with patch.object(
            ops, "_verify_claim", side_effect=lambda _: events.append("claim")
        ), patch.object(
            ops, "_harden", side_effect=lambda _c, mode: events.append(mode)
        ), patch.object(
            bootstrap.u0_runner.RealOperations,
            "start_controllers",
            side_effect=lambda _: events.append("start"),
        ):
            ops.start_controllers(contract())
        self.assertEqual(["claim", "verify", "start"], events)

    def test_unprotected_state_blocks_start_and_cidr_cannot_reuse_active_paths(self):
        ops = bootstrap.RealOperations()
        with patch.object(ops, "_verify_claim"), patch.object(
            ops, "_harden", side_effect=ToolError("not protected")
        ), patch.object(
            bootstrap.u0_runner.RealOperations, "start_controllers"
        ) as start, self.assertRaises(
            ToolError
        ):
            ops.start_controllers(contract())
        start.assert_not_called()
        # CIDR's override is a separate immutable no-controller/no-session gate.
        self.assertIsNot(
            cidr_runner.RealOperations._verify_claim,
            bootstrap.RealOperations._verify_claim,
        )
        cidr = cidr_runner.RealOperations.__new__(cidr_runner.RealOperations)
        for mode in ("protect", "verify", "restore"):
            with self.assertRaises(ToolError):
                cidr._harden(None, mode)


if __name__ == "__main__":
    unittest.main()
