from __future__ import annotations

import base64
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts/eks_lifecycle"))
import harden_management_kind as hardening
from common import EKS_ROOT, ToolError, load_yaml


class ManagementHardeningTests(unittest.TestCase):
    def test_encryption_is_first_with_plaintext_read_fallback(self):
        document = hardening.encryption_document(b"k" * 32)
        entry = document["resources"][0]
        self.assertEqual(["secrets"], entry["resources"])
        self.assertEqual({"identity": {}}, entry["providers"][1])
        self.assertEqual(
            b"k" * 32,
            base64.b64decode(entry["providers"][0]["secretbox"]["keys"][0]["secret"]),
        )

    def test_bad_key_length_rejected(self):
        with self.assertRaises(ToolError):
            hardening.encryption_document(b"too-short")

    @staticmethod
    def manifest():
        return {"spec": {"containers": [{"name": "kube-apiserver", "command": [
            "kube-apiserver", "--authorization-mode=Node,RBAC"
        ], "volumeMounts": []}], "volumes": []}}

    def test_additive_manifest_does_not_mutate_original(self):
        original = self.manifest()
        before = copy.deepcopy(original)
        result = hardening.encrypted_manifest(original)
        self.assertEqual(original, before)
        self.assertEqual(original["spec"]["containers"][0]["command"],
                         result["spec"]["containers"][0]["command"][:-1])
        self.assertTrue(result["spec"]["containers"][0]["volumeMounts"][0]["readOnly"])

    def test_existing_encryption_never_replaced(self):
        existing = hardening.encrypted_manifest(self.manifest())
        with self.assertRaises(ToolError):
            hardening.encrypted_manifest(existing)

    def test_pause_has_identity_and_concurrency_preconditions(self):
        item = {"metadata": {"uid": "u", "resourceVersion": "r", "annotations": {"keep": "yes"}}}
        patch_value = hardening.pause_patch(item, "token")
        self.assertEqual(["/metadata/uid", "/metadata/resourceVersion"],
                         [entry["path"] for entry in patch_value[:2]])
        self.assertEqual("true", patch_value[-2]["value"])
        self.assertEqual("/metadata/annotations/crossplane.io~1paused", patch_value[-2]["path"])
        self.assertNotIn("keep", str(patch_value))

    def test_existing_pause_not_taken_over(self):
        item = {"metadata": {"uid": "u", "resourceVersion": "r", "annotations": {hardening.PAUSE: "true"}}}
        with self.assertRaises(ToolError):
            hardening.pause_patch(item, "token")

    def test_restore_rejects_drift(self):
        item = {"metadata": {"uid": "u", "resourceVersion": "r", "annotations": {
            hardening.PAUSE: "true", hardening.MARKER: "different-owner"
        }}}
        with self.assertRaises(ToolError):
            hardening.pause_patch(item, "token", restore=True)

    def test_restore_touches_only_our_annotations(self):
        item = {"metadata": {"uid": "u", "resourceVersion": "r", "annotations": {
            hardening.PAUSE: "true", hardening.MARKER: "token", "last-applied": "do-not-copy"
        }}}
        result = hardening.pause_patch(item, "token", restore=True)
        self.assertEqual(["remove", "remove"], [entry["op"] for entry in result[2:]])
        self.assertNotIn("do-not-copy", str(result))

    def test_provider_cluster_admin_manifest_is_an_empty_tombstone(self):
        root = EKS_ROOT.parent / "crossplane-managed-kind/local-cluster"
        document = load_yaml(root / "provider-runtime-cluster-admin.yaml")
        self.assertEqual("ClusterRole", document["kind"])
        self.assertEqual([], document["rules"])
        self.assertNotIn("subjects", document)
        self.assertNotIn("roleRef", document)
        self.assertNotEqual("crossplane-local-runtime-cluster-admin", document["metadata"]["name"])

    def test_private_state_is_exclusive_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "private"
            with patch.object(hardening, "STATE", state):
                hardening.save_new("test.json", b"{}")
                self.assertEqual(0o600, (state / "test.json").stat().st_mode & 0o777)
                with self.assertRaises(FileExistsError):
                    hardening.save_new("test.json", b"overwrite")
                (state / "link.json").symlink_to(state / "test.json")
                with self.assertRaises(ToolError):
                    hardening.read_private("link.json")


if __name__ == "__main__":
    unittest.main()
