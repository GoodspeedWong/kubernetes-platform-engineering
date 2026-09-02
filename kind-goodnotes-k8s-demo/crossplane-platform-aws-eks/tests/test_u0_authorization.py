from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "eks_lifecycle"))

import validate_u0_authorization as u0  # noqa: E402
from common import ToolError  # noqa: E402


def authorization(status: str = u0.PENDING_STATUS) -> dict:
    approved = status == u0.APPROVED_STATUS
    return {
        "schemaVersion": u0.SCHEMA_VERSION,
        "bundle": "u0-preflight-2026-09-02",
        "windowId": "u0-20260902-01",
        "singleUse": True,
        "generatedAt": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
        "reviewStatus": status,
        "approvedBy": "operator" if approved else None,
        "approvedAt": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        if approved
        else None,
        "authorizationType": u0.AUTHORIZATION_TYPE,
        "notAManagementSessionReview": True,
        "requiresSeparateApprovedManagementSessionReview": True,
        "preparationEvidence": u0.PREPARATION_EVIDENCE,
        "requestedU0Window": {
            "purpose": "Complete U0 management-plane preflight only",
            "maximumSessionSeconds": u0.MAX_SESSION_SECONDS,
            "stsSessionIssuanceAllowed": True,
            "awsResourceMutationAllowed": False,
            "kubernetesMutationAllowed": True,
            "kubernetesMutationScope": list(u0.KUBERNETES_MUTATION_SCOPE),
            "credentialHandling": dict(u0.CREDENTIAL_HANDLING),
            "allowed": list(u0.ALLOWED_ACTIONS),
            "forbidden": list(u0.FORBIDDEN_ACTIONS),
        },
        "decisions": {
            key: True if approved else None for key in sorted(u0.DECISION_KEYS)
        },
    }


class U0AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "u0-preflight-2026-09-02"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_bundle(self, document: dict) -> Path:
        payloads = {
            "REVIEW_SUMMARY.md": b"private review\n",
            "authorization-contract.json": (
                json.dumps(document, indent=2, sort_keys=True) + "\n"
            ).encode(),
            "aws-readonly-snapshot.json": b'{"snapshot":"safe"}\n',
            "environment.candidate.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: safe\n",
            "node-image.candidate.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: safe\n",
            "platform-release.candidate.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: safe\n",
            "u0-inputs.json": b'{"inputs":"safe"}\n',
        }
        for name, payload in payloads.items():
            path = self.directory / name
            path.write_bytes(payload)
            os.chmod(path, 0o600)
        checksums = "".join(
            f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
            for name in sorted(payloads)
        )
        checksum_path = self.directory / "SHA256SUMS"
        checksum_path.write_text(checksums)
        os.chmod(checksum_path, 0o600)
        return self.directory / "authorization-contract.json"

    def test_pending_plan_is_non_mutating_but_not_executable(self) -> None:
        path = self.write_bundle(authorization())
        result = u0.validate_authorization(path, require_approved=False)
        self.assertFalse(result["approved"])
        self.assertFalse(result["awsApiCalls"])
        self.assertFalse(result["kubernetesApiCalls"])
        self.assertFalse(result["mutationPerformed"])
        with self.assertRaisesRegex(ToolError, "not approved"):
            u0.validate_authorization(path, require_approved=True)

    def test_approved_window_requires_all_decisions_and_exact_scope(self) -> None:
        path = self.write_bundle(authorization(u0.APPROVED_STATUS))
        result = u0.validate_authorization(path, require_approved=True)
        self.assertTrue(result["approved"])
        self.assertEqual(11, len(u0.DECISION_KEYS))
        self.assertFalse(result["awsResourceMutationAllowed"])
        self.assertEqual(5, result["kubernetesMutationActions"])

    def test_scope_drift_fails_even_with_refreshed_checksums(self) -> None:
        document = authorization(u0.APPROVED_STATUS)
        document["requestedU0Window"]["allowed"].append("create an EKS cluster")
        path = self.write_bundle(document)
        with self.assertRaisesRegex(ToolError, "allowlist"):
            u0.validate_authorization(path, require_approved=True)

    def test_missing_false_or_extra_decision_fails_closed(self) -> None:
        for mode in ("missing", "false", "extra"):
            document = authorization(u0.APPROVED_STATUS)
            if mode == "missing":
                document["decisions"].pop(next(iter(document["decisions"])))
            elif mode == "false":
                document["decisions"][next(iter(document["decisions"]))] = False
            else:
                document["decisions"]["unreviewed"] = True
            path = self.write_bundle(document)
            with self.subTest(mode=mode), self.assertRaises(ToolError):
                u0.validate_authorization(path, require_approved=True)

    def test_checksum_tamper_is_rejected(self) -> None:
        path = self.write_bundle(authorization())
        candidate = self.directory / "environment.candidate.yaml"
        candidate.write_text(candidate.read_text() + "data: {}\n")
        os.chmod(candidate, 0o600)
        with self.assertRaisesRegex(ToolError, "checksum differs"):
            u0.validate_authorization(path, require_approved=False)

    def test_unreviewed_extra_bundle_file_is_rejected(self) -> None:
        path = self.write_bundle(authorization())
        extra = self.directory / "operator-notes.txt"
        extra.write_text("not checksummed\n")
        os.chmod(extra, 0o600)
        with self.assertRaisesRegex(ToolError, "unreviewed file"):
            u0.validate_authorization(path, require_approved=False)

    def test_owner_only_directory_and_files_are_required(self) -> None:
        path = self.write_bundle(authorization())
        os.chmod(path, 0o640)
        with self.assertRaisesRegex(ToolError, "owner-only regular"):
            u0.validate_authorization(path, require_approved=False)
        os.chmod(path, 0o600)
        os.chmod(self.directory, 0o750)
        with self.assertRaisesRegex(ToolError, "owner-only"):
            u0.validate_authorization(path, require_approved=False)

    def test_symlink_authorization_is_rejected(self) -> None:
        path = self.write_bundle(authorization())
        target = self.directory / "authorization-target.json"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(ToolError):
            u0.validate_authorization(path, require_approved=False)

    def test_future_stale_pre_generation_or_anonymous_approval_is_rejected(self) -> None:
        for mode in ("future", "stale", "pre-generation", "anonymous"):
            document = authorization(u0.APPROVED_STATUS)
            if mode == "future":
                document["approvedAt"] = (
                    datetime.now(timezone.utc) + timedelta(minutes=5)
                ).isoformat()
            elif mode == "stale":
                document["approvedAt"] = (
                    datetime.now(timezone.utc) - timedelta(days=2)
                ).isoformat()
            elif mode == "pre-generation":
                document["approvedAt"] = (
                    datetime.fromisoformat(document["generatedAt"])
                    - timedelta(seconds=1)
                ).isoformat()
            else:
                document["approvedBy"] = " "
            path = self.write_bundle(document)
            with self.subTest(mode=mode), self.assertRaises(ToolError):
                u0.validate_authorization(path, require_approved=True)

    def test_preparation_and_requested_mutation_fields_cannot_be_conflated(self) -> None:
        document = authorization()
        self.assertFalse(document["preparationEvidence"]["kubernetesMutation"])
        self.assertTrue(document["requestedU0Window"]["kubernetesMutationAllowed"])
        path = self.write_bundle(document)
        result = u0.validate_authorization(path, require_approved=False)
        self.assertEqual(u0.PENDING_STATUS, result["reviewStatus"])

    def test_checksum_manifest_permissions_are_checked(self) -> None:
        path = self.write_bundle(authorization())
        checksum = self.directory / "SHA256SUMS"
        os.chmod(checksum, stat.S_IRUSR | stat.S_IRGRP)
        with self.assertRaisesRegex(ToolError, "owner-only regular"):
            u0.validate_authorization(path, require_approved=False)


if __name__ == "__main__":
    unittest.main()
