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
        "executionCode": u0.execution_code_state(),
    }


class U0AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "u0-preflight-2026-09-02"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)
        self.claim_root = Path(self.temporary.name).resolve() / "claim-state"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_bundle(
        self,
        document: dict,
        *,
        catalog_payload: bytes | None = None,
    ) -> Path:
        catalog_payload = catalog_payload or (
            b"apiVersion: apiextensions.crossplane.io/v1beta1\n"
            b"kind: EnvironmentConfig\n"
            b"metadata:\n  name: safe\n"
            b"data:\n  safe: true\n"
        )
        payloads = {
            "REVIEW_SUMMARY.md": b"private review\n",
            "authorization-contract.json": (
                json.dumps(document, indent=2, sort_keys=True) + "\n"
            ).encode(),
            "aws-readonly-snapshot.json": b'{"snapshot":"safe"}\n',
            "environment.candidate.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: safe\n",
            "node-image.candidate.yaml": catalog_payload,
            "platform-release.candidate.yaml": catalog_payload,
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

    def test_same_day_sequence_bundle_is_supported_without_reusing_a_claim(self) -> None:
        sequenced = self.directory.with_name("u0-preflight-2026-09-02-02")
        self.directory.rename(sequenced)
        self.directory = sequenced
        document = authorization()
        document["bundle"] = self.directory.name
        document["windowId"] = "u0-20260902-02"
        result = u0.validate_authorization(
            self.write_bundle(document),
            require_approved=False,
        )
        self.assertEqual(self.directory.name, result["bundle"])
        self.assertEqual("u0-20260902-02", result["windowId"])
        self.assertFalse(result["approved"])

    def test_approved_window_requires_all_decisions_and_exact_scope(self) -> None:
        path = self.write_bundle(authorization(u0.APPROVED_STATUS))
        result = u0.validate_authorization(path, require_approved=True)
        self.assertTrue(result["approved"])
        self.assertEqual(11, len(u0.DECISION_KEYS))
        self.assertFalse(result["awsResourceMutationAllowed"])
        self.assertEqual(6, result["kubernetesMutationActions"])

    def test_catalog_candidates_require_live_environment_config_envelope(self) -> None:
        legacy = (
            b"apiVersion: apiextensions.crossplane.io/v1beta1\n"
            b"kind: EnvironmentConfig\n"
            b"metadata:\n  name: safe\n"
            b"spec:\n  data:\n    safe: true\n"
        )
        path = self.write_bundle(authorization(), catalog_payload=legacy)
        with self.assertRaisesRegex(ToolError, "top-level field"):
            u0.validate_authorization(path, require_approved=False)

    def test_scope_drift_fails_even_with_refreshed_checksums(self) -> None:
        document = authorization(u0.APPROVED_STATUS)
        document["requestedU0Window"]["allowed"].append("create an EKS cluster")
        path = self.write_bundle(document)
        with self.assertRaisesRegex(ToolError, "allowlist"):
            u0.validate_authorization(path, require_approved=True)

    def test_execution_code_commit_digest_or_inventory_drift_fails(self) -> None:
        for mode in ("commit", "digest", "roots", "count", "untracked"):
            document = authorization(u0.APPROVED_STATUS)
            execution = document["executionCode"]
            if mode == "commit":
                execution["gitCommit"] = "0" * 40
            elif mode == "digest":
                execution["aggregateSha256"] = "0" * 64
            elif mode == "roots":
                execution["roots"].append("unreviewed")
            elif mode == "count":
                execution["trackedNonMarkdownFiles"] += 1
            else:
                execution["untrackedNonMarkdownFiles"] = 1
            path = self.write_bundle(document)
            with self.subTest(mode=mode), self.assertRaisesRegex(
                ToolError,
                "execution code differs",
            ):
                u0.validate_authorization(path, require_approved=True)

    def test_execution_code_state_is_commit_bound_and_excludes_markdown(self) -> None:
        state = u0.execution_code_state()
        self.assertRegex(state["gitCommit"], r"^[0-9a-f]{40}$")
        self.assertRegex(state["aggregateSha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(state["trackedNonMarkdownFiles"], 0)
        self.assertEqual(0, state["untrackedNonMarkdownFiles"])
        self.assertTrue(state["markdownDriftExcluded"])
        self.assertEqual(list(u0.EXECUTION_ROOTS), state["roots"])

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

    def test_claim_is_atomic_owner_only_and_verifiable(self) -> None:
        path = self.write_bundle(authorization(u0.APPROVED_STATUS))
        claim_root = self.claim_root
        result = u0.claim_authorization(
            path,
            u0.CLAIM_ACKNOWLEDGEMENT,
            claim_root=claim_root,
        )
        receipt = claim_root / "u0-20260902-01.json"
        self.assertTrue(result["claimed"])
        self.assertTrue(result["localAuthorizationStateMutation"])
        self.assertFalse(result["awsApiCalls"])
        self.assertFalse(result["kubernetesApiCalls"])
        self.assertEqual(0o700, stat.S_IMODE(claim_root.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(receipt.stat().st_mode))
        verified = u0.verify_claim(path, claim_root=claim_root)
        self.assertTrue(verified["claimActive"])
        self.assertFalse(verified["localAuthorizationStateMutation"])

    def test_claim_rejects_pending_wrong_acknowledgement_and_reuse(self) -> None:
        claim_root = self.claim_root
        pending = self.write_bundle(authorization())
        with self.assertRaisesRegex(ToolError, "not approved"):
            u0.claim_authorization(
                pending,
                u0.CLAIM_ACKNOWLEDGEMENT,
                claim_root=claim_root,
            )
        self.assertFalse(claim_root.exists())

        approved = self.write_bundle(authorization(u0.APPROVED_STATUS))
        with self.assertRaisesRegex(ToolError, "acknowledgement"):
            u0.claim_authorization(approved, "", claim_root=claim_root)
        self.assertFalse(claim_root.exists())
        u0.claim_authorization(
            approved,
            u0.CLAIM_ACKNOWLEDGEMENT,
            claim_root=claim_root,
        )
        with self.assertRaisesRegex(ToolError, "already claimed"):
            u0.claim_authorization(
                approved,
                u0.CLAIM_ACKNOWLEDGEMENT,
                claim_root=claim_root,
            )

    def test_claim_receipt_tamper_or_unsafe_state_is_rejected(self) -> None:
        path = self.write_bundle(authorization(u0.APPROVED_STATUS))
        claim_root = self.claim_root
        u0.claim_authorization(
            path,
            u0.CLAIM_ACKNOWLEDGEMENT,
            claim_root=claim_root,
        )
        receipt = claim_root / "u0-20260902-01.json"
        document = json.loads(receipt.read_text())
        document["authorizationSha256"] = "0" * 64
        receipt.write_text(json.dumps(document))
        os.chmod(receipt, 0o600)
        with self.assertRaisesRegex(ToolError, "does not match"):
            u0.verify_claim(path, claim_root=claim_root)

        receipt.unlink()
        target = Path(self.temporary.name) / "foreign-receipt.json"
        target.write_text("{}")
        os.chmod(target, 0o600)
        receipt.symlink_to(target)
        with self.assertRaises(ToolError):
            u0.verify_claim(path, claim_root=claim_root)

    def test_claim_binds_the_exact_reviewed_authorization_bytes(self) -> None:
        document = authorization(u0.APPROVED_STATUS)
        path = self.write_bundle(document)
        claim_root = self.claim_root
        u0.claim_authorization(
            path,
            u0.CLAIM_ACKNOWLEDGEMENT,
            claim_root=claim_root,
        )
        document["approvedBy"] = "different-operator"
        path = self.write_bundle(document)
        self.assertTrue(u0.validate_authorization(path, require_approved=True)["approved"])
        with self.assertRaisesRegex(ToolError, "does not match"):
            u0.verify_claim(path, claim_root=claim_root)

    def test_expired_claim_blocks_start_but_remains_valid_for_recovery(self) -> None:
        path = self.write_bundle(authorization(u0.APPROVED_STATUS))
        claim_root = self.claim_root
        claimed = u0.claim_authorization(
            path,
            u0.CLAIM_ACKNOWLEDGEMENT,
            claim_root=claim_root,
        )
        deadline = datetime.fromisoformat(claimed["deadline"])
        after_deadline = deadline + timedelta(seconds=1)
        with self.assertRaisesRegex(ToolError, "only recovery"):
            u0.verify_claim(
                path,
                claim_root=claim_root,
                now=after_deadline,
            )
        recovery = u0.verify_claim(
            path,
            claim_root=claim_root,
            require_active=False,
            now=after_deadline,
        )
        self.assertFalse(recovery["claimActive"])

    def test_claim_state_directory_must_not_be_shared_or_symlinked(self) -> None:
        path = self.write_bundle(authorization(u0.APPROVED_STATUS))
        claim_root = self.claim_root
        claim_root.mkdir(mode=0o700)
        os.chmod(claim_root, 0o750)
        with self.assertRaisesRegex(ToolError, "0700"):
            u0.claim_authorization(
                path,
                u0.CLAIM_ACKNOWLEDGEMENT,
                claim_root=claim_root,
            )
        claim_root.rmdir()
        target = Path(self.temporary.name) / "claim-target"
        target.mkdir(mode=0o700)
        claim_root.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ToolError, "symlink"):
            u0.claim_authorization(
                path,
                u0.CLAIM_ACKNOWLEDGEMENT,
                claim_root=claim_root,
            )


if __name__ == "__main__":
    unittest.main()
