from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "eks_lifecycle"))

from common import ToolError  # noqa: E402
import validate_u0_admission_authorization as admission  # noqa: E402


EXECUTION_STATE = {
    "gitCommit": "a" * 40,
    "roots": ["scripts/eks_lifecycle"],
    "trackedNonMarkdownFiles": 200,
    "aggregateSha256": "b" * 64,
    "untrackedNonMarkdownFiles": 0,
    "markdownDriftExcluded": True,
}


def fixture(window_id: str) -> dict:
    return {
        "apiVersion": "platform.aws.goodnotes.io/v1alpha1",
        "kind": "XEKSEnvironment",
        "metadata": {
            "name": admission.FIXTURE_NAME,
            "labels": {
                "platform.aws.goodnotes.io/managed-by": "u0-admission-preflight",
                "platform.aws.goodnotes.io/window-id": window_id,
            },
            "annotations": {"crossplane.io/paused": "true"},
        },
        "spec": {
            "crossplane": {"compositionUpdatePolicy": "Manual"},
            "parameters": {
                "lifecycle": {
                    "retirementStage": "Active",
                    "deletionProtection": True,
                }
            },
        },
    }


def authorization(status: str = admission.PENDING_STATUS) -> dict:
    approved = status == admission.APPROVED_STATUS
    generated = datetime.now(timezone.utc) - timedelta(minutes=2)
    return {
        "schemaVersion": admission.SCHEMA_VERSION,
        "bundle": "u0-admission-2026-09-04-01",
        "windowId": "u0a-20260904-01",
        "singleUse": True,
        "generatedAt": generated.isoformat(),
        "reviewStatus": status,
        "approvedBy": "GoodspeedWong" if approved else None,
        "approvedAt": (
            (generated + timedelta(minutes=1)).isoformat() if approved else None
        ),
        "authorizationType": admission.AUTHORIZATION_TYPE,
        "preparationEvidence": admission.PREPARATION_EVIDENCE,
        "requestedWindow": admission.requested_window(),
        "decisions": {
            key: True if approved else None for key in admission.DECISION_KEYS
        },
        "executionCode": EXECUTION_STATE,
    }


class U0AdmissionAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = (
            Path(self.temporary.name) / "u0-admission-2026-09-04-01"
        )
        self.directory.mkdir(mode=0o700)
        self.claim_root = Path(self.temporary.name).resolve() / "claims"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, name: str, payload: bytes) -> None:
        path = self.directory / name
        path.write_bytes(payload)
        os.chmod(path, 0o600)

    def write_bundle(self, document: dict) -> Path:
        window_id = document["windowId"]
        files = {
            "REVIEW_SUMMARY.md": b"private review\n",
            "authorization-contract.json": (
                json.dumps(document, indent=2, sort_keys=True) + "\n"
            ).encode(),
            "admission-test-plan.json": (
                json.dumps(
                    admission.expected_test_plan(window_id),
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode(),
            "environment-fixture.yaml": (
                json.dumps(fixture(window_id), indent=2) + "\n"
            ).encode(),
            "temporary-rbac.yaml": (
                json.dumps(admission.expected_temporary_rbac(window_id), indent=2)
                + "\n"
            ).encode(),
        }
        for name, payload in files.items():
            self._write(name, payload)
        sums = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(files.items())
        )
        self._write("SHA256SUMS", sums.encode())
        return self.directory / "authorization-contract.json"

    def rewrite_checksums(self) -> None:
        files = {
            path.name: path.read_bytes()
            for path in self.directory.iterdir()
            if path.name != "SHA256SUMS"
        }
        sums = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(files.items())
        )
        self._write("SHA256SUMS", sums.encode())

    def validate(self, path: Path, require_approved: bool = False) -> dict:
        with patch.object(
            admission.u0_authorization,
            "execution_code_state",
            return_value=EXECUTION_STATE,
        ):
            return admission.validate_authorization(path, require_approved)

    def test_pending_plan_is_local_only_and_exact(self) -> None:
        result = self.validate(self.write_bundle(authorization()))
        self.assertFalse(result["approved"])
        self.assertEqual(52, result["ordinaryAuthorizationChecks"])
        self.assertEqual(9, result["dryRunAdmissionChecks"])
        self.assertEqual(3, result["temporaryKubernetesResources"])
        self.assertFalse(result["awsApiCalls"])
        self.assertFalse(result["kubernetesApiCalls"])

    def test_pending_contract_cannot_run(self) -> None:
        path = self.write_bundle(authorization())
        with self.assertRaisesRegex(ToolError, "not approved"):
            self.validate(path, require_approved=True)

    def test_approved_contract_requires_every_decision(self) -> None:
        document = authorization(admission.APPROVED_STATUS)
        document["decisions"]["TemporaryPausedFixture"] = False
        path = self.write_bundle(document)
        with self.assertRaisesRegex(ToolError, "every U0 admission decision"):
            self.validate(path, require_approved=True)

    def test_bundle_bytes_and_semantics_are_both_pinned(self) -> None:
        path = self.write_bundle(authorization())
        plan_path = self.directory / "admission-test-plan.json"
        plan_path.write_text(plan_path.read_text() + "\n")
        os.chmod(plan_path, 0o600)
        with self.assertRaisesRegex(ToolError, "checksum differs"):
            self.validate(path)

        self.temporary.cleanup()
        self.setUp()
        path = self.write_bundle(authorization())
        plan_path = self.directory / "admission-test-plan.json"
        plan = json.loads(plan_path.read_text())
        plan["dryRunCases"][0]["expectedAllowed"] = True
        self._write(
            "admission-test-plan.json",
            (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode(),
        )
        self.rewrite_checksums()
        with self.assertRaisesRegex(ToolError, "test plan differs"):
            self.validate(path)

    def test_fixture_and_temporary_rbac_cannot_expand(self) -> None:
        path = self.write_bundle(authorization())
        fixture_path = self.directory / "environment-fixture.yaml"
        value = json.loads(fixture_path.read_text())
        value["metadata"]["annotations"].pop("crossplane.io/paused")
        self._write(
            "environment-fixture.yaml", (json.dumps(value, indent=2) + "\n").encode()
        )
        self.rewrite_checksums()
        with self.assertRaisesRegex(ToolError, "fixture differs"):
            self.validate(path)

        self.temporary.cleanup()
        self.setUp()
        path = self.write_bundle(authorization())
        rbac_path = self.directory / "temporary-rbac.yaml"
        rbac = json.loads(rbac_path.read_text())
        rbac["items"][0]["rules"][0].pop("resourceNames")
        self._write(
            "temporary-rbac.yaml", (json.dumps(rbac, indent=2) + "\n").encode()
        )
        self.rewrite_checksums()
        with self.assertRaisesRegex(ToolError, "temporary admission-test RBAC"):
            self.validate(path)

    def test_claim_is_atomic_owner_only_and_single_use(self) -> None:
        path = self.write_bundle(authorization(admission.APPROVED_STATUS))
        with patch.object(
            admission.u0_authorization,
            "execution_code_state",
            return_value=EXECUTION_STATE,
        ):
            claimed = admission.claim_authorization(
                path,
                admission.CLAIM_ACKNOWLEDGEMENT,
                claim_root=self.claim_root,
            )
            verified = admission.verify_claim(path, claim_root=self.claim_root)
            with self.assertRaisesRegex(ToolError, "already claimed"):
                admission.claim_authorization(
                    path,
                    admission.CLAIM_ACKNOWLEDGEMENT,
                    claim_root=self.claim_root,
                )
        receipt = self.claim_root / "u0a-20260904-01.json"
        self.assertTrue(claimed["claimed"])
        self.assertTrue(verified["claimActive"])
        self.assertEqual(0o700, stat.S_IMODE(self.claim_root.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(receipt.stat().st_mode))

    def test_claim_expiry_allows_recovery_verification_only(self) -> None:
        path = self.write_bundle(authorization(admission.APPROVED_STATUS))
        with patch.object(
            admission.u0_authorization,
            "execution_code_state",
            return_value=EXECUTION_STATE,
        ):
            claimed = admission.claim_authorization(
                path,
                admission.CLAIM_ACKNOWLEDGEMENT,
                claim_root=self.claim_root,
            )
            deadline = datetime.fromisoformat(claimed["deadline"])
            with self.assertRaisesRegex(ToolError, "expired"):
                admission.verify_claim(
                    path,
                    claim_root=self.claim_root,
                    now=deadline,
                )
            recovered = admission.verify_claim(
                path,
                claim_root=self.claim_root,
                require_active=False,
                now=deadline,
            )
        self.assertFalse(recovered["claimActive"])

    def test_claim_receipt_tamper_is_rejected(self) -> None:
        path = self.write_bundle(authorization(admission.APPROVED_STATUS))
        with patch.object(
            admission.u0_authorization,
            "execution_code_state",
            return_value=EXECUTION_STATE,
        ):
            admission.claim_authorization(
                path,
                admission.CLAIM_ACKNOWLEDGEMENT,
                claim_root=self.claim_root,
            )
            receipt = self.claim_root / "u0a-20260904-01.json"
            value = json.loads(receipt.read_text())
            value["authorizationSha256"] = "0" * 64
            receipt.write_text(json.dumps(value))
            os.chmod(receipt, 0o600)
            with self.assertRaisesRegex(ToolError, "does not match"):
                admission.verify_claim(path, claim_root=self.claim_root)

    def test_request_boundary_rejects_any_aws_or_controller_permission(self) -> None:
        document = authorization()
        document["requestedWindow"] = copy.deepcopy(document["requestedWindow"])
        document["requestedWindow"]["awsApiCallsAllowed"] = True
        path = self.write_bundle(document)
        with self.assertRaisesRegex(ToolError, "boundary differs"):
            self.validate(path)

    def test_bundle_and_window_sequence_must_match(self) -> None:
        document = authorization()
        document["windowId"] = "u0a-20260904-02"
        path = self.write_bundle(document)
        with self.assertRaisesRegex(ToolError, "identities differ"):
            self.validate(path)


if __name__ == "__main__":
    unittest.main()
