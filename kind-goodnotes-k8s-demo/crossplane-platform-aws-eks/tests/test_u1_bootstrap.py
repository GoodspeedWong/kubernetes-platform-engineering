from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "eks_lifecycle"))

from common import ToolError  # noqa: E402
import renew_management_credentials as credentials  # noqa: E402
import run_u1_bootstrap as runner  # noqa: E402


def contract() -> runner.U1Contract:
    bootstrap = credentials.BootstrapContract(
        environment="eks-dev-spot",
        region="us-east-1",
        context="kind-kube-nebula-a",
        source_role_arn="arn:aws:iam::123456789012:role/source",
        provider_role_arn="arn:aws:iam::123456789012:role/eks-dev-spot-xp-aws",
        deployment_role_arn="arn:aws:iam::123456789012:role/eks-dev-spot-eks-deploy",
        boundary_arn="arn:aws:iam::123456789012:policy/eks-dev-spot-boundary",
    )
    environment_document = {
        "apiVersion": "platform.aws.goodnotes.io/v1alpha1",
        "kind": "XEKSEnvironment",
        "metadata": {
            "name": "eks-dev-spot",
            "labels": {
                "platform.aws.goodnotes.io/environment": "eks-dev-spot",
                "platform.aws.goodnotes.io/managed-by": "crossplane",
            },
            "annotations": {
                "platform.aws.goodnotes.io/authorization-bundle": (
                    "u1-bootstrap-2026-09-04"
                ),
                "platform.aws.goodnotes.io/do-not-apply-outside-runner": "true",
            },
        },
        "spec": {
            "crossplane": {"compositionUpdatePolicy": "Manual"},
            "parameters": {
                "class": "dev",
                "region": "us-east-1",
                "lifecycle": {
                    "retirementStage": "Active",
                    "deletionProtection": True,
                },
            },
        },
    }
    return runner.U1Contract(
        authorization_path=Path("authorization-contract.json"),
        session_review_path=Path("identity-review.json"),
        authorization={
            "bundle": "u1-bootstrap-2026-09-04",
            "windowId": "u1b-20260904-01",
            "reviewStatus": "APPROVED_FOR_ONE_U1_BOOTSTRAP_CREATE_WINDOW",
            "approved": True,
            "reviewedGitCommit": "1" * 40,
            "executionCodeSha256": "2" * 64,
        },
        session_review={"reviewStatus": "APPROVED"},
        bootstrap=bootstrap,
        bundle_directory=Path("bundle"),
        environment_document=environment_document,
        expected_resources={
            "awsApiGroups": [
                "ec2.aws.m.upbound.io",
                "eks.aws.m.upbound.io",
            ]
        },
        environment="eks-dev-spot",
        region="us-east-1",
        account_id="123456789012",
        audit_profile="warlock-cli-codex-admin",
        expected_public_ip="203.0.113.10",
        node_image_id="ami-0123456789abcdef0",
        controller_names=(
            "crossplane",
            *(f"controller-{index}" for index in range(13)),
        ),
        run_id="a05-20260904-u1-01",
    )


class FakeJournal:
    def __init__(self) -> None:
        self.events: list[str] = []

    def append(self, event: str) -> None:
        self.events.append(event)


class FakeOperations:
    def __init__(
        self,
        *,
        fail_at: str | None = None,
        checkpoint_reached: bool = True,
    ) -> None:
        self.calls: list[str] = []
        self.fail_at = fail_at
        self.checkpoint_reached = checkpoint_reached
        self.cleanup_uid: str | None = None

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            raise ToolError(f"test failure at {name}")

    def baseline(self, _contract, _audit_profile):
        self._call("baseline")
        return {"controllersStopped": 14}

    def protect(self, _contract):
        self._call("protect")

    def open_session(self, _contract, _profile, _audit_profile, *, progress=None):
        self._call("open")
        if progress is not None:
            for stage in credentials.SESSION_PROGRESS_STAGES:
                progress(stage)

    def start_controllers(self, _contract):
        self._call("start")

    def wait_ready(self, _contract):
        self._call("wait")

    def dry_run_environment(self, _contract):
        self._call("dry-run")

    def create_environment(self, _contract):
        self._call("create")
        return {"name": "eks-dev-spot", "uid": "uid-1", "generation": 1}

    def wait_checkpoint(self, _contract, _environment):
        self._call("checkpoint")
        return {
            "checkpointReached": self.checkpoint_reached,
            "allChildrenObserved": True,
            "infrastructureReady": self.checkpoint_reached,
        }

    def capture_evidence(self, _contract, _environment, _checkpoint, _audit_profile):
        self._call("evidence")
        return {"captured": True}

    def cleanup(self, _contract, *, expected_environment_uid):
        self.cleanup_uid = expected_environment_uid
        self._call("cleanup")
        return {
            "controllersStopped": 14,
            "sessionSecretAbsent": True,
            "sharedProtectionRestored": True,
            "environmentPresent": expected_environment_uid is not None,
            "environmentDeleted": False,
            "awsDeletionAttempted": False,
        }


class U1BootstrapTests(unittest.TestCase):
    def run_with(self, operations: FakeOperations):
        reviewed = contract()
        journal = FakeJournal()
        reports: list[dict] = []

        def write_result(_path, document):
            reports.append(document)
            return Path("private-result.json")

        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization"),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(runner, "_write_private_json", side_effect=write_result),
        ):
            result = runner.execute(
                reviewed,
                "source-profile",
                "warlock-cli-codex-admin",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        return result, journal, reports[0]

    def test_plan_is_local_only_and_discloses_persistent_billable_mutation(self) -> None:
        result = runner.public_plan(contract())
        self.assertFalse(result["awsApiCalls"])
        self.assertFalse(result["kubernetesApiCalls"])
        self.assertFalse(result["directAwsCliMutationAllowed"])
        self.assertTrue(result["crossplaneAwsResourceMutationAllowed"])
        self.assertTrue(result["persistentEnvironmentAfterWindow"])
        self.assertFalse(result["automaticRetry"])
        self.assertFalse(result["automaticCloudDeletion"])
        self.assertFalse(result["networkApprovalOrGitBootstrap"])
        self.assertEqual(14, result["controllerDeployments"])

    def test_claim_precedes_baseline_and_success_always_parks(self) -> None:
        operations = FakeOperations()
        reviewed = contract()
        journal = FakeJournal()
        order: list[str] = []

        def claim(*_args, **_kwargs):
            order.append("claim")

        def baseline(_contract, _audit_profile):
            order.append("baseline")
            return {}

        operations.baseline = baseline
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(
                runner.authorization_tool,
                "claim_authorization",
                side_effect=claim,
            ),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(runner, "_write_private_json", return_value=Path("result.json")),
        ):
            result = runner.execute(
                reviewed,
                "source-profile",
                "warlock-cli-codex-admin",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        self.assertEqual(["claim", "baseline"], order)
        self.assertEqual(
            [
                "protect",
                "open",
                "start",
                "wait",
                "dry-run",
                "create",
                "checkpoint",
                "evidence",
                "cleanup",
            ],
            operations.calls,
        )
        self.assertEqual("U1_01_PASS", result["status"])
        self.assertEqual("uid-1", operations.cleanup_uid)
        self.assertLess(
            journal.events.index("ENVIRONMENT_DRY_RUN_VERIFIED"),
            journal.events.index("ENVIRONMENT_CREATED"),
        )
        self.assertEqual("CLEANUP_COMPLETE", journal.events[-1])

    def test_clean_timeout_is_pending_not_pass_and_still_parks(self) -> None:
        result, journal, report = self.run_with(
            FakeOperations(checkpoint_reached=False)
        )
        self.assertEqual("U1_BOOTSTRAP_PENDING_CONTINUATION", result["status"])
        self.assertFalse(result["infrastructureReady"])
        self.assertTrue(result["environmentPersisted"])
        self.assertEqual("U1_BOOTSTRAP_PENDING_CONTINUATION", report["status"])
        self.assertIn("MONITOR_WINDOW_ENDED", journal.events)
        self.assertEqual("CLEANUP_COMPLETE", journal.events[-1])

    def test_baseline_failure_consumes_claim_without_cleanup_or_mutation(self) -> None:
        reviewed = contract()
        operations = FakeOperations(fail_at="baseline")
        journal = FakeJournal()
        reports: list[dict] = []
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization") as claim,
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(
                runner,
                "_write_private_json",
                side_effect=lambda _path, value: reports.append(value) or Path("result.json"),
            ),
            self.assertRaisesRegex(ToolError, "no Kubernetes or AWS mutation"),
        ):
            runner.execute(
                reviewed,
                "source-profile",
                "warlock-cli-codex-admin",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        claim.assert_called_once()
        self.assertEqual(["baseline"], operations.calls)
        self.assertNotIn("CLEANUP_STARTED", journal.events)
        self.assertEqual("BASELINE_REJECTED_NO_MUTATION", journal.events[-1])
        self.assertEqual("U1_BOOTSTRAP_FAILED_SAFE", reports[0]["status"])

    def test_failure_after_create_parks_and_preserves_environment(self) -> None:
        reviewed = contract()
        operations = FakeOperations(fail_at="checkpoint")
        journal = FakeJournal()
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization"),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(runner, "_write_private_json", return_value=Path("result.json")),
            self.assertRaisesRegex(ToolError, "environment was preserved"),
        ):
            runner.execute(
                reviewed,
                "source-profile",
                "warlock-cli-codex-admin",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        self.assertEqual("uid-1", operations.cleanup_uid)
        self.assertEqual("cleanup", operations.calls[-1])
        self.assertEqual("FAILED_CLEANUP_COMPLETE", journal.events[-1])

    def test_cleanup_failure_requires_recovery(self) -> None:
        reviewed = contract()
        operations = FakeOperations(fail_at="cleanup")
        journal = FakeJournal()
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization"),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(runner, "_write_private_json", return_value=Path("result.json")),
            self.assertRaisesRegex(ToolError, "recovery-only"),
        ):
            runner.execute(
                reviewed,
                "source-profile",
                "warlock-cli-codex-admin",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        self.assertEqual("RECOVERY_REQUIRED", journal.events[-1])

    def test_wrong_ack_and_profile_fail_before_claim(self) -> None:
        reviewed = contract()
        for source, audit, acknowledgement in (
            ("source", "audit", ""),
            ("same", "same", runner.RUN_ACKNOWLEDGEMENT),
            ("source", "wrong-audit", runner.RUN_ACKNOWLEDGEMENT),
        ):
            with (
                self.subTest(source=source, audit=audit),
                patch.object(runner, "load_contract", return_value=reviewed),
                patch.object(runner.authorization_tool, "claim_authorization") as claim,
                self.assertRaises(ToolError),
            ):
                runner.execute(
                    reviewed,
                    source,
                    audit,
                    acknowledgement,
                    operations=FakeOperations(),
                )
            claim.assert_not_called()

    def test_aws_allowlist_rejects_write_and_does_not_mask_access_denied(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()
        with (
            patch.object(subprocess, "run") as command,
            self.assertRaisesRegex(ToolError, "read-only allowlist"),
        ):
            operations._aws_json(
                reviewed,
                reviewed.audit_profile,
                "ec2",
                "run-instances",
            )
        command.assert_not_called()

        access_denied = subprocess.CompletedProcess(
            args=[], returncode=255, stdout="", stderr="AccessDenied"
        )
        with (
            patch.object(subprocess, "run", return_value=access_denied),
            self.assertRaisesRegex(ToolError, "failed"),
        ):
            operations._aws_json(
                reviewed,
                reviewed.audit_profile,
                "iam",
                "get-role",
                "--role-name",
                "missing",
                allow_no_such_entity=True,
            )

        missing = subprocess.CompletedProcess(
            args=[], returncode=255, stdout="", stderr="NoSuchEntity"
        )
        with patch.object(subprocess, "run", return_value=missing):
            self.assertIsNone(
                operations._aws_json(
                    reviewed,
                    reviewed.audit_profile,
                    "iam",
                    "get-role",
                    "--role-name",
                    "missing",
                    allow_no_such_entity=True,
                )
            )

    def test_environment_create_is_server_dry_run_then_single_create(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()
        dry_run = {
            "metadata": {"name": reviewed.environment},
        }
        created = {
            "metadata": {
                **reviewed.environment_document["metadata"],
                "uid": "uid-1",
                "generation": 1,
            },
            "spec": reviewed.environment_document["spec"],
        }
        with (
            patch.object(operations, "_verify_claim"),
            patch.object(operations, "_optional", side_effect=[None, None, None]),
            patch.object(operations, "_kube", side_effect=[dry_run, created]) as kube,
        ):
            operations.dry_run_environment(reviewed)
            result = operations.create_environment(reviewed)
        self.assertEqual("uid-1", result["uid"])
        self.assertIn("--dry-run=server", kube.call_args_list[0].args)
        self.assertNotIn("--dry-run=server", kube.call_args_list[1].args)
        self.assertEqual(2, kube.call_count)

    def test_inventory_rejects_foreign_owner_and_forbidden_resources(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()
        fixtures = (
            {
                "apiVersion": "kubernetes.crossplane.io/v1alpha2",
                "kind": "Object",
                "metadata": {"name": "foreign", "labels": {}},
                "spec": {},
            },
            {
                "apiVersion": "ec2.aws.m.upbound.io/v1beta1",
                "kind": "Instance",
                "metadata": {"labels": {}},
                "spec": {},
            },
            {
                "apiVersion": "eks.aws.m.upbound.io/v1beta1",
                "kind": "NodeGroup",
                "metadata": {
                    "labels": {
                        "platform.aws.goodnotes.io/environment": reviewed.environment
                    }
                },
                "spec": {},
            },
            {
                "apiVersion": "eks.aws.m.upbound.io/v1beta1",
                "kind": "Addon",
                "metadata": {
                    "labels": {
                        "platform.aws.goodnotes.io/environment": reviewed.environment
                    }
                },
                "spec": {"forProvider": {"addonName": "vpc-cni"}},
            },
        )
        for item in fixtures:
            with (
                self.subTest(kind=item["kind"]),
                patch.object(operations, "_kube", return_value={"items": [item]}),
                self.assertRaises(ToolError),
            ):
                operations._managed_inventory(reviewed)

    def test_aws_checkpoint_rejects_non_spot_instance(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()

        def aws(_contract, _profile, service, operation, *_args, **_kwargs):
            responses = {
                ("eks", "describe-cluster"): {
                    "cluster": {
                        "name": "eks-dev-spot-cluster",
                        "status": "ACTIVE",
                        "version": "1.35",
                        "deletionProtection": True,
                        "accessConfig": {
                            "authenticationMode": "API",
                            "bootstrapClusterCreatorAdminPermissions": False,
                        },
                        "resourcesVpcConfig": {
                            "endpointPrivateAccess": True,
                            "endpointPublicAccess": True,
                            "publicAccessCidrs": ["203.0.113.10/32"],
                        },
                        "computeConfig": None,
                    }
                },
                ("eks", "list-fargate-profiles"): {
                    "fargateProfileNames": ["karpenter"]
                },
                ("eks", "describe-fargate-profile"): {
                    "fargateProfile": {
                        "status": "ACTIVE",
                        "selectors": [
                            {
                                "namespace": "karpenter",
                                "labels": {
                                    "app.kubernetes.io/instance": "karpenter",
                                    "app.kubernetes.io/name": "karpenter",
                                },
                            }
                        ],
                    }
                },
                ("eks", "list-nodegroups"): {"nodegroups": []},
                ("eks", "list-addons"): {"addons": []},
                ("ec2", "describe-instances"): {
                    "Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]
                },
            }
            return responses[(service, operation)]

        with (
            patch.object(operations, "_aws_json", side_effect=aws),
            self.assertRaisesRegex(ToolError, "non-Spot"),
        ):
            operations.verify_aws_checkpoint(reviewed, reviewed.audit_profile)

    def test_recovery_only_parks_without_aws_profiles_or_deletion(self) -> None:
        reviewed = contract()
        operations = FakeOperations()
        journal = FakeJournal()
        with (
            patch.object(runner.authorization_tool, "verify_claim") as verify,
            patch.object(runner.Journal, "existing", return_value=journal),
        ):
            result = runner.recover(
                reviewed,
                runner.RECOVER_ACKNOWLEDGEMENT,
                operations=operations,
            )
        verify.assert_called_once_with(
            Path("authorization-contract.json"),
            require_active=False,
        )
        self.assertEqual(["cleanup"], operations.calls)
        self.assertIsNone(operations.cleanup_uid)
        self.assertFalse(result["environmentDeletionAttempted"])
        self.assertFalse(result["directAwsApiCalls"])
        self.assertEqual(["RECOVERY_STARTED", "RECOVERY_COMPLETE"], journal.events)

    def test_recovery_can_load_stale_a05_review_without_reapproval(self) -> None:
        reviewed = contract()
        review = {
            "contract": reviewed.bootstrap.__dict__,
            "sessionMode": credentials.SESSION_MODE,
            "reviewStatus": "STALE_AFTER_EXECUTION",
        }
        with (
            patch.object(runner.credentials, "load_private_review", return_value=review),
            patch.object(runner.credentials, "validate_contract"),
            patch.object(runner.credentials, "verify_review_approval") as approval,
        ):
            loaded, bootstrap = runner._session_contract(
                Path("identity-review.json"),
                recovery_only=True,
            )
        approval.assert_not_called()
        self.assertEqual(review, loaded)
        self.assertEqual(reviewed.bootstrap, bootstrap)

    def test_all_a05_roles_must_match_the_exact_u1_account(self) -> None:
        reviewed = contract()
        bad_bootstrap = replace(
            reviewed.bootstrap,
            source_role_arn="arn:aws:iam::999999999999:role/source",
        )
        authorization = {
            **reviewed.authorization,
            "environment": reviewed.environment,
            "region": reviewed.region,
            "accountId": reviewed.account_id,
            "auditProfile": reviewed.audit_profile,
            "hostPublicEgressIp": reviewed.expected_public_ip,
        }
        node_catalog = {
            "data": {"images": {"amd64": {"amiId": reviewed.node_image_id}}}
        }
        with (
            patch.object(
                runner.authorization_tool,
                "validate_authorization",
                return_value=authorization,
            ),
            patch.object(
                runner,
                "_session_contract",
                return_value=({"reviewStatus": "APPROVED"}, bad_bootstrap),
            ),
            patch.object(
                runner,
                "load_yaml",
                side_effect=[reviewed.environment_document, node_catalog],
            ),
            patch.object(
                runner.authorization_tool,
                "_load_json",
                return_value=reviewed.expected_resources,
            ),
            self.assertRaisesRegex(ToolError, "account differs"),
        ):
            runner.load_contract(
                reviewed.authorization_path,
                reviewed.session_review_path,
                require_approved=True,
            )

    def test_private_result_is_owner_only_and_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "results"
            target = root / "u1b-20260904-01.json"
            runner._write_private_json(target, {"status": "safe"})
            self.assertEqual(0o700, stat.S_IMODE(root.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
            self.assertEqual({"status": "safe"}, json.loads(target.read_text()))
            with self.assertRaisesRegex(ToolError, "already exists"):
                runner._write_private_json(target, {"status": "overwrite"})


if __name__ == "__main__":
    unittest.main()
