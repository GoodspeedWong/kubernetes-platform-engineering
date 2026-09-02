from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "eks_lifecycle"))

import run_u0_management_preflight as runner  # noqa: E402
from common import ToolError  # noqa: E402
import renew_management_credentials as credentials  # noqa: E402


def contract() -> runner.U0Contract:
    bootstrap = credentials.BootstrapContract(
        environment="eks-dev-spot",
        region="us-east-1",
        context="kind-kube-nebula-a",
        source_role_arn="arn:aws:iam::123456789012:role/source",
        provider_role_arn="arn:aws:iam::123456789012:role/eks-dev-spot-xp-aws",
        deployment_role_arn="arn:aws:iam::123456789012:role/eks-dev-spot-eks-deploy",
        boundary_arn="arn:aws:iam::123456789012:policy/eks-dev-spot-boundary",
    )
    return runner.U0Contract(
        authorization_path=Path("authorization-contract.json"),
        session_review_path=Path("identity-review.json"),
        authorization={
            "bundle": "u0-preflight-2026-09-02",
            "windowId": "u0-20260902-01",
            "reviewStatus": "APPROVED_FOR_ONE_U0_WINDOW",
            "approved": True,
        },
        session_review={"reviewStatus": "APPROVED"},
        bootstrap=bootstrap,
        bundle_directory=Path("bundle"),
        environment_candidate={
            "apiVersion": "platform.aws.goodnotes.io/v1alpha1",
            "kind": "XEKSEnvironment",
            "metadata": {"name": "eks-dev-spot"},
        },
        provider_config_name="eks-dev-spot-aws",
        controller_names=(
            "crossplane",
            *(f"controller-{index}" for index in range(13)),
        ),
        run_id="a05-20260902-u0-01",
    )


class FakeJournal:
    def __init__(self) -> None:
        self.events: list[str] = []

    def append(self, event: str) -> None:
        self.events.append(event)


class FakeOperations:
    def __init__(self, fail_at: str | None = None) -> None:
        self.calls: list[str] = []
        self.fail_at = fail_at

    def _call(self, name: str):
        self.calls.append(name)
        if self.fail_at == name:
            raise ToolError(f"test failure at {name}")

    def baseline(self, _contract):
        self._call("baseline")
        return {}

    def protect(self, _contract):
        self._call("protect")

    def apply_definitions(self, _contract):
        self._call("apply")

    def open_session(self, _contract, _profile, _audit_profile):
        self._call("open")

    def start_controllers(self, _contract):
        self._call("start")

    def wait_ready(self, _contract):
        self._call("wait")

    def verify(self, _contract):
        self._call("verify")
        return {
            "runtimeAuthenticationVerified": True,
            "onlinePreflight": True,
            "environmentCandidatePersisted": False,
            "awsResourceMutation": False,
        }

    def cleanup(self, _contract):
        self._call("cleanup")
        return {
            "controllersStopped": 14,
            "sessionSecretAbsent": True,
        }


class U0ManagementPreflightTests(unittest.TestCase):
    def execute_with(self, operations: FakeOperations):
        journal = FakeJournal()
        reviewed = contract()
        patches = (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization"),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
        )
        for item in patches:
            item.start()
        try:
            result = runner.execute(
                reviewed,
                "source-profile",
                "audit-profile",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
            return result, journal
        finally:
            for item in reversed(patches):
                item.stop()

    def test_controller_inventory_is_exactly_fourteen_and_digest_derived(self) -> None:
        names = runner.controller_inventory()
        self.assertEqual(14, len(names))
        self.assertEqual(14, len(set(names)))
        self.assertIn("crossplane", names)
        self.assertIn("function-kcl-01ce52d97135", names)
        self.assertIn("function-auto-ready-49cc4de71731", names)
        self.assertIn("function-patch-and-transform-c05a9add149b", names)

    def test_public_plan_is_explicitly_local_and_never_applies_environment(self) -> None:
        result = runner.public_plan(contract())
        self.assertFalse(result["awsApiCalls"])
        self.assertFalse(result["kubernetesApiCalls"])
        self.assertFalse(result["mutationPerformed"])
        self.assertFalse(result["environmentCandidateApplyAllowed"])
        self.assertTrue(result["environmentCandidateServerDryRunOnly"])
        self.assertEqual(14, result["controllerDeployments"])
        self.assertEqual(3, result["sharedXRsToProtect"])
        self.assertEqual(73, result["ownedObjectsToProtect"])

    def test_run_claims_before_baseline_and_always_cleans_success(self) -> None:
        operations = FakeOperations()
        journal = FakeJournal()
        reviewed = contract()
        order: list[str] = []

        def claim(*_args, **_kwargs):
            order.append("claim")

        def baseline(_contract):
            order.append("baseline")
            return {}

        operations.baseline = baseline
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization", side_effect=claim),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
        ):
            result = runner.execute(
                reviewed,
                "source-profile",
                "audit-profile",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        self.assertEqual(["claim", "baseline"], order)
        self.assertEqual(
            ["protect", "apply", "open", "start", "wait", "verify", "cleanup"],
            operations.calls,
        )
        self.assertEqual("U0_MANAGEMENT_PREFLIGHT_PASS", result["status"])
        self.assertEqual("CLEANUP_COMPLETE", journal.events[-1])

    def test_baseline_failure_consumes_claim_without_api_cleanup_mutation(self) -> None:
        operations = FakeOperations(fail_at="baseline")
        journal = FakeJournal()
        reviewed = contract()
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization") as claim,
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            self.assertRaisesRegex(ToolError, "no API mutation was attempted"),
        ):
            runner.execute(
                reviewed,
                "source-profile",
                "audit-profile",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        claim.assert_called_once()
        self.assertEqual(["baseline"], operations.calls)
        self.assertNotIn("CLEANUP_STARTED", journal.events)

    def test_failure_after_protection_runs_cleanup_and_requires_no_retry(self) -> None:
        operations = FakeOperations(fail_at="apply")
        journal = FakeJournal()
        reviewed = contract()
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization"),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            self.assertRaisesRegex(ToolError, "bounded cleanup completed"),
        ):
            runner.execute(
                reviewed,
                "source-profile",
                "audit-profile",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        self.assertEqual(["baseline", "protect", "apply", "cleanup"], operations.calls)
        self.assertEqual("FAILED_CLEANUP_COMPLETE", journal.events[-1])

    def test_cleanup_failure_requires_recovery(self) -> None:
        operations = FakeOperations(fail_at="cleanup")
        reviewed = contract()
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(runner.authorization_tool, "claim_authorization"),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=FakeJournal()),
            self.assertRaisesRegex(ToolError, "run recovery"),
        ):
            runner.execute(
                reviewed,
                "source-profile",
                "audit-profile",
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )

    def test_wrong_acknowledgement_fails_before_claim_or_operations(self) -> None:
        operations = FakeOperations()
        with (
            patch.object(runner.authorization_tool, "claim_authorization") as claim,
            self.assertRaisesRegex(ToolError, "acknowledgement"),
        ):
            runner.execute(
                contract(),
                "source-profile",
                "audit-profile",
                "",
                operations=operations,
            )
        claim.assert_not_called()
        self.assertEqual([], operations.calls)

    def test_recovery_uses_expired_claim_and_cleanup_only(self) -> None:
        operations = FakeOperations()
        journal = FakeJournal()
        with (
            patch.object(runner.authorization_tool, "verify_claim") as verify,
            patch.object(runner.Journal, "existing", return_value=journal),
        ):
            result = runner.recover(
                contract(),
                runner.RECOVER_ACKNOWLEDGEMENT,
                operations=operations,
            )
        verify.assert_called_once_with(
            Path("authorization-contract.json"),
            require_active=False,
        )
        self.assertEqual(["cleanup"], operations.calls)
        self.assertEqual(["RECOVERY_STARTED", "RECOVERY_COMPLETE"], journal.events)
        self.assertFalse(result["awsApiCalls"])

    def test_recovery_can_load_original_session_contract_without_reapproval(self) -> None:
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

    def test_apply_contract_dry_runs_everything_and_never_persists_environment(self) -> None:
        reviewed = contract()
        operations = runner.RealOperations()
        kustomizations: list[tuple[Path, bool]] = []
        documents: list[tuple[dict, bool]] = []
        catalogs = {
            "platform-release.candidate.yaml": {"kind": "EnvironmentConfig", "metadata": {"name": "release"}},
            "node-image.candidate.yaml": {"kind": "EnvironmentConfig", "metadata": {"name": "image"}},
        }

        def load(path: Path):
            return catalogs[path.name]

        with (
            patch.object(runner, "load_yaml", side_effect=load),
            patch.object(
                runner.provider_maintenance,
                "provider_config",
                return_value={"kind": "ClusterProviderConfig", "metadata": {"name": "provider"}},
            ),
            patch.object(
                operations,
                "_apply_kustomization",
                side_effect=lambda _c, root, dry_run: kustomizations.append((root, dry_run)),
            ),
            patch.object(
                operations,
                "_apply_document",
                side_effect=lambda _c, document, dry_run: documents.append((document, dry_run)),
            ),
            patch.object(operations, "_assert_no_runtime_instances", return_value=0),
        ):
            operations.apply_definitions(reviewed)
        self.assertEqual(len(runner.APPLY_KUSTOMIZATIONS) * 2, len(kustomizations))
        self.assertEqual(3, sum(dry for _, dry in documents))
        self.assertEqual(3, sum(not dry for _, dry in documents))
        self.assertNotIn(reviewed.environment_candidate, [item for item, _ in documents])

    def test_low_level_apply_guards_refuse_environment_persistence_and_unreviewed_paths(self) -> None:
        reviewed = contract()
        operations = runner.RealOperations()
        with (
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner, "_run_suppressed") as command,
            self.assertRaisesRegex(ToolError, "forbids persisting"),
        ):
            operations._apply_document(
                reviewed,
                reviewed.environment_candidate,
                dry_run=False,
            )
        command.assert_not_called()

        with (
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner, "_run_suppressed") as command,
            self.assertRaisesRegex(ToolError, "not reviewed"),
        ):
            operations._apply_kustomization(
                reviewed,
                Path("unreviewed"),
                dry_run=True,
            )
        command.assert_not_called()

    def test_scale_starts_crossplane_last_and_stops_it_first(self) -> None:
        reviewed = contract()
        operations = runner.RealOperations()

        def deployments(replicas: int):
            return {
                name: {
                    "metadata": {
                        "name": name,
                        "uid": "uid-" + name,
                        "resourceVersion": "1",
                    },
                    "spec": {"replicas": replicas},
                }
                for name in reviewed.controller_names
            }

        started: list[str] = []
        with (
            patch.object(operations, "_deployment_map", return_value=deployments(0)),
            patch.object(
                operations,
                "_kube",
                side_effect=lambda _c, *args, **_kwargs: started.append(args[4]),
            ),
            patch.object(runner.authorization_tool, "verify_claim"),
        ):
            operations._patch_replicas(
                reviewed,
                1,
                require_active_claim=True,
            )
        self.assertEqual("crossplane", started[-1])

        stopped: list[str] = []
        with (
            patch.object(operations, "_deployment_map", return_value=deployments(1)),
            patch.object(
                operations,
                "_kube",
                side_effect=lambda _c, *args, **_kwargs: stopped.append(args[4]),
            ),
        ):
            operations._patch_replicas(
                reviewed,
                0,
                require_active_claim=False,
            )
        self.assertEqual("crossplane", stopped[0])

    def test_runtime_inventory_allows_missing_preinstall_apis_but_requires_them_after_apply(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()

        def names(command: list[str], **_kwargs):
            if "api-resources" in command:
                return ["xnetworks.platform.aws.goodnotes.io"]
            if "managed" in command:
                return [f"object.kubernetes.crossplane.io/object-{index}" for index in range(73)]
            return []

        with patch.object(runner, "_run_names", side_effect=names):
            self.assertEqual(73, operations._assert_no_runtime_instances(reviewed))
            with self.assertRaisesRegex(ToolError, "not all installed"):
                operations._assert_no_runtime_instances(
                    reviewed,
                    require_all_apis=True,
                )

    def test_runtime_inventory_rejects_any_lifecycle_xr_or_aws_managed_resource(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()

        def with_xr(command: list[str], **_kwargs):
            if "api-resources" in command:
                return list(runner.XR_RESOURCES)
            if "xeksenvironments.platform.aws.goodnotes.io" in command:
                return ["xeksenvironment.platform.aws.goodnotes.io/eks-dev-spot"]
            return []

        with (
            patch.object(runner, "_run_names", side_effect=with_xr),
            self.assertRaisesRegex(ToolError, "XR instance"),
        ):
            operations._assert_no_runtime_instances(
                reviewed,
                require_all_apis=True,
            )

        def with_aws(command: list[str], **_kwargs):
            if "api-resources" in command:
                return list(runner.XR_RESOURCES)
            if "managed" in command:
                return ["vpc.ec2.aws.upbound.io/test"]
            return []

        with (
            patch.object(runner, "_run_names", side_effect=with_aws),
            self.assertRaisesRegex(ToolError, "AWS managed"),
        ):
            operations._assert_no_runtime_instances(
                reviewed,
                require_all_apis=True,
            )

    def test_lifecycle_api_waits_for_crossplane_to_establish_all_xr_crds(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()
        discoveries = [
            ["xnetworks.platform.aws.goodnotes.io"],
            list(runner.XR_RESOURCES),
        ]
        with (
            patch.object(runner, "_run_names", side_effect=discoveries) as read,
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.time, "sleep"),
        ):
            operations._wait_lifecycle_apis(reviewed)
        self.assertEqual(2, read.call_count)

    def test_journal_is_owner_only_append_only_and_single_create(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "claims"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            with patch.object(runner.authorization_tool, "CLAIM_ROOT", root):
                journal = runner.Journal.create("u0-20260902-01")
                journal.append("CLAIMED")
                self.assertEqual(0o600, stat.S_IMODE(journal.path.stat().st_mode))
                self.assertIn('"event": "CLAIMED"', journal.path.read_text())
                with self.assertRaisesRegex(ToolError, "already exists"):
                    runner.Journal.create("u0-20260902-01")


if __name__ == "__main__":
    unittest.main()
