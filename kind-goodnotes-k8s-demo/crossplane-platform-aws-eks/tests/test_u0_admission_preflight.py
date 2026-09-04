from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "eks_lifecycle"))

from common import ToolError  # noqa: E402
import run_u0_admission_preflight as runner  # noqa: E402
import validate_u0_admission_authorization as authorization  # noqa: E402


def contract() -> runner.AdmissionContract:
    window_id = "u0a-20260904-01"
    return runner.AdmissionContract(
        authorization_path=Path("authorization-contract.json"),
        authorization={
            "bundle": "u0-admission-2026-09-04-01",
            "windowId": window_id,
            "reviewStatus": authorization.APPROVED_STATUS,
            "approved": True,
        },
        bundle_directory=Path("bundle"),
        context=authorization.CONTEXT,
        fixture={
            "apiVersion": "platform.aws.goodnotes.io/v1alpha1",
            "kind": "XEKSEnvironment",
            "metadata": {
                "name": authorization.FIXTURE_NAME,
                "labels": {
                    "platform.aws.goodnotes.io/managed-by": "u0-admission-preflight",
                    "platform.aws.goodnotes.io/window-id": window_id,
                },
                "annotations": {"crossplane.io/paused": "true"},
            },
        },
        temporary_rbac=tuple(
            authorization.expected_temporary_rbac(window_id)["items"]
        ),
        test_plan=authorization.expected_test_plan(window_id),
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
        self.evidence = {
            "ordinaryOwnerWriteMatrix": [
                {"allowed": False}
                for _ in range(
                    len(authorization.OWNER_WRITE_TARGETS)
                    * len(authorization.WRITE_VERBS)
                )
            ],
            "dryRunCases": [
                {"observedAllowed": item["expectedAllowed"]}
                for item in authorization.expected_test_plan(
                    "u0a-20260904-01"
                )["dryRunCases"]
            ],
        }

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            raise ToolError(f"test failure at {name}")

    def baseline(self, _contract):
        self._call("baseline")
        return {
            "controllersStopped": 14,
            "managementSessionSecretAccessed": False,
            "awsManagedResources": 0,
            "nonAwsManagedResources": 73,
        }

    def setup(self, _contract, progress=None):
        self._call("setup")
        if progress:
            progress("FIXTURE_CREATED")
            progress("TEMPORARY_RBAC_CREATED")
        return {"fixtureUid": "fixture-uid", "fixtureResourceVersion": "7"}

    def run_tests(self, _contract):
        self._call("tests")
        return self.evidence

    def cleanup(self, _contract):
        self._call("cleanup")
        return {
            "temporaryResourcesDeleted": 3,
            "baselineRestored": True,
            "controllersStopped": 14,
            "managementSessionSecretAccessed": False,
            "awsManagedResources": 0,
            "nonAwsManagedResources": 73,
        }


class U0AdmissionPreflightTests(unittest.TestCase):
    def execute_with(self, operations: FakeOperations):
        reviewed = contract()
        journal = FakeJournal()
        claim = {
            "reviewedGitCommit": "a" * 40,
            "executionCodeSha256": "b" * 64,
        }
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(
                runner.authorization_tool,
                "claim_authorization",
                return_value=claim,
            ) as claimed,
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(
                runner,
                "_write_result",
                return_value=Path("result.json"),
            ) as write_result,
        ):
            result = runner.execute(
                reviewed,
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        return result, journal, claimed, write_result

    def test_plan_is_kubernetes_only_and_does_not_claim(self) -> None:
        result = runner.public_plan(contract())
        self.assertEqual(52, result["ordinaryAuthorizationChecks"])
        self.assertEqual(9, result["dryRunAdmissionChecks"])
        self.assertEqual(3, result["temporaryKubernetesResources"])
        self.assertFalse(result["managementSessionRequired"])
        self.assertFalse(result["awsProfilesAccepted"])
        self.assertFalse(result["awsApiCalls"])
        self.assertFalse(result["kubernetesApiCalls"])
        self.assertFalse(result["mutationPerformed"])

    def test_run_claims_before_api_work_and_restores_baseline(self) -> None:
        operations = FakeOperations()
        result, journal, claimed, write_result = self.execute_with(operations)
        claimed.assert_called_once_with(
            Path("authorization-contract.json"),
            authorization.CLAIM_ACKNOWLEDGEMENT,
        )
        self.assertEqual(["baseline", "setup", "tests", "cleanup"], operations.calls)
        self.assertEqual(
            [
                "CLAIMED",
                "BASELINE_VERIFIED",
                "SETUP_STARTED",
                "FIXTURE_CREATED",
                "TEMPORARY_RBAC_CREATED",
                "TESTS_STARTED",
                "TESTS_VERIFIED",
                "CLEANUP_STARTED",
                "CLEANUP_COMPLETE",
            ],
            journal.events,
        )
        self.assertEqual("U0_ADMISSION_PREFLIGHT_PASS", result["status"])
        self.assertTrue(result["baselineRestored"])
        self.assertTrue(result["managementSessionSecretUntouched"])
        self.assertFalse(result["awsApiCalls"])
        report = write_result.call_args.args[1]
        self.assertFalse(report["stsSessionIssued"])
        self.assertFalse(report["managementSessionSecretAccessed"])
        self.assertFalse(report["controllersStarted"])

    def test_failure_after_setup_runs_cleanup_and_consumes_window(self) -> None:
        reviewed = contract()
        journal = FakeJournal()
        operations = FakeOperations(fail_at="tests")
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(
                runner.authorization_tool,
                "claim_authorization",
                return_value={
                    "reviewedGitCommit": "a" * 40,
                    "executionCodeSha256": "b" * 64,
                },
            ),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(runner, "_write_result") as write_result,
            self.assertRaisesRegex(ToolError, "bounded cleanup completed"),
        ):
            runner.execute(
                reviewed,
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        self.assertEqual(["baseline", "setup", "tests", "cleanup"], operations.calls)
        self.assertEqual("FAILED_CLEANUP_COMPLETE", journal.events[-1])
        self.assertEqual(
            "U0_ADMISSION_PREFLIGHT_FAILED_CLOSED",
            write_result.call_args.args[1]["status"],
        )

    def test_baseline_failure_does_not_delete_preexisting_objects(self) -> None:
        reviewed = contract()
        journal = FakeJournal()
        operations = FakeOperations(fail_at="baseline")
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(
                runner.authorization_tool,
                "claim_authorization",
                return_value={
                    "reviewedGitCommit": "a" * 40,
                    "executionCodeSha256": "b" * 64,
                },
            ),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=journal),
            patch.object(runner, "_write_result"),
            self.assertRaisesRegex(ToolError, "baseline failed before mutation"),
        ):
            runner.execute(
                reviewed,
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )
        self.assertEqual(["baseline"], operations.calls)
        self.assertNotIn("CLEANUP_STARTED", journal.events)

    def test_cleanup_failure_requires_recovery(self) -> None:
        reviewed = contract()
        operations = FakeOperations(fail_at="cleanup")
        with (
            patch.object(runner, "load_contract", return_value=reviewed),
            patch.object(
                runner.authorization_tool,
                "claim_authorization",
                return_value={
                    "reviewedGitCommit": "a" * 40,
                    "executionCodeSha256": "b" * 64,
                },
            ),
            patch.object(runner.authorization_tool, "verify_claim"),
            patch.object(runner.Journal, "create", return_value=FakeJournal()),
            patch.object(runner, "_write_result"),
            self.assertRaisesRegex(ToolError, "recovery-only"),
        ):
            runner.execute(
                reviewed,
                runner.RUN_ACKNOWLEDGEMENT,
                operations=operations,
            )

    def test_wrong_acknowledgement_fails_before_claim_or_api(self) -> None:
        operations = FakeOperations()
        with (
            patch.object(runner, "load_contract") as load,
            patch.object(runner.authorization_tool, "claim_authorization") as claim,
            self.assertRaisesRegex(ToolError, "acknowledgement"),
        ):
            runner.execute(contract(), "", operations=operations)
        load.assert_not_called()
        claim.assert_not_called()
        self.assertEqual([], operations.calls)

    def test_recovery_verifies_consumed_claim_and_only_cleans(self) -> None:
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
            Path("authorization-contract.json"), require_active=False
        )
        self.assertEqual(["cleanup"], operations.calls)
        self.assertEqual(["RECOVERY_STARTED", "RECOVERY_COMPLETE"], journal.events)
        self.assertTrue(result["baselineRestored"])
        self.assertTrue(result["managementSessionSecretUntouched"])
        self.assertFalse(result["awsApiCalls"])

    def test_patch_contract_uses_uid_resource_version_and_exact_transitions(self) -> None:
        fixture = {
            "metadata": {"uid": "fixture-uid", "resourceVersion": "17"}
        }
        valid = runner.RealOperations._patch("valid-transition", fixture)
        skipped = runner.RealOperations._patch("stage-skip", fixture)
        unprotected = runner.RealOperations._patch("unprotect", fixture)
        self.assertEqual("fixture-uid", valid[0]["value"])
        self.assertEqual("17", valid[1]["value"])
        self.assertEqual("DrainWorkloads", valid[-1]["value"])
        self.assertEqual("RemoveGitOps", skipped[-1]["value"])
        self.assertFalse(unprotected[-1]["value"])

    def test_dry_run_records_hashes_without_persisting_response_body(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()
        fixture = {
            "metadata": {
                "name": authorization.FIXTURE_NAME,
                "uid": "uid-1",
                "resourceVersion": "3",
            }
        }
        allowed_case = next(
            item
            for item in reviewed.test_plan["dryRunCases"]
            if item["id"] == "approver-valid-transition-allow"
        )
        response = subprocess.CompletedProcess(
            ["kubectl"],
            0,
            stdout=json.dumps(
                {"metadata": {"name": authorization.FIXTURE_NAME}}
            ),
            stderr="",
        )
        with (
            patch.object(operations, "_kubectl", return_value=response) as command,
            patch.object(operations, "_assert_fixture_unchanged"),
        ):
            evidence = operations._dry_run_case(reviewed, allowed_case, fixture)
        self.assertTrue(evidence["observedAllowed"])
        self.assertRegex(evidence["responseSha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("stdout", evidence)
        arguments = command.call_args.args
        self.assertIn("--dry-run=server", arguments)
        self.assertIn("--as", arguments)
        self.assertIn("--as-group", arguments)

    def test_policy_denial_requires_the_exact_reviewed_message(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()
        fixture = {
            "metadata": {
                "uid": "uid-1",
                "resourceVersion": "3",
            }
        }
        denied_case = next(
            item
            for item in reviewed.test_plan["dryRunCases"]
            if item["id"] == "delegated-valid-transition-policy-deny"
        )
        denied = subprocess.CompletedProcess(
            ["kubectl"],
            1,
            stdout="",
            stderr=denied_case["expectedMarker"],
        )
        with (
            patch.object(operations, "_kubectl", return_value=denied),
            patch.object(operations, "_assert_fixture_unchanged"),
        ):
            evidence = operations._dry_run_case(reviewed, denied_case, fixture)
        self.assertFalse(evidence["observedAllowed"])
        self.assertTrue(evidence["expectedMarkerMatched"])

        wrong = subprocess.CompletedProcess(
            ["kubectl"], 1, stdout="", stderr="some other rejection"
        )
        with (
            patch.object(operations, "_kubectl", return_value=wrong),
            self.assertRaisesRegex(ToolError, "outcome differs"),
        ):
            operations._dry_run_case(reviewed, denied_case, fixture)

    def test_live_policy_requires_exact_expressions_and_deny_binding(self) -> None:
        operations = runner.RealOperations()
        policy = {
            "metadata": {"uid": "policy-uid", "resourceVersion": "9"},
            "spec": {
                "failurePolicy": "Fail",
                "matchConstraints": {
                    "resourceRules": [
                        {
                            "apiGroups": ["platform.aws.goodnotes.io"],
                            "apiVersions": ["v1alpha1"],
                            "operations": ["UPDATE"],
                            "resources": ["xeksenvironments"],
                        }
                    ]
                },
                "matchConditions": [
                    {
                        "name": "lifecycle-change",
                        "expression": "object.spec.parameters.lifecycle != oldObject.spec.parameters.lifecycle",
                    }
                ],
                "validations": [
                    {
                        "expression": "request.userInfo.groups.exists(group, group == 'platform-eks-lifecycle-approvers')",
                        "message": "lifecycle changes require the platform-eks-lifecycle-approvers group",
                        "reason": "Forbidden",
                    },
                    {
                        "expression": "object.spec.parameters.lifecycle.retirementStage == 'Active' || has(object.spec.parameters.lifecycle.evidenceRef)",
                        "message": "non-Active lifecycle stages require an immutable evidenceRef",
                        "reason": "Invalid",
                    },
                ],
            },
            "status": {"typeChecking": {"expressionWarnings": []}},
        }
        binding = {
            "metadata": {"uid": "binding-uid"},
            "spec": {
                "policyName": runner.POLICY_NAME,
                "validationActions": ["Deny"],
            },
        }
        with patch.object(operations, "_json", side_effect=[policy, binding]):
            result = operations._assert_reviewed_policy(contract())
        self.assertEqual("policy-uid", result["policyUid"])

        policy["spec"]["validations"][0]["expression"] = "true"
        with (
            patch.object(operations, "_json", side_effect=[policy, binding]),
            self.assertRaisesRegex(ToolError, "policy differs"),
        ):
            operations._assert_reviewed_policy(contract())

    def test_cleanup_refuses_objects_without_exact_window_ownership(self) -> None:
        operations = runner.RealOperations()
        reviewed = contract()
        foreign = {
            "metadata": {
                "name": authorization.FIXTURE_NAME,
                "labels": {
                    "platform.aws.goodnotes.io/managed-by": "someone-else"
                },
            }
        }
        with (
            patch.object(operations, "_optional", return_value=foreign),
            patch.object(operations, "_kubectl") as delete,
            self.assertRaisesRegex(ToolError, "not owned"),
        ):
            operations._delete_owned(
                reviewed,
                "xeksenvironment.platform.aws.goodnotes.io",
                authorization.FIXTURE_NAME,
                require_paused=True,
            )
        delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
