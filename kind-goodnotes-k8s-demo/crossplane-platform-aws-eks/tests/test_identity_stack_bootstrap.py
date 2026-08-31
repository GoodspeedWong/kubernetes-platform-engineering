from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))
import bootstrap_identity_stacks as stacks
import bootstrap_upstream_role as upstream
from common import ToolError


class IdentityStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identity = upstream.Contract("eks-dev-spot", "111122223333", "arn:aws:iam::111122223333:role/login")
        cls.bundle = stacks.Bundle("source", cls.identity)

    def description(self):
        return {"Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
                "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in self.bundle.parameters.items()],
                "Changes": [{"ResourceChange": {"Action": "Add", "LogicalResourceId": k, "ResourceType": r["Type"]}}
                            for k, r in self.bundle.resources().items()]}

    def read(self, description):
        def invoke(profile, service, action, **parameters):
            if action == "describe-change-set":
                return description
            if action == "get-template":
                return {"TemplateBody": self.bundle.template}
            self.fail("unexpected API: " + action)
        return invoke

    def test_resource_counts_and_explicit_source_trust(self):
        for kind, count in (("source", 8), ("bootstrap", 6), ("slr", 3)):
            bundle = stacks.Bundle(kind, self.identity)
            self.assertEqual(count, len(bundle.resources()))
            self.assertNotEqual("reviewed-20260829", bundle.change_set)
        source = self.bundle.resources()["RenewableSourceRole"]["Properties"]
        self.assertEqual(self.identity.role_arn, source["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"])
        self.assertEqual(self.identity.source_arn.rsplit("/", 1)[0].replace("role/platform-bootstrap", "policy") + "/eks-dev-spot-xp-source-boundary", source["PermissionsBoundary"])

    def test_no_credentials_delete_or_update_apis(self):
        for service, action in (("sts", "assume-role"), ("iam", "create-access-key"),
                                ("cloudformation", "delete-stack"), ("cloudformation", "update-stack")):
            with patch.object(stacks.subprocess, "run") as run, self.assertRaises(ToolError):
                stacks.aws("profile", service, action)
            run.assert_not_called()

    def test_execution_requires_ack_before_any_reads(self):
        with patch.object(stacks, "review") as review, self.assertRaises(ToolError):
            stacks.execute("profile", self.bundle, "")
        review.assert_not_called()

    def test_complete_exact_additions_review_passes(self):
        with patch.object(stacks, "aws", side_effect=self.read(self.description())):
            self.assertEqual("REVIEWED", stacks.review("profile", self.bundle)["status"])

    def test_review_rejects_removal_extra_missing_duplicate_and_parameter_drift(self):
        valid = self.description()
        variants = []
        changed = copy.deepcopy(valid)
        changed["Changes"][0]["ResourceChange"]["Action"] = "Remove"
        variants.append(changed)
        changed = copy.deepcopy(valid)
        changed["Changes"][0]["ResourceChange"]["ResourceType"] = "AWS::EC2::Instance"
        variants.append(changed)
        changed = copy.deepcopy(valid)
        changed["Changes"].pop()
        variants.append(changed)
        changed = copy.deepcopy(valid)
        changed["Changes"].append(changed["Changes"][0])
        variants.append(changed)
        changed = copy.deepcopy(valid)
        changed["Parameters"][0]["ParameterValue"] = "another-environment"
        variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed), patch.object(stacks, "aws", side_effect=self.read(changed)), self.assertRaises(ToolError):
                stacks.review("profile", self.bundle)

    def test_review_rejects_cloudformation_role_pagination_or_nested_stack(self):
        for field, value in (("RoleARN", "unexpected"), ("NextToken", "more"), ("IncludeNestedStacks", True)):
            with self.subTest(field=field), patch.object(stacks, "aws", side_effect=self.read(self.description() | {field: value})), self.assertRaises(ToolError):
                stacks.review("profile", self.bundle)

    def test_uploaded_template_drift_is_rejected(self):
        remote = copy.deepcopy(self.bundle.template)
        remote["Description"] = "changed after review"
        with patch.object(stacks, "aws", side_effect=[self.description(), {"TemplateBody": remote}]), self.assertRaises(ToolError):
            stacks.review("profile", self.bundle)

    def test_existing_resource_is_never_adopted(self):
        with patch.object(upstream, "optional", return_value={"exists": True}), self.assertRaises(ToolError):
            stacks.require_absent("profile", self.bundle)

    def test_validation_blocks_security_warnings(self):
        with patch.object(stacks, "aws", return_value={"findings": [{"findingType": "SECURITY_WARNING", "issueCode": "TEST"}]}), self.assertRaises(ToolError):
            stacks.policy_checks("profile", self.bundle)

    def test_validation_rejects_partial_response(self):
        with patch.object(stacks, "aws", return_value={"findings": [], "nextToken": "more"}), self.assertRaises(ToolError):
            stacks.policy_checks("profile", self.bundle)

    def test_execute_rereviews_rechecks_and_disables_rollback(self):
        with patch.object(stacks, "review") as review, patch.object(stacks, "require_absent") as absent, patch.object(stacks, "policy_checks") as validate, patch.object(stacks, "aws") as aws:
            stacks.execute("profile", self.bundle, stacks.ACK_EXECUTE)
            review.assert_called_once()
            absent.assert_called_once()
            validate.assert_called_once()
            self.assertEqual("execute-change-set", aws.call_args.args[2])
            self.assertTrue(aws.call_args.kwargs["DisableRollback"])

    def test_failed_stack_does_not_trigger_cleanup_or_claim_success(self):
        with patch.object(stacks, "aws", return_value={"Stacks": [{"StackStatus": "CREATE_FAILED"}]}) as aws:
            self.assertFalse(stacks.verify("profile", self.bundle)["complete"])
        self.assertEqual(1, aws.call_count)


if __name__ == "__main__":
    unittest.main()
