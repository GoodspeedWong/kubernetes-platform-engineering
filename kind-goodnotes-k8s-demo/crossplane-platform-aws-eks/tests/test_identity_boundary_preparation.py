from __future__ import annotations

import copy
import json
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))
import prepare_identity_boundaries as preparation
import renew_management_credentials as credentials
from common import ToolError, load_yaml
from test_security_remediation import decision

ACCOUNT = "111122223333"
ENVIRONMENT = "eks-dev-spot"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:role/test-federated-operator"


def resolve(value, values):
    if isinstance(value, list):
        return [resolve(item, values) for item in value]
    if isinstance(value, dict):
        if set(value) == {"Fn::Sub"}:
            return re.sub(r"\$\{([^}]+)\}", lambda match: values[match[1]], value["Fn::Sub"])
        if set(value) == {"Ref"}:
            return values[value["Ref"]]
        return {key: resolve(item, values) for key, item in value.items()}
    return value


def without_sids(policy):
    result = copy.deepcopy(policy)
    for statement in result["Statement"]:
        statement.pop("Sid", None)
    return result


class IdentityBoundaryPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = preparation.compile_template()
        cls.docs = preparation.boundary_documents(ENVIRONMENT, ACCOUNT)
        cls.pack = preparation.review_pack(ENVIRONMENT, OPERATOR)
        cls.contract = preparation.role_contract(ENVIRONMENT, ACCOUNT)

    def approved_pack(self):
        return copy.deepcopy(self.pack) | {
            "reviewStatus": "APPROVED", "approvedBy": "unit-test-reviewer",
            "approvedAt": "2020-01-01T00:00:00Z",
        }

    def test_generated_template_matches_repository(self):
        self.assertEqual(self.template, load_yaml(preparation.TEMPLATE))

    def test_template_drift_fails_closed(self):
        changed = copy.deepcopy(self.template)
        changed["Resources"]["RenewableSourceRole"]["Properties"].pop("PermissionsBoundary")
        with patch.object(preparation, "compile_template", return_value=changed), self.assertRaises(ToolError):
            preparation.check_template()

    def test_only_external_retained_source_role_and_seven_boundaries(self):
        resources = self.template["Resources"]
        types = [item["Type"] for item in resources.values()]
        self.assertEqual(7, types.count("AWS::IAM::ManagedPolicy"))
        self.assertEqual(1, types.count("AWS::IAM::Role"))
        self.assertEqual(8, len(types))
        for item in resources.values():
            self.assertEqual("Retain", item["DeletionPolicy"])
            self.assertEqual("Retain", item["UpdateReplacePolicy"])
        self.assertEqual("ManagementPlaneOperator", self.template["Metadata"]["Owner"])
        self.assertEqual("PENDING_SECURITY_APPROVAL", self.template["Metadata"]["ReviewStatus"])
        for path in credentials.EKS_ROOT.rglob("kustomization.yaml"):
            self.assertNotIn(preparation.TEMPLATE.name, path.read_text())

    def test_upstream_role_is_explicit_and_source_is_boundary_limited(self):
        parameter = self.template["Parameters"]["TrustedOperatorRoleArn"]
        self.assertNotIn("Default", parameter)
        self.assertRegex(OPERATOR, parameter["AllowedPattern"])
        for bad in (OPERATOR.replace(":role/", ":user/"), "arn:aws:sts::111122223333:assumed-role/test/session"):
            self.assertNotRegex(bad, parameter["AllowedPattern"])
        source = self.template["Resources"]["RenewableSourceRole"]["Properties"]
        self.assertEqual("/platform-bootstrap/", source["Path"])
        self.assertEqual(3600, source["MaxSessionDuration"])
        self.assertEqual({"Ref": "BoundaryXpSource"}, source["PermissionsBoundary"])
        self.assertNotIn("ManagedPolicyArns", source)
        self.assertEqual(["assume-platform-roles"], [item["PolicyName"] for item in source["Policies"]])

    def test_source_can_assume_only_exact_two_targets(self):
        statements = self.docs["xp-source"]["Statement"]
        for role in (self.contract.provider_role_arn, self.contract.deployment_role_arn):
            self.assertEqual("allowed", decision(statements, "sts:AssumeRole", role, {}))
        for action, resource in (("sts:AssumeRole", OPERATOR), ("iam:CreateAccessKey", "*"),
                                 ("iam:PutRolePolicy", self.contract.source_role_arn)):
            self.assertEqual("implicitDeny", decision(statements, action, resource, {}))

    def test_boundary_substitution_includes_dynamic_condition_keys(self):
        for environment in (ENVIRONMENT, "a" * 52):
            docs = preparation.boundary_documents(environment, ACCOUNT)
            values = {"EnvironmentName": environment, "AWS::AccountId": ACCOUNT,
                      "AWS::Partition": "aws", "TargetRegion": "us-east-1"}
            for suffix, expected in docs.items():
                resource = "Boundary" + "".join(part.title() for part in suffix.split("-"))
                policy = self.template["Resources"][resource]["Properties"]["PolicyDocument"]
                rendered = resolve(policy, values)
                self.assertNotIn("${", rendered)
                self.assertNotIn(preparation.SYNTHETIC_ENVIRONMENT, rendered)
                self.assertEqual(expected, json.loads(rendered))
                self.assertLessEqual(len(json.dumps(expected, separators=(",", ":"))), 6144)
            self.assertIn("aws:ResourceTag/kubernetes.io/cluster/" + environment,
                          json.dumps(docs["karpenter"]))

    def test_controller_boundaries_do_not_widen_composition_policy(self):
        for suffix, policy in preparation.controller_policies(ENVIRONMENT, ACCOUNT).items():
            self.assertEqual(without_sids(policy), self.docs[suffix])

    def test_service_boundaries_match_explicit_public_snapshots(self):
        snapshots = json.loads(preparation.BASELINES.read_text())
        policies = snapshots["policies"]
        versions = {"AmazonEKSClusterPolicy": "v10", "AmazonEKSFargatePodExecutionRolePolicy": "v1",
                    "AmazonEKSWorkerNodePolicy": "v3", "AmazonEC2ContainerRegistryPullOnly": "v1"}
        for name, version in versions.items():
            self.assertEqual(version, policies[name]["version"])
            self.assertEqual("https://docs.aws.amazon.com/aws-managed-policy/latest/reference/" + name + ".html",
                             policies[name]["source"])
        minimum = snapshots["clusterMinimum"]["document"]
        self.assertEqual([s["Action"] for s in minimum["Statement"]],
                         [s["Action"] for s in self.docs["eks-control"]["Statement"]])
        self.assertEqual(without_sids(policies["AmazonEKSFargatePodExecutionRolePolicy"]["document"]), self.docs["fargate-pod"])
        node = preparation.document(policies["AmazonEKSWorkerNodePolicy"]["document"]["Statement"] +
                                    policies["AmazonEC2ContainerRegistryPullOnly"]["document"]["Statement"])
        self.assertEqual(without_sids(node), self.docs["ec2-node"])

    def test_bootstrap_action_cap_has_no_allow_wildcards_and_keeps_denies(self):
        statements = self.docs["xp-bootstrap"]["Statement"]
        actions = statements[0]["Action"]
        self.assertTrue(actions)
        self.assertFalse(any("*" in action or "?" in action for action in actions))
        for resource in (self.contract.provider_role_arn, self.contract.deployment_role_arn,
                         self.contract.source_role_arn, self.contract.boundary_arn):
            self.assertEqual("explicitDeny", decision(statements, "iam:PutRolePolicy", resource, {}))
        self.assertEqual("implicitDeny", decision(statements, "iam:CreateAccessKey", "*", {}))
        self.assertEqual("explicitDeny", decision(statements, "sts:AssumeRole", OPERATOR, {}))
        self.assertEqual("explicitDeny", decision(statements, "ec2:DeleteVpc", "*",
                                                 {"aws:RequestedRegion": "us-west-2"}))

    def test_control_boundary_cannot_mutate_network_or_adopt_foreign_nodes(self):
        statements = self.docs["eks-control"]["Statement"]
        tag = "kubernetes.io/cluster/" + ENVIRONMENT
        context = {"aws:RequestedRegion": "us-east-1", "ec2:ResourceTag/" + tag: "owned",
                   "aws:RequestTag/" + tag: "owned", "aws:TagKeys": [tag]}
        instance = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-test"
        self.assertEqual("allowed", decision(statements, "ec2:CreateTags", instance, context))
        for change in ({"ec2:ResourceTag/" + tag: None}, {"aws:RequestTag/" + tag: "shared"},
                       {"aws:TagKeys": [tag, "foreign-tag"]}, {"aws:TagKeys": None},
                       {"aws:RequestedRegion": "us-west-2"}):
            self.assertEqual("implicitDeny", decision(statements, "ec2:CreateTags", instance, context | change))
        for action in ("ec2:DeleteVpc", "ec2:DeleteSecurityGroup", "ec2:CreateRoute",
                       "elasticloadbalancing:CreateLoadBalancer", "iam:CreateServiceLinkedRole"):
            self.assertEqual("implicitDeny", decision(statements, action, "*", context))

    def test_bootstrap_boundary_passrole_retains_identity_scope(self):
        statements = self.docs["xp-bootstrap"]["Statement"]
        self.assertNotIn("iam:PassRole", statements[0]["Action"])
        expected = [s for r in preparation.resolve_template(self.contract)["Resources"].values()
                    if r["Type"] == "AWS::IAM::Role"
                    for p in r["Properties"]["Policies"] for s in p["PolicyDocument"]["Statement"]
                    if s.get("Action") == "iam:PassRole"]
        actual = [s for s in statements if s.get("Action") == "iam:PassRole"]
        self.assertEqual(1, len(actual))
        self.assertEqual(without_sids(preparation.document(expected))["Statement"], actual)
        self.assertTrue(all("*" not in arn for arn in actual[0]["Resource"]))

    def test_bootstrap_boundary_rejects_foreign_or_unqualified_passrole(self):
        statements = self.docs["xp-bootstrap"]["Statement"]
        role = f"arn:aws:iam::{ACCOUNT}:role/{ENVIRONMENT}-ec2-node"
        context = {"iam:PassedToService": "ec2.amazonaws.com"}
        self.assertEqual("allowed", decision(statements, "iam:PassRole", role, context))
        for resource, values in ((role, {}), (role, {"iam:PassedToService": "lambda.amazonaws.com"}),
                                 (role.replace(ENVIRONMENT, "another-env"), context)):
            self.assertEqual("implicitDeny", decision(statements, "iam:PassRole", resource, values))

    def test_pending_pack_is_rejected_before_aws_reads(self):
        with patch.object(credentials, "_aws") as aws, self.assertRaisesRegex(ToolError, "approval"):
            credentials.verify_aws_identity(self.contract, "audit", self.pack)
        aws.assert_not_called()

    def test_approval_is_bound_to_reviewer_time_contract_and_both_templates(self):
        credentials.verify_review_approval(self.contract, self.approved_pack())
        changes = ({"approvedBy": ""}, {"approvedBy": "__REPLACE_REVIEWER__"}, {"approvedAt": None},
                   {"approvedAt": "2020-01-01T00:00:00"},
                   {"approvedAt": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
                   {"contract": self.contract.__dict__ | {"environment": "wrong-env"}},
                   {"sourceTemplateSha256": "0" * 64}, {"bootstrapTemplateSha256": "0" * 64})
        for change in changes:
            with self.subTest(change=change), patch.object(credentials, "_aws") as aws, self.assertRaises(ToolError):
                credentials.verify_aws_identity(self.contract, "audit", self.approved_pack() | change)
            aws.assert_not_called()

    def test_no_self_trust_or_user_source_upstream(self):
        for bad in (self.contract.source_role_arn, self.contract.provider_role_arn,
                    self.contract.deployment_role_arn, OPERATOR.replace(":role/", ":user/")):
            with self.assertRaises(ToolError):
                preparation.review_pack(ENVIRONMENT, bad)


if __name__ == "__main__":
    unittest.main()
