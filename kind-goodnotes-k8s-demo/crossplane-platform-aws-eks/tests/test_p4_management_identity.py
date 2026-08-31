from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
EKS_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-eks"
SCRIPT_ROOT = REPO_ROOT / "scripts" / "eks_lifecycle"
BOOTSTRAP_ROOT = EKS_ROOT / "management-aws-auth"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402


def policy_statements(role: dict[str, Any]) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    for policy in role["Properties"]["Policies"]:
        statements.extend(policy["PolicyDocument"]["Statement"])
    return statements


def actions(statement: dict[str, Any]) -> list[str]:
    value = statement["Action"]
    return value if isinstance(value, list) else [value]


class P4ManagementIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.template = common.load_yaml(BOOTSTRAP_ROOT / "cloudformation.yaml")
        cls.provider_config = common.load_yaml(
            BOOTSTRAP_ROOT / "provider-config.template.yaml"
        )
        cls.service_linked_roles = common.load_yaml(
            BOOTSTRAP_ROOT / "service-linked-roles.yaml"
        )
        cls.role = cls.template["Resources"]["CrossplaneAWSProviderRole"]
        cls.statements = policy_statements(cls.role)
        for resource in cls.template["Resources"].values():
            if resource["Type"] == "AWS::IAM::ManagedPolicy":
                cls.statements.extend(resource["Properties"]["PolicyDocument"]["Statement"])

    def test_bootstrap_role_is_external_retained_and_trust_is_exact(self) -> None:
        self.assertEqual("AWS::IAM::Role", self.role["Type"])
        self.assertEqual("Retain", self.role["DeletionPolicy"])
        self.assertEqual("Retain", self.role["UpdateReplacePolicy"])
        self.assertEqual(
            "${EnvironmentName}-xp-aws",
            self.role["Properties"]["RoleName"]["Fn::Sub"],
        )
        trust = self.role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
        self.assertEqual(1, len(trust))
        self.assertEqual("sts:AssumeRole", trust[0]["Action"])
        self.assertEqual(
            {"Ref": "TrustedSourcePrincipalArn"},
            trust[0]["Principal"]["AWS"],
        )
        self.assertNotIn("*", json.dumps(trust, sort_keys=True))

    def test_dedicated_source_has_no_credentials_or_console_login(self) -> None:
        self.assertNotIn("DedicatedSourceUser", self.template["Resources"])
        serialized = json.dumps(self.template, sort_keys=True)
        self.assertNotIn("AWS::IAM::AccessKey", serialized)
        self.assertNotIn("AWS::IAM::User", serialized)
        self.assertNotIn("Default", self.template["Parameters"]["TrustedSourcePrincipalArn"])
        self.assertNotIn("Default", self.template["Parameters"]["PermissionsBoundaryArn"])

    def test_roles_have_no_admin_policy_or_service_linked_role_permission(self) -> None:
        serialized = json.dumps(self.template, sort_keys=True)
        for forbidden in (
            "AWS::IAM::AccessKey",
            "AdministratorAccess",
            "iam:CreateServiceLinkedRole",
        ):
            self.assertNotIn(forbidden, serialized)
        for statement in self.statements:
            if statement["Effect"] != "Allow":
                continue
            for action in actions(statement):
                self.assertNotEqual("*", action)
                self.assertFalse(action.endswith(":*"), action)

    def test_deployment_role_is_retained_distinct_and_describe_only(self) -> None:
        deployment = self.template["Resources"]["EKSDeploymentRole"]
        self.assertEqual("AWS::IAM::Role", deployment["Type"])
        self.assertEqual("Retain", deployment["DeletionPolicy"])
        self.assertEqual("Retain", deployment["UpdateReplacePolicy"])
        self.assertEqual(
            "${EnvironmentName}-eks-deploy",
            deployment["Properties"]["RoleName"]["Fn::Sub"],
        )
        self.assertNotEqual(
            self.role["Properties"]["RoleName"],
            deployment["Properties"]["RoleName"],
        )
        statement = deployment["Properties"]["Policies"][0]["PolicyDocument"][
            "Statement"
        ]
        self.assertEqual(1, len(statement))
        self.assertEqual("eks:DescribeCluster", statement[0]["Action"])
        self.assertIn(
            "${EnvironmentName}-cluster",
            statement[0]["Resource"]["Fn::Sub"],
        )

    def test_policy_covers_composition_services_and_lifecycle_directions(self) -> None:
        granted = {
            action
            for statement in self.statements
            if statement["Effect"] == "Allow"
            for action in actions(statement)
        }
        required = {
            "ec2:CreateVpc",
            "ec2:DeleteVpc",
            "ec2:CreateNatGateway",
            "ec2:DeleteNatGateway",
            "eks:CreateCluster",
            "eks:DeleteCluster",
            "eks:CreateFargateProfile",
            "eks:DeleteFargateProfile",
            "eks:CreateAddon",
            "eks:DeleteAddon",
            "eks:CreateAccessEntry",
            "eks:DeleteAccessEntry",
            "eks:AssociateAccessPolicy",
            "eks:DisassociateAccessPolicy",
            "iam:CreateRole",
            "iam:DeleteRole",
            "iam:CreateInstanceProfile",
            "iam:DeleteInstanceProfile",
            "iam:CreateOpenIDConnectProvider",
            "iam:DeleteOpenIDConnectProvider",
            "iam:PassRole",
            "sqs:CreateQueue",
            "sqs:DeleteQueue",
            "events:PutRule",
            "events:DeleteRule",
            "events:PutTargets",
            "events:RemoveTargets",
        }
        self.assertEqual(set(), required - granted)
        compact_policy_size = sum(
            len(json.dumps(policy["PolicyDocument"], separators=(",", ":")))
            for policy in self.role["Properties"]["Policies"]
        )
        self.assertLessEqual(compact_policy_size, 10240)

    def test_region_and_passrole_are_fail_closed(self) -> None:
        parameters = self.template["Parameters"]
        self.assertEqual("us-east-1", parameters["TargetRegion"]["Default"])
        self.assertEqual(["us-east-1"], parameters["TargetRegion"]["AllowedValues"])
        deny = next(
            statement
            for statement in self.statements
            if statement["Sid"] == "DenyRegionalServicesOutsideApprovedRegion"
        )
        self.assertEqual("Deny", deny["Effect"])
        self.assertEqual(
            {"Ref": "TargetRegion"},
            deny["Condition"]["StringNotEquals"]["aws:RequestedRegion"],
        )
        pass_role = next(
            statement
            for statement in self.statements
            if statement["Sid"] == "PassOnlyEnvironmentServiceRoles"
        )
        resources = json.dumps(pass_role["Resource"], sort_keys=True)
        self.assertIn("${EnvironmentName}-eks-control", resources)
        self.assertIn("${EnvironmentName}-fargate-pod", resources)
        self.assertIn("${EnvironmentName}-ec2-node", resources)
        self.assertNotIn("${EnvironmentName}-*", resources)
        self.assertEqual(
            {
                "ec2.amazonaws.com",
                "eks.amazonaws.com",
                "eks-fargate-pods.amazonaws.com",
            },
            set(pass_role["Condition"]["StringEquals"]["iam:PassedToService"]),
        )

    def test_provider_config_uses_direct_execution_session_without_assume_chain(self) -> None:
        self.assertEqual("ClusterProviderConfig", self.provider_config["kind"])
        credentials = self.provider_config["spec"]["credentials"]
        self.assertEqual("Secret", credentials["source"])
        self.assertEqual(
            {
                "key": "credentials",
                "name": "eks-platform-aws-session",
                "namespace": "crossplane-system",
            },
            credentials["secretRef"],
        )
        self.assertNotIn("assumeRoleChain", self.provider_config["spec"])
        self.assertEqual(
            "true",
            self.provider_config["metadata"]["annotations"][
                "platform.aws.goodnotes.io/do-not-apply"
            ],
        )

    def test_templates_contain_placeholders_but_no_material_credentials(self) -> None:
        provider_text = (BOOTSTRAP_ROOT / "provider-config.template.yaml").read_text()
        parameters_text = (BOOTSTRAP_ROOT / "parameters.example.json").read_text()
        source_policy = json.loads(
            (BOOTSTRAP_ROOT / "source-principal-policy.template.json").read_text()
        )
        self.assertRegex(provider_text, r"__REPLACE_[A-Z0-9_]+__")
        self.assertRegex(parameters_text, r"__REPLACE_[A-Z0-9_]+__")
        self.assertEqual("sts:AssumeRole", source_policy["Statement"][0]["Action"])
        self.assertEqual(
            [
                "__REPLACE_CROSSPLANE_PROVIDER_ROLE_ARN__",
                "__REPLACE_EKS_DEPLOYMENT_ROLE_ARN__",
            ],
            source_policy["Statement"][0]["Resource"],
        )
        combined = provider_text + parameters_text + json.dumps(source_policy)
        self.assertIsNone(re.search(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", combined))
        self.assertNotIn("aws_secret_access_key", combined)

    def test_service_linked_roles_are_exact_external_retained(self) -> None:
        resources = self.service_linked_roles["Resources"]
        expected = {
            "EC2SpotServiceLinkedRole": (
                "CreatesEC2SpotServiceLinkedRole",
                "spot.amazonaws.com",
            ),
            "EKSServiceLinkedRole": (
                "CreatesEKSServiceLinkedRole",
                "eks.amazonaws.com",
            ),
            "EKSFargateServiceLinkedRole": (
                "CreatesEKSFargateServiceLinkedRole",
                "eks-fargate.amazonaws.com",
            ),
        }
        self.assertEqual(set(expected), set(resources))
        for logical_id, (condition, service_name) in expected.items():
            resource = resources[logical_id]
            self.assertEqual("AWS::IAM::ServiceLinkedRole", resource["Type"])
            self.assertEqual(condition, resource["Condition"])
            self.assertEqual("Retain", resource["DeletionPolicy"])
            self.assertEqual("Retain", resource["UpdateReplacePolicy"])
            self.assertEqual(
                service_name,
                resource["Properties"]["AWSServiceName"],
            )
            self.assertNotIn("CustomSuffix", resource["Properties"])

    def test_service_linked_role_creation_is_default_off(self) -> None:
        parameters = self.service_linked_roles["Parameters"]
        expected = {
            "CreateEC2SpotServiceLinkedRole",
            "CreateEKSServiceLinkedRole",
            "CreateEKSFargateServiceLinkedRole",
        }
        self.assertEqual(expected, set(parameters))
        for parameter in parameters.values():
            self.assertEqual("false", parameter["Default"])
            self.assertEqual(["false", "true"], parameter["AllowedValues"])

        root = common.load_yaml(EKS_ROOT / "kustomization.yaml")
        self.assertNotIn("service-linked-roles.yaml", json.dumps(root))

    def test_bootstrap_is_not_owned_or_installed_by_environment_root(self) -> None:
        ownership = common.load_yaml(EKS_ROOT / "ownership-contract.yaml")
        bootstrap = ownership["platformBootstrap"]
        prerequisites = {
            item["id"]: item for item in bootstrap["externalPrerequisites"]
        }
        for prerequisite_id in (
            "aws-provider-source-principal",
            "aws-provider-execution-role",
            "eks-deployment-role",
            "aws-provider-source-credentials",
            "provider-runtime-aws-credentials",
        ):
            self.assertIn(prerequisite_id, prerequisites)
            self.assertIn(
                prerequisite_id,
                bootstrap["forbiddenEnvironmentOwnership"],
            )
        self.assertEqual(
            "externally-provisioned-bootstrap-retained",
            prerequisites["aws-provider-execution-role"]["lifecycle"],
        )
        for prerequisite_id in (
            "aws-spot-service-linked-role",
            "aws-eks-service-linked-role",
            "aws-eks-fargate-service-linked-role",
        ):
            self.assertIn(
                prerequisite_id,
                ownership["externalPrerequisites"],
            )
        root = common.load_yaml(EKS_ROOT / "kustomization.yaml")
        self.assertNotIn("management-aws-auth", root["resources"])

    def test_taskbook_keeps_code_delivery_separate_from_live_account_gate(self) -> None:
        todo = (EKS_ROOT / "TODO.md").read_text()
        prerequisites = (EKS_ROOT / "AWS_ACCOUNT_PREREQUISITES.md").read_text()
        self.assertRegex(
            todo,
            r"(?s)- \[x\] P4-09 .*?management-aws-auth/.*?assumeRoleChain",
        )
        self.assertRegex(
            prerequisites,
            r"(?s)- \[[ xX]\] A04 .*?management-aws-auth/.*?execution role",
        )
        # A04 can advance after real IAM creation; M1 must not force it to stay
        # unchecked forever or treat identity creation as runtime acceptance.
        if "- [x] A04 " in prerequisites or "- [X] A04 " in prerequisites:
            evidence = "evidence/2026-08-30-a04-management-iam-created.md"
            self.assertIn(evidence, prerequisites)
            self.assertTrue((EKS_ROOT / evidence).is_file())
            self.assertIn("不代替 A05/A08 或 UAT", prerequisites)
        self.assertIn("management-aws-auth/README.md", (EKS_ROOT / "README.md").read_text())
        self.assertIn("AWS Provider execution role 门禁", (EKS_ROOT / "BOOTSTRAP.md").read_text())


if __name__ == "__main__":
    unittest.main()
