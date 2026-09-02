from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
EKS_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-eks"
SCRIPT_ROOT = REPO_ROOT / "scripts" / "eks_lifecycle"
FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p4"
SCHEMAS = EKS_ROOT / "tests" / "schemas" / "generated"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import render_cluster  # noqa: E402


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"


class P4ClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.instance = common.load_yaml(FIXTURES / "cluster-valid.yaml")
        cls.observed_oidc = common.load_yaml(FIXTURES / "observed-oidc-ready.yaml")
        cls.composition = common.load_yaml(EKS_ROOT / "cluster" / "composition.yaml")
        cls.source = cls.composition["spec"]["pipeline"][0]["input"]["spec"][
            "source"
        ]
        cls.initial = render_cluster.render(copy.deepcopy(cls.instance))
        cls.staged = render_cluster.render(
            copy.deepcopy(cls.instance), copy.deepcopy(cls.observed_oidc)
        )
        cls.initial_resources = cls._resources_by_name(cls.initial)
        cls.staged_resources = cls._resources_by_name(cls.staged)
        cls.schema_index = cls._schema_index()

    def test_cluster_composition_lints_and_renders_unique_stable_names(self) -> None:
        lint = subprocess.run(
            ["kcl", "lint", "-", "--quiet", "--no_style"],
            input=self.source,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, lint.returncode, lint.stderr)
        self.assertEqual(56, len(self.initial["items"]))
        self.assertEqual(56, len(self.initial_resources))
        self.assertEqual(70, len(self.staged["items"]))
        self.assertEqual(70, len(self.staged_resources))
        self.assertEqual(
            {
                "eks-control-plane",
                "eks-cluster-role",
                "fargate-pod-execution-role",
                "ec2-node-role",
                "ec2-node-instance-profile",
                "karpenter-fargate-profile",
                "coredns-addon",
                "admin-access-entry",
                "deployment-access-entry",
                "node-access-entry",
                "admin-access-policy-association",
                "deployment-access-policy-association",
                "interruption-queue",
                "interruption-queue-policy",
                "spot-interruption-rule",
                "spot-interruption-target",
                "rebalance-rule",
                "rebalance-target",
                "instance-state-rule",
                "instance-state-target",
                "scheduled-change-rule",
                "scheduled-change-target",
                "cluster-uses-network",
            },
            {
                name
                for name in self.initial_resources
                if not name.startswith("usage-")
            }
            - {
                "node-security-group",
                "node-security-group-self-ingress",
                "node-security-group-egress",
                "eks-cluster-policy-attachment",
                "fargate-execution-policy-attachment",
                "node-worker-policy-attachment",
                "node-ecr-pull-policy-attachment",
            },
        )
        for name in (
            "eks-oidc-provider",
            "karpenter-controller-role",
            "cilium-operator-role",
            "karpenter-controller-policy",
            "cilium-operator-policy",
        ):
            self.assertNotIn(name, self.initial_resources)
            self.assertIn(name, self.staged_resources)

    def test_every_rendered_resource_matches_locked_crd_field_schema(self) -> None:
        for name, resource in self.staged_resources.items():
            with self.subTest(resource=name):
                if (resource["apiVersion"], resource["kind"]) == ("v1", "Secret"):
                    self.assertEqual("Opaque", resource["type"])
                    self.assertIn("kubeconfig", resource["stringData"])
                    continue
                key = (resource["apiVersion"], resource["kind"])
                self.assertIn(key, self.schema_index)
                root_schema = self.schema_index[key]
                spec_schema = root_schema.get("properties", {}).get("spec")
                self.assertIsInstance(spec_schema, dict)
                self._validate_schema_value(resource.get("spec"), spec_schema, f"{name}.spec")

    def test_managed_resources_use_explicit_namespaced_provider_identity(self) -> None:
        provider = {"kind": "ClusterProviderConfig", "name": "test-only-aws"}
        for name, resource in self.staged_resources.items():
            if resource["apiVersion"].startswith("protection.crossplane.io/") or (
                resource["apiVersion"], resource["kind"]
            ) == ("v1", "Secret"):
                continue
            with self.subTest(resource=name):
                self.assertEqual("crossplane-system", resource["metadata"]["namespace"])
                self.assertEqual(provider, resource["spec"]["providerConfigRef"])
                self.assertEqual(["*"], resource["spec"]["managementPolicies"])
                self.assertNotIn("deletionPolicy", resource["spec"])

    def test_eks_control_plane_is_api_only_private_and_no_default_compute_owner(self) -> None:
        cluster = self.initial_resources["eks-control-plane"]
        for_provider = cluster["spec"]["forProvider"]
        self.assertEqual(
            {
                "authenticationMode": "API",
                "bootstrapClusterCreatorAdminPermissions": False,
            },
            for_provider["accessConfig"],
        )
        self.assertFalse(for_provider["bootstrapSelfManagedAddons"])
        self.assertTrue(for_provider["deletionProtection"])
        self.assertEqual("1.35", for_provider["version"])
        self.assertNotIn("computeConfig", for_provider)
        self.assertNotIn("kubernetesNetworkConfig", for_provider)
        vpc = for_provider["vpcConfig"]
        self.assertTrue(vpc["endpointPrivateAccess"])
        self.assertTrue(vpc["endpointPublicAccess"])
        self.assertEqual(["203.0.113.10/32"], vpc["publicAccessCidrs"])
        self.assertNotIn("0.0.0.0/0", vpc["publicAccessCidrs"])
        self.assertFalse(vpc["subnetIdSelector"]["matchControllerRef"])
        self.assertEqual(
            "private",
            vpc["subnetIdSelector"]["matchLabels"][
                "platform.aws.goodnotes.io/subnet-visibility"
            ],
        )
        self.assertTrue(vpc["securityGroupIdSelector"]["matchControllerRef"])

        addons = [item for item in self.initial["items"] if item["kind"] == "Addon"]
        self.assertEqual(1, len(addons))
        self.assertEqual("coredns", addons[0]["spec"]["forProvider"]["addonName"])
        self.assertEqual(
            "v1.14.3-eksbuild.3",
            addons[0]["spec"]["forProvider"]["addonVersion"],
        )
        kinds = {item["kind"] for item in self.initial["items"]}
        self.assertTrue({"NodeGroup", "LaunchTemplate"}.isdisjoint(kinds))
        lower_source = self.source.lower()
        self.assertNotIn("aws-node", lower_source)
        self.assertNotIn("vpc-cni", lower_source)
        self.assertNotIn("kube-proxy", lower_source)
        self.assertNotIn("aws-auth", lower_source)

    def test_platform_release_ref_drives_coredns_and_cluster_does_not_own_node_images(self) -> None:
        xrd = common.load_yaml(EKS_ROOT / "cluster" / "xrd.yaml")
        parameters = xrd["spec"]["versions"][0]["schema"]["openAPIV3Schema"][
            "properties"
        ]["spec"]["properties"]["parameters"]
        self.assertNotIn("nodeImageRef", parameters["required"])
        self.assertNotIn("nodeImageRef", parameters["properties"])
        self.assertNotIn(
            "nodeImageRef", self.initial_resources["eks-control-plane"]["spec"]
        )
        self.assertIn('kind = "ExtraResources"', self.source)
        self.assertIn("platform_release_ref.name", self.source)
        self.assertIn('type = "CatalogResolved"', self.source)

        extra = render_cluster.default_extra_resources()
        expected = extra["platform-release"][0]["Resource"]["spec"]["data"][
            "coreDNSAddon"
        ]
        addon = self.initial_resources["coredns-addon"]
        self.assertEqual(expected, addon["spec"]["forProvider"]["addonVersion"])

        missing = {"platform-release": None}
        with self.assertRaisesRegex(
            common.ToolError,
            "platformReleaseRef must resolve exactly one EnvironmentConfig",
        ):
            render_cluster.render(
                copy.deepcopy(self.instance), extra_resources=missing
            )

        incompatible = render_cluster.default_extra_resources()
        incompatible["platform-release"][0]["Resource"]["spec"]["data"][
            "coreDNSAddon"
        ] = "v0.0.0-eksbuild.0"
        with self.assertRaisesRegex(
            common.ToolError,
            "CoreDNS add-on is not locked",
        ):
            render_cluster.render(
                copy.deepcopy(self.instance), extra_resources=incompatible
            )

    def test_dedicated_security_group_is_owned_here_and_network_is_reference_only(self) -> None:
        security_group = self.initial_resources["node-security-group"]
        tags = security_group["spec"]["forProvider"]["tags"]
        self.assertEqual("eks-dev-spot", tags["karpenter.sh/discovery"])
        self.assertEqual(
            "owned", tags["kubernetes.io/cluster/eks-dev-spot-cluster"]
        )
        self.assertFalse(
            security_group["spec"]["forProvider"]["vpcIdSelector"][
                "matchControllerRef"
            ]
        )
        self.assertEqual(
            "XNetwork",
            self.initial_resources["cluster-uses-network"]["spec"]["of"]["kind"],
        )
        network_mutators = [
            item
            for item in self.initial["items"]
            if item["kind"]
            in {
                "VPC",
                "Subnet",
                "RouteTable",
                "Route",
                "InternetGateway",
                "NATGateway",
            }
        ]
        self.assertEqual([], network_mutators)

    def test_iam_roles_have_separate_trust_and_exact_attachments(self) -> None:
        initial_roles = {
            name: resource
            for name, resource in self.initial_resources.items()
            if resource["kind"] == "Role"
        }
        self.assertEqual(
            {"eks-cluster-role", "fargate-pod-execution-role", "ec2-node-role"},
            set(initial_roles),
        )
        eks_trust = self._json_policy(initial_roles["eks-cluster-role"], "assumeRolePolicy")
        self.assertEqual(
            "eks.amazonaws.com",
            eks_trust["Statement"][0]["Principal"]["Service"],
        )
        fargate_trust = self._json_policy(
            initial_roles["fargate-pod-execution-role"], "assumeRolePolicy"
        )
        statement = fargate_trust["Statement"][0]
        self.assertEqual(
            "eks-fargate-pods.amazonaws.com", statement["Principal"]["Service"]
        )
        self.assertEqual(
            "arn:aws:eks:us-east-1:000000000000:fargateprofile/eks-dev-spot-cluster/*",
            statement["Condition"]["ArnLike"]["aws:SourceArn"],
        )
        node_trust = self._json_policy(initial_roles["ec2-node-role"], "assumeRolePolicy")
        self.assertEqual(
            "ec2.amazonaws.com",
            node_trust["Statement"][0]["Principal"]["Service"],
        )

        attachments = {
            item["spec"]["forProvider"]["policyArn"]
            for item in self.initial["items"]
            if item["kind"] == "RolePolicyAttachment"
        }
        self.assertEqual(
            {
                "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
                "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy",
                "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
                "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
            },
            attachments,
        )
        self.assertNotIn("arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy", attachments)

    def test_oidc_and_irsa_are_staged_from_actual_issuer_with_exact_subjects(self) -> None:
        provider = self.staged_resources["eks-oidc-provider"]
        self.assertEqual(
            "https://oidc.eks.test-only.invalid/id/EXAMPLE",
            provider["spec"]["forProvider"]["url"],
        )
        self.assertEqual(
            ["sts.amazonaws.com"], provider["spec"]["forProvider"]["clientIdList"]
        )
        expected_subjects = {
            "karpenter-controller-role": "system:serviceaccount:karpenter:karpenter",
            "cilium-operator-role": "system:serviceaccount:kube-system:cilium-operator",
        }
        for name, subject in expected_subjects.items():
            with self.subTest(role=name):
                trust = self._json_policy(
                    self.staged_resources[name], "assumeRolePolicy"
                )
                statement = trust["Statement"][0]
                self.assertEqual("sts:AssumeRoleWithWebIdentity", statement["Action"])
                self.assertEqual(
                    "arn:aws:iam::000000000000:oidc-provider/oidc.eks.test-only.invalid/id/EXAMPLE",
                    statement["Principal"]["Federated"],
                )
                conditions = statement["Condition"]["StringEquals"]
                self.assertEqual(
                    subject,
                    conditions["oidc.eks.test-only.invalid/id/EXAMPLE:sub"],
                )
                self.assertEqual(
                    "sts.amazonaws.com",
                    conditions["oidc.eks.test-only.invalid/id/EXAMPLE:aud"],
                )
        fargate_trust = self._json_policy(
            self.staged_resources["fargate-pod-execution-role"],
            "assumeRolePolicy",
        )
        self.assertNotIn("Federated", fargate_trust["Statement"][0]["Principal"])

    def test_controller_policies_constrain_passrole_queue_cluster_and_eni_tags(self) -> None:
        karpenter = self._json_policy(
            self.staged_resources["karpenter-controller-policy"], "policy"
        )
        by_sid = {statement["Sid"]: statement for statement in karpenter["Statement"]}
        self.assertEqual(
            "arn:aws:iam::000000000000:role/eks-dev-spot-ec2-node",
            by_sid["AllowExactNodeRolePassRole"]["Resource"],
        )
        self.assertEqual(
            "arn:aws:eks:us-east-1:000000000000:cluster/eks-dev-spot-cluster",
            by_sid["AllowExactClusterRead"]["Resource"],
        )
        self.assertEqual(
            "arn:aws:sqs:us-east-1:000000000000:eks-dev-spot-karpenter-events",
            by_sid["AllowExactInterruptionQueueConsumption"]["Resource"],
        )
        self.assertEqual(
            {"sqs:DeleteMessage", "sqs:GetQueueUrl", "sqs:ReceiveMessage"},
            set(by_sid["AllowExactInterruptionQueueConsumption"]["Action"]),
        )
        for sid in (
            "AllowScopedEC2LaunchTemplateAccessActions",
            "AllowScopedEC2InstanceActionsWithTags",
            "AllowScopedResourceCreationTagging",
            "AllowScopedResourceTagging",
            "AllowScopedDeletion",
        ):
            self.assertIn("Condition", by_sid[sid])
        self.assertEqual(
            {
                "ec2:DescribeCapacityReservations",
                "ec2:DescribeImages",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeInstanceTypeOfferings",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeLaunchTemplates",
                "ec2:DescribePlacementGroups",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSpotPriceHistory",
                "ec2:DescribeSubnets",
            },
            set(by_sid["AllowRegionalReadOnlyDiscovery"]["Action"]),
        )
        creation_conditions = json.dumps(
            by_sid["AllowScopedEC2InstanceActionsWithTags"]["Condition"],
            sort_keys=True,
        )
        for expected in (
            "aws:RequestTag/kubernetes.io/cluster/eks-dev-spot-cluster",
            "aws:RequestTag/eks:eks-cluster-name",
            "aws:RequestTag/platform.aws.goodnotes.io/environment",
            "aws:RequestTag/karpenter.sh/nodepool",
        ):
            self.assertIn(expected, creation_conditions)
        source_resources = set(
            by_sid["AllowScopedEC2InstanceAccessActions"]["Resource"]
        )
        self.assertIn(
            "arn:aws:ec2:us-east-1::image/*", source_resources
        )
        self.assertIn(
            "arn:aws:ec2:us-east-1:000000000000:subnet/*",
            source_resources,
        )
        self.assertEqual(
            "iam:ListInstanceProfiles",
            by_sid["AllowUnscopedInstanceProfileList"]["Action"],
        )
        self.assertEqual(
            "arn:aws:iam::000000000000:instance-profile/eks-dev-spot-ec2-node",
            by_sid["AllowExactInstanceProfileRead"]["Resource"],
        )
        karpenter_actions = {
            action
            for statement in karpenter["Statement"]
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        }
        self.assertTrue(
            {
                "iam:CreateInstanceProfile",
                "iam:TagInstanceProfile",
                "iam:AddRoleToInstanceProfile",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:DeleteInstanceProfile",
            }.isdisjoint(karpenter_actions),
            "Crossplane owns the pre-created instance profile; Karpenter is read-only",
        )

        cilium = self._json_policy(
            self.staged_resources["cilium-operator-policy"], "policy"
        )
        cilium_by_sid = {
            statement["Sid"]: statement for statement in cilium["Statement"]
        }
        self.assertEqual(
            {
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeTags",
                "ec2:DescribeVpcs",
            },
            set(cilium_by_sid["AllowRegionalENIDiscovery"]["Action"]),
        )
        for sid in (
            "AllowTaggedENICreation",
            "AllowPrivateSubnetENICreation",
            "AllowDedicatedSecurityGroupENICreation",
            "AllowTaggedENIAtCreation",
            "AllowOwnedENIAttach",
            "AllowOwnedNodeENIAttach",
            "AllowOwnedENIMutation",
        ):
            conditions = json.dumps(cilium_by_sid[sid]["Condition"], sort_keys=True)
            self.assertIn("platform.aws.goodnotes.io/environment", conditions)
            self.assertIn("eks-dev-spot", conditions)
        self.assertEqual(
            "arn:aws:ec2:us-east-1:000000000000:network-interface/*",
            cilium_by_sid["AllowTaggedENICreation"]["Resource"],
        )
        self.assertEqual(
            "arn:aws:ec2:us-east-1:000000000000:subnet/*",
            cilium_by_sid["AllowPrivateSubnetENICreation"]["Resource"],
        )
        self.assertEqual(
            "arn:aws:ec2:us-east-1:000000000000:security-group/*",
            cilium_by_sid["AllowDedicatedSecurityGroupENICreation"]["Resource"],
        )
        self.assertEqual(
            "arn:aws:ec2:us-east-1:000000000000:instance/*",
            cilium_by_sid["AllowOwnedNodeENIAttach"]["Resource"],
        )
        for statement in cilium["Statement"]:
            actions = (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
            if any(not action.startswith("ec2:Describe") for action in actions):
                self.assertNotEqual("*", statement["Resource"])
        cilium_actions = {
            action
            for statement in cilium["Statement"]
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        }
        self.assertTrue(
            {
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateNetworkInterface",
                "ec2:AttachNetworkInterface",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:AssignPrivateIpAddresses",
                "ec2:CreateTags",
            }.issubset(cilium_actions)
        )
        self.assertNotIn("ec2:DetachNetworkInterface", cilium_actions)

    def test_instance_profile_is_single_role_reference_for_future_nodeclass(self) -> None:
        profile = self.initial_resources["ec2-node-instance-profile"]
        for_provider = profile["spec"]["forProvider"]
        self.assertIn("roleSelector", for_provider)
        self.assertNotIn("role", for_provider)
        self.assertEqual(
            "ec2-node-role",
            for_provider["roleSelector"]["matchLabels"][
                "platform.aws.goodnotes.io/resource-role"
            ],
        )
        contract = common.load_yaml(EKS_ROOT / "ownership-contract.yaml")
        self.assertIn(
            "ec2-node-instance-profile",
            contract["plannedCompositionResourceNames"]["XEKSCluster"],
        )
        self.assertEqual(
            set(self.staged_resources),
            set(contract["plannedCompositionResourceNames"]["XEKSCluster"]),
            "the ownership contract must enumerate every stable cluster resource name",
        )

    def test_access_api_has_distinct_human_deployment_and_node_entries_only(self) -> None:
        entries = {
            name: resource
            for name, resource in self.initial_resources.items()
            if resource["kind"] == "AccessEntry"
        }
        self.assertEqual(
            {"admin-access-entry", "deployment-access-entry", "node-access-entry"},
            set(entries),
        )
        self.assertEqual(
            "arn:aws:iam::000000000000:role/TEST-ONLY-EksAdmin",
            entries["admin-access-entry"]["spec"]["forProvider"]["principalArn"],
        )
        self.assertEqual(
            "arn:aws:iam::000000000000:role/TEST-ONLY-EksDeployer",
            entries["deployment-access-entry"]["spec"]["forProvider"][
                "principalArn"
            ],
        )
        node = entries["node-access-entry"]["spec"]["forProvider"]
        self.assertEqual("EC2_LINUX", node["type"])
        self.assertIn("principalArnFromRoleSelector", node)
        self.assertFalse(
            any("fargate" in name for name in entries),
            "Fargate access entries are created automatically by EKS and must not be duplicated",
        )
        associations = [
            item
            for item in self.initial["items"]
            if item["kind"] == "AccessPolicyAssociation"
        ]
        self.assertEqual(2, len(associations))

    def test_fargate_profile_matches_only_labeled_karpenter_pods_in_private_subnets(self) -> None:
        profile = self.initial_resources["karpenter-fargate-profile"]["spec"][
            "forProvider"
        ]
        self.assertEqual(
            [
                {
                    "namespace": "karpenter",
                    "labels": {
                        "app.kubernetes.io/instance": "karpenter",
                        "app.kubernetes.io/name": "karpenter",
                    },
                }
            ],
            profile["selector"],
        )
        self.assertEqual(
            "private",
            profile["subnetIdSelector"]["matchLabels"][
                "platform.aws.goodnotes.io/subnet-visibility"
            ],
        )
        self.assertNotEqual("kube-system", profile["selector"][0]["namespace"])
        self.assertNotEqual("argocd", profile["selector"][0]["namespace"])

    def test_interruption_queue_policy_rules_and_targets_are_scoped(self) -> None:
        queue = self.initial_resources["interruption-queue"]["spec"]["forProvider"]
        self.assertTrue(queue["sqsManagedSseEnabled"])
        self.assertEqual(300, queue["messageRetentionSeconds"])
        queue_policy = self._json_policy(
            self.initial_resources["interruption-queue-policy"], "policy"
        )
        allow = next(
            statement
            for statement in queue_policy["Statement"]
            if statement["Sid"] == "AllowOnlyOwnedEventRules"
        )
        self.assertEqual("events.amazonaws.com", allow["Principal"]["Service"])
        self.assertEqual(
            {
                "arn:aws:events:us-east-1:000000000000:rule/eks-dev-spot-spot",
                "arn:aws:events:us-east-1:000000000000:rule/eks-dev-spot-rebalance",
                "arn:aws:events:us-east-1:000000000000:rule/eks-dev-spot-state",
                "arn:aws:events:us-east-1:000000000000:rule/eks-dev-spot-health",
            },
            set(allow["Condition"]["ArnEquals"]["aws:SourceArn"]),
        )
        rules = [item for item in self.initial["items"] if item["kind"] == "Rule"]
        targets = [item for item in self.initial["items"] if item["kind"] == "Target"]
        self.assertEqual((4, 4), (len(rules), len(targets)))
        detail_types = {
            json.loads(rule["spec"]["forProvider"]["eventPattern"])["detail-type"][0]
            for rule in rules
        }
        self.assertEqual(
            {
                "EC2 Spot Instance Interruption Warning",
                "EC2 Instance Rebalance Recommendation",
                "EC2 Instance State-change Notification",
                "AWS Health Event",
            },
            detail_types,
        )
        for target in targets:
            self.assertEqual(
                "arn:aws:sqs:us-east-1:000000000000:eks-dev-spot-karpenter-events",
                target["spec"]["forProvider"]["arn"],
            )

    def test_usage_graph_is_unique_replayable_and_acyclic(self) -> None:
        resources = self.staged_resources
        usages = {
            name: item for name, item in resources.items() if item["kind"] == "Usage"
        }
        self.assertEqual(34, len(usages))
        edges: list[tuple[str, str]] = []
        for name, usage in usages.items():
            with self.subTest(usage=name):
                self.assertTrue(usage["spec"]["replayDeletion"])
                by_name = self._resolve_usage_endpoint(resources, usage["spec"]["by"])
                of_name = self._resolve_usage_endpoint(resources, usage["spec"]["of"])
                edges.append((of_name, by_name))
        self._assert_acyclic(edges)
        self.assertIn(("eks-control-plane", "karpenter-fargate-profile"), edges)
        self.assertIn(("eks-oidc-provider", "karpenter-controller-role"), edges)
        self.assertIn(("interruption-queue", "karpenter-controller-policy"), edges)
        self.assertIn(("eks-control-plane", "remote-kubeconfig-secret"), edges)
        cluster_usage = resources["cluster-uses-network"]
        self.assertEqual("ClusterUsage", cluster_usage["kind"])
        self.assertTrue(cluster_usage["spec"]["replayDeletion"])

    def test_missing_cluster_observation_preserves_existing_irsa_resources(self) -> None:
        observed = {
            name: {"Resource": copy.deepcopy(self.staged_resources[name])}
            for name in (
                "karpenter-controller-role",
                "cilium-operator-role",
                "karpenter-controller-policy",
                "cilium-operator-policy",
            )
        }
        rendered = render_cluster.render(copy.deepcopy(self.instance), observed)
        resources = self._resources_by_name(rendered)
        for name in observed:
            self.assertIn(name, resources)

    def test_infrastructure_ready_excludes_coredns_but_requires_api_and_fargate(self) -> None:
        observed: dict[str, dict[str, Any]] = {}
        for name, item in self.staged_resources.items():
            resource = copy.deepcopy(item)
            resource.setdefault("status", {})["conditions"] = [
                {"type": "Ready", "status": "True"}
            ]
            resource["status"].setdefault("atProvider", {})
            observed[name] = {"Resource": resource}
        observed["eks-control-plane"]["Resource"]["status"]["atProvider"] = {
            "certificateAuthority": [{"data": "VEVTVC1PTkxZLUNB"}],
            "endpoint": "https://test-only.eks.invalid",
            "identity": [
                {
                    "oidc": [
                        {
                            "issuer": "https://oidc.eks.test-only.invalid/id/EXAMPLE"
                        }
                    ]
                }
            ],
            "status": "ACTIVE",
            "version": "1.35",
        }
        observed["karpenter-fargate-profile"]["Resource"]["status"][
            "atProvider"
        ] = {"status": "ACTIVE"}
        observed["eks-oidc-provider"]["Resource"]["status"]["atProvider"] = {
            "arn": "arn:aws:iam::000000000000:oidc-provider/oidc.eks.test-only.invalid/id/EXAMPLE"
        }
        observed["coredns-addon"]["Resource"]["status"]["conditions"] = [
            {"type": "Ready", "status": "False"}
        ]

        output = self._run_kcl(observed)
        condition_object = next(
            item for item in output["items"] if item.get("kind") == "Conditions"
        )
        infrastructure = next(
            entry["condition"]
            for entry in condition_object["conditions"]
            if entry["condition"]["type"] == "InfrastructureReady"
        )
        self.assertEqual(("True", "Available"), (infrastructure["status"], infrastructure["reason"]))
        desired = next(
            item for item in output["items"] if item.get("kind") == "XEKSCluster"
        )
        self.assertEqual(
            "https://test-only.eks.invalid", desired["status"]["endpoint"]
        )
        self.assertEqual(
            "VEVTVC1PTkxZLUNB", desired["status"]["certificateAuthorityData"]
        )

    def test_account_level_prerequisites_remain_external_and_explicit(self) -> None:
        kinds = {resource["kind"] for resource in self.staged_resources.values()}
        self.assertNotIn("ServiceLinkedRole", kinds)
        account_checklist = (EKS_ROOT / "AWS_ACCOUNT_PREREQUISITES.md").read_text()
        for expected in (
            "AWSServiceRoleForEC2Spot",
            "Provider",
            "Git",
            "AWS 托管策略",
        ):
            self.assertIn(expected, account_checklist)
        self.assertIn("AccountPrerequisitesReady", self.source)
        self.assertIn("RequiresAccountOwnerVerification", self.source)

    def _run_kcl(self, observed: dict[str, Any]) -> dict[str, Any]:
        desired = {
            "apiVersion": self.instance["apiVersion"],
            "kind": self.instance["kind"],
            "metadata": {"name": self.instance["metadata"]["name"]},
            "status": {},
        }
        params = {
            "oxr": self.instance,
            "dxr": desired,
            "ocds": observed,
            "extraResources": render_cluster.default_extra_resources(),
        }
        result = subprocess.run(
            [
                "kcl",
                "run",
                "-",
                "--format",
                "json",
                "--no_style",
                "-D",
                f"params={json.dumps(params, separators=(',', ':'))}",
            ],
            input=self.source,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        output = json.loads(result.stdout)
        self.assertIsInstance(output, dict)
        return output

    @staticmethod
    def _resources_by_name(rendered: dict[str, Any]) -> dict[str, dict[str, Any]]:
        resources: dict[str, dict[str, Any]] = {}
        for item in rendered["items"]:
            name = item.get("metadata", {}).get("annotations", {}).get(RESOURCE_NAME)
            if name:
                if name in resources:
                    raise AssertionError(f"duplicate composition resource name: {name}")
                resources[name] = item
        return resources

    @staticmethod
    def _json_policy(resource: dict[str, Any], field: str) -> dict[str, Any]:
        return json.loads(resource["spec"]["forProvider"][field])

    @staticmethod
    def _resolve_usage_endpoint(
        resources: dict[str, dict[str, Any]], endpoint: dict[str, Any]
    ) -> str:
        selector = endpoint["resourceSelector"]
        if not selector.get("matchControllerRef"):
            raise AssertionError("internal Usage selector must match its controller")
        labels = selector["matchLabels"]
        matches = [
            name
            for name, item in resources.items()
            if item.get("apiVersion") == endpoint["apiVersion"]
            and item.get("kind") == endpoint["kind"]
            and all(
                item.get("metadata", {}).get("labels", {}).get(key) == value
                for key, value in labels.items()
            )
        ]
        if len(matches) != 1:
            raise AssertionError(f"Usage endpoint resolved to {matches}")
        return matches[0]

    @staticmethod
    def _assert_acyclic(edges: list[tuple[str, str]]) -> None:
        graph: dict[str, set[str]] = {}
        nodes: set[str] = set()
        for source, target in edges:
            graph.setdefault(source, set()).add(target)
            nodes.update((source, target))
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                raise AssertionError(f"cycle at {node}")
            if node in visited:
                return
            visiting.add(node)
            for child in graph.get(node, set()):
                visit(child)
            visiting.remove(node)
            visited.add(node)

        for node in nodes:
            visit(node)

    @staticmethod
    def _schema_index() -> dict[tuple[str, str], dict[str, Any]]:
        index: dict[tuple[str, str], dict[str, Any]] = {}
        for path in SCHEMAS.rglob("*.yaml"):
            crd = common.load_yaml(path)
            group = crd["spec"]["group"]
            kind = crd["spec"]["names"]["kind"]
            for version in crd["spec"]["versions"]:
                if version.get("served"):
                    api_version = f"{group}/{version['name']}"
                    index[(api_version, kind)] = version["schema"]["openAPIV3Schema"]
        return index

    @classmethod
    def _validate_schema_value(
        cls, value: Any, schema: dict[str, Any], path: str
    ) -> None:
        if value is None:
            if schema.get("nullable"):
                return
            raise AssertionError(f"{path} is null")
        if "enum" in schema and value not in schema["enum"]:
            raise AssertionError(f"{path} is not in enum {schema['enum']}")
        schema_type = schema.get("type")
        if schema_type == "object" or "properties" in schema:
            if not isinstance(value, dict):
                raise AssertionError(f"{path} must be an object")
            properties = schema.get("properties", {})
            for required in schema.get("required", []):
                if required not in value:
                    raise AssertionError(f"{path}.{required} is required")
            additional = schema.get("additionalProperties", False)
            for key, child in value.items():
                if key in properties:
                    cls._validate_schema_value(child, properties[key], f"{path}.{key}")
                elif additional is True:
                    continue
                elif isinstance(additional, dict):
                    cls._validate_schema_value(child, additional, f"{path}.{key}")
                elif schema.get("x-kubernetes-preserve-unknown-fields"):
                    continue
                else:
                    raise AssertionError(f"{path}.{key} is not declared by the locked CRD")
        elif schema_type == "array":
            if not isinstance(value, list):
                raise AssertionError(f"{path} must be an array")
            item_schema = schema.get("items", {})
            for index, child in enumerate(value):
                cls._validate_schema_value(child, item_schema, f"{path}[{index}]")
        elif schema_type == "string" and not isinstance(value, str):
            raise AssertionError(f"{path} must be a string")
        elif schema_type == "boolean" and not isinstance(value, bool):
            raise AssertionError(f"{path} must be a boolean")
        elif schema_type == "integer" and (
            not isinstance(value, int) or isinstance(value, bool)
        ):
            raise AssertionError(f"{path} must be an integer")
        elif schema_type == "number" and (
            not isinstance(value, (int, float)) or isinstance(value, bool)
        ):
            raise AssertionError(f"{path} must be a number")


if __name__ == "__main__":
    unittest.main()
