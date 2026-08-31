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
P4_FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p4"
P5_FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p5"
P6_FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p6"
SCHEMAS = EKS_ROOT / "tests" / "schemas" / "generated"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import render_cluster  # noqa: E402
import render_foundation  # noqa: E402
import validate_spot_contract  # noqa: E402


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"


class P6KarpenterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.foundation_instance = common.load_yaml(
            P5_FIXTURES / "foundation-valid.yaml"
        )
        cls.cluster_instance = common.load_yaml(P4_FIXTURES / "cluster-valid.yaml")
        cls.cluster_observed = common.load_yaml(
            P4_FIXTURES / "observed-oidc-ready.yaml"
        )
        cls.crds_ready_observed = common.load_yaml(
            P6_FIXTURES / "observed-karpenter-crds-ready.yaml"
        )
        cls.karpenter_ready_observed = common.load_yaml(
            P6_FIXTURES / "observed-karpenter-ready.yaml"
        )
        cls.spot_unavailable_observed = common.load_yaml(
            P6_FIXTURES / "observed-spot-unavailable.yaml"
        )
        cls.bootstrap_capacity = common.load_yaml(
            P6_FIXTURES / "bootstrap-capacity.yaml"
        )
        cls.lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        cls.composition = common.load_yaml(EKS_ROOT / "foundation" / "composition.yaml")
        cls.source = cls.composition["spec"]["pipeline"][0]["input"]["spec"][
            "source"
        ]
        cls.initial = render_foundation.render(copy.deepcopy(cls.foundation_instance))
        cls.staged = render_foundation.render(
            copy.deepcopy(cls.foundation_instance), copy.deepcopy(cls.crds_ready_observed)
        )
        cls.ready = render_foundation.render(
            copy.deepcopy(cls.foundation_instance),
            copy.deepcopy(cls.karpenter_ready_observed),
        )
        cls.initial_resources = cls._resources_by_name(cls.initial)
        cls.staged_resources = cls._resources_by_name(cls.staged)
        cls.cluster_staged = render_cluster.render(
            copy.deepcopy(cls.cluster_instance), copy.deepcopy(cls.cluster_observed)
        )
        cls.cluster_resources = cls._resources_by_name(cls.cluster_staged)

    def test_crd_release_is_the_unique_gate_for_all_p6_resources(self) -> None:
        lint = subprocess.run(
            ["kcl", "lint", "-", "--quiet", "--no_style"],
            input=self.source,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, lint.returncode, lint.stderr)
        self.assertEqual(
            {
                "kubernetes-provider-config",
                "helm-provider-config",
                "karpenter-crds-release",
                "remote-auth-probe",
                "network-uat-approval",
                "foundation-uses-cluster",
            },
            set(self.initial_resources),
        )
        self.assertEqual(6, len(self.initial["items"]))
        self.assertEqual(
            {
                *self.initial_resources,
                "karpenter-controller-release",
                "ec2-node-class",
                "spot-general-node-pool",
                "cilium-release",
            },
            set(self.staged_resources),
        )
        self.assertEqual(10, len(self.staged["items"]))

        crds = self.staged_resources["karpenter-crds-release"]
        controller = self.staged_resources["karpenter-controller-release"]
        self.assertEqual("karpenter-crd", crds["metadata"]["annotations"]["crossplane.io/external-name"])
        self.assertFalse(crds["spec"]["forProvider"]["skipCRDs"])
        self.assertEqual("karpenter", controller["metadata"]["annotations"]["crossplane.io/external-name"])
        self.assertTrue(controller["spec"]["forProvider"]["skipCRDs"])
        self.assertEqual(
            self.lock["charts"]["karpenterCRD"]["version"],
            crds["spec"]["forProvider"]["chart"]["version"],
        )
        self.assertEqual(
            self.lock["charts"]["karpenter"]["version"],
            controller["spec"]["forProvider"]["chart"]["version"],
        )

    def test_stage_remains_open_during_crd_observation_gap(self) -> None:
        observed = {
            name: {"Resource": copy.deepcopy(self.staged_resources[name])}
            for name in (
                "karpenter-controller-release",
                "ec2-node-class",
                "spot-general-node-pool",
                "cilium-release",
            )
        }
        rendered = render_foundation.render(
            copy.deepcopy(self.foundation_instance), observed
        )
        resources = self._resources_by_name(rendered)
        self.assertEqual(set(self.staged_resources), set(resources))

    def test_controller_values_match_fargate_irsa_and_zero_node_bootstrap(self) -> None:
        release = self.staged_resources["karpenter-controller-release"]
        provider = release["spec"]["forProvider"]
        values = provider["values"]
        review_values = common.load_yaml(EKS_ROOT / "values" / "karpenter.yaml")
        for item in review_values["controller"]["env"]:
            if item["value"] == "__INJECTED_AWS_REGION__":
                item["value"] = self.foundation_instance["spec"]["parameters"]["region"]
        self.assertEqual(review_values, values)
        self.assertEqual(2, values["replicas"])
        self.assertFalse(values["hostNetwork"])
        self.assertEqual("Default", values["dnsPolicy"])
        self.assertEqual(
            {
                "app.kubernetes.io/instance": "karpenter",
                "app.kubernetes.io/name": "karpenter",
            },
            values["podLabels"],
        )
        fargate_profile = self.cluster_resources["karpenter-fargate-profile"]
        selector = fargate_profile["spec"]["forProvider"]["selector"]
        self.assertEqual([{"namespace": "karpenter", "labels": values["podLabels"]}], selector)
        self.assertEqual(
            {"create": True, "name": "karpenter"}, values["serviceAccount"]
        )
        self.assertEqual(
            [{
                "secretKeyRef": {
                    "key": "karpenter-values",
                    "name": "eks-dev-spot-eks-access",
                }
            }],
            provider["valuesFrom"],
        )
        env = {item["name"]: item["value"] for item in values["controller"]["env"]}
        self.assertEqual("us-east-1", env["AWS_REGION"])
        self.assertEqual("us-east-1", env["AWS_DEFAULT_REGION"])
        self.assertEqual("true", env["AWS_EC2_METADATA_DISABLED"])
        self.assertEqual(
            {"requests": {"cpu": "1", "memory": "1Gi"}, "limits": {"cpu": "1", "memory": "1Gi"}},
            values["controller"]["resources"],
        )
        image = values["controller"]["image"]
        self.assertEqual("1.14.1", image["tag"])
        self.assertEqual(
            self.lock["charts"]["karpenter"]["controllerImage"].split("@", 1)[1],
            image["digest"],
        )
        self.assertEqual(
            [],
            values["affinity"]["podAntiAffinity"][
                "requiredDuringSchedulingIgnoredDuringExecution"
            ],
        )
        self.assertEqual(
            "ScheduleAnyway",
            values["topologySpreadConstraints"][0]["whenUnsatisfiable"],
        )
        self.assertEqual(1, values["podDisruptionBudget"]["maxUnavailable"])
        self.assertFalse(values["settings"]["featureGates"]["reservedCapacity"])

        secret = self.cluster_resources["remote-kubeconfig-secret"]
        runtime_values = json.loads(secret["stringData"]["karpenter-values"])
        self.assertEqual("eks-dev-spot-cluster", runtime_values["settings"]["clusterName"])
        self.assertEqual(
            "https://test-only.eks.invalid",
            runtime_values["settings"]["clusterEndpoint"],
        )
        self.assertEqual(
            "eks-dev-spot-karpenter-events",
            runtime_values["settings"]["interruptionQueue"],
        )
        self.assertEqual(
            "arn:aws:iam::000000000000:role/eks-dev-spot-karpenter",
            runtime_values["serviceAccount"]["annotations"][
                "eks.amazonaws.com/role-arn"
            ],
        )
        serialized = json.dumps(runtime_values, sort_keys=True).lower()
        for forbidden in ("token", "password", "secretaccesskey", "client-key-data"):
            self.assertNotIn(forbidden, serialized)

    def test_ec2_node_class_uses_private_discovery_and_reviewed_image(self) -> None:
        wrapper = self.staged_resources["ec2-node-class"]
        manifest = wrapper["spec"]["forProvider"]["manifest"]
        self.assertEqual(("karpenter.k8s.aws/v1", "EC2NodeClass"), (manifest["apiVersion"], manifest["kind"]))
        spec = manifest["spec"]
        self.assertEqual("AL2023", spec["amiFamily"])
        self.assertEqual(
            [{"alias": self.lock["nodeImages"]["al2023"]["alias"]}],
            spec["amiSelectorTerms"],
        )
        self.assertEqual("eks-dev-spot-ec2-node", spec["instanceProfile"])
        self.assertNotIn("role", spec)
        self.assertEqual(
            {
                "karpenter.sh/discovery": "eks-dev-spot",
                "platform.aws.goodnotes.io/environment": "eks-dev-spot",
                "platform.aws.goodnotes.io/subnet-visibility": "private",
            },
            spec["subnetSelectorTerms"][0]["tags"],
        )
        self.assertEqual(
            {
                "karpenter.sh/discovery": "eks-dev-spot",
                "kubernetes.io/cluster/eks-dev-spot-cluster": "owned",
                "platform.aws.goodnotes.io/environment": "eks-dev-spot",
            },
            spec["securityGroupSelectorTerms"][0]["tags"],
        )
        self.assertEqual("required", spec["metadataOptions"]["httpTokens"])
        self.assertEqual(1, spec["metadataOptions"]["httpPutResponseHopLimit"])
        self.assertNotIn("eks:eks-cluster-name", spec["tags"])
        self.assertFalse(
            any(key.startswith("kubernetes.io/cluster/") for key in spec["tags"])
        )

    def test_node_pool_is_dynamic_flexible_bounded_and_spot_only(self) -> None:
        summary = validate_spot_contract.validate_spot_contract(
            self.staged, {"us-east-1a", "us-east-1b"}
        )
        self.assertEqual(
            {
                "capacityType": "spot",
                "dynamicCapacity": True,
                "nodePoolCount": 1,
                "nodePools": ["spot-general"],
            },
            summary,
        )
        manifest = self.staged_resources["spot-general-node-pool"]["spec"][
            "forProvider"
        ]["manifest"]
        spec = manifest["spec"]
        self.assertNotIn("replicas", spec)
        self.assertEqual({"cpu": "16", "memory": "64Gi"}, spec["limits"])
        self.assertEqual(
            {
                "budgets": [{"nodes": "1"}],
                "consolidateAfter": "5m",
                "consolidationPolicy": "WhenEmpty",
            },
            spec["disruption"],
        )

    def test_spot_contract_rejects_every_purchase_and_scaling_bypass(self) -> None:
        wrapper = self.staged_resources["spot-general-node-pool"]
        valid = wrapper["spec"]["forProvider"]["manifest"]

        def requirement(pool: dict[str, Any]) -> dict[str, Any]:
            return next(
                item
                for item in pool["spec"]["template"]["spec"]["requirements"]
                if item["key"] == "karpenter.sh/capacity-type"
            )

        cases: list[tuple[str, Any]] = []
        missing = copy.deepcopy(valid)
        missing["spec"]["template"]["spec"]["requirements"] = [
            item
            for item in missing["spec"]["template"]["spec"]["requirements"]
            if item["key"] != "karpenter.sh/capacity-type"
        ]
        cases.append(("missing-capacity-type", missing))
        for label, values in (
            ("on-demand", ["on-demand"]),
            ("mixed", ["spot", "on-demand"]),
            ("reserved", ["reserved"]),
        ):
            pool = copy.deepcopy(valid)
            pool["metadata"]["name"] = label
            requirement(pool)["values"] = values
            cases.append((label, pool))
        wrong_operator = copy.deepcopy(valid)
        requirement(wrong_operator)["operator"] = "NotIn"
        cases.append(("wrong-operator", wrong_operator))
        fixed = copy.deepcopy(valid)
        fixed["spec"]["replicas"] = 1
        cases.append(("fixed-replicas", fixed))
        wrong_zones = copy.deepcopy(valid)
        next(
            item
            for item in wrong_zones["spec"]["template"]["spec"]["requirements"]
            if item["key"] == "topology.kubernetes.io/zone"
        )["values"] = ["us-east-1a"]
        cases.append(("single-zone", wrong_zones))

        for label, document in cases:
            with self.subTest(case=label):
                with self.assertRaises(common.ToolError):
                    validate_spot_contract.validate_spot_contract(document)

        extra_pool = copy.deepcopy(valid)
        extra_pool["metadata"]["name"] = "fallback"
        requirement(extra_pool)["values"] = ["on-demand"]
        with self.assertRaises(common.ToolError):
            validate_spot_contract.validate_spot_contract(
                {"items": [copy.deepcopy(wrapper), extra_pool]}
            )
        with self.assertRaisesRegex(common.ToolError, "no karpenter.sh/v1 NodePool"):
            validate_spot_contract.validate_spot_contract(
                {"values": {"nodePools": [valid]}}
            )

    def test_locked_crds_validate_both_remote_manifests(self) -> None:
        cases = (
            (
                "ec2-node-class",
                SCHEMAS / "remote" / "karpenter" / "ec2nodeclasses.yaml",
            ),
            (
                "spot-general-node-pool",
                SCHEMAS / "remote" / "karpenter" / "nodepools.yaml",
            ),
        )
        for resource_name, schema_path in cases:
            with self.subTest(resource=resource_name):
                manifest = self.staged_resources[resource_name]["spec"]["forProvider"][
                    "manifest"
                ]
                crd = common.load_yaml(schema_path)
                version = next(
                    item
                    for item in crd["spec"]["versions"]
                    if item["name"] == "v1"
                )
                root = version["schema"]["openAPIV3Schema"]
                self._validate_schema_value(
                    manifest["spec"], root["properties"]["spec"], f"{resource_name}.spec"
                )

    def test_conditions_distinguish_gating_ready_and_spot_unavailable(self) -> None:
        cases = (
            ({}, "KarpenterCRDsReady", ("False", "WaitingForCRDRelease")),
            (
                self.crds_ready_observed,
                "KarpenterCRDsReady",
                ("True", "Available"),
            ),
            (
                self.crds_ready_observed,
                "KarpenterReady",
                ("False", "WaitingForRemoteResources"),
            ),
            (self.karpenter_ready_observed, "KarpenterReady", ("True", "Available")),
            (
                self.spot_unavailable_observed,
                "KarpenterReady",
                ("False", "SpotCapacityUnavailable"),
            ),
        )
        for observed, condition_type, expected in cases:
            with self.subTest(condition=condition_type, expected=expected):
                output = self._run_kcl(observed)
                condition = self._condition(output, condition_type)
                self.assertEqual(expected, (condition["status"], condition["reason"]))
        unavailable = render_foundation.render(
            copy.deepcopy(self.foundation_instance),
            copy.deepcopy(self.spot_unavailable_observed),
        )
        self.assertEqual(set(self.staged_resources), set(self._resources_by_name(unavailable)))

    def test_bootstrap_capacity_envelope_fits_smallest_allowed_node(self) -> None:
        fixture = self.bootstrap_capacity
        self.assertEqual("planning-envelope-not-runtime-measurement", fixture["scope"])
        cpu = sum(
            item["countOnFirstNode"] * item["cpuMilliEach"]
            for item in fixture["requests"]
        )
        memory = sum(
            item["countOnFirstNode"] * item["memoryMiEach"]
            for item in fixture["requests"]
        )
        margin = 1 + fixture["safetyMarginPercent"] / 100
        self.assertLessEqual(cpu * margin, fixture["smallestAllowedNode"]["cpuMilli"])
        self.assertLessEqual(memory * margin, fixture["smallestAllowedNode"]["memoryMi"])
        names = {item["name"] for item in fixture["requests"]}
        self.assertNotIn("karpenter-controller", names)
        self.assertTrue({"cilium-agent", "cilium-operator", "coredns"}.issubset(names))

    def test_dynamic_capacity_has_no_second_crossplane_owner(self) -> None:
        contract = common.load_yaml(EKS_ROOT / "ownership-contract.yaml")
        by_id = {item["id"]: item for item in contract["resources"]}
        self.assertEqual(
            "XClusterFoundation", by_id["foundation/spot-node-pool"]["owner"]
        )
        for resource_id in (
            "karpenter/nodeclaims",
            "karpenter/nodes",
            "karpenter/ec2-instances",
            "karpenter/launch-templates",
        ):
            self.assertEqual("Karpenter", by_id[resource_id]["owner"])

    def _run_kcl(self, observed: dict[str, Any]) -> dict[str, Any]:
        desired = {
            "apiVersion": self.foundation_instance["apiVersion"],
            "kind": self.foundation_instance["kind"],
            "metadata": {"name": self.foundation_instance["metadata"]["name"]},
            "status": {},
        }
        params = {
            "oxr": self.foundation_instance,
            "dxr": desired,
            "ocds": observed,
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
        return json.loads(result.stdout)

    @staticmethod
    def _condition(output: dict[str, Any], condition_type: str) -> dict[str, Any]:
        condition_items = [
            item
            for item in output["items"]
            if isinstance(item, dict) and item.get("kind") == "Conditions"
        ]
        if len(condition_items) != 1:
            raise AssertionError("expected exactly one Conditions object")
        return next(
            item["condition"]
            for item in condition_items[0]["conditions"]
            if item["condition"]["type"] == condition_type
        )

    @staticmethod
    def _resources_by_name(rendered: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            item["metadata"]["annotations"][RESOURCE_NAME]: item
            for item in rendered["items"]
        }

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
                elif additional is True or schema.get(
                    "x-kubernetes-preserve-unknown-fields"
                ):
                    continue
                elif isinstance(additional, dict):
                    cls._validate_schema_value(child, additional, f"{path}.{key}")
                else:
                    raise AssertionError(
                        f"{path}.{key} is not declared by the locked CRD"
                    )
        elif schema_type == "array":
            if not isinstance(value, list):
                raise AssertionError(f"{path} must be an array")
            for index, child in enumerate(value):
                cls._validate_schema_value(
                    child, schema.get("items", {}), f"{path}[{index}]"
                )
        elif schema_type == "string" and not isinstance(value, str):
            raise AssertionError(f"{path} must be a string")
        elif schema_type == "boolean" and not isinstance(value, bool):
            raise AssertionError(f"{path} must be a boolean")
        elif schema_type == "integer" and (
            not isinstance(value, int) or isinstance(value, bool)
        ):
            raise AssertionError(f"{path} must be an integer")


if __name__ == "__main__":
    unittest.main()
