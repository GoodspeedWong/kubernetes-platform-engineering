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
P7_FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p7"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import render_cluster  # noqa: E402
import render_foundation  # noqa: E402
import validate_cilium_contract  # noqa: E402


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"


class P7CiliumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.foundation_instance = common.load_yaml(P5_FIXTURES / "foundation-valid.yaml")
        cls.cluster_instance = common.load_yaml(P4_FIXTURES / "cluster-valid.yaml")
        cls.cluster_observed = common.load_yaml(P4_FIXTURES / "observed-oidc-ready.yaml")
        cls.crds_ready_observed = common.load_yaml(
            P6_FIXTURES / "observed-karpenter-crds-ready.yaml"
        )
        cls.cilium_ready_observed = common.load_yaml(
            P7_FIXTURES / "observed-cilium-ready.yaml"
        )
        cls.cilium_failed_observed = common.load_yaml(
            P7_FIXTURES / "observed-cilium-failed.yaml"
        )
        cls.sequence = common.load_yaml(P7_FIXTURES / "bootstrap-sequence.yaml")
        cls.lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        cls.composition = common.load_yaml(EKS_ROOT / "foundation" / "composition.yaml")
        cls.source = cls.composition["spec"]["pipeline"][0]["input"]["spec"]["source"]
        cls.initial = render_foundation.render(copy.deepcopy(cls.foundation_instance))
        cls.staged = render_foundation.render(
            copy.deepcopy(cls.foundation_instance), copy.deepcopy(cls.crds_ready_observed)
        )
        cls.ready = render_foundation.render(
            copy.deepcopy(cls.foundation_instance), copy.deepcopy(cls.cilium_ready_observed)
        )
        cls.failed = render_foundation.render(
            copy.deepcopy(cls.foundation_instance), copy.deepcopy(cls.cilium_failed_observed)
        )
        cls.cluster = render_cluster.render(
            copy.deepcopy(cls.cluster_instance), copy.deepcopy(cls.cluster_observed)
        )
        cls.initial_resources = cls._resources_by_name(cls.initial)
        cls.staged_resources = cls._resources_by_name(cls.staged)
        cls.cluster_resources = cls._resources_by_name(cls.cluster)

    def test_cilium_is_pinned_and_declared_with_capacity_not_after_readiness(self) -> None:
        self.assertNotIn("cilium-release", self.initial_resources)
        self.assertIn("cilium-release", self.staged_resources)
        self.assertIn("spot-general-node-pool", self.staged_resources)
        self.assertEqual(10, len(self.staged["items"]))
        release = self.staged_resources["cilium-release"]
        provider = release["spec"]["forProvider"]
        self.assertEqual(
            {
                "name": "cilium",
                "repository": "oci://quay.io/cilium/charts",
                "digest": self.lock["charts"]["cilium"]["manifestDigest"],
                "version": self.lock["charts"]["cilium"]["version"],
            },
            provider["chart"],
        )
        self.assertEqual("cilium", release["metadata"]["annotations"]["crossplane.io/external-name"])
        self.assertEqual("kube-system", provider["namespace"])
        self.assertTrue(provider["skipCRDs"])
        self.assertTrue(provider["wait"])

    def test_merged_values_match_review_contract_and_cluster_runtime_material(self) -> None:
        provider = self.staged_resources["cilium-release"]["spec"]["forProvider"]
        self.assertEqual(
            [{"secretKeyRef": {"key": "cilium-values", "name": "eks-dev-spot-eks-access"}}],
            provider["valuesFrom"],
        )
        secret = self.cluster_resources["remote-kubeconfig-secret"]
        runtime = json.loads(secret["stringData"]["cilium-values"])
        merged = self._deep_merge(copy.deepcopy(provider["values"]), runtime)
        review = common.load_yaml(EKS_ROOT / "values" / "cilium.yaml")
        replacements = {
            "__INJECTED_CLUSTER_NAME__": "eks-dev-spot-cluster",
            "__INJECTED_ENVIRONMENT_NAME__": "eks-dev-spot",
            "__INJECTED_CILIUM_OPERATOR_ROLE_ARN__": "arn:aws:iam::000000000000:role/eks-dev-spot-cilium",
            "__INJECTED_EKS_API_HOST__": "test-only.eks.invalid",
            "__INJECTED_NATIVE_ROUTING_CIDR__": "10.40.0.0/16",
            "__INJECTED_AWS_REGION__": "us-east-1",
        }
        expected = self._replace_strings(review, replacements)
        self.assertEqual(expected, merged)
        self.assertEqual("test-only.eks.invalid", runtime["k8sServiceHost"])
        self.assertNotIn("https://", runtime["k8sServiceHost"])
        self.assertEqual("443", runtime["k8sServicePort"])
        serialized = json.dumps(runtime, sort_keys=True).lower()
        for forbidden in ("accesskey", "secretkey", "password", "token"):
            self.assertNotIn(forbidden, serialized)

    def test_eni_native_kpr_and_non_chaining_contract(self) -> None:
        values = self.staged_resources["cilium-release"]["spec"]["forProvider"]["values"]
        self.assertEqual({"mode": "eni"}, values["ipam"])
        self.assertTrue(values["eni"]["enabled"])
        self.assertEqual("native", values["routingMode"])
        self.assertEqual("10.40.0.0/16", values["ipv4NativeRoutingCIDR"])
        self.assertFalse(values["autoDirectNodeRoutes"])
        self.assertEqual("none", values["cni"]["chainingMode"])
        self.assertTrue(values["cni"]["exclusive"])
        self.assertTrue(values["cni"]["iptablesRemoveAWSRules"])
        self.assertFalse(values["cni"]["uninstall"])
        self.assertTrue(values["kubeProxyReplacement"])
        self.assertTrue(values["ipv4"]["enabled"])
        self.assertFalse(values["ipv6"]["enabled"])

    def test_agent_and_operator_are_ec2_only_and_bootstrap_without_coredns(self) -> None:
        values = self.staged_resources["cilium-release"]["spec"]["forProvider"]["values"]
        selector = {"karpenter.sh/nodepool": "spot-general", "kubernetes.io/os": "linux"}
        self.assertEqual(selector, values["nodeSelector"])
        self.assertEqual(selector, values["operator"]["nodeSelector"])
        self.assertEqual("Default", values["dnsPolicy"])
        self.assertEqual("Default", values["operator"]["dnsPolicy"])
        self.assertTrue(values["operator"]["hostNetwork"])
        self.assertEqual(
            [],
            values["operator"]["affinity"]["podAntiAffinity"][
                "requiredDuringSchedulingIgnoredDuringExecution"
            ],
        )
        self.assertEqual(
            "ScheduleAnyway",
            values["operator"]["topologySpreadConstraints"][0]["whenUnsatisfiable"],
        )
        self.assertTrue(
            any(
                item.get("key") == "node.cilium.io/agent-not-ready"
                and item.get("operator") == "Exists"
                for item in values["tolerations"]
            )
        )
        self.assertTrue(values["operator"]["removeNodeTaints"])
        self.assertTrue(values["operator"]["setNodeTaints"])
        self.assertTrue(values["operator"]["setNodeNetworkStatus"])

    def test_operator_irsa_tag_scope_and_eni_cleanup_are_explicit(self) -> None:
        values = self.staged_resources["cilium-release"]["spec"]["forProvider"]["values"]
        eni = values["eni"]
        runtime = json.loads(
            self.cluster_resources["remote-kubeconfig-secret"]["stringData"]["cilium-values"]
        )
        self.assertEqual(
            "arn:aws:iam::000000000000:role/eks-dev-spot-cilium",
            runtime["eni"]["iamRole"],
        )
        self.assertTrue(eni["awsReleaseExcessIPs"])
        self.assertTrue(eni["nodeSpec"]["deleteOnTermination"])
        self.assertIn(
            "platform.aws.goodnotes.io/environment=eks-dev-spot",
            eni["instanceTagsFilter"],
        )
        self.assertIn(
            "platform.aws.goodnotes.io/subnet-visibility=private",
            eni["nodeSpec"]["subnetTags"],
        )
        self.assertIn(
            "kubernetes.io/cluster/eks-dev-spot-cluster=owned",
            eni["nodeSpec"]["securityGroupTags"],
        )
        self.assertEqual(eni["eniTags"], eni["gcTags"])

    def test_locked_images_and_bootstrap_requests_match_capacity_envelope(self) -> None:
        values = self.staged_resources["cilium-release"]["spec"]["forProvider"]["values"]
        agent = values["image"]
        operator = values["operator"]["image"]
        self.assertEqual(
            self.lock["charts"]["cilium"]["images"]["agent"].split("@", 1)[1],
            agent["digest"],
        )
        self.assertEqual(
            self.lock["charts"]["cilium"]["images"]["operatorAWS"].split("@", 1)[1],
            operator["awsDigest"],
        )
        self.assertEqual(
            {"cpu": "100m", "memory": "128Mi"}, values["resources"]["requests"]
        )
        self.assertEqual(
            {"cpu": "100m", "memory": "256Mi"},
            values["operator"]["resources"]["requests"],
        )

    def test_coredns_has_one_owner_and_neither_cni_runs_on_fargate(self) -> None:
        addons = [
            resource
            for resource in self.cluster_resources.values()
            if resource.get("kind") == "Addon"
        ]
        self.assertEqual(1, len(addons))
        self.assertEqual("coredns", addons[0]["spec"]["forProvider"]["addonName"])
        self.assertEqual(
            self.lock["eksAddons"]["coreDNS"]["version"],
            addons[0]["spec"]["forProvider"]["addonVersion"],
        )
        control_plane = self.cluster_resources["eks-control-plane"]
        self.assertFalse(control_plane["spec"]["forProvider"]["bootstrapSelfManagedAddons"])
        selectors = self.cluster_resources["karpenter-fargate-profile"]["spec"][
            "forProvider"
        ]["selector"]
        self.assertFalse(any(item["namespace"] == "kube-system" for item in selectors))
        self.assertEqual(["karpenter"], [item["namespace"] for item in selectors])

    def test_pending_coredns_cilium_or_operator_never_retracts_nodepool(self) -> None:
        coredns_pending = copy.deepcopy(self.cluster_observed)
        coredns_pending["coredns-addon"] = {
            "Resource": {
                "status": {
                    "conditions": [
                        {"type": "Ready", "status": "False", "reason": "Creating"}
                    ]
                }
            }
        }
        cluster = render_cluster.render(copy.deepcopy(self.cluster_instance), coredns_pending)
        self.assertIn("coredns-addon", self._resources_by_name(cluster))
        for observed in (self.crds_ready_observed, self.cilium_failed_observed):
            with self.subTest(observed=list(observed)):
                rendered = render_foundation.render(
                    copy.deepcopy(self.foundation_instance), copy.deepcopy(observed)
                )
                resources = self._resources_by_name(rendered)
                self.assertIn("spot-general-node-pool", resources)
                self.assertIn("cilium-release", resources)

    def test_conditions_separate_declaration_release_readiness_and_runtime_uat(self) -> None:
        cases = (
            ({}, "CiliumDeclared", ("False", "WaitingForKarpenterCRDRelease")),
            (self.crds_ready_observed, "CiliumDeclared", ("True", "Available")),
            (self.crds_ready_observed, "CiliumReady", ("False", "WaitingForRelease")),
            (self.cilium_failed_observed, "CiliumReady", ("False", "ReleaseFailed")),
            (self.cilium_ready_observed, "CiliumReady", ("True", "Available")),
            (self.cilium_ready_observed, "RuntimeNetworkUAT", ("Unknown", "RequiresAWSUAT")),
        )
        for observed, condition_type, expected in cases:
            with self.subTest(condition=condition_type, expected=expected):
                output = self._run_kcl(observed)
                condition = self._condition(output, condition_type)
                self.assertEqual(expected, (condition["status"], condition["reason"]))
        ready_output = self._run_kcl(self.cilium_ready_observed)
        desired = next(item for item in ready_output["items"] if item.get("kind") == "XClusterFoundation")
        self.assertEqual("1.20.1", desired["status"]["actualVersions"]["cilium"])

    def test_zero_node_bootstrap_model_is_acyclic_and_keeps_uat_as_last_gate(self) -> None:
        self.assertEqual("static-zero-node-bootstrap-model-not-runtime-evidence", self.sequence["scope"])
        nodes = {item["id"]: item for item in self.sequence["nodes"]}
        self.assertEqual(len(nodes), len(self.sequence["nodes"]))
        order: list[str] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise AssertionError(f"bootstrap cycle at {node_id}")
            if node_id in visited:
                return
            visiting.add(node_id)
            for dependency in nodes[node_id]["requires"]:
                self.assertIn(dependency, nodes)
                visit(dependency)
            visiting.remove(node_id)
            visited.add(node_id)
            order.append(node_id)

        for node_id in nodes:
            visit(node_id)
        self.assertLess(order.index("capacity-and-cilium-declarations"), order.index("spot-ec2-node"))
        self.assertLess(order.index("spot-ec2-node"), order.index("eni-ipam-and-taint-removal"))
        self.assertEqual("runtime-network-uat", order[-1])
        self.assertFalse(self.sequence["invariants"]["staticModelProvesRuntimeConnectivity"])
        self.assertFalse(self.sequence["invariants"]["onDemandFallbackAllowed"])

    def test_validator_rejects_cni_fargate_and_runtime_endpoint_regressions(self) -> None:
        summary = validate_cilium_contract.validate_cilium_contract(self.staged, self.cluster)
        self.assertEqual("eni", summary["ipam"])
        self.assertTrue(summary["kubeProxyReplacement"])
        self.assertFalse(summary["runtimeUAT"])

        wrong_ipam = copy.deepcopy(self.staged)
        self._resources_by_name(wrong_ipam)["cilium-release"]["spec"]["forProvider"][
            "values"
        ]["ipam"]["mode"] = "cluster-pool"
        with self.assertRaises(common.ToolError):
            validate_cilium_contract.validate_cilium_contract(wrong_ipam, self.cluster)

        fargate_cni = copy.deepcopy(self.cluster)
        self._resources_by_name(fargate_cni)["karpenter-fargate-profile"]["spec"][
            "forProvider"
        ]["selector"].append({"namespace": "kube-system"})
        with self.assertRaises(common.ToolError):
            validate_cilium_contract.validate_cilium_contract(self.staged, fargate_cni)

        missing_endpoint = copy.deepcopy(self.cluster)
        secret = self._resources_by_name(missing_endpoint)["remote-kubeconfig-secret"]
        runtime = json.loads(secret["stringData"]["cilium-values"])
        runtime.pop("k8sServiceHost")
        secret["stringData"]["cilium-values"] = json.dumps(runtime)
        with self.assertRaises(common.ToolError):
            validate_cilium_contract.validate_cilium_contract(self.staged, missing_endpoint)

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
            "extraResources": render_foundation.default_extra_resources(),
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
        conditions = next(item for item in output["items"] if item.get("kind") == "Conditions")
        return next(
            item["condition"]
            for item in conditions["conditions"]
            if item["condition"]["type"] == condition_type
        )

    @staticmethod
    def _resources_by_name(rendered: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            item["metadata"]["annotations"][RESOURCE_NAME]: item
            for item in rendered["items"]
        }

    @classmethod
    def _replace_strings(cls, value: Any, replacements: dict[str, str]) -> Any:
        if isinstance(value, dict):
            return {key: cls._replace_strings(child, replacements) for key, child in value.items()}
        if isinstance(value, list):
            return [cls._replace_strings(child, replacements) for child in value]
        if isinstance(value, str):
            for old, new in replacements.items():
                value = value.replace(old, new)
        return value

    @classmethod
    def _deep_merge(cls, base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = cls._deep_merge(base[key], value)
            else:
                base[key] = copy.deepcopy(value)
        return base


if __name__ == "__main__":
    unittest.main()
