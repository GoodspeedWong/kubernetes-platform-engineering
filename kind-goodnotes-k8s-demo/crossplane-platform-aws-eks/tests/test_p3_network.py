from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
EKS_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-eks"
NETWORK_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-network"
SCRIPT_ROOT = REPO_ROOT / "scripts" / "eks_lifecycle"
FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p3"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import render_network  # noqa: E402
import validate_network_contract as network_contract  # noqa: E402


LEGACY_RESOURCE_NAMES = (
    "vpc",
    "internet-gateway",
    "public-route-table",
    "private-route-table",
    "public-default-route",
    "public-subnet-a",
    "public-subnet-b",
    "private-subnet-a",
    "private-subnet-b",
    "public-subnet-a-association",
    "public-subnet-b-association",
    "private-subnet-a-association",
    "private-subnet-b-association",
)


class P3NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.composition = common.load_yaml(NETWORK_ROOT / "composition.yaml")
        cls.source = cls.composition["spec"]["pipeline"][0]["input"]["spec"]["source"]
        cls.legacy = common.load_yaml(FIXTURES / "legacy-no-nat.yaml")
        cls.single_nat = common.load_yaml(FIXTURES / "eks-single-nat.yaml")
        cls.baseline = common.load_yaml(FIXTURES / "legacy-identity.yaml")
        cls.negative = common.load_yaml(FIXTURES / "negative-cases.yaml")

    def test_xrd_is_v2_manual_and_preserves_optional_legacy_defaults(self) -> None:
        xrd = common.load_yaml(NETWORK_ROOT / "xrd.yaml")
        self.assertEqual("apiextensions.crossplane.io/v2", xrd["apiVersion"])
        self.assertEqual("Cluster", xrd["spec"]["scope"])
        self.assertEqual("Manual", xrd["spec"]["defaultCompositionUpdatePolicy"])
        self.assertEqual(
            "xnetworks.platform.aws.goodnotes.io",
            xrd["spec"]["enforcedCompositionRef"]["name"],
        )
        parameters = xrd["spec"]["versions"][0]["schema"]["openAPIV3Schema"][
            "properties"
        ]["spec"]["properties"]["parameters"]
        self.assertNotIn("egress", parameters["required"])
        self.assertNotIn("environmentRef", parameters["required"])
        self.assertEqual("None", parameters["properties"]["egress"]["properties"]["mode"]["default"])
        self.assertEqual(
            ["ClusterProviderConfig"],
            parameters["properties"]["providerConfigRef"]["properties"]["kind"]["enum"],
        )
        rules = "\n".join(rule["rule"] for rule in parameters["x-kubernetes-validations"])
        for immutable in ("region", "cidrBlock", "publicSubnets", "privateSubnets", "egress"):
            self.assertIn(f"self.{immutable}", rules)

    def test_composition_migrated_to_pipeline_and_kcl_lints(self) -> None:
        self.assertEqual("Pipeline", self.composition["spec"]["mode"])
        self.assertNotIn("resources", self.composition["spec"])
        self.assertEqual(
            ["function-kcl", "function-auto-ready"],
            [step["functionRef"]["name"] for step in self.composition["spec"]["pipeline"]],
        )
        result = subprocess.run(
            ["kcl", "lint", "-", "--quiet", "--no_style"],
            input=self.source,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_v2_xrd_schema_converts_with_current_cli_compatibility_envelope(self) -> None:
        xrd = common.load_yaml(NETWORK_ROOT / "xrd.yaml")
        compatibility = copy.deepcopy(xrd)
        compatibility["apiVersion"] = "apiextensions.crossplane.io/v1"
        with tempfile.TemporaryDirectory(prefix="p3-xnetwork-xrd-") as temporary:
            source = Path(temporary) / "xrd-v1-envelope.json"
            output = Path(temporary) / "generated-crd.yaml"
            source.write_text(json.dumps(compatibility, indent=2, sort_keys=True) + "\n")
            result = subprocess.run(
                ["crossplane", "xrd", "convert", str(source), "--output-file", str(output)],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            crd = common.load_yaml(output)
            self.assertEqual("CustomResourceDefinition", crd["kind"])
            self.assertEqual("xnetworks.platform.aws.goodnotes.io", crd["metadata"]["name"])
            self.assertEqual("Cluster", crd["spec"]["scope"])

    def test_legacy_fixture_matches_existing_instance_and_keeps_13_aws_identities(self) -> None:
        current_instance = common.load_yaml(NETWORK_ROOT / "instances" / "shared-dev-network.yaml")
        self.assertEqual(self.legacy, current_instance)
        rendered = self._run_kcl(self.legacy)
        resources = self._resources_by_name(rendered)
        aws = {name: item for name, item in resources.items() if item["apiVersion"].startswith("ec2.aws.m.upbound.io/")}
        baseline = self.baseline["spec"]["awsManagedResources"]
        self.assertEqual(list(LEGACY_RESOURCE_NAMES), [item["name"] for item in baseline])
        self.assertEqual(set(LEGACY_RESOURCE_NAMES), set(aws))
        self.assertEqual(
            {item["name"]: item["kind"] for item in baseline},
            {name: item["kind"] for name, item in aws.items()},
        )
        for name, item in aws.items():
            with self.subTest(resource=name):
                self.assertEqual("crossplane-system", item["metadata"]["namespace"])
                self.assertNotIn("crossplane.io/external-name", item["metadata"].get("annotations", {}))
                self.assertEqual(
                    {"kind": "ClusterProviderConfig", "name": "default"},
                    item["spec"]["providerConfigRef"],
                )
                self.assertEqual(["*"], item["spec"]["managementPolicies"])
                self.assertNotIn("deletionPolicy", item["spec"])
        self.assertNotIn("nat-eip", resources)
        self.assertNotIn("nat-gateway", resources)
        self.assertNotIn("private-default-route", resources)
        desired = next(item for item in rendered["items"] if item.get("kind") == "XNetwork")
        self.assertEqual("None", desired["status"]["egressMode"])
        self.assertNotIn("discoveryValue", desired["status"])

    def test_legacy_remote_semantics_remain_stable(self) -> None:
        resources = self._resources_by_name(self._run_kcl(self.legacy))
        vpc = resources["vpc"]
        self.assertTrue(vpc["spec"]["forProvider"]["enableDnsHostnames"])
        self.assertTrue(vpc["spec"]["forProvider"]["enableDnsSupport"])
        self.assertEqual("10.40.0.0/16", vpc["spec"]["forProvider"]["cidrBlock"])
        self.assertEqual("shared-dev-network-vpc", vpc["spec"]["forProvider"]["tags"]["Name"])
        self.assertEqual(
            "shared-dev-network",
            vpc["metadata"]["labels"]["platform.aws.goodnotes.io/network"],
        )
        self.assertNotIn("platform.aws.goodnotes.io/environment", vpc["spec"]["forProvider"]["tags"])
        for slot in ("a", "b"):
            public = resources[f"public-subnet-{slot}"]
            private = resources[f"private-subnet-{slot}"]
            self.assertTrue(public["spec"]["forProvider"]["mapPublicIpOnLaunch"])
            self.assertFalse(private["spec"]["forProvider"]["mapPublicIpOnLaunch"])
            self.assertNotIn("karpenter.sh/discovery", private["spec"]["forProvider"]["tags"])

    def test_orphan_intent_maps_to_v2_management_policies_without_delete(self) -> None:
        orphan = copy.deepcopy(self.legacy)
        orphan["spec"]["parameters"]["deletionPolicy"] = "Orphan"
        resources = self._resources_by_name(self._run_kcl(orphan))
        for name in LEGACY_RESOURCE_NAMES:
            policies = resources[name]["spec"]["managementPolicies"]
            self.assertEqual(["Observe", "Create", "Update", "LateInitialize"], policies)
            self.assertNotIn("Delete", policies)

    def test_single_nat_renders_private_egress_and_scoped_discovery(self) -> None:
        rendered = self._run_kcl(self.single_nat)
        resources = self._resources_by_name(rendered)
        aws = {name: item for name, item in resources.items() if item["apiVersion"].startswith("ec2.aws.m.upbound.io/")}
        self.assertEqual(set(LEGACY_RESOURCE_NAMES) | {"nat-eip", "nat-gateway", "private-default-route"}, set(aws))
        eip = resources["nat-eip"]
        nat = resources["nat-gateway"]
        route = resources["private-default-route"]
        self.assertEqual("vpc", eip["spec"]["forProvider"]["domain"])
        self.assertEqual("public", nat["spec"]["forProvider"]["connectivityType"])
        self.assertEqual(
            {"platform.aws.goodnotes.io/subnet-slot": "a", "platform.aws.goodnotes.io/subnet-visibility": "public"},
            {
                key: value
                for key, value in nat["spec"]["forProvider"]["subnetIdSelector"]["matchLabels"].items()
                if key in {"platform.aws.goodnotes.io/subnet-slot", "platform.aws.goodnotes.io/subnet-visibility"}
            },
        )
        self.assertEqual("0.0.0.0/0", route["spec"]["forProvider"]["destinationCidrBlock"])
        self.assertEqual(
            "private",
            route["spec"]["forProvider"]["routeTableIdSelector"]["matchLabels"][
                "platform.aws.goodnotes.io/route-table-scope"
            ],
        )
        self.assertIn("natGatewayIdSelector", route["spec"]["forProvider"])
        for slot in ("a", "b"):
            private = resources[f"private-subnet-{slot}"]
            tags = private["spec"]["forProvider"]["tags"]
            self.assertEqual("eks-dev-spot", tags["karpenter.sh/discovery"])
            self.assertEqual("eks-dev-spot", tags["platform.aws.goodnotes.io/environment"])
            self.assertEqual(
                "shared", tags["kubernetes.io/cluster/eks-dev-spot-cluster"]
            )
            self.assertEqual("private", tags["platform.aws.goodnotes.io/subnet-visibility"])
            public_tags = resources[f"public-subnet-{slot}"]["spec"]["forProvider"]["tags"]
            self.assertNotIn("karpenter.sh/discovery", public_tags)
            self.assertEqual(
                "shared",
                public_tags["kubernetes.io/cluster/eks-dev-spot-cluster"],
            )
            self.assertEqual("public", public_tags["platform.aws.goodnotes.io/subnet-visibility"])

    def test_standalone_renderer_emits_api_server_dry_run_lists(self) -> None:
        legacy = render_network.render(copy.deepcopy(self.legacy), standalone_names=True)
        single = render_network.render(copy.deepcopy(self.single_nat), standalone_names=True)
        self.assertEqual(("v1", "List", 30), (legacy["apiVersion"], legacy["kind"], len(legacy["items"])))
        self.assertEqual(("v1", "List", 37), (single["apiVersion"], single["kind"], len(single["items"])))
        for item in single["items"]:
            self.assertTrue(item["metadata"]["name"].startswith("dryrun-"))

    def test_usage_edges_are_unique_replayable_and_acyclic(self) -> None:
        for instance, expected_count in ((self.legacy, 17), (self.single_nat, 21)):
            with self.subTest(network=instance["metadata"]["name"]):
                rendered = self._run_kcl(instance)
                resources = self._resources_by_name(rendered)
                usages = {name: item for name, item in resources.items() if item["kind"] == "Usage"}
                self.assertEqual(expected_count, len(usages))
                edges: list[tuple[str, str]] = []
                for name, usage in usages.items():
                    with self.subTest(usage=name):
                        self.assertTrue(usage["spec"]["replayDeletion"])
                        self.assertTrue(usage["spec"]["by"]["resourceSelector"]["matchControllerRef"])
                        self.assertTrue(usage["spec"]["of"]["resourceSelector"]["matchControllerRef"])
                        by_name = self._resolve_usage_endpoint(resources, usage["spec"]["by"])
                        of_name = self._resolve_usage_endpoint(resources, usage["spec"]["of"])
                        edges.append((of_name, by_name))
                self._assert_acyclic(edges)
                self.assertTrue(any(of_name == "vpc" for of_name, _ in edges))
                if instance is self.single_nat:
                    self.assertIn(("nat-eip", "nat-gateway"), edges)
                    self.assertIn(("nat-gateway", "private-default-route"), edges)

    def test_offline_validator_accepts_both_topologies_and_rejects_negative_cases(self) -> None:
        legacy_report = network_contract.validate_network(self.legacy)
        self.assertEqual("None", legacy_report["egressMode"])
        self.assertIsNone(legacy_report["discoveryValue"])
        single_report = network_contract.validate_network(self.single_nat)
        self.assertEqual("SingleNAT", single_report["egressMode"])
        self.assertEqual("eks-dev-spot", single_report["discoveryValue"])
        for case in self.negative["mutations"]:
            with self.subTest(case=case["id"]):
                candidate = copy.deepcopy(self.single_nat)
                self._mutate(candidate, case)
                with self.assertRaisesRegex(common.ToolError, case["expectedError"]):
                    network_contract.validate_network(candidate)
        for case in self.negative["immutableMutations"]:
            with self.subTest(case=case["id"]):
                candidate = copy.deepcopy(self.single_nat)
                self._mutate(candidate, case)
                with self.assertRaisesRegex(common.ToolError, case["expectedError"]):
                    network_contract.validate_network(candidate, self.single_nat)

    def test_environment_aggregate_maps_single_nat_and_exact_owner_reference(self) -> None:
        environment = common.load_yaml(EKS_ROOT / "environment" / "composition.yaml")
        source = environment["spec"]["pipeline"][0]["input"]["spec"]["source"]
        self.assertIn('mode = "SingleNAT"', source)
        self.assertIn('kind = "XEKSEnvironment"', source)
        self.assertIn("providerConfigRef = params.providerConfigRef", source)
        self.assertNotIn("providerConfigRef = {\n                            name", source)

    def test_machine_readable_owner_contract_records_migration_invariants(self) -> None:
        contract = common.load_yaml(EKS_ROOT / "ownership-contract.yaml")["networkContract"]
        self.assertEqual(list(LEGACY_RESOURCE_NAMES), contract["legacyAwsCompositionResourceNames"])
        self.assertEqual(
            ["nat-eip", "nat-gateway", "private-default-route"],
            contract["singleNatAdditionalResourceNames"],
        )
        self.assertEqual(["*"], contract["deletionPolicyMapping"]["Delete"]["managementPolicies"])
        self.assertNotIn(
            "Delete", contract["deletionPolicyMapping"]["Orphan"]["managementPolicies"]
        )
        self.assertEqual((17, 21, True), (
            contract["usageGraph"]["legacyEdges"],
            contract["usageGraph"]["singleNatEdges"],
            contract["usageGraph"]["acyclic"],
        ))
        self.assertEqual("XEKSCluster", contract["discovery"]["securityGroupOwner"])
        self.assertEqual("P4", contract["discovery"]["securityGroupImplementationPhase"])
        self.assertIn(
            "karpenter.sh/discovery", contract["discovery"]["securityGroupAwsTags"]
        )

    def test_examples_and_instances_remain_isolated_from_install_roots(self) -> None:
        network_root = common.load_yaml(NETWORK_ROOT / "kustomization.yaml")
        self.assertEqual(["xrd.yaml", "composition.yaml"], network_root["resources"])
        instance_root = common.load_yaml(NETWORK_ROOT / "instances" / "kustomization.yaml")
        self.assertEqual(["shared-dev-network.yaml"], instance_root["resources"])
        eks_root = common.load_yaml(EKS_ROOT / "kustomization.yaml")
        self.assertNotIn("tests", " ".join(eks_root["resources"]))
        self.assertNotIn("instances", " ".join(eks_root["resources"]))
        for path in (REPO_ROOT / "kind-goodnotes-k8s-demo" / "argocd").rglob("*.yaml"):
            text = path.read_text()
            self.assertNotIn("crossplane-platform-aws-network/examples", text)
            self.assertNotIn("crossplane-platform-aws-network/instances", text)
            self.assertNotIn("crossplane-platform-aws-eks/tests/fixtures/p3", text)

    @staticmethod
    def _run_kcl(instance: dict[str, object]) -> dict[str, object]:
        desired = {
            "apiVersion": instance["apiVersion"],
            "kind": instance["kind"],
            "metadata": {"name": instance["metadata"]["name"]},
            "status": {},
        }
        composition = common.load_yaml(NETWORK_ROOT / "composition.yaml")
        source = composition["spec"]["pipeline"][0]["input"]["spec"]["source"]
        params = {"oxr": instance, "dxr": desired, "ocds": {}}
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
            input=source,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        output = json.loads(result.stdout)
        if not isinstance(output, dict):
            raise AssertionError("KCL output must be an object")
        return output

    @staticmethod
    def _resources_by_name(rendered: dict[str, object]) -> dict[str, dict[str, object]]:
        resources: dict[str, dict[str, object]] = {}
        for item in rendered["items"]:
            if not isinstance(item, dict):
                continue
            annotation = item.get("metadata", {}).get("annotations", {}).get(
                "krm.kcl.dev/composition-resource-name"
            )
            if annotation:
                resources[str(annotation)] = item
        return resources

    @staticmethod
    def _resolve_usage_endpoint(
        resources: dict[str, dict[str, object]], endpoint: dict[str, object]
    ) -> str:
        selector = endpoint["resourceSelector"]
        labels = selector["matchLabels"]
        matches = [
            name
            for name, item in resources.items()
            if item.get("apiVersion") == endpoint["apiVersion"]
            and item.get("kind") == endpoint["kind"]
            and all(item.get("metadata", {}).get("labels", {}).get(key) == value for key, value in labels.items())
        ]
        if len(matches) != 1:
            raise AssertionError(f"usage endpoint must resolve uniquely, got {matches}")
        return matches[0]

    @staticmethod
    def _assert_acyclic(edges: list[tuple[str, str]]) -> None:
        graph: dict[str, set[str]] = {}
        for source, destination in edges:
            graph.setdefault(source, set()).add(destination)
            graph.setdefault(destination, set())
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                raise AssertionError(f"usage dependency cycle contains {node}")
            if node in visited:
                return
            visiting.add(node)
            for destination in graph[node]:
                visit(destination)
            visiting.remove(node)
            visited.add(node)

        for node in graph:
            visit(node)

    @staticmethod
    def _mutate(document: dict[str, object], case: dict[str, object]) -> None:
        keys = str(case["path"]).split(".")
        current = document
        for key in keys[:-1]:
            current = current[key]
        if case.get("delete"):
            del current[keys[-1]]
        else:
            current[keys[-1]] = case["value"]


if __name__ == "__main__":
    unittest.main()
