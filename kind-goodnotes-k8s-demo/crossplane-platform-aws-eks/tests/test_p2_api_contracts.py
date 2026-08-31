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
SCRIPT_ROOT = REPO_ROOT / "scripts" / "eks_lifecycle"
FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p2"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import validate_api_contract as api_contract  # noqa: E402


XRD_CASES = {
    "cluster": ("XEKSCluster", "xeksclusters.platform.aws.goodnotes.io"),
    "foundation": (
        "XClusterFoundation",
        "xclusterfoundations.platform.aws.goodnotes.io",
    ),
    "environment": (
        "XEKSEnvironment",
        "xeksenvironments.platform.aws.goodnotes.io",
    ),
}


class P2APIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.instance = common.load_yaml(FIXTURES / "environment-valid.yaml")
        cls.release = common.load_yaml(FIXTURES / "platform-release-compatible.yaml")
        cls.node_image = common.load_yaml(FIXTURES / "node-image-compatible.yaml")
        cls.lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        cls.negative_cases = common.load_yaml(FIXTURES / "negative-cases.yaml")

    def test_xrds_are_cluster_scoped_v2_contracts_and_convert_to_crds(self) -> None:
        for directory, (kind, plural_name) in XRD_CASES.items():
            with self.subTest(directory=directory):
                path = EKS_ROOT / directory / "xrd.yaml"
                xrd = common.load_yaml(path)
                self.assertEqual("apiextensions.crossplane.io/v2", xrd["apiVersion"])
                self.assertEqual("CompositeResourceDefinition", xrd["kind"])
                self.assertEqual("platform.aws.goodnotes.io", xrd["spec"]["group"])
                self.assertEqual("Cluster", xrd["spec"]["scope"])
                self.assertEqual(kind, xrd["spec"]["names"]["kind"])
                self.assertEqual("Manual", xrd["spec"]["defaultCompositionUpdatePolicy"])
                self.assertEqual(
                    plural_name,
                    xrd["spec"]["enforcedCompositionRef"]["name"],
                )
                version = xrd["spec"]["versions"]
                self.assertEqual(1, len(version))
                self.assertEqual("v1alpha1", version[0]["name"])
                self.assertTrue(version[0]["served"])
                self.assertTrue(version[0]["referenceable"])

                with tempfile.TemporaryDirectory(prefix="p2-xrd-") as temporary:
                    # Crossplane CLI v2.3.0's beta converter still decodes only the
                    # v1 XRD envelope. The v2 spec shape is identical for these
                    # cluster-scoped fields, so convert an ephemeral compatibility
                    # copy while the real source remains v2 and is server-dry-run
                    # against the management cluster in P2 acceptance.
                    converter_input = Path(temporary) / "xrd-v1-envelope.yaml"
                    compatibility_xrd = copy.deepcopy(xrd)
                    compatibility_xrd["apiVersion"] = "apiextensions.crossplane.io/v1"
                    converter_input.write_text(
                        json.dumps(compatibility_xrd, indent=2, sort_keys=True) + "\n"
                    )
                    output = Path(temporary) / "generated.yaml"
                    result = subprocess.run(
                        [
                            "crossplane",
                            "xrd",
                            "convert",
                            str(converter_input),
                            "--output-file",
                            str(output),
                        ],
                        cwd=REPO_ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    crd = common.load_yaml(output)
                    self.assertEqual("CustomResourceDefinition", crd["kind"])
                    self.assertEqual(plural_name, crd["metadata"]["name"])
                    self.assertEqual("Cluster", crd["spec"]["scope"])
                    generated_spec = crd["spec"]["versions"][0]["schema"][
                        "openAPIV3Schema"
                    ]["properties"]["spec"]["properties"]
                    self.assertIn("crossplane", generated_spec)
                    self.assertEqual(
                        ["Automatic", "Manual"],
                        generated_spec["crossplane"]["properties"][
                            "compositionUpdatePolicy"
                        ]["enum"],
                    )

    def test_environment_api_exposes_intent_and_blocks_bypass_fields(self) -> None:
        xrd = common.load_yaml(EKS_ROOT / "environment" / "xrd.yaml")
        schema = xrd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
        parameters = schema["properties"]["spec"]["properties"]["parameters"]
        properties = parameters["properties"]
        self.assertEqual(["dev"], properties["class"]["enum"])
        self.assertEqual(["spot-general"], properties["compute"]["properties"]["class"]["enum"])
        self.assertEqual(
            ["ClusterProviderConfig"],
            properties["providerConfigRef"]["properties"]["kind"]["enum"],
        )
        self.assertEqual(
            ["EnvironmentConfig"],
            properties["platformReleaseRef"]["properties"]["kind"]["enum"],
        )
        self.assertEqual(
            ["EnvironmentConfig"],
            properties["nodeImageRef"]["properties"]["kind"]["enum"],
        )
        self.assertEqual(
            {
                "adminPrincipalArn",
                "deploymentPrincipalArn",
                "publicAccessCidrs",
            },
            set(properties["access"]["required"]),
        )
        self.assertEqual(
            api_contract.CPU_LIMITS,
            set(
                properties["compute"]["properties"]["limits"]["properties"]["cpu"][
                    "enum"
                ]
            ),
        )
        self.assertEqual(
            api_contract.MEMORY_LIMITS,
            set(
                properties["compute"]["properties"]["limits"]["properties"][
                    "memory"
                ]["enum"]
            ),
        )
        all_keys = self._mapping_keys(parameters)
        self.assertTrue(api_contract.FORBIDDEN_FIELDS.isdisjoint(all_keys))
        rules = "\n".join(
            validation["rule"] for validation in parameters["x-kubernetes-validations"]
        )
        self.assertIn("self.region == oldSelf.region", rules)
        self.assertIn("self.network == oldSelf.network", rules)
        self.assertIn("self.providerConfigRef == oldSelf.providerConfigRef", rules)
        lifecycle_rules = properties["lifecycle"]["x-kubernetes-validations"]
        transition = next(
            rule
            for rule in lifecycle_rules
            if rule.get("optionalOldSelf") and "retirementStage" in rule["rule"]
        )
        self.assertIn("oldSelf.hasValue()", transition["rule"])
        self.assertIn("RemoveFoundation", transition["rule"])
        self.assertIn("DeleteReady", transition["rule"])
        self.assertIn("self.deletionProtection", transition["rule"])

    def test_compositions_are_pipeline_and_preserve_stable_desired_children(self) -> None:
        compositions = {
            directory: common.load_yaml(EKS_ROOT / directory / "composition.yaml")
            for directory in XRD_CASES
        }
        for directory, composition in compositions.items():
            with self.subTest(directory=directory):
                self.assertEqual("Pipeline", composition["spec"]["mode"])
                self.assertEqual("function-kcl", composition["spec"]["pipeline"][0]["functionRef"]["name"])

        environment_source = compositions["environment"]["spec"]["pipeline"][0][
            "input"
        ]["spec"]["source"]
        self.assertEqual(3, environment_source.count('compositionUpdatePolicy = "Manual"'))
        for resource_name in ("network", "cluster", "foundation"):
            self.assertIn(
                f'"krm.kcl.dev/composition-resource-name" = "{resource_name}"',
                environment_source,
            )
        self.assertIn(
            "items = [network, cluster, foundation, *root_protection_resources, conditions, _dxr]",
            environment_source,
        )
        self.assertLess(
            environment_source.index("network = {"),
            environment_source.index('if "cluster" in ocds:'),
        )
        self.assertIn('networkClass = "application"', environment_source)
        self.assertIn('management_namespace = "crossplane-system"', environment_source)
        self.assertNotIn("subnetIds", environment_source)
        self.assertNotIn("securityGroupIds", environment_source)

        cluster_source = compositions["cluster"]["spec"]["pipeline"][0]["input"][
            "spec"
        ]["source"]
        self.assertNotIn('reason = "ImplementationPending"', cluster_source)
        self.assertIn('type = "InfrastructureReady"', cluster_source)
        self.assertEqual(
            ["function-kcl", "function-auto-ready"],
            [
                step["functionRef"]["name"]
                for step in compositions["cluster"]["spec"]["pipeline"]
            ],
        )

        foundation_source = compositions["foundation"]["spec"]["pipeline"][0][
            "input"
        ]["spec"]["source"]
        self.assertNotIn('reason = "ImplementationPending"', foundation_source)
        self.assertIn('type = "FoundationReady"', foundation_source)
        self.assertIn('type = "NetworkUATApproved"', foundation_source)
        self.assertIn('type = "ArgoCDReady"', foundation_source)
        self.assertNotIn(
            "function-auto-ready",
            [
                step["functionRef"]["name"]
                for step in compositions["foundation"]["spec"]["pipeline"]
            ],
        )

    def test_kcl_sources_lint_locally(self) -> None:
        for directory in XRD_CASES:
            composition = common.load_yaml(EKS_ROOT / directory / "composition.yaml")
            source = composition["spec"]["pipeline"][0]["input"]["spec"]["source"]
            result = subprocess.run(
                ["kcl", "lint", "-", "--quiet", "--no_style"],
                input=source,
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)

    def test_environment_kcl_renders_three_children_with_or_without_observation(self) -> None:
        composition = common.load_yaml(EKS_ROOT / "environment" / "composition.yaml")
        source = composition["spec"]["pipeline"][0]["input"]["spec"]["source"]

        empty_render = self._run_environment_kcl(source, {})
        empty_items = empty_render["items"]
        children = {
            item["metadata"]["annotations"][
                "krm.kcl.dev/composition-resource-name"
            ]: item
            for item in empty_items
            if isinstance(item, dict)
            and item.get("kind")
            in {"XNetwork", "XEKSCluster", "XClusterFoundation"}
        }
        self.assertEqual({"network", "cluster", "foundation"}, set(children))
        self.assertEqual("eks-dev-spot-network", children["network"]["metadata"]["name"])
        self.assertEqual("application", children["network"]["spec"]["parameters"]["networkClass"])
        for child in children.values():
            self.assertEqual(
                "Manual", child["spec"]["crossplane"]["compositionUpdatePolicy"]
            )

        observed = {
            "cluster": {
                "Resource": {
                    "status": {
                        "clusterName": "test-only-observed-cluster",
                        "endpoint": "https://test-only.eks.invalid",
                        "actualVersions": {
                            "controlPlane": "1.35",
                            "coreDNSAddon": "v1.14.3-eksbuild.3",
                        },
                    }
                }
            },
            "foundation": {
                "Resource": {
                    "status": {
                        "actualVersions": {
                            "cilium": "1.20.1",
                            "karpenter": "1.14.1",
                            "argoCD": "v3.5.1",
                            "nodeImage": "al2023@v20260728",
                        }
                    }
                }
            },
        }
        observed_render = self._run_environment_kcl(source, observed)
        observed_children = [
            item
            for item in observed_render["items"]
            if isinstance(item, dict)
            and item.get("kind")
            in {"XNetwork", "XEKSCluster", "XClusterFoundation"}
        ]
        self.assertEqual(3, len(observed_children))
        desired_xr = next(
            item
            for item in observed_render["items"]
            if isinstance(item, dict) and item.get("kind") == "XEKSEnvironment"
        )
        self.assertEqual(
            "test-only-observed-cluster", desired_xr["status"]["clusterName"]
        )
        self.assertEqual(
            "1.20.1", desired_xr["status"]["actualVersions"]["cilium"]
        )

    def test_single_owner_inventory_includes_remote_and_cloud_derived_objects(self) -> None:
        contract = common.load_yaml(EKS_ROOT / "ownership-contract.yaml")
        resources = contract["resources"]
        resource_ids = [resource["id"] for resource in resources]
        self.assertEqual(len(resource_ids), len(set(resource_ids)))
        self.assertEqual(
            ["network", "cluster", "foundation"],
            contract["aggregate"]["stableCompositionResourceNames"],
        )
        by_id = {resource["id"]: resource for resource in resources}
        self.assertEqual("XNetwork", by_id["network/vpc"]["owner"])
        self.assertEqual("XEKSCluster", by_id["cluster/eks-control-plane"]["owner"])
        self.assertEqual(
            "XClusterFoundation", by_id["foundation/spot-node-pool"]["owner"]
        )
        self.assertEqual("Karpenter", by_id["karpenter/ec2-instances"]["owner"])
        self.assertEqual("CiliumOperator", by_id["cilium/ec2-eni-ipam"]["owner"])
        self.assertEqual(
            "ArgoCD", by_id["argocd/authorized-business-applications"]["owner"]
        )
        lifecycles = {resource["lifecycle"] for resource in resources}
        self.assertIn("remote-kubernetes-object", lifecycles)
        self.assertIn("cloud-derived", lifecycles)
        self.assertFalse(contract["rules"]["sharedLifecycleOwnershipAllowed"])

    def test_status_contract_separates_infrastructure_foundation_and_runtime_uat(self) -> None:
        contract = common.load_yaml(EKS_ROOT / "ownership-contract.yaml")
        conditions = contract["conditionSemantics"]
        self.assertIn("CoreDNS workload readiness", conditions["InfrastructureReady"]["excludes"])
        self.assertIn("runtime network UAT", conditions["FoundationReady"]["excludes"])
        self.assertEqual("Unknown", conditions["RuntimeNetworkUAT"]["staticValue"])
        for directory in XRD_CASES:
            xrd = common.load_yaml(EKS_ROOT / directory / "xrd.yaml")
            status = xrd["spec"]["versions"][0]["schema"]["openAPIV3Schema"][
                "properties"
            ]["status"]["properties"]
            self.assertIn("conditions", status)
        environment_status = common.load_yaml(EKS_ROOT / "environment" / "xrd.yaml")[
            "spec"
        ]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["status"][
            "properties"
        ]
        for output in ("clusterName", "endpoint", "references", "actualVersions"):
            self.assertIn(output, environment_status)

    def test_valid_fixture_and_catalogs_pass_reusable_validator(self) -> None:
        report = api_contract.validate_environment(
            self.instance,
            self.release,
            self.node_image,
            self.lock,
        )
        self.assertEqual("eks-dev-spot", report["environment"])
        self.assertEqual("spot-general", report["capacityClass"])
        self.assertFalse(report["awsMutation"])
        self.assertFalse(report["kubernetesMutation"])

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_ROOT / "validate_api_contract.py"),
                "--instance",
                str(FIXTURES / "environment-valid.yaml"),
                "--platform-release",
                str(FIXTURES / "platform-release-compatible.yaml"),
                "--node-image",
                str(FIXTURES / "node-image-compatible.yaml"),
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("spot-general", json.loads(result.stdout)["capacityClass"])

    def test_declared_negative_mutations_fail_closed(self) -> None:
        for case in self.negative_cases["mutations"]:
            with self.subTest(case=case["id"]):
                mutated = copy.deepcopy(self.instance)
                self._set_path(mutated, case["path"], case["value"])
                with self.assertRaisesRegex(
                    common.ToolError, self._literal_regex(case["expectedError"])
                ):
                    api_contract.validate_environment(
                        mutated,
                        self.release,
                        self.node_image,
                        self.lock,
                    )

    def test_incompatible_release_fixture_is_rejected(self) -> None:
        incompatible = common.load_yaml(FIXTURES / "platform-release-incompatible.yaml")
        with self.assertRaisesRegex(
            common.ToolError,
            "platform release is incompatible with kubernetesVersion",
        ):
            api_contract.validate_environment(
                self.instance,
                incompatible,
                self.node_image,
                self.lock,
            )

    def test_retirement_old_new_transition_matrix(self) -> None:
        for case in self.negative_cases["retirementTransitions"]:
            with self.subTest(old=case["old"], new=case["new"]):
                if case["allowed"]:
                    api_contract.validate_retirement_transition(case["old"], case["new"])
                else:
                    with self.assertRaises(common.ToolError):
                        api_contract.validate_retirement_transition(
                            case["old"], case["new"]
                        )

    def test_root_kustomization_excludes_instances_dependencies_and_catalogs(self) -> None:
        root = common.load_yaml(EKS_ROOT / "kustomization.yaml")
        self.assertEqual(["cluster", "foundation", "environment"], root["resources"])
        rendered = subprocess.run(
            ["kubectl", "kustomize", str(EKS_ROOT)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, rendered.returncode, rendered.stderr)
        self.assertEqual(3, rendered.stdout.count("kind: CompositeResourceDefinition"))
        self.assertEqual(3, rendered.stdout.count("kind: Composition"))
        self.assertEqual(5, rendered.stdout.count("\n---\n"))
        self.assertNotIn("kind: Provider", rendered.stdout)
        self.assertNotIn("kind: EnvironmentConfig", rendered.stdout)

    @staticmethod
    def _mapping_keys(value: object) -> set[str]:
        keys: set[str] = set()
        if isinstance(value, dict):
            keys.update(str(key) for key in value)
            for child in value.values():
                keys.update(P2APIContractTests._mapping_keys(child))
        elif isinstance(value, list):
            for child in value:
                keys.update(P2APIContractTests._mapping_keys(child))
        return keys

    @staticmethod
    def _set_path(document: dict[str, object], path: str, value: object) -> None:
        keys = path.split(".")
        current: dict[str, object] = document
        for key in keys[:-1]:
            child = current.get(key)
            if not isinstance(child, dict):
                child = {}
                current[key] = child
            current = child
        current[keys[-1]] = value

    @staticmethod
    def _literal_regex(value: str) -> str:
        import re

        return re.escape(value)

    def _run_environment_kcl(
        self, source: str, observed: dict[str, object]
    ) -> dict[str, object]:
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
            input=source,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        output = json.loads(result.stdout)
        self.assertIsInstance(output, dict)
        return output


if __name__ == "__main__":
    unittest.main()
