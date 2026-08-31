from __future__ import annotations

import ast
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
EKS_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-eks"
NETWORK_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-network"
SCRIPT_ROOT = REPO_ROOT / "scripts" / "eks_lifecycle"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import render as high_fidelity_render  # noqa: E402
import render_foundation  # noqa: E402
import validate_argocd_contract  # noqa: E402
import validate_cilium_contract  # noqa: E402
import validate_rendered_schemas  # noqa: E402
import validate_spot_contract  # noqa: E402


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"


class P10ValidationTests(unittest.TestCase):
    def test_all_kustomize_entrypoints_build_and_root_has_no_instances(self) -> None:
        entries = (
            EKS_ROOT,
            EKS_ROOT / "environment",
            EKS_ROOT / "cluster",
            EKS_ROOT / "foundation",
            EKS_ROOT / "dependencies",
            EKS_ROOT / "catalog",
            EKS_ROOT / "examples",
            EKS_ROOT / "instances",
            EKS_ROOT / "management-auth",
            EKS_ROOT / "lifecycle-policy",
            NETWORK_ROOT,
        )
        rendered: dict[Path, str] = {}
        for entry in entries:
            with self.subTest(entry=entry.name):
                result = subprocess.run(
                    ["kubectl", "kustomize", str(entry)],
                    cwd=REPO_ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                rendered[entry] = result.stdout
        root = rendered[EKS_ROOT]
        root_kinds = [
            line
            for line in subprocess.run(
                ["yq", "eval-all", "-r", ".kind", "-"],
                input=root,
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.splitlines()
            if line and line != "null"
        ]
        self.assertEqual(3, root_kinds.count("CompositeResourceDefinition"))
        self.assertEqual(3, root_kinds.count("Composition"))
        self.assertNotIn("XEKSEnvironment", root_kinds)
        self.assertNotIn("Provider", root_kinds)
        self.assertEqual("", rendered[EKS_ROOT / "instances"])
        self.assertEqual(2, rendered[EKS_ROOT / "catalog"].count("kind: EnvironmentConfig"))
        self.assertIn(
            'platform.aws.goodnotes.io/do-not-apply: "true"',
            rendered[EKS_ROOT / "examples"],
        )

    def test_required_openapi_bundle_contains_every_locked_custom_kind(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p10-openapi-") as temporary:
            output = high_fidelity_render.write_required_schema_bundle(Path(temporary))
            document = json.loads(output.read_text())
        schemas = document["components"]["schemas"]
        self.assertGreaterEqual(len(schemas), 41)
        gvks = {
            (
                marker["group"],
                marker["version"],
                marker["kind"],
            )
            for schema in schemas.values()
            for marker in schema.get("x-kubernetes-group-version-kind", [])
        }
        for identity in (
            ("platform.aws.goodnotes.io", "v1alpha1", "XEKSEnvironment"),
            ("platform.aws.goodnotes.io", "v1alpha1", "XNetwork"),
            ("karpenter.sh", "v1", "NodePool"),
            ("argoproj.io", "v1alpha1", "Application"),
        ):
            self.assertIn(identity, gvks)

    def test_recursive_and_embedded_validation_contracts_are_fail_closed(self) -> None:
        render_source = (SCRIPT_ROOT / "render.py").read_text()
        recursive_source = (SCRIPT_ROOT / "render_recursive.py").read_text()
        schema_source = (SCRIPT_ROOT / "validate_rendered_schemas.py").read_text()
        lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        management = lock["targets"]["managementPlane"]
        engine = high_fidelity_render.render_engine(lock)
        self.assertEqual("source-cli", engine["mode"])
        self.assertEqual(management["crossplaneCore"], engine["version"])
        self.assertEqual("cmd/crank", engine["command"])
        self.assertNotEqual(management["crossplaneCLI"], engine["version"])
        validation = validate_rendered_schemas.schema_validation_contract(lock)
        self.assertEqual("source-cache", validation["mode"])
        self.assertEqual(21, validation["coreCRDCount"])
        self.assertEqual(64, len(validation["coreCRDsSha256"]))
        for package_name in ("functionKCL", "functionAutoReady"):
            package = lock["packages"][package_name]
            self.assertTrue(package["repository"].startswith("https://github.com/"))
            self.assertRegex(package["sourceCommit"], r"^[0-9a-f]{40}$")
        self.assertIn("--include-full-xr", render_source)
        self.assertIn("--required-schemas=", render_source)
        self.assertIn("--observed-resources", render_source)
        self.assertIn("--required-resources", render_source)
        self.assertIn('"render"', render_source)
        self.assertNotIn('"composition",\n            "render"', render_source)
        self.assertIn("validate_rendered_schemas.strict_validate", recursive_source)
        self.assertIn('"--error-on-missing-schemas"', schema_source)
        self.assertNotIn('f"--crossplane-version=', render_source)
        with self.assertRaisesRegex(common.ToolError, "--renderer-binary is required"):
            high_fidelity_render.validate_renderer_binary(None, lock)
        targets = high_fidelity_render.validate_function_targets(
            "127.0.0.1:9443", "127.0.0.1:9444"
        )
        self.assertNotEqual(
            targets["function-kcl"], targets["function-auto-ready"]
        )
        with self.assertRaisesRegex(common.ToolError, "must be distinct"):
            high_fidelity_render.validate_function_targets(
                "127.0.0.1:9443", "127.0.0.1:9443"
            )
        with tempfile.TemporaryDirectory(prefix="p10-functions-") as temporary:
            generated = high_fidelity_render.write_development_functions(
                EKS_ROOT / "tests" / "fixtures" / "p2" / "functions.yaml",
                Path(temporary) / "functions.yaml",
                targets,
            )
            result = subprocess.run(
                ["yq", "eval-all", "-o=json", "-I=0", ".", str(generated)],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
        functions = [
            json.loads(line) for line in result.stdout.splitlines() if line.strip()
        ]
        self.assertEqual(
            {"function-kcl", "function-auto-ready"},
            {item["metadata"]["name"] for item in functions},
        )
        for item in functions:
            annotations = item["metadata"]["annotations"]
            self.assertEqual("Development", annotations["render.crossplane.io/runtime"])
            self.assertEqual(
                targets[item["metadata"]["name"]],
                annotations["render.crossplane.io/runtime-development-target"],
            )
            self.assertNotIn(
                "render.crossplane.io/runtime-docker-pull-policy", annotations
            )
        wrappers, embedded = validate_rendered_schemas.foundation_inputs()
        self.assertGreaterEqual(len(wrappers), 10)
        self.assertGreaterEqual(len(embedded), 7)
        builtins, custom = validate_rendered_schemas.split_builtin_manifests(embedded)
        self.assertEqual(5, len(builtins))
        self.assertEqual(4, len(custom))
        invalid_builtin = copy.deepcopy(builtins[0])
        invalid_builtin["unknownField"] = True
        with self.assertRaisesRegex(common.ToolError, "unknown keys"):
            validate_rendered_schemas.validate_builtin_manifest(invalid_builtin)
        embedded_kinds = {item["kind"] for item in embedded}
        self.assertTrue(
            {"NodePool", "EC2NodeClass", "AppProject", "Application"}.issubset(
                embedded_kinds
            )
        )
        with tempfile.TemporaryDirectory(prefix="p10-strict-") as temporary:
            path = Path(temporary) / "resource.yaml"
            path.write_text("apiVersion: missing.example/v1\nkind: Missing\nmetadata:\n  name: bad\n")
            failure = subprocess.CompletedProcess(
                args=["crossplane"],
                returncode=1,
                stdout="",
                stderr="schema missing",
            )
            with mock.patch.object(
                validate_rendered_schemas, "run_checked", side_effect=common.ToolError("schema missing")
            ):
                with self.assertRaisesRegex(common.ToolError, "schema missing"):
                    validate_rendered_schemas.strict_validate(path)
            self.assertEqual(1, failure.returncode)

    def test_chart_auditors_cover_actual_workloads_crds_and_rbac(self) -> None:
        contracts = {
            "validate_karpenter_chart.py": (
                "Deployment",
                "PodDisruptionBudget",
                "ServiceAccount",
                "CustomResourceDefinition",
                "controllerImage",
            ),
            "validate_cilium_chart.py": (
                "DaemonSet",
                "Deployment",
                "ServiceAccount",
                "cilium-config",
                "CustomResourceDefinition",
            ),
            "validate_argocd_chart.py": (
                "StatefulSet",
                "Deployment",
                "ClusterRole",
                "PodDisruptionBudget",
                "CustomResourceDefinition",
            ),
        }
        for script, tokens in contracts.items():
            with self.subTest(script=script):
                source = (SCRIPT_ROOT / script).read_text()
                for token in tokens:
                    self.assertIn(token, source)
                result = subprocess.run(
                    [sys.executable, str(SCRIPT_ROOT / script), "--help"],
                    cwd=REPO_ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)

    def test_negative_injection_breaks_real_validators(self) -> None:
        foundation = common.load_yaml(
            EKS_ROOT / "tests" / "fixtures" / "p5" / "foundation-valid.yaml"
        )
        observed = common.load_yaml(
            EKS_ROOT
            / "tests"
            / "fixtures"
            / "p6"
            / "observed-karpenter-crds-ready.yaml"
        )
        rendered = render_foundation.render(foundation, observed)
        spot_bypass = copy.deepcopy(rendered)
        pool = self._resource(spot_bypass, "spot-general-node-pool")
        manifest = pool["spec"]["forProvider"]["manifest"]
        capacity = next(
            item
            for item in manifest["spec"]["template"]["spec"]["requirements"]
            if item["key"] == "karpenter.sh/capacity-type"
        )
        capacity["values"] = ["on-demand"]
        with self.assertRaisesRegex(common.ToolError, r"exactly \[spot\]"):
            validate_spot_contract.validate_spot_contract(spot_bypass)

        cluster = common.load_yaml(
            EKS_ROOT / "tests" / "fixtures" / "p4" / "cluster-valid.yaml"
        )
        cluster_observed = common.load_yaml(
            EKS_ROOT / "tests" / "fixtures" / "p4" / "observed-oidc-ready.yaml"
        )
        import render_cluster

        cluster_render = render_cluster.render(cluster, cluster_observed)
        cilium_bypass = copy.deepcopy(rendered)
        cilium = self._resource(cilium_bypass, "cilium-release")
        cilium["spec"]["forProvider"]["values"]["kubeProxyReplacement"] = False
        with self.assertRaises(common.ToolError):
            validate_cilium_contract.validate_cilium_contract(
                cilium_bypass, cluster_render
            )

        p8 = EKS_ROOT / "tests" / "fixtures" / "p8"
        network = common.load_yaml(p8 / "observed-network-approved.yaml")
        prereqs = common.load_yaml(p8 / "observed-argocd-prerequisites-ready.yaml")
        network.update(prereqs)
        argocd = render_foundation.render(foundation, network)
        role = self._resource(argocd, "argocd-apps-role")
        role["spec"]["forProvider"]["manifest"]["rules"][0]["verbs"] = ["*"]
        with self.assertRaisesRegex(common.ToolError, "wildcard"):
            validate_argocd_contract.validate_argocd_contract(argocd)

    def test_matrix_references_real_tests_and_covers_s01_through_s21(self) -> None:
        matrix = common.load_yaml(EKS_ROOT / "static-test-matrix.yaml")
        scenarios = matrix.get("scenarios", [])
        expected_ids = {f"S{number:02d}" for number in range(1, 22)}
        actual_ids = {item.get("id") for item in scenarios}
        self.assertEqual(expected_ids, actual_ids)
        self.assertEqual(21, len(scenarios))
        for scenario in scenarios:
            self.assertTrue(str(scenario.get("assertion", "")).strip())
            tests = scenario.get("tests")
            self.assertIsInstance(tests, list)
            self.assertGreater(len(tests), 0)
            for reference in tests:
                with self.subTest(scenario=scenario["id"], reference=reference):
                    file_name, target = reference.split("::", 1)
                    class_name, method_name = target.split(".", 1)
                    tree = ast.parse((EKS_ROOT / "tests" / file_name).read_text())
                    classes = {
                        node.name: {
                            child.name
                            for child in node.body
                            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                        }
                        for node in tree.body
                        if isinstance(node, ast.ClassDef)
                    }
                    self.assertIn(class_name, classes)
                    self.assertIn(method_name, classes[class_name])

    def test_upgrade_and_last_node_contracts_have_explicit_stop_points(self) -> None:
        upgrade = (EKS_ROOT / "UPGRADE.md").read_text()
        retirement = (EKS_ROOT / "RETIREMENT.md").read_text()
        for required in (
            "Spot",
            "NodeClaim",
            "Fargate",
            "停止",
            "NOT_RUN",
        ):
            self.assertIn(required.lower(), upgrade.lower())
        for required in (
            "PDB",
            "末节点",
            "finalizer",
            "ENI",
            "Karpenter",
        ):
            self.assertIn(required.lower(), retirement.lower())
        inventory = common.load_yaml(EKS_ROOT / "lifecycle-inventory.yaml")
        stages = inventory["spec"]["stages"]
        self.assertIn(
            "foundation/spot-general-node-pool", stages["DrainCapacity"]["remove"]
        )
        self.assertIn(
            "foundation/karpenter-controller-release",
            stages["DrainCapacity"]["retain"],
        )

    @staticmethod
    def _resource(document: dict, name: str) -> dict:
        matches = [
            item
            for item in document["items"]
            if item.get("metadata", {}).get("annotations", {}).get(RESOURCE_NAME)
            == name
        ]
        if len(matches) != 1:
            raise AssertionError(f"expected one composition resource {name}")
        return matches[0]


if __name__ == "__main__":
    unittest.main()
