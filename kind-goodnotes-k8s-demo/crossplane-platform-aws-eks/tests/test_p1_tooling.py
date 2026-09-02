from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
EKS_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-eks"
SCRIPT_ROOT = REPO_ROOT / "scripts" / "eks_lifecycle"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402


class P1ToolingTests(unittest.TestCase):
    def run_script(self, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT_ROOT / script), *arguments],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_all_script_help_commands_succeed(self) -> None:
        for script in (
            "bootstrap_management_credentials.py",
            "preflight.py",
            "prepare_schemas.py",
            "render.py",
            "render_cluster.py",
            "render_foundation.py",
            "render_network.py",
            "render_recursive.py",
            "run_m1_validation.py",
            "run_u0_management_preflight.py",
            "validate_karpenter_chart.py",
            "validate_rendered_schemas.py",
            "validate_static.py",
            "validate_network_contract.py",
            "validate_spot_contract.py",
            "validate_u0_authorization.py",
            "plan_retirement.py",
        ):
            with self.subTest(script=script):
                result = self.run_script(script, "--help")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)

    def test_schema_cache_is_complete_and_verified_offline(self) -> None:
        checksum_file = EKS_ROOT / "tests" / "schemas" / "checksums.sha256"
        lines = [line for line in checksum_file.read_text().splitlines() if line]
        self.assertEqual(len(lines), 37)
        result = self.run_script("prepare_schemas.py", "--verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SCHEMA VERIFY PASS: 37 files", result.stdout)

    def test_version_lock_has_exact_package_and_chart_pins(self) -> None:
        lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        self.assertFalse(lock["policy"]["floatingVersionsAllowed"])
        self.assertEqual(lock["targets"]["workloadPlane"]["capacityType"], "spot")
        self.assertEqual(lock["targets"]["workloadPlane"]["approvedRegion"], "us-east-1")
        self.assertEqual(
            lock["targets"]["workloadPlane"]["approvedAvailabilityZones"],
            ["us-east-1a", "us-east-1b"],
        )
        self.assertEqual(lock["charts"]["cilium"]["version"], "1.20.1")
        self.assertEqual(lock["charts"]["karpenter"]["version"], "1.14.1")
        self.assertEqual(lock["charts"]["argoCD"]["chartVersion"], "10.4.0")
        self.assertEqual(lock["nodeImages"]["al2023"]["alias"], "al2023@v20260728")
        self.assertEqual(
            lock["nodeImages"]["al2023"]["regionalAMI"],
            {
                "region": "us-east-1",
                "imageId": "ami-00edcc837bc2137e0",
                "resolvedAt": "2026-08-29",
            },
        )
        for package in lock["packages"].values():
            self.assertRegex(package["version"], r"^v[0-9]+\.[0-9]+\.[0-9]+$")
            self.assertRegex(package["reference"], r"@sha256:[0-9a-f]{64}$")

    def test_new_provider_entry_is_independent_and_digest_pinned(self) -> None:
        rendered = subprocess.run(
            ["kubectl", "kustomize", str(EKS_ROOT / "dependencies")],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertEqual(rendered.stdout.count("kind: Provider"), 2)
        self.assertEqual(rendered.stdout.count("@sha256:"), 2)
        self.assertIn("provider-aws-sqs@sha256:", rendered.stdout)
        self.assertIn("provider-aws-cloudwatchevents@sha256:", rendered.stdout)
        self.assertNotIn("provider-family-aws", rendered.stdout)

    def test_locked_namespaced_schema_identity(self) -> None:
        expected = {
            "providers/aws-sqs/queues.yaml": ("sqs.aws.m.upbound.io", "Namespaced"),
            "providers/aws-cloudwatchevents/rules.yaml": (
                "cloudwatchevents.aws.m.upbound.io",
                "Namespaced",
            ),
            "providers/helm/releases.yaml": ("helm.m.crossplane.io", "Namespaced"),
            "providers/kubernetes/objects.yaml": (
                "kubernetes.m.crossplane.io",
                "Namespaced",
            ),
        }
        generated = EKS_ROOT / "tests" / "schemas" / "generated"
        for relative, (group, scope) in expected.items():
            with self.subTest(schema=relative):
                document = common.load_yaml(generated / relative)
                self.assertEqual(document["spec"]["group"], group)
                self.assertEqual(document["spec"]["scope"], scope)

    def test_fake_inputs_are_rejected_in_deployment_mode(self) -> None:
        fixture = EKS_ROOT / "tests" / "fixtures" / "p1-fake-inputs.yaml"
        result = self.run_script(
            "preflight.py",
            "--offline",
            "--deployment-input",
            str(fixture),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test placeholders", result.stderr)

    def test_catalog_contract_matches_lock_and_keeps_region_fail_closed(self) -> None:
        lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        releases = common.load_yaml(EKS_ROOT / "catalog" / "platform-releases.template.yaml")
        images = common.load_yaml(EKS_ROOT / "catalog" / "node-images.template.yaml")
        release_data = releases["spec"]["data"]
        image_data = images["spec"]["data"]
        self.assertEqual(release_data["kubernetes"], lock["targets"]["workloadPlane"]["eksKubernetes"])
        self.assertEqual(release_data["cilium"]["chart"], lock["charts"]["cilium"]["version"])
        self.assertEqual(
            release_data["karpenter"]["controllerChart"],
            lock["charts"]["karpenter"]["version"],
        )
        self.assertEqual(release_data["argoCD"]["chart"], lock["charts"]["argoCD"]["chartVersion"])
        self.assertEqual(image_data["images"]["amd64"]["alias"], "al2023@v20260728")
        self.assertTrue(common.find_placeholders(images))
        with self.assertRaisesRegex(common.ToolError, "test placeholders"):
            common.assert_deployment_safe(EKS_ROOT / "catalog" / "node-images.template.yaml")

    def test_helm_schema_exposes_exact_skip_crds_field(self) -> None:
        release_crd = common.load_yaml(
            EKS_ROOT
            / "tests"
            / "schemas"
            / "generated"
            / "providers"
            / "helm"
            / "releases.yaml"
        )
        version = next(item for item in release_crd["spec"]["versions"] if item["name"] == "v1beta1")
        fields = version["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"][
            "forProvider"
        ]["properties"]
        self.assertIn("skipCRDs", fields)
        self.assertNotIn("skipCrds", fields)

    def test_chart_lifecycle_records_unique_crd_owners_and_ec2_boundary(self) -> None:
        lifecycle = (EKS_ROOT / "CHART_LIFECYCLE.md").read_text()
        self.assertIn("`skipCRDs: true`", lifecycle)
        self.assertIn("operator.skipCRDCreation: false", lifecycle)
        self.assertIn("`crds.keep: false`", lifecycle)
        self.assertIn("need Spot EC2", lifecycle)

    def test_offline_preflight_does_not_need_aws(self) -> None:
        result = self.run_script("preflight.py", "--offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["mode"], "offline")
        self.assertFalse(report["awsMutation"])
        self.assertFalse(report["kubernetesMutation"])

    def test_missing_dependency_is_a_hard_failure(self) -> None:
        with mock.patch.object(common.shutil, "which", return_value=None):
            with self.assertRaisesRegex(common.ToolError, "required tool is missing"):
                common.require_tool("definitely-not-installed")

    def test_redaction_covers_cloud_and_github_tokens(self) -> None:
        text = (
            "AKIAABCDEFGHIJKLMNOP "
            "ghp_abcdefghijklmnopqrstuvwxyz123456 "
            "Authorization: Bearer visible-token"
        )
        redacted = common.redact(text)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", redacted)
        self.assertNotIn("visible-token", redacted)
        self.assertIn("<redacted>", redacted)

    def test_default_output_directory_is_temporary(self) -> None:
        with common.output_directory(None, "eks-test-") as directory:
            marker = directory / "marker"
            marker.write_text("test")
            self.assertTrue(marker.is_file())
        self.assertFalse(directory.exists())

    def test_scripts_do_not_contain_mutating_command_literals(self) -> None:
        forbidden = (
            "kubectl apply",
            "kubectl delete",
            "helm install",
            "helm upgrade",
            "crossplane xpkg install",
            "aws eks create",
            "aws ec2 create",
        )
        for script in SCRIPT_ROOT.glob("*.py"):
            text = script.read_text().lower()
            for command in forbidden:
                with self.subTest(script=script.name, command=command):
                    self.assertNotIn(command, text)

    def test_render_fails_closed_before_scenarios_exist(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p1-empty-scenarios-") as temporary:
            scenario_file = Path(temporary) / "empty.yaml"
            scenario_file.write_text("schemaVersion: 1\nscenarios: []\n")
            result = self.run_script(
                "render.py",
                "--all-scenarios",
                "--check",
                "--scenario-file",
                str(scenario_file),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no render scenarios are declared", result.stderr)

    def test_retirement_planner_never_executes(self) -> None:
        result = self.run_script(
            "plan_retirement.py",
            "--current-stage",
            "Active",
            "--target-stage",
            "DrainWorkloads",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["execute"])
        self.assertEqual(
            {"from": "Active", "to": "DrainWorkloads"}, report["transition"]
        )
        self.assertFalse(report["readyToAdvance"])
        backward = self.run_script(
            "plan_retirement.py",
            "--current-stage",
            "DrainCapacity",
            "--target-stage",
            "Active",
        )
        self.assertNotEqual(backward.returncode, 0)


if __name__ == "__main__":
    unittest.main()
