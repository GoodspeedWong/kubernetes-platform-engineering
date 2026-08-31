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
P2_FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p2"
P5_FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p5"
P8_FIXTURES = EKS_ROOT / "tests" / "fixtures" / "p8"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import render_foundation  # noqa: E402
import validate_api_contract  # noqa: E402
import validate_argocd_contract  # noqa: E402


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"


class P8ArgoCDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        cls.empty_instance = common.load_yaml(P5_FIXTURES / "foundation-valid.yaml")
        cls.git_instance = common.load_yaml(P8_FIXTURES / "foundation-gitops-valid.yaml")
        cls.network_observed = common.load_yaml(
            P8_FIXTURES / "observed-network-approved.yaml"
        )
        cls.argocd_observed = common.load_yaml(
            P8_FIXTURES / "observed-argocd-prerequisites-ready.yaml"
        )
        cls.project_observed = common.load_yaml(
            P8_FIXTURES / "observed-project-ready.yaml"
        )
        cls.bootstrap_observed = common.load_yaml(
            P8_FIXTURES / "observed-bootstrap-ready.yaml"
        )
        cls.composition = common.load_yaml(EKS_ROOT / "foundation" / "composition.yaml")
        cls.source = cls.composition["spec"]["pipeline"][0]["input"]["spec"]["source"]
        cls.initial = render_foundation.render(copy.deepcopy(cls.empty_instance))
        cls.network_stage = render_foundation.render(
            copy.deepcopy(cls.empty_instance), copy.deepcopy(cls.network_observed)
        )
        prereqs = cls._merge_observed(cls.network_observed, cls.argocd_observed)
        cls.project_stage = render_foundation.render(
            copy.deepcopy(cls.empty_instance), copy.deepcopy(prereqs)
        )
        app_observed = cls._merge_observed(prereqs, cls.project_observed)
        cls.application_stage = render_foundation.render(
            copy.deepcopy(cls.git_instance), copy.deepcopy(app_observed)
        )

    def test_network_evidence_is_observe_only_and_blocks_argocd_by_default(self) -> None:
        initial = self._resources_by_name(self.initial)
        approval = initial["network-uat-approval"]
        self.assertEqual(["Observe"], approval["spec"]["managementPolicies"])
        self.assertEqual("ConfigMap", approval["spec"]["forProvider"]["manifest"]["kind"])
        self.assertEqual(
            "kube-system",
            approval["spec"]["forProvider"]["manifest"]["metadata"]["namespace"],
        )
        for name in (
            "argocd-release",
            "gitops-apps-namespace",
            "argocd-apps-role",
            "argocd-apps-rolebinding",
            "argocd-project",
            "gitops-bootstrap",
        ):
            self.assertNotIn(name, initial)

    def test_bound_network_approval_opens_argocd_without_faking_runtime_condition(self) -> None:
        resources = self._resources_by_name(self.network_stage)
        self.assertTrue(
            {
                "argocd-release",
                "gitops-apps-namespace",
                "argocd-apps-role",
                "argocd-apps-rolebinding",
            }.issubset(resources)
        )
        self.assertNotIn("argocd-project", resources)
        output = self._run_kcl(self.empty_instance, self.network_observed)
        self.assertEqual(
            ("True", "Approved"),
            self._condition_pair(output, "NetworkUATApproved"),
        )
        self.assertEqual(
            ("Unknown", "RequiresAWSUAT"),
            self._condition_pair(output, "RuntimeNetworkUAT"),
        )

    def test_wrong_environment_generation_namespace_or_digest_rejects_approval(self) -> None:
        mutations = (
            (("metadata", "labels", "platform.aws.goodnotes.io/environment"), "other"),
            (("data", "foundation-generation"), "7"),
            (("data", "kube-system-uid"), "wrong"),
            (("data", "evidence-sha256"), "z" * 64),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                observed = copy.deepcopy(self.network_observed)
                approval = observed["network-uat-approval"]["Resource"]["status"][
                    "atProvider"
                ]["manifest"]
                self._set_path(approval, path, value)
                output = self._run_kcl(self.empty_instance, observed)
                self.assertEqual(
                    ("False", "EvidenceRejected"),
                    self._condition_pair(output, "NetworkUATApproved"),
                )
                self.assertNotIn(
                    "argocd-release",
                    self._resources_by_name({"items": output["items"]}),
                )

    def test_argocd_release_uses_reviewed_spot_only_namespace_scoped_values(self) -> None:
        resources = self._resources_by_name(self.network_stage)
        release = resources["argocd-release"]
        provider = release["spec"]["forProvider"]
        self.assertEqual(
            {
                "name": "argo-cd",
                "repository": "oci://ghcr.io/argoproj/argo-helm",
                "digest": self.lock["charts"]["argoCD"]["manifestDigest"],
                "version": "10.4.0",
            },
            provider["chart"],
        )
        self.assertEqual("argocd", provider["namespace"])
        self.assertEqual(
            common.load_yaml(EKS_ROOT / "values" / "argocd.yaml"),
            provider["values"],
        )
        values = provider["values"]
        self.assertFalse(values["createClusterRoles"])
        self.assertEqual(0, values["applicationSet"]["replicas"])
        self.assertEqual("spot-general", values["global"]["nodeSelector"]["karpenter.sh/nodepool"])
        self.assertFalse(values["configs"]["cm"]["admin.enabled"])
        self.assertEqual("ClusterIP", values["server"]["service"]["type"])

    def test_business_rbac_and_project_are_namespaced_and_fail_closed(self) -> None:
        summary = validate_argocd_contract.validate_argocd_contract(
            self.project_stage, expect_bootstrap=False
        )
        self.assertEqual(0, summary["clusterScopedBusinessPermissions"])
        self.assertEqual(0, summary["sourceRepositories"])
        resources = self._resources_by_name(self.project_stage)
        project = resources["argocd-project"]["spec"]["forProvider"]["manifest"]
        self.assertEqual([], project["spec"]["sourceRepos"])
        self.assertEqual(
            [{"group": "*", "kind": "*"}],
            project["spec"]["clusterResourceBlacklist"],
        )
        role = resources["argocd-apps-role"]["spec"]["forProvider"]["manifest"]
        serialized = json.dumps(role, sort_keys=True)
        for forbidden in ("secrets", "roles", "rolebindings", "nodepools", "ec2nodeclasses"):
            self.assertNotIn(forbidden, serialized.lower())

    def test_controlled_git_source_creates_one_crossplane_owned_application(self) -> None:
        summary = validate_argocd_contract.validate_argocd_contract(
            self.application_stage, expect_bootstrap=True
        )
        self.assertTrue(summary["applicationConfigured"])
        resources = self._resources_by_name(self.application_stage)
        app = resources["gitops-bootstrap"]
        remote = app["spec"]["forProvider"]["manifest"]
        source = remote["spec"]["source"]
        expected = self.git_instance["spec"]["parameters"]["gitOps"]
        self.assertEqual(expected["repositoryURL"], source["repoURL"])
        self.assertEqual(expected["revision"], source["targetRevision"])
        self.assertEqual(expected["path"], source["path"])
        self.assertEqual(
            expected["credentialsSecretRef"]["name"],
            remote["metadata"]["annotations"][
                "platform.aws.goodnotes.io/repository-credentials-secret"
            ],
        )
        self.assertEqual(
            ["resources-finalizer.argocd.argoproj.io/foreground"],
            remote["metadata"]["finalizers"],
        )

    def test_git_source_contract_accepts_static_fixture_and_rejects_floating_revision(self) -> None:
        environment = common.load_yaml(P2_FIXTURES / "environment-valid.yaml")
        environment["spec"]["parameters"]["gitOps"] = copy.deepcopy(
            self.git_instance["spec"]["parameters"]["gitOps"]
        )
        release = common.load_yaml(P2_FIXTURES / "platform-release-compatible.yaml")
        image = common.load_yaml(P2_FIXTURES / "node-image-compatible.yaml")
        report = validate_api_contract.validate_environment(
            environment, release, image, common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        )
        self.assertTrue(report["gitOpsConfigured"])
        environment["spec"]["parameters"]["gitOps"]["revision"] = "main"
        with self.assertRaises(common.ToolError):
            validate_api_contract.validate_environment(
                environment, release, image, common.load_yaml(EKS_ROOT / "versions.lock.yaml")
            )

    def test_transient_observation_gap_does_not_retract_declared_argocd(self) -> None:
        observed = {
            name: {"Resource": copy.deepcopy(resource)}
            for name, resource in self._resources_by_name(self.network_stage).items()
            if name
            in {
                "argocd-release",
                "gitops-apps-namespace",
                "argocd-apps-role",
                "argocd-apps-rolebinding",
            }
        }
        rendered = render_foundation.render(copy.deepcopy(self.empty_instance), observed)
        resources = self._resources_by_name(rendered)
        self.assertIn("argocd-release", resources)
        self.assertIn("gitops-apps-namespace", resources)

    def test_drain_workloads_without_p9_evidence_retains_application_and_argocd(self) -> None:
        retiring = copy.deepcopy(self.git_instance)
        retiring["spec"]["parameters"]["lifecycle"]["retirementStage"] = "DrainWorkloads"
        observed = self._merge_observed(
            self.network_observed, self.argocd_observed, self.project_observed
        )
        rendered = render_foundation.render(retiring, observed)
        resources = self._resources_by_name(rendered)
        self.assertIn("gitops-bootstrap", resources)
        self.assertIn("argocd-release", resources)
        self.assertIn("argocd-project", resources)

    def test_full_ready_state_reports_versions_without_claiming_runtime_execution(self) -> None:
        observed = self._merge_observed(
            self.network_observed,
            self.argocd_observed,
            self.project_observed,
            self.bootstrap_observed,
        )
        output = self._run_kcl(self.git_instance, observed)
        self.assertEqual(("True", "Available"), self._condition_pair(output, "ArgoCDReady"))
        self.assertEqual(
            ("True", "Available"), self._condition_pair(output, "GitOpsBootstrapReady")
        )
        self.assertEqual(("True", "Available"), self._condition_pair(output, "FoundationReady"))
        desired = next(
            item for item in output["items"] if item.get("kind") == "XClusterFoundation"
        )
        self.assertEqual("v3.5.1", desired["status"]["actualVersions"]["argoCD"])
        self.assertEqual(
            ("Unknown", "RequiresAWSUAT"),
            self._condition_pair(output, "RuntimeNetworkUAT"),
        )

    def test_duplicate_remote_owner_identity_is_rejected(self) -> None:
        duplicate = copy.deepcopy(self.application_stage)
        resources = self._resources_by_name(duplicate)
        binding_manifest = resources["argocd-apps-rolebinding"]["spec"]["forProvider"][
            "manifest"
        ]
        binding_manifest["apiVersion"] = "rbac.authorization.k8s.io/v1"
        binding_manifest["kind"] = "Role"
        binding_manifest["metadata"]["name"] = "argocd-business-manager"
        with self.assertRaises(common.ToolError):
            validate_argocd_contract.validate_argocd_contract(
                duplicate, expect_bootstrap=True
            )

    def test_gitops_uat_and_exit_contract_are_non_persistent_and_explicit(self) -> None:
        text = (EKS_ROOT / "GITOPS_UAT.md").read_text()
        for required in (
            "NOT_RUN",
            "Deployment",
            "ConfigMap",
            "Service",
            "foreground",
            "ApplicationSet",
            "PersistentVolumeClaim",
            "LoadBalancer",
        ):
            self.assertIn(required, text)

    def _run_kcl(
        self, instance: dict[str, Any], observed: dict[str, Any]
    ) -> dict[str, Any]:
        desired = {
            "apiVersion": instance["apiVersion"],
            "kind": instance["kind"],
            "metadata": {"name": instance["metadata"]["name"]},
            "status": {},
        }
        params = {"oxr": instance, "dxr": desired, "ocds": observed}
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
    def _condition_pair(output: dict[str, Any], name: str) -> tuple[str, str]:
        conditions = next(item for item in output["items"] if item.get("kind") == "Conditions")
        condition = next(
            item["condition"]
            for item in conditions["conditions"]
            if item["condition"]["type"] == name
        )
        return condition["status"], condition["reason"]

    @staticmethod
    def _resources_by_name(rendered: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            item["metadata"]["annotations"][RESOURCE_NAME]: item
            for item in rendered["items"]
            if RESOURCE_NAME in item.get("metadata", {}).get("annotations", {})
        }

    @staticmethod
    def _merge_observed(*documents: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for document in documents:
            merged.update(copy.deepcopy(document))
        return merged

    @staticmethod
    def _set_path(document: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
        current = document
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = value


if __name__ == "__main__":
    unittest.main()
