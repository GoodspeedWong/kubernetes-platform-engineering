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
SCHEMAS = EKS_ROOT / "tests" / "schemas" / "generated" / "providers"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import preflight  # noqa: E402
import render_cluster  # noqa: E402
import render_foundation  # noqa: E402


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"


class P5RemoteAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.foundation_instance = common.load_yaml(
            P5_FIXTURES / "foundation-valid.yaml"
        )
        cls.cluster_instance = common.load_yaml(P4_FIXTURES / "cluster-valid.yaml")
        cls.cluster_observed = common.load_yaml(
            P4_FIXTURES / "observed-oidc-ready.yaml"
        )
        cls.ready_observed = common.load_yaml(
            P5_FIXTURES / "observed-auth-ready.yaml"
        )
        cls.denied_observed = common.load_yaml(
            P5_FIXTURES / "observed-auth-denied.yaml"
        )
        cls.expired_observed = common.load_yaml(
            P5_FIXTURES / "observed-auth-expired.yaml"
        )
        cls.missing_source_observed = common.load_yaml(
            P5_FIXTURES / "observed-auth-source-missing.yaml"
        )
        cls.foundation_composition = common.load_yaml(
            EKS_ROOT / "foundation" / "composition.yaml"
        )
        cls.cluster_composition = common.load_yaml(
            EKS_ROOT / "cluster" / "composition.yaml"
        )
        cls.foundation_source = cls.foundation_composition["spec"]["pipeline"][0][
            "input"
        ]["spec"]["source"]
        cls.cluster_source = cls.cluster_composition["spec"]["pipeline"][0][
            "input"
        ]["spec"]["source"]
        cls.foundation_initial = render_foundation.render(
            copy.deepcopy(cls.foundation_instance)
        )
        cls.foundation_ready = render_foundation.render(
            copy.deepcopy(cls.foundation_instance), copy.deepcopy(cls.ready_observed)
        )
        cls.foundation_denied = render_foundation.render(
            copy.deepcopy(cls.foundation_instance), copy.deepcopy(cls.denied_observed)
        )
        cls.foundation_resources = cls._resources_by_name(cls.foundation_initial)
        cls.cluster_staged = render_cluster.render(
            copy.deepcopy(cls.cluster_instance), copy.deepcopy(cls.cluster_observed)
        )
        cls.cluster_resources = cls._resources_by_name(cls.cluster_staged)

    def test_foundation_kcl_lints_and_keeps_auth_resources_during_p6_staging(self) -> None:
        lint = subprocess.run(
            ["kcl", "lint", "-", "--quiet", "--no_style"],
            input=self.foundation_source,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, lint.returncode, lint.stderr)
        expected = {
            "kubernetes-provider-config",
            "helm-provider-config",
            "karpenter-crds-release",
            "remote-auth-probe",
            "network-uat-approval",
            "foundation-uses-cluster",
        }
        for rendered in (
            self.foundation_initial,
            self.foundation_ready,
            self.foundation_denied,
        ):
            resources = self._resources_by_name(rendered)
            self.assertEqual(expected, set(resources))
            self.assertEqual(6, len(rendered["items"]))

    def test_provider_configs_use_cluster_owned_secret_and_injected_aws_identity(
        self,
    ) -> None:
        expected_secret = {
            "namespace": "crossplane-system",
            "name": "eks-dev-spot-eks-access",
            "key": "kubeconfig",
        }
        expected_identity = {
            "source": "InjectedIdentity",
            "type": "AWSWebIdentityCredentials",
        }
        expectations = {
            "kubernetes-provider-config": (
                "kubernetes.m.crossplane.io/v1alpha1",
                "eks-dev-spot-kubernetes",
            ),
            "helm-provider-config": (
                "helm.m.crossplane.io/v1beta1",
                "eks-dev-spot-helm",
            ),
        }
        for resource_name, (api_version, actual_name) in expectations.items():
            with self.subTest(resource=resource_name):
                resource = self.foundation_resources[resource_name]
                self.assertEqual(api_version, resource["apiVersion"])
                self.assertEqual("ClusterProviderConfig", resource["kind"])
                self.assertEqual(actual_name, resource["metadata"]["name"])
                self.assertEqual(
                    {"source": "Secret", "secretRef": expected_secret},
                    resource["spec"]["credentials"],
                )
                self.assertEqual(expected_identity, resource["spec"]["identity"])

    def test_locked_provider_schemas_support_aws_web_identity(self) -> None:
        schemas = (
            (
                SCHEMAS / "kubernetes" / "clusterproviderconfigs.yaml",
                "v1alpha1",
            ),
            (SCHEMAS / "helm" / "clusterproviderconfigs.yaml", "v1beta1"),
        )
        for path, version_name in schemas:
            with self.subTest(schema=path.parent.name):
                crd = common.load_yaml(path)
                version = next(
                    item
                    for item in crd["spec"]["versions"]
                    if item["name"] == version_name
                )
                identity = version["schema"]["openAPIV3Schema"]["properties"][
                    "spec"
                ]["properties"]["identity"]
                self.assertIn(
                    "AWSWebIdentityCredentials",
                    identity["properties"]["type"]["enum"],
                )

    def test_cluster_exports_only_endpoint_ca_and_cluster_name(self) -> None:
        secret = self.cluster_resources["remote-kubeconfig-secret"]
        self.assertEqual(("v1", "Secret"), (secret["apiVersion"], secret["kind"]))
        self.assertEqual("crossplane-system", secret["metadata"]["namespace"])
        self.assertEqual("eks-dev-spot-eks-access", secret["metadata"]["name"])
        kubeconfig = json.loads(secret["stringData"]["kubeconfig"])
        self.assertEqual("eks-dev-spot-cluster", kubeconfig["current-context"])
        self.assertEqual(
            "https://test-only.eks.invalid",
            kubeconfig["clusters"][0]["cluster"]["server"],
        )
        self.assertEqual(
            "VEVTVC1PTkxZLUNB",
            kubeconfig["clusters"][0]["cluster"]["certificate-authority-data"],
        )
        self.assertEqual({}, kubeconfig["users"][0]["user"])
        karpenter_values = json.loads(secret["stringData"]["karpenter-values"])
        self.assertEqual(
            "arn:aws:iam::000000000000:role/eks-dev-spot-karpenter",
            karpenter_values["serviceAccount"]["annotations"][
                "eks.amazonaws.com/role-arn"
            ],
        )
        self.assertEqual(
            {
                "clusterCABundle": "VEVTVC1PTkxZLUNB",
                "clusterEndpoint": "https://test-only.eks.invalid",
                "clusterName": "eks-dev-spot-cluster",
                "eksControlPlane": True,
                "interruptionQueue": "eks-dev-spot-karpenter-events",
            },
            karpenter_values["settings"],
        )
        serialized = json.dumps(kubeconfig, sort_keys=True).lower()
        for forbidden in (
            '"token"',
            '"exec"',
            '"password"',
            '"client-key-data"',
            '"client-certificate-data"',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_cluster_does_not_create_connection_secret_before_api_is_ready(
        self,
    ) -> None:
        initial = render_cluster.render(copy.deepcopy(self.cluster_instance))
        resources = self._resources_by_name(initial)
        self.assertNotIn("remote-kubeconfig-secret", resources)
        self.assertNotIn("usage-remote-kubeconfig-cluster", resources)
        output = self._run_kcl(self.cluster_source, self.cluster_instance, {})
        condition = self._condition(output, "RemoteConnectionMaterialReady")
        self.assertEqual(("False", "WaitingForEKSAPI"), (
            condition["status"],
            condition["reason"],
        ))

    def test_existing_connection_secret_is_preserved_during_observation_gaps(
        self,
    ) -> None:
        observed = {
            "remote-kubeconfig-secret": {
                "Resource": {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": "eks-dev-spot-eks-access",
                        "namespace": "crossplane-system",
                        "annotations": {RESOURCE_NAME: "remote-kubeconfig-secret"},
                        "labels": {
                            "platform.aws.goodnotes.io/environment": "eks-dev-spot"
                        },
                    },
                    "type": "Opaque",
                    "data": {"kubeconfig": "VEVTVC1PTkxZQ=="},
                }
            }
        }
        rendered = render_cluster.render(copy.deepcopy(self.cluster_instance), observed)
        resources = self._resources_by_name(rendered)
        secret = resources["remote-kubeconfig-secret"]
        self.assertEqual(
            {"kubeconfig": "VEVTVC1PTkxZQ=="},
            secret["data"],
        )
        self.assertNotIn("stringData", secret)
        self.assertIn("usage-remote-kubeconfig-cluster", resources)

    def test_remote_auth_probe_is_observe_only_and_uses_kubernetes_config(
        self,
    ) -> None:
        probe = self.foundation_resources["remote-auth-probe"]
        self.assertEqual(["Observe"], probe["spec"]["managementPolicies"])
        self.assertEqual(
            {"kind": "ClusterProviderConfig", "name": "eks-dev-spot-kubernetes"},
            probe["spec"]["providerConfigRef"],
        )
        manifest = probe["spec"]["forProvider"]["manifest"]
        self.assertEqual(
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system"}},
            manifest,
        )
        self.assertEqual(
            "DeriveFromCelQuery", probe["spec"]["readiness"]["policy"]
        )

    def test_auth_conditions_distinguish_waiting_ready_and_denied(self) -> None:
        cases = (
            ({}, ("False", "WaitingForProbe")),
            (self.ready_observed, ("True", "Available")),
            (self.denied_observed, ("False", "ProbeFailed")),
            (self.expired_observed, ("False", "ProbeFailed")),
            (self.missing_source_observed, ("False", "ProbeFailed")),
        )
        for observed, expected in cases:
            with self.subTest(expected=expected):
                output = self._run_kcl(
                    self.foundation_source, self.foundation_instance, observed
                )
                condition = self._condition(output, "RemoteAuthenticationReady")
                self.assertEqual(expected, (condition["status"], condition["reason"]))
                self.assertEqual(
                    {
                        "kubernetes-provider-config",
                        "helm-provider-config",
                        "karpenter-crds-release",
                        "remote-auth-probe",
                        "network-uat-approval",
                        "foundation-uses-cluster",
                    },
                    set(self._resources_by_name({"items": output["items"]})),
                )
                self.assertEqual(
                    ("False", "WaitingForFoundationComponents"),
                    (
                        self._condition(output, "FoundationReady")["status"],
                        self._condition(output, "FoundationReady")["reason"],
                    ),
                )

    def test_cluster_usage_holds_cluster_until_remote_cleanup_finishes(self) -> None:
        usage = self.foundation_resources["foundation-uses-cluster"]
        self.assertEqual("ClusterUsage", usage["kind"])
        self.assertTrue(usage["spec"]["replayDeletion"])
        self.assertEqual(
            {
                "apiVersion": "platform.aws.goodnotes.io/v1alpha1",
                "kind": "XClusterFoundation",
                "resourceRef": {"name": "eks-dev-spot-foundation"},
            },
            usage["spec"]["by"],
        )
        self.assertEqual(
            {
                "apiVersion": "platform.aws.goodnotes.io/v1alpha1",
                "kind": "XEKSCluster",
                "resourceRef": {"name": "eks-dev-spot-cluster"},
            },
            usage["spec"]["of"],
        )

    def test_management_auth_bundle_is_pinned_external_and_non_secret(self) -> None:
        rendered = subprocess.run(
            ["kubectl", "kustomize", str(EKS_ROOT / "management-auth")],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, rendered.returncode, rendered.stderr)
        documents = self._load_yaml_documents(rendered.stdout)
        self.assertEqual(4, len(documents))
        self.assertNotIn("Secret", {item["kind"] for item in documents})

        lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        providers = {
            item["metadata"]["name"]: item
            for item in documents
            if item["kind"] == "Provider"
        }
        self.assertEqual({"provider-kubernetes", "provider-helm"}, set(providers))
        self.assertEqual(
            lock["packages"]["providerKubernetes"]["reference"],
            providers["provider-kubernetes"]["spec"]["package"],
        )
        self.assertEqual(
            lock["packages"]["providerHelm"]["reference"],
            providers["provider-helm"]["spec"]["package"],
        )
        for provider in providers.values():
            self.assertEqual(
                {
                    "apiVersion": "pkg.crossplane.io/v1beta1",
                    "kind": "DeploymentRuntimeConfig",
                    "name": "eks-remote-auth",
                },
                provider["spec"]["runtimeConfigRef"],
            )

        runtime = next(
            item for item in documents if item["kind"] == "DeploymentRuntimeConfig"
            and item["metadata"]["name"] == "eks-remote-auth"
        )
        pod_spec = runtime["spec"]["deploymentTemplate"]["spec"]["template"][
            "spec"
        ]
        self.assertNotIn("serviceAccountTemplate", runtime["spec"])
        container = pod_spec["containers"][0]
        env = {item["name"]: item["value"] for item in container["env"]}
        self.assertEqual("eks-deployment", env["AWS_PROFILE"])
        self.assertEqual("true", env["AWS_EC2_METADATA_DISABLED"])
        secret = next(v["secret"] for v in pod_spec["volumes"] if "secret" in v)
        self.assertEqual("eks-platform-aws-session", secret["secretName"])
        self.assertFalse(secret["optional"])
        self.assertEqual(
            {"credentials", "config"}, {item["key"] for item in secret["items"]}
        )

    def test_shared_runtime_credentials_are_platform_bootstrap_owned(self) -> None:
        contract = common.load_yaml(EKS_ROOT / "ownership-contract.yaml")
        bootstrap = contract["platformBootstrap"]
        self.assertEqual("ManagementPlaneOperator", bootstrap["owner"])
        self.assertIn(
            "provider-runtime-aws-credentials",
            bootstrap["forbiddenEnvironmentOwnership"],
        )
        root = common.load_yaml(EKS_ROOT / "kustomization.yaml")
        self.assertNotIn("management-auth", root["resources"])

    def test_online_runtime_evaluator_is_exact_and_fail_closed(self) -> None:
        lock = common.load_yaml(EKS_ROOT / "versions.lock.yaml")
        providers: list[dict[str, Any]] = []
        revisions: list[dict[str, Any]] = []
        deployments: list[dict[str, Any]] = []
        for provider_name, lock_key in preflight.REMOTE_AUTH_PROVIDERS.items():
            revision_name = f"{provider_name}-locked"
            providers.append(
                {
                    "metadata": {"name": provider_name},
                    "spec": {
                        "package": lock["packages"][lock_key]["reference"],
                        "runtimeConfigRef": {
                            "name": preflight.REMOTE_AUTH_RUNTIME_CONFIG
                        },
                    },
                    "status": {
                        "currentRevision": revision_name,
                        "conditions": [
                            {"type": "Installed", "status": "True"},
                            {"type": "Healthy", "status": "True"},
                        ],
                    },
                }
            )
            revisions.append(
                {
                    "metadata": {"name": revision_name},
                    "spec": {
                        "desiredState": "Active",
                        "runtimeConfigRef": {
                            "name": preflight.REMOTE_AUTH_RUNTIME_CONFIG
                        },
                    },
                    "status": {
                        "conditions": [
                            {"type": "RevisionHealthy", "status": "True"},
                            {"type": "RuntimeHealthy", "status": "True"},
                        ]
                    },
                }
            )
            deployments.append(self._available_deployment(revision_name))
        deployments.extend(
            self._available_deployment(name)
            for name in ("crossplane", "crossplane-rbac-manager")
        )
        report = preflight.evaluate_online_runtime(
            lock,
            {"items": providers},
            {"items": revisions},
            {"items": deployments},
        )
        self.assertTrue(report["requiredDeploymentsAvailable"])

        providers[1]["spec"]["package"] = "provider-helm:stale"
        with self.assertRaisesRegex(common.ToolError, "U0 remote-auth runtime gate failed"):
            preflight.evaluate_online_runtime(
                lock,
                {"items": providers},
                {"items": revisions},
                {"items": deployments},
            )

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
    def _run_kcl(
        source: str, instance: dict[str, Any], observed: dict[str, Any]
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
            input=source,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def _condition(output: dict[str, Any], condition_type: str) -> dict[str, Any]:
        condition_object = next(
            item for item in output["items"] if item.get("kind") == "Conditions"
        )
        return next(
            item["condition"]
            for item in condition_object["conditions"]
            if item["condition"]["type"] == condition_type
        )

    @staticmethod
    def _load_yaml_documents(value: str) -> list[dict[str, Any]]:
        result = subprocess.run(
            ["yq", "eval-all", "-o=json", "[.]", "-"],
            input=value,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        documents = json.loads(result.stdout)
        if not isinstance(documents, list):
            raise AssertionError("expected a YAML document list")
        return documents

    @staticmethod
    def _available_deployment(name: str) -> dict[str, Any]:
        return {
            "metadata": {"name": name},
            "spec": {"replicas": 1},
            "status": {"availableReplicas": 1},
        }


if __name__ == "__main__":
    unittest.main()
