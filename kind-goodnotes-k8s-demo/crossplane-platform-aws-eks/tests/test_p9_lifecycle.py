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
P2 = EKS_ROOT / "tests" / "fixtures" / "p2"
P8 = EKS_ROOT / "tests" / "fixtures" / "p8"
P9 = EKS_ROOT / "tests" / "fixtures" / "p9"
sys.path.insert(0, str(SCRIPT_ROOT))

import common  # noqa: E402
import render_foundation  # noqa: E402
import validate_lifecycle_contract  # noqa: E402


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"
STAGES = (
    "Active",
    "DrainWorkloads",
    "RemoveGitOps",
    "DrainCapacity",
    "RemoveFoundation",
    "DeleteReady",
)


class P9LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.foundation = common.load_yaml(P8 / "foundation-gitops-valid.yaml")
        cls.environment = common.load_yaml(P2 / "environment-valid.yaml")
        cls.inventory = common.load_yaml(EKS_ROOT / "lifecycle-inventory.yaml")["spec"][
            "stages"
        ]
        cls.base_evidence = common.load_yaml(
            P9 / "observed-retirement-drain-workloads.yaml"
        )
        cls.base_observed = cls._merge_observed(
            common.load_yaml(P8 / "observed-network-approved.yaml"),
            common.load_yaml(P8 / "observed-argocd-prerequisites-ready.yaml"),
            common.load_yaml(P8 / "observed-project-ready.yaml"),
            common.load_yaml(P8 / "observed-bootstrap-ready.yaml"),
        )
        composition = common.load_yaml(EKS_ROOT / "environment" / "composition.yaml")
        cls.environment_source = composition["spec"]["pipeline"][0]["input"]["spec"][
            "source"
        ]

    def test_inventory_hashes_admission_policy_and_observer_fail_closed(self) -> None:
        report = validate_lifecycle_contract.validate_lifecycle_contract()
        self.assertEqual(5, report["stages"])
        self.assertEqual("fail-closed", report["admissionPolicy"])
        self.assertFalse(report["rootReplayDeletion"])
        self.assertFalse(report["awsMutation"])

    def test_each_approved_stage_removes_only_its_controlled_inventory(self) -> None:
        cases = {
            "DrainWorkloads": {
                "absent": {"gitops-bootstrap"},
                "present": {"argocd-release", "argocd-project", "spot-general-node-pool"},
            },
            "RemoveGitOps": {
                "absent": {
                    "gitops-bootstrap",
                    "argocd-release",
                    "argocd-project",
                    "argocd-apps-role",
                    "argocd-apps-rolebinding",
                    "gitops-apps-namespace",
                },
                "present": {"spot-general-node-pool", "cilium-release", "remote-auth-probe"},
            },
            "DrainCapacity": {
                "absent": {"spot-general-node-pool", "argocd-release"},
                "present": {
                    "karpenter-controller-release",
                    "ec2-node-class",
                    "cilium-release",
                    "remote-auth-probe",
                },
            },
            "RemoveFoundation": {
                "absent": {
                    "spot-general-node-pool",
                    "karpenter-controller-release",
                    "karpenter-crds-release",
                    "ec2-node-class",
                    "cilium-release",
                    "network-uat-approval",
                },
                "present": {
                    "kubernetes-provider-config",
                    "helm-provider-config",
                    "remote-auth-probe",
                    "foundation-uses-cluster",
                },
            },
            "DeleteReady": {
                "absent": {
                    "kubernetes-provider-config",
                    "helm-provider-config",
                    "remote-auth-probe",
                    "foundation-uses-cluster",
                },
                "present": {"retirement-evidence"},
            },
        }
        for index, target in enumerate(STAGES[1:], start=1):
            with self.subTest(stage=target):
                previous = STAGES[index - 1]
                rendered = self._render_stage(previous, target, 8 + index, 2 + index)
                resources = self._resources(rendered)
                self.assertTrue(cases[target]["absent"].isdisjoint(resources))
                self.assertTrue(cases[target]["present"].issubset(resources))

    def test_stale_wrong_environment_or_nonzero_cleanup_evidence_retains_resources(self) -> None:
        mutations = (
            ("environment-generation", "999"),
            ("environment-uid", "wrong-environment"),
            ("inventory-sha256", "0" * 64),
            ("nodeclaim-count", "1"),
            ("business-pdb-blockers", "1"),
        )
        for key, value in mutations:
            with self.subTest(field=key):
                instance = self._foundation_instance("RemoveGitOps", "DrainCapacity", 11, 5)
                evidence = self._evidence("RemoveGitOps", "DrainCapacity", 11, 5)
                evidence["retirement-evidence"]["Resource"]["status"]["atProvider"][
                    "manifest"
                ]["data"][key] = value
                observed = self._merge_observed(self.base_observed, evidence)
                rendered = render_foundation.render(instance, observed)
                resources = self._resources(rendered)
                self.assertIn("spot-general-node-pool", resources)
                output = self._run_foundation_kcl(instance, observed)
                self.assertEqual(
                    ("False", "EvidenceRejected"),
                    self._condition(output, "RetirementEvidenceAccepted"),
                )

    def test_observation_gap_never_recreates_a_resource_removed_by_approved_stage(self) -> None:
        instance = self._foundation_instance(
            "DrainCapacity", "DrainCapacity", generation=12, environment_generation=6
        )
        rendered = render_foundation.render(instance, copy.deepcopy(self.base_observed))
        resources = self._resources(rendered)
        self.assertNotIn("spot-general-node-pool", resources)
        self.assertIn("karpenter-controller-release", resources)

    def test_aggregate_owns_three_children_and_non_replaying_root_protection(self) -> None:
        output = self._run_environment_kcl(copy.deepcopy(self.environment), {})
        resources = self._resources({"items": output["items"]})
        child_kinds = {
            name: item["kind"]
            for name, item in resources.items()
            if item["kind"]
            in {"XNetwork", "XEKSCluster", "XClusterFoundation", "ClusterUsage"}
        }
        self.assertEqual(
            {
                "network": "XNetwork",
                "cluster": "XEKSCluster",
                "foundation": "XClusterFoundation",
                "root-deletion-protection": "ClusterUsage",
            },
            child_kinds,
        )
        protection = resources["root-deletion-protection"]
        self.assertFalse(protection["spec"]["replayDeletion"])
        self.assertEqual("XClusterFoundation", protection["spec"]["by"]["kind"])
        self.assertEqual("XEKSEnvironment", protection["spec"]["of"]["kind"])

    def test_delete_ready_cleanup_releases_root_and_native_protection_only_after_observation(self) -> None:
        instance = copy.deepcopy(self.environment)
        instance["metadata"]["generation"] = 7
        instance["spec"]["parameters"]["lifecycle"] = {
            "retirementStage": "DeleteReady",
            "deletionProtection": False,
            "evidenceRef": {
                "kind": "ConfigMap",
                "name": "eks-dev-spot-retirement-evidence",
                "namespace": "crossplane-system",
            },
        }
        instance["status"] = {
            "retirement": {
                "approvedStage": "RemoveFoundation",
                "cleanupComplete": False,
            }
        }
        without_observation = self._run_environment_kcl(instance, {})
        blocked = self._resources({"items": without_observation["items"]})
        self.assertIn("root-deletion-protection", blocked)
        self.assertTrue(blocked["cluster"]["spec"]["parameters"]["lifecycle"]["deletionProtection"])

        observed = {
            "foundation": {
                "Resource": {
                    "status": {
                        "retirement": {
                            "approvedStage": "DeleteReady",
                            "cleanupComplete": True,
                            "evidenceAccepted": True,
                        }
                    }
                }
            },
            "cluster": {
                "Resource": {
                    "status": {
                        "deletionProtectionEnabled": False,
                    }
                }
            }
        }
        released_output = self._run_environment_kcl(instance, observed)
        released = self._resources({"items": released_output["items"]})
        self.assertNotIn("root-deletion-protection", released)
        self.assertFalse(
            released["cluster"]["spec"]["parameters"]["lifecycle"][
                "deletionProtection"
            ]
        )

    def test_composition_revisions_are_manual_and_require_review(self) -> None:
        for layer in ("environment", "cluster", "foundation"):
            with self.subTest(layer=layer):
                xrd = common.load_yaml(EKS_ROOT / layer / "xrd.yaml")
                composition = common.load_yaml(EKS_ROOT / layer / "composition.yaml")
                self.assertEqual("Manual", xrd["spec"]["defaultCompositionUpdatePolicy"])
                self.assertEqual(
                    composition["metadata"]["name"],
                    xrd["spec"]["enforcedCompositionRef"]["name"],
                )
                self.assertEqual(
                    "required",
                    composition["metadata"]["labels"][
                        "platform.aws.goodnotes.io/revision-review"
                    ],
                )

    def test_planner_outputs_only_next_stage_and_never_executes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT_ROOT / "plan_retirement.py"), "--current-stage", "Active"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["execute"])
        self.assertEqual("DrainWorkloads", report["nextStage"])
        self.assertFalse(report["readyToAdvance"])
        self.assertFalse(report["compositionRunsDuringDeletion"])
        skipped = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_ROOT / "plan_retirement.py"),
                "--current-stage",
                "Active",
                "--target-stage",
                "DrainCapacity",
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(0, skipped.returncode)

    def _render_stage(
        self, previous: str, target: str, generation: int, environment_generation: int
    ) -> dict[str, Any]:
        instance = self._foundation_instance(
            previous, target, generation, environment_generation
        )
        observed = self._merge_observed(
            self.base_observed,
            self._evidence(previous, target, generation, environment_generation),
        )
        output = self._run_foundation_kcl(instance, observed)
        desired = next(
            item for item in output["items"] if item.get("kind") == "XClusterFoundation"
        )
        self.assertEqual(target, desired["status"]["retirement"]["approvedStage"])
        return {"items": output["items"]}

    def _foundation_instance(
        self, previous: str, target: str, generation: int, environment_generation: int
    ) -> dict[str, Any]:
        instance = copy.deepcopy(self.foundation)
        instance["metadata"]["generation"] = generation
        instance["spec"]["parameters"]["environmentIdentity"][
            "generation"
        ] = environment_generation
        instance["spec"]["parameters"]["lifecycle"] = {
            "retirementStage": target,
            "deletionProtection": target != "DeleteReady",
            "evidenceRef": {
                "kind": "ConfigMap",
                "name": "eks-dev-spot-retirement-evidence",
                "namespace": "crossplane-system",
            },
        }
        instance["status"] = {
            "retirement": {
                "approvedStage": previous,
                "cleanupComplete": False,
                "evidenceAccepted": previous != "Active",
            }
        }
        return instance

    def _evidence(
        self, previous: str, target: str, generation: int, environment_generation: int
    ) -> dict[str, Any]:
        evidence = copy.deepcopy(self.base_evidence)
        data = evidence["retirement-evidence"]["Resource"]["status"]["atProvider"][
            "manifest"
        ]["data"]
        data.update(
            {
                "environment-generation": str(environment_generation),
                "foundation-generation": str(generation),
                "from-stage": previous,
                "to-stage": target,
                "inventory-sha256": self.inventory[target]["inventorySha256"],
            }
        )
        data.update(self.inventory[target]["requiredEvidence"])
        return evidence

    def _run_foundation_kcl(
        self, instance: dict[str, Any], observed: dict[str, Any]
    ) -> dict[str, Any]:
        composition = common.load_yaml(EKS_ROOT / "foundation" / "composition.yaml")
        source = composition["spec"]["pipeline"][0]["input"]["spec"]["source"]
        desired = {
            "apiVersion": instance["apiVersion"],
            "kind": instance["kind"],
            "metadata": {"name": instance["metadata"]["name"]},
            "status": {},
        }
        return self._run_kcl(
            source,
            {
                "oxr": instance,
                "dxr": desired,
                "ocds": observed,
                "extraResources": render_foundation.default_extra_resources(),
            },
        )

    def _run_environment_kcl(
        self, instance: dict[str, Any], observed: dict[str, Any]
    ) -> dict[str, Any]:
        desired = {
            "apiVersion": instance["apiVersion"],
            "kind": instance["kind"],
            "metadata": {"name": instance["metadata"]["name"]},
            "status": {},
        }
        return self._run_kcl(
            self.environment_source,
            {"oxr": instance, "dxr": desired, "ocds": observed},
        )

    @staticmethod
    def _run_kcl(source: str, params: dict[str, Any]) -> dict[str, Any]:
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
    def _resources(rendered: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            item["metadata"]["annotations"][RESOURCE_NAME]: item
            for item in rendered["items"]
            if RESOURCE_NAME in item.get("metadata", {}).get("annotations", {})
        }

    @staticmethod
    def _condition(output: dict[str, Any], name: str) -> tuple[str, str]:
        conditions = next(item for item in output["items"] if item.get("kind") == "Conditions")
        condition = next(
            item["condition"]
            for item in conditions["conditions"]
            if item["condition"]["type"] == name
        )
        return condition["status"], condition["reason"]

    @staticmethod
    def _merge_observed(*documents: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for document in documents:
            merged.update(copy.deepcopy(document))
        return merged


if __name__ == "__main__":
    unittest.main()
