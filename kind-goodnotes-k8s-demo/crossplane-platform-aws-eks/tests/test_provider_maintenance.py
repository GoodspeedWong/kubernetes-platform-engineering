from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))

import provider_maintenance as maintenance
from common import EKS_ROOT, ToolError, load_yaml


class ProviderMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.reviewed = maintenance.contract()
        self.providers = maintenance.provider_documents(self.reviewed)

    def test_all_ten_packages_are_digest_pinned_and_match_lock(self):
        lock = load_yaml(EKS_ROOT / "versions.lock.yaml")["packages"]
        self.assertEqual(10, len(self.providers))
        for contract, provider in zip(self.reviewed["providers"], self.providers):
            self.assertEqual(
                lock[contract["lockKey"]]["reference"],
                provider["spec"]["package"],
            )
            self.assertIn("@sha256:", provider["spec"]["package"])
            self.assertEqual("Automatic", provider["spec"]["revisionActivationPolicy"])
            self.assertEqual(2, provider["spec"]["revisionHistoryLimit"])

    def test_exactly_seven_runtimes_consume_sessions(self):
        consumers = {
            item["metadata"]["name"]
            for item in self.providers
            if item["metadata"]["labels"][
                maintenance.LABEL_PREFIX + "session-consumer"
            ]
            == "true"
        }
        readers = {p["name"] for p in self.reviewed["providers"] if p["sessionReader"]}
        self.assertEqual(7, len(consumers))
        self.assertEqual(5, len(readers))
        self.assertTrue(readers < consumers)

    def test_aws_service_packages_use_the_explicit_family_provider(self):
        by_name = {
            item["metadata"]["name"]: item for item in self.providers
        }
        service_names = {
            item["name"]
            for item in self.reviewed["providers"]
            if item["service"] in maintenance.rbac.AWS_SERVICES - {"aws"}
        }
        self.assertEqual(7, len(service_names))
        for name in service_names:
            self.assertTrue(by_name[name]["spec"]["skipDependencyResolution"])
        for name in set(by_name) - service_names:
            self.assertNotIn("skipDependencyResolution", by_name[name]["spec"])

    def test_rendered_provider_file_matches_inventory(self):
        self.assertEqual(
            maintenance.rendered_bytes(self.reviewed),
            maintenance.PROVIDERS_FILE.read_bytes(),
        )

    def test_dependency_entries_cannot_override_session_runtime(self):
        expected = {
            item["metadata"]["name"]: item for item in self.providers
        }
        for name, path in maintenance.DEPENDENCY_FILES.items():
            self.assertEqual(expected[name], load_yaml(path))

    def test_lock_or_inventory_drift_fails_closed(self):
        lock = copy.deepcopy(load_yaml(EKS_ROOT / "versions.lock.yaml"))
        lock["packages"]["providerHelm"]["reference"] = "provider-helm:stale"
        with self.assertRaises(ToolError):
            maintenance.contract(lock)

    def test_provider_config_is_direct_session_only(self):
        document = maintenance.provider_config("eks-dev-spot")
        self.assertEqual("eks-dev-spot", document["metadata"]["name"])
        self.assertNotIn(
            maintenance.LABEL_PREFIX + "do-not-apply",
            document["metadata"].get("annotations", {}),
        )
        spec = document["spec"]
        self.assertNotIn("assumeRoleChain", spec)
        self.assertNotIn("profile", spec)
        self.assertTrue(spec["skip_metadata_api_check"])
        self.assertEqual(
            {
                "namespace": "crossplane-system",
                "name": "eks-platform-aws-session",
                "key": "credentials",
            },
            spec["credentials"]["secretRef"],
        )

    def test_invalid_provider_config_name_is_rejected(self):
        for name in ("", "Uppercase", "bad/name", "-leading"):
            with self.assertRaises(ToolError):
                maintenance.provider_config(name)

    def test_plan_is_explicitly_non_mutating(self):
        plan = maintenance.public_plan(self.reviewed)
        self.assertEqual(10, plan["providerCount"])
        self.assertEqual(7, plan["sessionConsumerCount"])
        self.assertEqual(5, plan["sessionSecretReaderCount"])
        self.assertEqual(7, plan["manualAwsFamilyDependencyCount"])
        for key in (
            "awsMutation",
            "kubernetesMutation",
            "startsControllers",
            "publishesCredentials",
        ):
            self.assertFalse(plan[key])


if __name__ == "__main__":
    unittest.main()
