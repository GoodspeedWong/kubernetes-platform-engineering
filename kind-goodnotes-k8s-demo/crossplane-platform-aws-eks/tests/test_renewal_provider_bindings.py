from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))

import renew_management_credentials as renewal
import provider_maintenance
from common import EKS_ROOT, ToolError, load_yaml
from test_security_remediation import contract, session


class RenewalProviderBindingsTests(unittest.TestCase):
    def test_names_match_existing_and_dependency_provider_manifests(self):
        reviewed = provider_maintenance.contract()
        names = {
            provider["name"]
            for provider in reviewed["providers"]
            if provider["runtimeConfig"] != "default"
        }
        expected = {
            provider["metadata"]["name"]: provider
            for provider in provider_maintenance.provider_documents(reviewed)
        }
        for service in ("sqs", "cloudwatchevents"):
            provider = load_yaml(
                EKS_ROOT / "dependencies" / f"provider-aws-{service}.yaml"
            )
            self.assertIn(provider["metadata"]["name"], names)
            self.assertEqual(expected[provider["metadata"]["name"]], provider)
        self.assertEqual(7, len(renewal.PROVIDERS))
        self.assertEqual(names, set(renewal.PROVIDERS))

    def test_plan_exposes_exact_provider_names_without_api_calls(self):
        with patch.object(renewal, "_run_json") as run:
            result = renewal.public_plan(contract())
        run.assert_not_called()
        self.assertEqual(list(renewal.PROVIDERS), result["requiredProviderNames"])
        self.assertFalse(result["kubernetesMutation"])

    @staticmethod
    def deployments():
        return {
            "items": [
                {
                    "metadata": {
                        "name": name + "-revision",
                        "labels": {"pkg.crossplane.io/provider": name},
                    }
                }
                for name in renewal.PROVIDERS
            ]
        }

    def assert_blocked_before_secret_access(self, deployments):
        with patch.object(renewal, "_run_json", return_value=deployments) as run:
            with self.assertRaises(ToolError):
                renewal.publish_session(contract(), session())
        self.assertEqual(1, run.call_count)
        self.assertIn("deployments", run.call_args.args[0])

    def test_package_basename_aliases_are_not_provider_identities(self):
        deployments = self.deployments()
        for deployment in deployments["items"]:
            labels = deployment["metadata"]["labels"]
            for prefix in ("crossplane-contrib-", "upbound-"):
                labels["pkg.crossplane.io/provider"] = labels[
                    "pkg.crossplane.io/provider"
                ].removeprefix(prefix)
        self.assert_blocked_before_secret_access(deployments)

    def test_duplicate_revision_does_not_expand_rollout_scope(self):
        deployments = self.deployments()
        extra = copy.deepcopy(deployments["items"][0])
        extra["metadata"]["name"] += "-old"
        deployments["items"].append(extra)
        self.assert_blocked_before_secret_access(deployments)

    def test_unrelated_provider_cannot_opt_into_session_renewal(self):
        deployments = self.deployments()
        labels = deployments["items"][-1]["metadata"]["labels"]
        labels["pkg.crossplane.io/provider"] = "crossplane-contrib-provider-aws-rds"
        self.assert_blocked_before_secret_access(deployments)

    def test_missing_dependency_stops_before_secret_access(self):
        deployments = self.deployments()
        deployments["items"].pop()
        self.assert_blocked_before_secret_access(deployments)

    def test_failed_live_rbac_gate_prevents_secret_access_and_rollout(self):
        with patch.object(renewal, "_run_json", return_value=self.deployments()) as run:
            with patch.object(renewal, "verify_explicit_provider_rbac", side_effect=ToolError("rbac drift")) as gate:
                with self.assertRaises(ToolError):
                    renewal.publish_session(contract(), session())
        gate.assert_called_once_with()
        self.assertEqual(1, run.call_count)


if __name__ == "__main__":
    unittest.main()
