from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts/eks_lifecycle"))
import manage_provider_rbac as rbac
from common import ToolError, load_yaml


class ExplicitProviderRBACTests(unittest.TestCase):
    def setUp(self):
        self.contract = rbac.inventory()
        self.documents = rbac.render(self.contract)

    def named(self, kind, name):
        return next(d for d in self.documents if d["kind"] == kind and d["metadata"]["name"] == name)

    def test_all_ten_service_accounts_are_exact_and_no_group_is_bound(self):
        bindings = [d for d in self.documents if d["kind"].endswith("Binding")]
        for document in bindings:
            self.assertTrue(all(s["kind"] == "ServiceAccount" for s in document["subjects"]))
            self.assertTrue(all(s["namespace"] == rbac.NS for s in document["subjects"]))
        self.assertEqual(10, len(self.contract["providers"]))

    def test_secret_permission_is_named_namespaced_get_only(self):
        secret_rules = [(d, rule) for d in self.documents for rule in d.get("rules", [])
                        if "secrets" in rule["resources"]]
        self.assertEqual(1, len(secret_rules))
        document, rule = secret_rules[0]
        self.assertEqual("Role", document["kind"])
        self.assertEqual(rbac.NS, document["metadata"]["namespace"])
        self.assertEqual(["get"], rule["verbs"])
        self.assertEqual([rbac.SESSION], rule["resourceNames"])

    def test_only_five_reviewed_aws_readers_are_bound(self):
        binding = self.named("RoleBinding", "eks-platform-session-reader")
        names = {s["name"] for s in binding["subjects"]}
        self.assertEqual(
            {
                p["revision"]
                for p in self.contract["providers"]
                if p["service"] in rbac.SESSION_READER_SERVICES
            },
            names,
        )

    def test_aws_service_cannot_manage_other_service_or_providerconfig(self):
        for service in rbac.AWS_SERVICES - {"aws"}:
            rules = self.named("ClusterRole", "eks-platform-provider-" + service)["rules"]
            self.assertEqual(rbac.groups(service), rules[0]["apiGroups"])
            self.assertEqual(rbac.READ, rules[1]["verbs"])
            self.assertNotIn("providerconfigs", rules[2]["resources"])
            self.assertTrue(all("*" not in r["apiGroups"] for r in rules))

    def test_runtime_permissions_are_namespaced_and_have_no_secrets(self):
        role = self.named("Role", "eks-platform-provider-runtime")
        self.assertEqual(rbac.NS, role["metadata"]["namespace"])
        resources = {resource for rule in role["rules"] for resource in rule["resources"]}
        self.assertEqual({"configmaps", "events", "leases"}, resources)

    def test_no_pods_tokens_or_rbac_permissions_in_provider_roles(self):
        for document in self.documents:
            for rule in document.get("rules", []):
                self.assertNotIn("rbac.authorization.k8s.io", rule["apiGroups"])
                self.assertFalse({"pods", "serviceaccounts/token", "deployments"} & set(rule["resources"]))
                self.assertFalse({"bind", "escalate", "impersonate"} & set(rule["verbs"]))

    def test_core_composition_permissions_include_existing_xrs(self):
        rule = self.named("ClusterRole", "eks-platform-core-composition")["rules"][0]
        self.assertTrue(set(self.contract["coreApiGroups"]).issubset(rule["apiGroups"]))
        self.assertIn("kubernetes.crossplane.io", rule["apiGroups"])

    def test_digest_revision_runtime_and_secret_reader_drift_fail_closed(self):
        for change in ("digest", "revision", "runtime", "reader"):
            bad = copy.deepcopy(self.contract)
            if change == "digest":
                bad["providers"][0]["package"] = "provider:v2.5.3"
            elif change == "revision":
                bad["providers"][0]["revision"] = "unreviewed"
            elif change == "runtime":
                bad["providers"][0]["runtimeConfig"] = "default"
            else:
                provider = next(
                    p for p in bad["providers"] if p["service"] == "rds"
                )
                provider["sessionReader"] = True
            with patch.object(rbac, "load_yaml", return_value=bad), self.assertRaises(ToolError):
                rbac.inventory()

    def test_exactly_seven_provider_runtimes_are_session_bound(self):
        consumers = {
            provider["name"]
            for provider in self.contract["providers"]
            if provider["runtimeConfig"] != rbac.RUNTIME_DEFAULT
        }
        self.assertEqual(
            {
                "provider-helm",
                "provider-kubernetes",
                "crossplane-contrib-provider-aws-ec2",
                "crossplane-contrib-provider-aws-eks",
                "crossplane-contrib-provider-aws-iam",
                "upbound-provider-aws-sqs",
                "upbound-provider-aws-cloudwatchevents",
            },
            consumers,
        )

    def test_retirement_is_exact_and_never_targets_business_resources(self):
        targets = rbac.retired_targets(self.contract)
        self.assertEqual(24, len(targets))
        self.assertTrue(all(ns in (None, rbac.NS) for _, _, ns in targets))
        self.assertTrue(all(kind in {"clusterrole", "clusterrolebinding", "deployment", "serviceaccount"} for kind, _, _ in targets))
        self.assertEqual(1, sum(kind == "deployment" for kind, _, _ in targets))

    def test_helm_values_disable_manager_and_maintenance_holds_core(self):
        values = load_yaml(rbac.EKS_ROOT.parent / "crossplane/values.yaml")
        self.assertIs(False, values["rbacManager"]["deploy"])
        maintenance = load_yaml(rbac.MAINTENANCE_ROOT / "kustomization.yaml")
        self.assertIn("value: 0", maintenance["patches"][0]["patch"])

    def test_sar_includes_serviceaccount_groups_and_no_credentials(self):
        with patch.object(rbac.maintenance, "kube", return_value={"status": {"allowed": False}}) as kube:
            self.assertFalse(rbac.can_i("test-account", "get", "secrets", rbac.NS, rbac.SESSION))
        request = kube.call_args.args[1]
        self.assertIn("system:serviceaccounts:" + rbac.NS, request["spec"]["groups"])
        self.assertEqual("get", request["spec"]["resourceAttributes"]["verb"])

    def test_incomplete_authorization_review_is_not_a_deny_pass(self):
        for status in ({}, {"allowed": False, "evaluationError": "incomplete"}):
            with patch.object(rbac.maintenance, "kube", return_value={"status": status}), self.assertRaises(ToolError):
                rbac.can_i("test-account", "get", "secrets")


if __name__ == "__main__":
    unittest.main()
