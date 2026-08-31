from __future__ import annotations

import base64
import copy
import fnmatch
import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))
import renew_management_credentials as credentials
import validate_chart_digests
from common import ToolError, load_yaml

ACCOUNT = "111122223333"
ENV = "eks-dev-spot"
IAM = f"arn:aws:iam::{ACCOUNT}:"
TAG = "platform.aws.goodnotes.io/environment"


def contract():
    return credentials.BootstrapContract(
        ENV, "us-east-1", "kind-kube-nebula-a", IAM + "role/source",
        IAM + f"role/{ENV}-xp-aws", IAM + f"role/{ENV}-eks-deploy", IAM + "policy/bootstrap-boundary")


def session():
    return {"AccessKeyId": "ASIA" + "TESTONLY", "SecretAccessKey": "secret-test-only",
            "SessionToken": "token-test-only",
            "Expiration": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()}


def target_sessions():
    execution = session() | {"AccessKeyId": "ASIAEXECUTIONTEST", "SecretAccessKey": "execution-test-only"}
    deployment = session() | {"AccessKeyId": "ASIADEPLOYMENTTEST", "SecretAccessKey": "deployment-test-only"}
    return credentials.TargetSessions(execution, deployment, datetime.now(timezone.utc) + timedelta(hours=1))


def inventory():
    c = contract()
    resources = credentials.resolve_template(c)["Resources"]
    deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    review = {"sourceRole": {"PermissionsBoundary": IAM + "policy/source-boundary",
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"AWS": IAM + "role/federated-entry"}, "Action": "sts:AssumeRole"}]}},
        "boundaries": {arn: copy.deepcopy(deny) for arn in [c.boundary_arn, IAM + "policy/source-boundary"] +
                       [IAM + f"policy/{ENV}-{s}-boundary" for s in credentials.CHILD_ROLES]}}
    review.update({"reviewStatus": "APPROVED", "approvedBy": "unit-test-reviewer",
                   "approvedAt": "2020-01-01T00:00:00Z", "contract": c.__dict__})
    review.update({key: credentials.template_digest(load_yaml(path))
                   for key, path in credentials.REVIEW_TEMPLATES.items()})
    policies = {IAM + "policy/" + r["Properties"]["ManagedPolicyName"]: r["Properties"]["PolicyDocument"]
                for r in resources.values() if r["Type"] == "AWS::IAM::ManagedPolicy"} | copy.deepcopy(review["boundaries"])
    roles = {r["Properties"]["RoleName"]: copy.deepcopy(r["Properties"])
             for r in resources.values() if r["Type"] == "AWS::IAM::Role"}
    roles["source"] = {**review["sourceRole"], "MaxSessionDuration": 3600, "Policies": [
        {"PolicyName": "assume-platform-roles", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": [c.provider_role_arn, c.deployment_role_arn]}]}}]}

    def aws(profile, region, service, action, *args):
        if action == "get-caller-identity":
            return {"Account": ACCOUNT}
        flags = dict(zip(args[::2], args[1::2]))
        if action == "get-policy":
            return {"Policy": {"Arn": flags["--policy-arn"], "DefaultVersionId": "v2"}}
        if action == "get-policy-version":
            return {"PolicyVersion": {"Document": policies[flags["--policy-arn"]]}}
        name = flags["--role-name"]
        role = roles[name]
        if action == "get-role":
            return {"Role": {"Arn": IAM + "role/" + name, "MaxSessionDuration": role["MaxSessionDuration"],
                "PermissionsBoundary": {"PermissionsBoundaryArn": role["PermissionsBoundary"]},
                "AssumeRolePolicyDocument": role["AssumeRolePolicyDocument"]}}
        if action == "list-attached-role-policies":
            return {"AttachedPolicies": [{"PolicyArn": arn} for arn in role.get("ManagedPolicyArns", [])]}
        if action == "list-role-policies":
            return {"PolicyNames": [p["PolicyName"] for p in role["Policies"]]}
        if action == "get-role-policy":
            return {"PolicyDocument": next(p["PolicyDocument"] for p in role["Policies"] if p["PolicyName"] == flags["--policy-name"])}
        raise AssertionError(action)
    return review, roles, policies, aws


def listed(value):
    return value if isinstance(value, list) else [value]


def decision(statements, action, resource, context):
    """Focused regression evaluator for the policy operators we emit, NOT AWS UAT."""
    allowed = False
    for s in statements:
        if not any(fnmatch.fnmatchcase(action, a) for a in listed(s["Action"])):
            continue
        if not any(fnmatch.fnmatchcase(resource, r) for r in listed(s["Resource"])):
            continue
        valid = True
        for op, conditions in s.get("Condition", {}).items():
            for key, expected in conditions.items():
                actual = context.get(key)
                expected = listed(expected)
                if op in ("StringEquals", "ArnEquals"):
                    valid &= actual in expected
                elif op == "StringNotEquals":
                    valid &= actual not in expected
                elif op == "StringEqualsIfExists":
                    valid &= actual is None or actual in expected
                elif op == "ForAllValues:StringNotEquals":
                    valid &= all(x not in expected for x in listed(actual or []))
                elif op == "ForAllValues:StringEquals":
                    valid &= all(x in expected for x in listed(actual or []))
                elif op == "Null":
                    valid &= (actual is None) == (expected[0] == "true")
                else:
                    raise AssertionError("unknown condition operator: " + op)
        if valid and s["Effect"] == "Deny":
            return "explicitDeny"
        allowed |= valid and s["Effect"] == "Allow"
    return "allowed" if allowed else "implicitDeny"


class SecurityRemediationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resources = credentials.resolve_template(contract())["Resources"]
        cls.statements = []
        for r in cls.resources.values():
            if r["Type"] == "AWS::IAM::ManagedPolicy":
                cls.statements += r["Properties"]["PolicyDocument"]["Statement"]
        for p in cls.resources["CrossplaneAWSProviderRole"]["Properties"]["Policies"]:
            cls.statements += p["PolicyDocument"]["Statement"]

    def test_bootstrap_roles_and_boundaries_cannot_be_modified(self):
        for resource in [contract().provider_role_arn, contract().deployment_role_arn, contract().source_role_arn,
                         contract().boundary_arn, IAM + f"policy/{ENV}-karpenter-boundary"]:
            for action in ("iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:CreatePolicyVersion"):
                self.assertEqual("explicitDeny", decision(self.statements, action, resource, {}))
        self.assertEqual("implicitDeny", decision(self.statements, "iam:PutRolePolicy", IAM + f"role/{ENV}-rogue", {}))

    def test_create_child_requires_exact_boundary_and_environment_tag(self):
        for suffix in credentials.CHILD_ROLES:
            resource = IAM + f"role/{ENV}-{suffix}"
            context = {"iam:PermissionsBoundary": IAM + f"policy/{ENV}-{suffix}-boundary", "aws:RequestTag/" + TAG: ENV}
            self.assertEqual("allowed", decision(self.statements, "iam:CreateRole", resource, context))
            for missing in context:
                bad = context.copy()
                bad.pop(missing)
                self.assertEqual("implicitDeny", decision(self.statements, "iam:CreateRole", resource, bad))

    def test_network_delete_and_routes_require_owned_tags(self):
        for action, kind in [("DeleteVpc", "vpc"), ("DeleteSubnet", "subnet"), ("DeleteRoute", "route-table"),
                             ("DeleteNatGateway", "natgateway"), ("DeleteSecurityGroup", "security-group"),
                             ("ReleaseAddress", "elastic-ip"), ("DisassociateRouteTable", "subnet")]:
            arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:{kind}/test-resource"
            for owner, expected in [(ENV, "allowed"), ("foreign-env", "implicitDeny"), (None, "implicitDeny")]:
                context = {"aws:RequestedRegion": "us-east-1", "ec2:ResourceTag/" + TAG: owner}
                self.assertEqual(expected, decision(self.statements, "ec2:" + action, arn, context))

    def test_cannot_adopt_foreign_network_or_remove_ownership(self):
        arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/vpc-test"
        context = {"aws:RequestedRegion": "us-east-1", "aws:RequestTag/" + TAG: ENV}
        self.assertEqual("implicitDeny", decision(self.statements, "ec2:CreateTags", arn, context))
        context = {"aws:RequestedRegion": "us-east-1", "ec2:ResourceTag/" + TAG: ENV, "aws:TagKeys": [TAG]}
        self.assertEqual("implicitDeny", decision(self.statements, "ec2:DeleteTags", arn, context))

    def test_policy_sizes_fit_aws_limits_even_at_max_environment_length(self):
        c = contract()
        name = "a" * 52
        c = credentials.BootstrapContract(**{k: v.replace(ENV, name) for k, v in c.__dict__.items()})
        for resource in credentials.resolve_template(c)["Resources"].values():
            props = resource["Properties"]
            if resource["Type"] == "AWS::IAM::ManagedPolicy":
                self.assertLessEqual(len(json.dumps(props["PolicyDocument"], separators=(",", ":"))), 6144)
            else:
                self.assertLessEqual(sum(len(json.dumps(p["PolicyDocument"], separators=(",", ":"))) for p in props["Policies"]), 10240)

    def test_full_policy_review_accepts_exact_inventory(self):
        review, _, _, aws = inventory()
        with patch.object(credentials, "_aws", side_effect=aws):
            credentials.verify_aws_identity(contract(), "audit-only", review)

    def test_same_name_inline_admin_policy_is_rejected(self):
        review, roles, _, aws = inventory()
        roles[f"{ENV}-xp-aws"]["Policies"][1]["PolicyDocument"]["Statement"] = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        with patch.object(credentials, "_aws", side_effect=aws), self.assertRaisesRegex(ToolError, "drift"):
            credentials.verify_aws_identity(contract(), "audit-only", review)

    def test_added_trust_principal_or_missing_boundary_is_rejected(self):
        for change in ("trust", "boundary"):
            review, roles, _, aws = inventory()
            role = roles[f"{ENV}-xp-aws"]
            if change == "trust":
                role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"] = "ec2.amazonaws.com"
            else:
                role["PermissionsBoundary"] = ""
            with patch.object(credentials, "_aws", side_effect=aws), self.assertRaises(ToolError):
                credentials.verify_aws_identity(contract(), "audit-only", review)

    def test_managed_default_version_or_boundary_drift_is_rejected(self):
        for key in (IAM + f"policy/{ENV}-xp-network-policy", contract().boundary_arn):
            review, _, policies, aws = inventory()
            policies[key] = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            with patch.object(credentials, "_aws", side_effect=aws), self.assertRaises(ToolError):
                credentials.verify_aws_identity(contract(), "audit-only", review)

    def test_one_secret_contains_two_target_sessions_but_no_source_or_role_chain(self):
        doc = credentials.secret_document(contract(), target_sessions())
        self.assertEqual({"credentials", "config"}, set(doc["data"]))
        raw = base64.b64decode(doc["data"]["credentials"]).decode()
        self.assertIn("aws_session_token=", raw)
        self.assertEqual(2, raw.count("aws_secret_access_key="))
        self.assertNotIn(session()["AccessKeyId"], raw)
        self.assertNotIn("secret-test-only", raw)
        config = base64.b64decode(doc["data"]["config"]).decode()
        self.assertNotIn("aws_secret_access_key", config)
        self.assertNotIn("role_arn", config)
        self.assertNotIn("source_profile", config)

    def test_long_lived_missing_token_expired_and_excessive_sessions_rejected(self):
        for changes in ({"AccessKeyId": "AKIA-TEST"}, {"SessionToken": ""}, {"Expiration": "2000-01-01T00:00:00Z"},
                        {"Expiration": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()}):
            with self.assertRaises(ToolError):
                credentials.validate_session(session() | changes)

    def test_export_environment_cannot_inherit_admin_credentials(self):
        with patch.dict("os.environ", {"AWS_PROFILE": "admin", "AWS_ACCESS_KEY_ID": "admin", "AWS_ROLE_ARN": "admin"}):
            env = credentials.session_environment(session())
            self.assertNotIn("AWS_PROFILE", env)
            self.assertNotIn("AWS_ROLE_ARN", env)
            self.assertEqual(session()["AccessKeyId"], env["AWS_ACCESS_KEY_ID"])

    def test_timeout_and_malformed_responses_never_echo_secrets(self):
        outputs = [subprocess.CompletedProcess([], 1, "secret-test-only", "token-test-only"),
                   subprocess.CompletedProcess([], 0, "secret-test-only", "")]
        for result in outputs:
            with patch.object(credentials.subprocess, "run", return_value=result) as run:
                with self.assertRaises(ToolError) as error:
                    credentials._run_json(["aws", "test"])
                self.assertNotIn("secret-test-only", str(error.exception))
                self.assertEqual(45, run.call_args.kwargs["timeout"])
        with patch.object(credentials.subprocess, "run", side_effect=subprocess.TimeoutExpired("aws", 45)), self.assertRaises(ToolError):
            credentials._run_json(["aws", "test"])

    def test_failed_new_session_assume_role_prevents_publication(self):
        with patch.object(credentials, "_run_json", return_value={"Account": ACCOUNT, "Arn": "wrong"}), self.assertRaises(ToolError):
            credentials.verify_session(contract(), session())

    def test_missing_rollout_opt_in_blocks_secret_write(self):
        with patch.object(credentials, "_run_json", return_value={"items": []}) as run, self.assertRaises(ToolError):
            credentials.publish_session(contract(), target_sessions())
        self.assertEqual(1, run.call_count)

    def test_session_publication_uses_cas_and_restarts_only_opted_in_providers(self):
        deployments = {"items": [{"metadata": {"name": name + "-revision", "labels": {
            "pkg.crossplane.io/provider": name}}} for name in credentials.PROVIDERS]}
        doc = credentials.secret_document(contract(), target_sessions())
        for key in ("expires-at", "all-expires-at", "deadline"):
            doc["metadata"]["annotations"][credentials.TAG_PREFIX + key] = "2000-01-01T00:00:00Z"
        current = {"items": [{"metadata": {**doc["metadata"], "resourceVersion": "42"}}]}
        with patch.object(credentials, "verify_direct_session_runtime"), patch.object(credentials, "verify_explicit_provider_rbac") as gate, patch.object(credentials, "_run_json", side_effect=[deployments, current, True, True] + [True] * len(credentials.PROVIDERS)) as run:
            credentials.publish_session(contract(), target_sessions())
        gate.assert_called_once_with()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn("--dry-run=server", commands[2])
        self.assertIn("replace", commands[3])
        self.assertEqual("42", json.loads(run.call_args_list[3].kwargs["input_text"])["metadata"]["resourceVersion"])
        self.assertEqual(len(credentials.PROVIDERS), sum("patch" in c for c in commands))
        self.assertNotIn("secret-test-only", json.dumps(commands))
        self.assertIn(r'\"items\"', commands[1][-1])

    def test_existing_foreign_secret_and_failed_publish_cannot_trigger_rollout(self):
        deployments = {"items": [{"metadata": {"name": name, "labels": {"pkg.crossplane.io/provider": name}}}
                                  for name in credentials.PROVIDERS]}
        for replies in ([deployments, {"items": [{"metadata": {"labels": {}}}]}],
                        [deployments, {"items": []}, True, ToolError("publication response unknown")]):
            with patch.object(credentials, "verify_direct_session_runtime"), patch.object(credentials, "verify_explicit_provider_rbac"), patch.object(credentials, "_run_json", side_effect=replies) as run, self.assertRaises(ToolError):
                credentials.publish_session(contract(), target_sessions())
            self.assertFalse(any("patch" in c.args[0] for c in run.call_args_list))

    def test_controller_role_boundaries_are_rendered_not_environment_owned(self):
        import render_cluster
        fixtures = credentials.EKS_ROOT / "tests/fixtures/p4"
        rendered = render_cluster.render(load_yaml(fixtures / "cluster-valid.yaml"), load_yaml(fixtures / "observed-oidc-ready.yaml"))
        roles = [r for r in rendered["items"] if r.get("kind") == "Role"]
        self.assertEqual(5, len(roles))
        for role in roles:
            name = role["metadata"]["annotations"]["crossplane.io/external-name"]
            self.assertTrue(role["spec"]["forProvider"]["permissionsBoundary"].endswith("policy/" + name + "-boundary"))

    def test_renew_needs_explicit_acknowledgement(self):
        with patch.object(credentials, "_run_json") as run, self.assertRaises(ToolError):
            credentials.renew(contract(), "source", "audit", {}, "")
        run.assert_not_called()

    def test_all_chart_digest_gates_reject_mutations(self):
        lock = load_yaml(credentials.EKS_ROOT / "versions.lock.yaml")
        for name, key in validate_chart_digests.CHART_KEYS.items():
            chart = {"name": name, "repository": lock["charts"][key]["reference"].rsplit("/", 1)[0],
                     "digest": lock["charts"][key]["manifestDigest"]}
            good = {"items": [{"apiVersion": "helm.m.crossplane.io/v1beta1", "kind": "Release", "spec": {"forProvider": {"chart": chart}}}]}
            self.assertEqual(1, validate_chart_digests.validate(good, lock))
            for changes in ({"digest": "sha256:" + "0" * 64}, {"digest": None}, {"url": "https://unreviewed.invalid/chart.tgz"},
                            {"repository": "https://mutable.invalid"}):
                bad = copy.deepcopy(good)
                bad["items"][0]["spec"]["forProvider"]["chart"].update(changes)
                with self.assertRaises(ToolError):
                    validate_chart_digests.validate(bad, lock)


if __name__ == "__main__":
    unittest.main()
