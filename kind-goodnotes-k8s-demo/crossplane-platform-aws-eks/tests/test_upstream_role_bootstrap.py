from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))
import bootstrap_upstream_role as upstream
from common import ToolError


def contract():
    return upstream.Contract("eks-dev-spot", "111122223333", "arn:aws:iam::111122223333:role/test-entry")


class Inventory:
    def __init__(self):
        self.c = contract()
        self.role = None
        self.boundary = None
        self.inline = {}
        self.attached = []
        self.writes = []

    def aws(self, profile, service, action, **parameters):
        c = self.c
        if action.startswith("create-") or action == "put-role-policy":
            self.writes.append((action, copy.deepcopy(parameters)))
        if action == "get-role":
            if parameters["RoleName"] != c.name or self.role is None:
                raise upstream.AWSFailure("NoSuchEntity")
            return {"Role": copy.deepcopy(self.role)}
        if action == "get-policy":
            if self.boundary is None:
                raise upstream.AWSFailure("NoSuchEntity")
            return {"Policy": {"Arn": c.boundary_arn, "Path": "/", "DefaultVersionId": "v1"}}
        if action == "create-policy":
            self.boundary = json.loads(parameters["PolicyDocument"])
            return {"Policy": {"Arn": c.boundary_arn}}
        if action == "list-policy-tags" or action == "list-role-tags":
            return {"Tags": c.tags}
        if action == "get-policy-version":
            return {"PolicyVersion": {"Document": self.boundary}}
        if action == "create-role":
            self.role = {"Arn": c.role_arn, "Path": parameters["Path"], "RoleId": "TEST-ROLE-ID",
                         "MaxSessionDuration": parameters["MaxSessionDuration"],
                         "PermissionsBoundary": {"PermissionsBoundaryArn": parameters["PermissionsBoundary"]},
                         "AssumeRolePolicyDocument": json.loads(parameters["AssumeRolePolicyDocument"])}
            return {"Role": copy.deepcopy(self.role)}
        if action == "list-attached-role-policies":
            return {"AttachedPolicies": self.attached}
        if action == "list-role-policies":
            return {"PolicyNames": list(self.inline)}
        if action == "put-role-policy":
            self.inline[parameters["PolicyName"]] = json.loads(parameters["PolicyDocument"])
            return {}
        if action == "get-role-policy":
            return {"PolicyDocument": self.inline[parameters["PolicyName"]]}
        raise AssertionError(action)


class UpstreamRoleBootstrapTests(unittest.TestCase):
    def test_only_source_is_allowed_and_all_other_capabilities_explicitly_denied(self):
        c = contract()
        self.assertEqual({"AWS": c.entry_arn}, c.trust["Statement"][0]["Principal"])
        self.assertEqual([{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": c.source_arn}],
                         c.policy["Statement"])
        self.assertEqual({"Effect": "Deny", "NotAction": "sts:AssumeRole", "Resource": "*"},
                         c.boundary["Statement"][1])
        self.assertEqual({"Effect": "Deny", "Action": "sts:AssumeRole", "NotResource": c.source_arn},
                         c.boundary["Statement"][2])
        self.assertNotIn(("sts", "assume-role"), upstream.ALLOWED_APIS)
        self.assertNotIn(("iam", "create-access-key"), upstream.ALLOWED_APIS)
        self.assertFalse(any(action.startswith("delete-") for _, action in upstream.ALLOWED_APIS))

    def test_identity_inputs_cannot_be_users_sessions_other_accounts_or_self(self):
        c = contract()
        for arn in (c.entry_arn.replace(":role/", ":user/"), c.entry_arn.replace(c.account, "999900001111"),
                    c.role_arn, c.source_arn, "arn:aws:sts::111122223333:assumed-role/test/session"):
            with self.assertRaises(ToolError):
                upstream.Contract(c.environment, c.account, arn)
        maximum = upstream.Contract("a" * 52, c.account, c.entry_arn)
        self.assertLessEqual(len(maximum.name), 64)
        self.assertLess(len(json.dumps(maximum.boundary)), 6144)

    def test_no_writes_without_acknowledgement(self):
        with patch.object(upstream, "aws") as aws, self.assertRaises(ToolError):
            upstream.create("profile", contract(), "")
        aws.assert_not_called()

    def test_create_is_exactly_boundary_role_and_single_inline_policy(self):
        state = Inventory()
        with patch.object(upstream, "aws", side_effect=state.aws):
            result = upstream.create("profile", state.c, upstream.ACK)
        self.assertTrue(result["createdRole"])
        self.assertTrue(result["createdBoundary"])
        self.assertFalse(result["sourceExists"])
        self.assertEqual(["create-policy", "create-role", "put-role-policy"], [a for a, _ in state.writes])
        self.assertEqual(state.c.trust, state.role["AssumeRolePolicyDocument"])
        self.assertEqual(3600, state.role["MaxSessionDuration"])

    def test_exact_existing_resources_are_reused_without_writes(self):
        state = Inventory()
        with patch.object(upstream, "aws", side_effect=state.aws):
            upstream.create("profile", state.c, upstream.ACK)
            state.writes.clear()
            result = upstream.create("profile", state.c, upstream.ACK)
        self.assertFalse(result["createdRole"])
        self.assertFalse(result["createdBoundary"])
        self.assertEqual([], state.writes)

    def test_existing_trust_policy_boundary_and_inventory_drift_are_never_overwritten(self):
        for mutation in ("trust", "inline", "boundary", "attached", "missing-inline"):
            state = Inventory()
            with patch.object(upstream, "aws", side_effect=state.aws):
                upstream.create("profile", state.c, upstream.ACK)
                state.writes.clear()
                if mutation == "trust":
                    state.role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] = {"AWS": "*"}
                elif mutation == "inline":
                    state.inline[upstream.INLINE_NAME]["Statement"][0]["Action"] = "*"
                elif mutation == "boundary":
                    state.boundary["Statement"][0]["Action"] = "*"
                elif mutation == "attached":
                    state.attached = [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
                else:
                    state.inline.clear()
                with self.assertRaises(ToolError):
                    upstream.create("profile", state.c, upstream.ACK)
                self.assertEqual([], state.writes)

    def test_access_denied_is_not_treated_as_resource_absence(self):
        with patch.object(upstream, "aws", side_effect=upstream.AWSFailure("AccessDenied")), self.assertRaises(ToolError):
            upstream.optional("profile", "get-role", RoleName=contract().name)

    def test_current_login_must_match_explicit_role_and_stable_role_id(self):
        c = contract()
        caller = {"Account": c.account, "Arn": f"arn:aws:sts::{c.account}:assumed-role/test-entry/session",
                  "UserId": "ROLE-ID:session"}
        role = {"Role": {"RoleName": "test-entry", "RoleId": "ROLE-ID", "Arn": c.entry_arn}}
        with patch.object(upstream, "aws", side_effect=[caller, role]):
            self.assertEqual((c.account, c.entry_arn), upstream.current_role("profile", "test-entry"))
        with patch.object(upstream, "aws", return_value=caller), self.assertRaises(ToolError):
            upstream.current_role("profile", "different-entry")
        role["Role"]["RoleId"] = "WRONG-ID"
        with patch.object(upstream, "aws", side_effect=[caller, role]), self.assertRaises(ToolError):
            upstream.current_role("profile", "test-entry")

    def test_invalid_response_and_timeout_do_not_echo_credentials(self):
        result = subprocess.CompletedProcess([], 0, "secret-test-only", "")
        with patch.object(upstream.subprocess, "run", return_value=result) as run, self.assertRaises(ToolError) as error:
            upstream.aws("profile", "sts", "get-caller-identity")
        self.assertNotIn("secret-test-only", str(error.exception))
        self.assertEqual(40, run.call_args.kwargs["timeout"])
        with patch.object(upstream.subprocess, "run", side_effect=subprocess.TimeoutExpired("aws", 40)), self.assertRaises(ToolError):
            upstream.aws("profile", "sts", "get-caller-identity")

    def test_simulation_never_accepts_a_negative_case_as_allowed(self):
        def aws(profile, service, action, **parameters):
            return {"EvaluationResults": [{"EvalDecision": "allowed", "MissingContextValues": [],
                "EvalActionName": parameters["ActionNames"][0], "EvalResourceName": parameters["ResourceArns"][0],
                "PermissionsBoundaryDecisionDetail": {"AllowedByPermissionsBoundary": True}}]}
        with patch.object(upstream, "aws", side_effect=aws) as run, self.assertRaisesRegex(ToolError, "expected allow/deny"):
            upstream.simulate("profile", contract())
        self.assertEqual(2, run.call_count)

    def test_uncertain_create_response_never_triggers_automatic_delete(self):
        state = Inventory()
        original = state.aws
        def aws(*args, **kwargs):
            if args[2] == "create-role":
                original(*args, **kwargs)
                raise upstream.AWSFailure("InvalidResponse")
            return original(*args, **kwargs)
        with patch.object(upstream, "aws", side_effect=aws), self.assertRaises(ToolError):
            upstream.create("profile", state.c, upstream.ACK)
        self.assertIsNotNone(state.role)
        self.assertEqual(["create-policy", "create-role"], [a for a, _ in state.writes])
        self.assertEqual({}, state.inline)


if __name__ == "__main__":
    unittest.main()
