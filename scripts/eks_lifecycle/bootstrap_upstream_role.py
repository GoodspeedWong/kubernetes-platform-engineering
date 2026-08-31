#!/usr/bin/env python3
"""Create one least-privilege upstream role with AWS CLI; never issue credentials.

plan performs only reads. apply creates its boundary, role and one inline policy.
Existing resources must match exactly; never overwrite drift or auto-delete on
an uncertain response. This is separate from every environment XR/CloudFormation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

from common import ToolError
from renew_management_credentials import _clean_env, canonical, expect_document

PATH = "/platform-bootstrap/"
INLINE_NAME = "assume-platform-source"
ACK = "CREATE-ONLY-UPSTREAM-ROLE-AND-BOUNDARY"
ALLOWED_APIS = {
    ("sts", "get-caller-identity"),
    *(('iam', action) for action in (
        "get-role", "get-policy", "get-policy-version", "list-policy-tags",
        "list-role-tags", "list-role-policies", "get-role-policy",
        "list-attached-role-policies", "create-policy", "create-role",
        "put-role-policy", "simulate-principal-policy",
    )),
}


class AWSFailure(ToolError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(f"AWS CLI failed: {code}; raw output suppressed; inspect exact targets before retrying")


def aws(profile: str, service: str, action: str, **parameters: Any) -> dict:
    if (service, action) not in ALLOWED_APIS:
        raise ToolError("API outside upstream bootstrap allowlist")
    command = ["aws", "--profile", profile, "--region", "us-east-1",
               "--cli-connect-timeout", "10", "--cli-read-timeout", "20",
               service, action, "--output", "json"]
    if parameters:
        command += ["--cli-input-json", json.dumps(parameters)]
    try:
        result = subprocess.run(command, env=_clean_env() | {"AWS_MAX_ATTEMPTS": "1"},
                                capture_output=True, text=True, timeout=40)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AWSFailure("UnavailableOrTimeout") from error
    if result.returncode:
        match = re.search(r"An error occurred \(([A-Za-z0-9]+)\)", result.stderr)
        raise AWSFailure(match[1] if match else "CLIError")
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except ValueError as error:
        raise AWSFailure("InvalidResponse") from error


def optional(profile: str, action: str, **parameters: Any) -> dict | None:
    try:
        return aws(profile, "iam", action, **parameters)
    except AWSFailure as error:
        if error.code == "NoSuchEntity":
            return None
        raise


def current_role(profile: str, expected_name: str) -> tuple[str, str]:
    caller = aws(profile, "sts", "get-caller-identity")
    match = re.fullmatch(r"arn:aws:sts::([0-9]{12}):assumed-role/([^/]+)/.+", caller.get("Arn", ""))
    if not match or match[1] != caller.get("Account") or match[2] != expected_name:
        raise ToolError("current caller is not the explicitly selected entry role")
    role = aws(profile, "iam", "get-role", RoleName=expected_name)["Role"]
    if (role.get("RoleId") != caller.get("UserId", "").split(":", 1)[0]
            or role.get("RoleName") != expected_name
            or not role.get("Arn", "").startswith(f"arn:aws:iam::{match[1]}:role/")):
        raise ToolError("entry role ID/account/ARN mismatch")
    return match[1], role["Arn"]


@dataclass(frozen=True)
class Contract:
    environment: str
    account: str
    entry_arn: str

    def __post_init__(self):
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,50}[a-z0-9]", self.environment):
            raise ToolError("invalid environment")
        if not re.fullmatch(r"[0-9]{12}", self.account):
            raise ToolError("invalid account")
        if not re.fullmatch(rf"arn:aws:iam::{self.account}:role/[A-Za-z0-9+=,.@_/-]+", self.entry_arn):
            raise ToolError("stable same-account entry role required")
        if self.entry_arn in (self.role_arn, self.source_arn):
            raise ToolError("entry, upstream and source roles must be distinct")

    @property
    def name(self):
        return self.environment + "-xp-upstream"

    @property
    def role_arn(self):
        return f"arn:aws:iam::{self.account}:role{PATH}{self.name}"

    @property
    def source_arn(self):
        return f"arn:aws:iam::{self.account}:role{PATH}{self.environment}-xp-source"

    @property
    def boundary_arn(self):
        return f"arn:aws:iam::{self.account}:policy/{self.name}-boundary"

    @property
    def policy(self):
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": self.source_arn}]}

    @property
    def boundary(self):
        # Explicit denies also constrain direct grants to a role session. They
        # apply to this upstream session, not the newly assumed source session.
        return {"Version": "2012-10-17", "Statement": self.policy["Statement"] + [
            {"Effect": "Deny", "NotAction": "sts:AssumeRole", "Resource": "*"},
            {"Effect": "Deny", "Action": "sts:AssumeRole", "NotResource": self.source_arn},
        ]}

    @property
    def trust(self):
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": self.entry_arn}}]}

    @property
    def tags(self):
        body = {"role": self.role_arn, "trust": self.trust, "boundary": self.boundary}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        return [
            {"Key": "managed-by", "Value": "eks-upstream-bootstrap"},
            {"Key": "platform.aws.goodnotes.io/environment", "Value": self.environment},
            {"Key": "platform.aws.goodnotes.io/owner", "Value": "ManagementPlaneOperator"},
            {"Key": "platform.aws.goodnotes.io/contract-sha256", "Value": digest},
        ]


def verify_boundary(profile: str, c: Contract, response: dict) -> None:
    policy = response["Policy"]
    if policy.get("Arn") != c.boundary_arn or policy.get("Path") != "/":
        raise ToolError("boundary ARN/path drift")
    tags = aws(profile, "iam", "list-policy-tags", PolicyArn=c.boundary_arn)["Tags"]
    if canonical(tags) != canonical(c.tags):
        raise ToolError("refusing an unowned or differently scoped boundary")
    body = aws(profile, "iam", "get-policy-version", PolicyArn=c.boundary_arn,
               VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]
    expect_document(body, c.boundary, "upstream boundary")


def verify_role(profile: str, c: Contract, response: dict, *, new: bool = False) -> None:
    role = response["Role"]
    if (role.get("Arn") != c.role_arn or role.get("Path") != PATH
            or role.get("MaxSessionDuration") != 3600
            or role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") != c.boundary_arn):
        raise ToolError("upstream role ARN/path/session/boundary drift")
    expect_document(role["AssumeRolePolicyDocument"], c.trust, "upstream trust")
    tags = aws(profile, "iam", "list-role-tags", RoleName=c.name)["Tags"]
    if canonical(tags) != canonical(c.tags):
        raise ToolError("refusing an unowned or differently scoped upstream role")
    if aws(profile, "iam", "list-attached-role-policies", RoleName=c.name)["AttachedPolicies"]:
        raise ToolError("upstream role must have no attached permission policies")
    names = aws(profile, "iam", "list-role-policies", RoleName=c.name)["PolicyNames"]
    if set(names) != (set() if new else {INLINE_NAME}):
        raise ToolError("upstream inline inventory drift; refusing to overwrite")
    if not new:
        body = aws(profile, "iam", "get-role-policy", RoleName=c.name,
                   PolicyName=INLINE_NAME)["PolicyDocument"]
        expect_document(body, c.policy, "upstream inline policy")


def inspect(profile: str, c: Contract) -> dict:
    role = optional(profile, "get-role", RoleName=c.name)
    boundary = optional(profile, "get-policy", PolicyArn=c.boundary_arn)
    if boundary:
        verify_boundary(profile, c, boundary)
    if role:
        if not boundary:
            raise ToolError("existing upstream role has no reviewed boundary")
        verify_role(profile, c, role)
    source = optional(profile, "get-role", RoleName=c.environment + "-xp-source")
    if source and source["Role"]["Arn"] != c.source_arn:
        raise ToolError("source role name exists at an unexpected path")
    return {"roleExists": bool(role), "boundaryExists": bool(boundary), "sourceExists": bool(source)}


def wait_read(profile: str, action: str, **parameters: Any) -> dict:
    for attempt in range(5):
        response = optional(profile, action, **parameters)
        if response:
            return response
        if attempt != 4:
            time.sleep(2)
    raise ToolError("IAM read-after-write not visible; inspect targets, do not blindly recreate")


def create(profile: str, c: Contract, acknowledgement: str) -> dict:
    if acknowledgement != ACK:
        raise ToolError("explicit upstream-only creation acknowledgement required")
    before = inspect(profile, c)
    if not before["boundaryExists"]:
        aws(profile, "iam", "create-policy", PolicyName=c.name + "-boundary", Path="/",
            Description="Only the dedicated platform source role may be assumed",
            PolicyDocument=json.dumps(c.boundary), Tags=c.tags)
        verify_boundary(profile, c, wait_read(profile, "get-policy", PolicyArn=c.boundary_arn))
    if not before["roleExists"]:
        created = aws(profile, "iam", "create-role", RoleName=c.name, Path=PATH,
                      Description="Non-admin EKS platform upstream entry; source role only",
                      AssumeRolePolicyDocument=json.dumps(c.trust), MaxSessionDuration=3600,
                      PermissionsBoundary=c.boundary_arn, Tags=c.tags)
        role = wait_read(profile, "get-role", RoleName=c.name)
        if role["Role"].get("RoleId") != created.get("Role", {}).get("RoleId"):
            raise ToolError("created role ID differs from readback; no policy written")
        verify_role(profile, c, role, new=True)
        aws(profile, "iam", "put-role-policy", RoleName=c.name, PolicyName=INLINE_NAME,
            PolicyDocument=json.dumps(c.policy))
    after = inspect(profile, c)
    return {"createdRole": not before["roleExists"], "createdBoundary": not before["boundaryExists"], **after}


def simulate(profile: str, c: Contract) -> list[dict]:
    scenarios = [
        ("sts:AssumeRole", c.source_arn, "allowed"),
        ("sts:AssumeRole", c.entry_arn, "explicitDeny"),
        ("sts:AssumeRole", f"arn:aws:iam::{c.account}:role/{c.environment}-xp-aws", "explicitDeny"),
        ("iam:PutRolePolicy", c.role_arn, "explicitDeny"),
        ("iam:DeleteRolePermissionsBoundary", c.role_arn, "explicitDeny"),
        ("ec2:RunInstances", "*", "explicitDeny"),
    ]
    results = []
    for action, resource, expected in scenarios:
        response = aws(profile, "iam", "simulate-principal-policy", PolicySourceArn=c.role_arn,
                       ActionNames=[action], ResourceArns=[resource])
        evaluations = response.get("EvaluationResults", [])
        if len(evaluations) != 1 or evaluations[0].get("EvalDecision") != expected:
            raise ToolError("upstream IAM simulation differs from expected allow/deny")
        if (evaluations[0].get("EvalActionName") != action
                or evaluations[0].get("EvalResourceName") != resource):
            raise ToolError("simulation returned a different action or resource")
        boundary_allowed = evaluations[0].get("PermissionsBoundaryDecisionDetail", {}).get("AllowedByPermissionsBoundary")
        if boundary_allowed is not (expected == "allowed"):
            raise ToolError("simulation did not confirm the actual boundary decision")
        if evaluations[0].get("MissingContextValues"):
            raise ToolError("incomplete simulation context")
        results.append({"action": action, "resource": resource.replace(c.account, "<ACCOUNT_ID>"),
                        "decision": expected, "allowedByBoundary": boundary_allowed})
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "apply", "verify"))
    parser.add_argument("--profile", required=True)
    parser.add_argument("--environment", default="eks-dev-spot")
    parser.add_argument("--trusted-entry-role-name", required=True)
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args(argv)
    try:
        account, entry = current_role(args.profile, args.trusted_entry_role_name)
        c = Contract(args.environment, account, entry)
        if args.mode == "apply":
            result = create(args.profile, c, args.acknowledge)
        else:
            result = inspect(args.profile, c)
        if args.mode in ("apply", "verify"):
            if not result["roleExists"] or not result["boundaryExists"]:
                raise ToolError("upstream role/boundary not present")
            result["simulation"] = simulate(args.profile, c)
        result.update(mode=args.mode, roleArn=c.role_arn.replace(account, "<ACCOUNT_ID>"),
                      trustedEntryRole=entry.replace(account, "<ACCOUNT_ID>"),
                      maximumSessionSeconds=3600, accessKeyCreated=False, stsSessionIssued=False,
                      kubernetesMutation=False, sourceRoleMutation=False)
        print(json.dumps(result, indent=2))
        return 0
    except (ToolError, KeyError, ValueError) as error:
        message = str(error) if isinstance(error, ToolError) else "invalid AWS response; output suppressed"
        print(message, file=sys.stderr)
        print("No automatic rollback. Created partial resources may remain; inspect only the exact upstream targets.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
