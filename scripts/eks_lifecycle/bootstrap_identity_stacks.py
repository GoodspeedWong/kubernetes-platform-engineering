#!/usr/bin/env python3
"""Explicit, create-only IAM bootstrap via reviewed CloudFormation change sets.

No users, keys, STS AssumeRole, Kubernetes, environment resources, updates,
deletes, automatic rollback or automatic approval of runtime review files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

import bootstrap_upstream_role as upstream
import prepare_identity_boundaries as preparation
from common import ToolError, load_yaml
from renew_management_credentials import expect_document, template_digest

ACK_PLAN = "CREATE-ONLY-IAM-CHANGE-SET"
ACK_EXECUTE = "EXECUTE-ONLY-REVIEWED-IAM-ADDITIONS"
SLRS = {
    "EC2SpotServiceLinkedRole": ("spot.amazonaws.com", "AWSServiceRoleForEC2Spot", "AWSEC2SpotServiceRolePolicy"),
    "EKSServiceLinkedRole": ("eks.amazonaws.com", "AWSServiceRoleForAmazonEKS", "AmazonEKSServiceRolePolicy"),
    "EKSFargateServiceLinkedRole": ("eks-fargate.amazonaws.com", "AWSServiceRoleForAmazonEKSForFargate", "AmazonEKSForFargateServiceRolePolicy"),
}
KINDS = {
    "source": ("source-boundaries", "source-and-boundaries.template.yaml"),
    "bootstrap": ("management-aws-auth", "cloudformation.yaml"),
    "slr": ("service-linked-roles", "service-linked-roles.yaml"),
}
ALLOWED_APIS = {
    ("accessanalyzer", "validate-policy"),
    *(("cloudformation", action) for action in (
        "validate-template", "describe-stacks", "create-change-set", "describe-change-set",
        "get-template", "execute-change-set", "list-stack-resources", "describe-stack-events",
    )),
}


class AWSFailure(ToolError):
    def __init__(self, code: str, missing: bool = False):
        self.code, self.missing = code, missing
        super().__init__(f"AWS {code}; raw response suppressed; read exact targets before retry")


def aws(profile: str, service: str, action: str, **parameters: Any) -> dict:
    if (service, action) not in ALLOWED_APIS:
        raise ToolError("API outside IAM-stack allowlist")
    try:
        result = subprocess.run(
            ["aws", "--profile", profile, "--region", "us-east-1", "--cli-connect-timeout", "10",
             "--cli-read-timeout", "20", service, action, "--cli-input-json", json.dumps(parameters),
             "--output", "json"], capture_output=True, text=True, timeout=45,
            env=upstream._clean_env() | {"AWS_MAX_ATTEMPTS": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AWSFailure("UnavailableOrTimeout") from error
    if result.returncode:
        match = re.search(r"An error occurred \(([A-Za-z0-9]+)\)", result.stderr)
        code = match[1] if match else "CLIError"
        missing = (code in {"ValidationError", "ChangeSetNotFound"}
                   and bool(re.search(r"does not exist|not exist|not found", result.stderr, re.I)))
        raise AWSFailure(code, missing)
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except ValueError as error:
        raise AWSFailure("InvalidResponse") from error


def optional(profile: str, action: str, **parameters: Any) -> dict | None:
    try:
        return aws(profile, "cloudformation", action, **parameters)
    except AWSFailure as error:
        if error.missing:
            return None
        raise


@dataclass
class Bundle:
    kind: str
    identity: upstream.Contract

    @property
    def template(self):
        return load_yaml(preparation.ROOT / KINDS[self.kind][1])

    @property
    def stack(self):
        return self.identity.environment + "-" + KINDS[self.kind][0]

    @property
    def contract(self):
        return preparation.role_contract(self.identity.environment, self.identity.account)

    @property
    def parameters(self):
        common = {"EnvironmentName": self.identity.environment, "TargetRegion": "us-east-1"}
        if self.kind == "source":
            return common | {"TrustedOperatorRoleArn": self.identity.role_arn}
        if self.kind == "bootstrap":
            return common | {"TrustedSourcePrincipalArn": self.contract.source_role_arn,
                             "PermissionsBoundaryArn": self.contract.boundary_arn,
                             "MaxSessionDurationSeconds": "3600"}
        return {"Create" + name: "true" for name in SLRS}

    @property
    def digest(self):
        return hashlib.sha256(json.dumps({"template": self.template, "parameters": self.parameters},
                                         sort_keys=True).encode()).hexdigest()

    @property
    def change_set(self):
        return "secure-20260830-" + self.kind + "-" + self.digest[:12]

    def resources(self):
        values = self.parameters | {"AWS::AccountId": self.identity.account, "AWS::Partition": "aws"}

        def render(value):
            if isinstance(value, list):
                return [render(v) for v in value]
            if not isinstance(value, dict):
                return value
            if set(value) == {"Ref"}:
                return values[value["Ref"]]
            if set(value) == {"Fn::Sub"}:
                return re.sub(r"\$\{([^}]+)\}", lambda m: str(values[m[1]]), value["Fn::Sub"])
            return {k: render(v) for k, v in value.items()}

        for name, resource in self.template["Resources"].items():
            if resource["Type"] == "AWS::IAM::ManagedPolicy":
                values[name] = f"arn:aws:iam::{self.identity.account}:policy/" + render(resource["Properties"]["ManagedPolicyName"])
        result = render(self.template["Resources"])
        for resource in result.values():
            props = resource["Properties"]
            if isinstance(props.get("PolicyDocument"), str):
                props["PolicyDocument"] = json.loads(props["PolicyDocument"])
            if resource.get("DeletionPolicy") != "Retain" or resource.get("UpdateReplacePolicy") != "Retain":
                raise ToolError("all bootstrap resources must be retained")
            if resource["Type"] not in {"AWS::IAM::ManagedPolicy", "AWS::IAM::Role", "AWS::IAM::ServiceLinkedRole"}:
                raise ToolError("non-IAM resource in bootstrap bundle")
        return result


def policy_checks(profile: str, bundle: Bundle) -> list[dict]:
    findings = []
    for name, resource in bundle.resources().items():
        props = resource["Properties"]
        documents = []
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            documents.append((name, props["PolicyDocument"], "IDENTITY_POLICY"))
        if resource["Type"] == "AWS::IAM::Role":
            documents += [(name + ":" + p["PolicyName"], p["PolicyDocument"], "IDENTITY_POLICY") for p in props["Policies"]]
            documents.append((name + ":trust", props["AssumeRolePolicyDocument"], "RESOURCE_POLICY"))
        for label, body, kind in documents:
            params = {"policyDocument": json.dumps(body), "policyType": kind, "locale": "EN"}
            if kind == "RESOURCE_POLICY":
                params["validatePolicyResourceType"] = "AWS::IAM::AssumeRolePolicyDocument"
            response = aws(profile, "accessanalyzer", "validate-policy", **params)
            if response.get("nextToken") or response.get("NextToken"):
                raise ToolError("incomplete policy validation response")
            findings += [{"document": label, "type": f["findingType"], "code": f["issueCode"]}
                         for f in response.get("findings", [])]
    if any(f["type"] in {"ERROR", "SECURITY_WARNING", "WARNING"} for f in findings):
        raise ToolError("policy validation requires review: " + json.dumps(findings))
    aws(profile, "cloudformation", "validate-template", TemplateBody=json.dumps(bundle.template))
    return findings


def require_absent(profile: str, bundle: Bundle) -> None:
    for name, resource in bundle.resources().items():
        props = resource["Properties"]
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            arn = f"arn:aws:iam::{bundle.identity.account}:policy/" + props["ManagedPolicyName"]
            found = upstream.optional(profile, "get-policy", PolicyArn=arn)
        else:
            role = SLRS[name][1] if resource["Type"] == "AWS::IAM::ServiceLinkedRole" else props["RoleName"]
            found = upstream.optional(profile, "get-role", RoleName=role)
        if found:
            raise ToolError("target already exists; no adoption, update or recreation: " + name)


def plan(profile: str, bundle: Bundle, acknowledgement: str) -> dict:
    if acknowledgement != ACK_PLAN:
        raise ToolError("change-set creation acknowledgement required")
    existing = optional(profile, "describe-change-set", StackName=bundle.stack, ChangeSetName=bundle.change_set)
    if existing:
        return {"alreadyExists": True, "status": existing["Status"]}
    stack = optional(profile, "describe-stacks", StackName=bundle.stack)
    if stack and (len(stack["Stacks"]) != 1 or stack["Stacks"][0]["StackStatus"] != "REVIEW_IN_PROGRESS"):
        raise ToolError("create-only workflow refuses existing or partially deployed stacks")
    require_absent(profile, bundle)
    findings = policy_checks(profile, bundle)
    aws(profile, "cloudformation", "create-change-set", StackName=bundle.stack,
        ChangeSetName=bundle.change_set, ChangeSetType="CREATE",
        TemplateBody=json.dumps(bundle.template), Capabilities=["CAPABILITY_NAMED_IAM"],
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in bundle.parameters.items()],
        Tags=[{"Key": "managed-by", "Value": "platform-bootstrap"},
              {"Key": "platform.aws.goodnotes.io/environment", "Value": bundle.identity.environment}],
        Description="Explicit operator-approved IAM-only additions; no runtime credentials or environment resources",
        ClientToken="plan-" + bundle.digest)
    return {"createdChangeSet": True, "policySuggestions": findings}


def review(profile: str, bundle: Bundle) -> dict:
    result = aws(profile, "cloudformation", "describe-change-set", StackName=bundle.stack, ChangeSetName=bundle.change_set)
    if result.get("Status") != "CREATE_COMPLETE" or result.get("ExecutionStatus") != "AVAILABLE":
        raise ToolError("change set is not ready: " + str(result.get("Status")) + "/" + str(result.get("ExecutionStatus")))
    if result.get("NextToken") or result.get("RoleARN") or result.get("IncludeNestedStacks"):
        raise ToolError("unexpected pagination, delegated CloudFormation role or nested stack")
    params = {p["ParameterKey"]: p["ParameterValue"] for p in result["Parameters"]}
    if params != bundle.parameters:
        raise ToolError("change-set parameters drift")
    remote = aws(profile, "cloudformation", "get-template", StackName=bundle.stack,
                 ChangeSetName=bundle.change_set, TemplateStage="Original")["TemplateBody"]
    if isinstance(remote, str):
        remote = json.loads(remote)
    if template_digest(remote) != template_digest(bundle.template):
        raise ToolError("uploaded template differs from locally reviewed template")
    expected = {k: r["Type"] for k, r in bundle.resources().items()}
    actual = {}
    for change in result.get("Changes", []):
        resource = change["ResourceChange"]
        if resource["Action"] != "Add" or resource.get("Replacement") in {"True", "Conditional"}:
            raise ToolError("change set contains a non-addition")
        name = resource["LogicalResourceId"]
        if name in actual:
            raise ToolError("duplicate logical resource")
        actual[name] = resource["ResourceType"]
    if actual != expected:
        raise ToolError("change-set resource inventory differs from approved IAM bundle")
    return {"status": "REVIEWED", "additions": actual, "digest": bundle.digest}


def execute(profile: str, bundle: Bundle, acknowledgement: str) -> dict:
    if acknowledgement != ACK_EXECUTE:
        raise ToolError("explicit IAM-only execution acknowledgement required")
    review(profile, bundle)
    require_absent(profile, bundle)
    policy_checks(profile, bundle)
    aws(profile, "cloudformation", "execute-change-set", StackName=bundle.stack,
        ChangeSetName=bundle.change_set, ClientRequestToken="execute-" + bundle.digest, DisableRollback=True)
    return {"executionSubmitted": True, "automaticRollbackDisabled": True}


def verify(profile: str, bundle: Bundle) -> dict:
    stack = aws(profile, "cloudformation", "describe-stacks", StackName=bundle.stack)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        return {"complete": False, "status": stack["StackStatus"]}
    resources = aws(profile, "cloudformation", "list-stack-resources", StackName=bundle.stack)["StackResourceSummaries"]
    expected = bundle.resources()
    if ({r["LogicalResourceId"]: r["ResourceType"] for r in resources} != {k: v["Type"] for k, v in expected.items()}
            or any(r["ResourceStatus"] != "CREATE_COMPLETE" for r in resources)):
        raise ToolError("stack resource inventory or status drift")
    for logical, resource in expected.items():
        props = resource["Properties"]
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            arn = f"arn:aws:iam::{bundle.identity.account}:policy/" + props["ManagedPolicyName"]
            policy = upstream.aws(profile, "iam", "get-policy", PolicyArn=arn)["Policy"]
            if policy["Arn"] != arn or policy["Path"] != "/":
                raise ToolError("policy ARN/path drift")
            body = upstream.aws(profile, "iam", "get-policy-version", PolicyArn=arn,
                                VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]
            expect_document(body, props["PolicyDocument"], "managed policy body")
            continue
        slr = resource["Type"] == "AWS::IAM::ServiceLinkedRole"
        name = SLRS[logical][1] if slr else props["RoleName"]
        role = upstream.aws(profile, "iam", "get-role", RoleName=name)["Role"]
        attached = upstream.aws(profile, "iam", "list-attached-role-policies", RoleName=name)["AttachedPolicies"]
        inline = upstream.aws(profile, "iam", "list-role-policies", RoleName=name)["PolicyNames"]
        if slr:
            service, _, policy_name = SLRS[logical]
            if role["Path"] != f"/aws-service-role/{service}/" or role.get("PermissionsBoundary") or inline:
                raise ToolError("service-linked role path/boundary/inline drift")
            trust = preparation.document([{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}])
            # AWS owns SLR trust metadata and policy versions; compare auth content,
            # not optional Sid, then verify the exact AWS managed policy attachment.
            body = json.loads(json.dumps(role["AssumeRolePolicyDocument"]))
            for statement in body["Statement"]:
                statement.pop("Sid", None)
            expect_document(body, trust, "service-linked trust")
            expected_attached = {f"arn:aws:iam::aws:policy/aws-service-role/{policy_name}"}
        else:
            path = props.get("Path", "/")
            arn = f"arn:aws:iam::{bundle.identity.account}:role{path}{name}"
            if (role["Arn"] != arn or role["Path"] != path or role["MaxSessionDuration"] != 3600
                    or role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") != props["PermissionsBoundary"]):
                raise ToolError("role ARN/path/session/boundary drift")
            expect_document(role["AssumeRolePolicyDocument"], props["AssumeRolePolicyDocument"], "complete role trust")
            policies = {p["PolicyName"]: p["PolicyDocument"] for p in props["Policies"]}
            if set(inline) != set(policies):
                raise ToolError("inline policy inventory drift")
            for policy_name, body in policies.items():
                expect_document(upstream.aws(profile, "iam", "get-role-policy", RoleName=name,
                                             PolicyName=policy_name)["PolicyDocument"], body, "inline policy body")
            expected_attached = set(props.get("ManagedPolicyArns", []))
        if {p["PolicyArn"] for p in attached} != expected_attached:
            raise ToolError("attached managed policy inventory drift")
    return {"complete": True, "status": stack["StackStatus"], "verifiedResources": len(expected)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("validate", "plan", "review", "execute", "verify"))
    parser.add_argument("--kind", choices=KINDS, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--environment", default="eks-dev-spot")
    parser.add_argument("--trusted-entry-role-name", required=True)
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args()
    try:
        preparation.check_template()
        account, entry = upstream.current_role(args.profile, args.trusted_entry_role_name)
        identity = upstream.Contract(args.environment, account, entry)
        if not upstream.inspect(args.profile, identity)["roleExists"]:
            raise ToolError("reviewed upstream role must already exist")
        bundle = Bundle(args.kind, identity)
        if args.mode == "validate":
            result = {"validated": True, "policySuggestions": policy_checks(args.profile, bundle)}
        elif args.mode in {"plan", "execute"}:
            result = globals()[args.mode](args.profile, bundle, args.acknowledge)
        else:
            result = globals()[args.mode](args.profile, bundle)
        print(json.dumps({"stack": bundle.stack, "changeSet": bundle.change_set,
                          "templateSha256": template_digest(bundle.template), **result}, indent=2))
        return 0
    except (ToolError, ValueError, KeyError) as error:
        print(f"IAM bootstrap stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
