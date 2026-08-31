#!/usr/bin/env python3
"""Compile an OFFLINE, pending-review source role and boundary preparation pack.

No AWS/Kubernetes API calls, credentials or automatic approval. Generated
CloudFormation is deliberately separate from every Kustomize/XR entrypoint.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from typing import Any

from common import EKS_ROOT, ToolError, load_yaml
from render_cluster import render
from renew_management_credentials import (
    BootstrapContract, ROLE_ARN_RE, canonical, resolve_template, template_digest, validate_contract,
)

ROOT = EKS_ROOT / "management-aws-auth"
BASELINES = ROOT / "aws-managed-policy-baselines.json"
TEMPLATE = ROOT / "source-and-boundaries.template.yaml"
SYNTHETIC_ACCOUNT = "000000000000"
SYNTHETIC_ENVIRONMENT = "eks-boundary-env"
RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"
BOUNDARY_SUFFIXES = ("xp-source", "xp-bootstrap", "eks-control", "fargate-pod", "ec2-node", "karpenter", "cilium")


def document(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def role_contract(environment: str, account: str) -> BootstrapContract:
    prefix = f"arn:aws:iam::{account}:"
    contract = BootstrapContract(
        environment, "us-east-1", "kind-kube-nebula-a",
        prefix + f"role/platform-bootstrap/{environment}-xp-source",
        prefix + f"role/{environment}-xp-aws", prefix + f"role/{environment}-eks-deploy",
        prefix + f"policy/{environment}-xp-bootstrap-boundary",
    )
    validate_contract(contract)
    return contract


def controller_policies(environment: str, account: str) -> dict[str, Any]:
    """Render only to derive RolePolicy documents, never export the synthetic XR.

    OIDC/endpoint/CA observations are synthetic because these policies do not
    depend on the eventual issuer. Reject any synthetic value escaping the result.
    """
    contract = role_contract(environment, account)
    instance = {
        "apiVersion": "platform.aws.goodnotes.io/v1alpha1", "kind": "XEKSCluster",
        "metadata": {"name": environment + "-cluster"},
        "spec": {"parameters": {
            "environmentRef": {"name": environment}, "networkRef": {"name": environment + "-network"},
            "managementNamespace": "crossplane-system", "region": "us-east-1",
            "kubernetesVersion": load_yaml(EKS_ROOT / "versions.lock.yaml")["targets"]["workloadPlane"]["eksKubernetes"],
            "providerConfigRef": {"kind": "ClusterProviderConfig", "name": "boundary-compiler-only"},
            "lifecycle": {"deletionProtection": True},
            "access": {"adminPrincipalArn": contract.provider_role_arn,
                       "deploymentPrincipalArn": contract.deployment_role_arn, "publicAccessCidrs": ["192.0.2.1/32"]},
        }},
    }
    observed = {
        "eks-control-plane": {"Resource": {"status": {"atProvider": {
            "identity": [{"oidc": [{"issuer": "https://boundary-compiler.invalid/id/UNUSED"}]}],
        }}}},
        "eks-oidc-provider": {"Resource": {"status": {"atProvider": {
            "arn": f"arn:aws:iam::{account}:oidc-provider/boundary-compiler.invalid/id/UNUSED",
        }}}},
    }
    names = {"karpenter-controller-policy": "karpenter", "cilium-operator-policy": "cilium"}
    result = {}
    for item in render(instance, observed)["items"]:
        name = item["metadata"]["annotations"].get(RESOURCE_NAME)
        if item.get("kind") == "RolePolicy" and name in names:
            result[names[name]] = json.loads(item["spec"]["forProvider"]["policy"])
    if set(result) != set(names.values()) or "boundary-compiler" in json.dumps(result):
        raise ToolError("controller policy derivation incomplete or synthetic material escaped")
    return result


def boundary_documents(environment: str, account: str) -> dict[str, Any]:
    contract = role_contract(environment, account)
    resources = resolve_template(contract)["Resources"]
    statements = []
    for resource in resources.values():
        props = resource["Properties"]
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            statements += props["PolicyDocument"]["Statement"]
        elif resource["Type"] == "AWS::IAM::Role":
            for policy in props["Policies"]:
                statements += policy["PolicyDocument"]["Statement"]
    allowed = set()
    denies = []
    pass_role = []
    for statement in statements:
        if statement["Effect"] == "Deny":
            denies.append(copy.deepcopy(statement))
        else:
            actions = statement["Action"]
            actions = actions if isinstance(actions, list) else [actions]
            allowed.update(action for action in actions if action != "iam:PassRole")
            if "iam:PassRole" in actions:
                # PassRole must retain its exact resources AND service condition
                # even in the action ceiling; never introduce Resource: * here.
                scoped = copy.deepcopy(statement)
                scoped["Action"] = "iam:PassRole"
                pass_role.append(scoped)
    if any("*" in action or "?" in action for action in allowed):
        raise ToolError("bootstrap boundary action cap cannot contain wildcards")
    snapshots = json.loads(BASELINES.read_text())
    baselines = snapshots["policies"]
    control = copy.deepcopy(snapshots["clusterMinimum"]["document"])
    cluster_tag = "kubernetes.io/cluster/" + environment
    # This platform has no legacy in-tree LoadBalancer or volume provisioning.
    # Restrict the documented minimum's tag write to already-owned nodes and one
    # exact tag key/value. Karpenter sets ownership at instance creation.
    control["Statement"][0]["Resource"] = f"arn:aws:ec2:us-east-1:{account}:instance/*"
    control["Statement"][0]["Condition"] = {
        "StringEquals": {"aws:RequestedRegion": "us-east-1",
                         "ec2:ResourceTag/" + cluster_tag: "owned",
                         "aws:RequestTag/" + cluster_tag: "owned"},
        "ForAllValues:StringEquals": {"aws:TagKeys": [cluster_tag]},
        "Null": {"aws:TagKeys": "false"},
    }
    control["Statement"][1]["Condition"] = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
    source = document([{
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Resource": [contract.provider_role_arn, contract.deployment_role_arn],
    }])
    result = {
        "xp-source": source,
        # This is an ACTION CEILING, not a replacement for the exact IAM/network
        # identity policies. Keep self-mutation/region denies in the ceiling too.
        "xp-bootstrap": document([{"Sid": "ReviewedBootstrapActionCeiling", "Effect": "Allow",
                                   "Action": sorted(allowed), "Resource": "*"}] + pass_role + denies),
        "eks-control": control,
        "fargate-pod": copy.deepcopy(baselines["AmazonEKSFargatePodExecutionRolePolicy"]["document"]),
        "ec2-node": document(copy.deepcopy(baselines["AmazonEKSWorkerNodePolicy"]["document"]["Statement"] +
                                          baselines["AmazonEC2ContainerRegistryPullOnly"]["document"]["Statement"])),
        **controller_policies(environment, account),
    }
    for policy in result.values():
        for statement in policy["Statement"]:
            # Sid is non-authorizing metadata. Omit it in boundaries to stay within
            # IAM's 6144-character maximum without widening actions or resources.
            statement.pop("Sid", None)
        if len(json.dumps(policy, separators=(",", ":"), ensure_ascii=True)) > 6144:
            raise ToolError("boundary exceeds IAM managed-policy size limit; do not weaken it to fit")
    return result


def _symbolic(value: Any) -> Any:
    replacements = {
        SYNTHETIC_ENVIRONMENT: "${EnvironmentName}", SYNTHETIC_ACCOUNT: "${AWS::AccountId}",
        "arn:aws:": "arn:${AWS::Partition}:", "us-east-1": "${TargetRegion}",
    }
    if isinstance(value, list):
        return [_symbolic(v) for v in value]
    if isinstance(value, dict):
        return {k: _symbolic(v) for k, v in value.items()}
    if isinstance(value, str):
        changed = value
        for old, new in replacements.items():
            changed = changed.replace(old, new)
        if changed != value:
            return {"Fn::Sub": changed}
    return value


def compile_template() -> dict[str, Any]:
    boundaries = boundary_documents(SYNTHETIC_ENVIRONMENT, SYNTHETIC_ACCOUNT)
    resources = {}
    ids = {}
    for suffix, policy in boundaries.items():
        logical_id = "Boundary" + "".join(part.title() for part in suffix.split("-"))
        ids[suffix] = logical_id
        # Fn::Sub must also substitute dynamic tag keys inside JSON policy text.
        encoded = json.dumps(policy, separators=(",", ":"))
        symbolic = _symbolic(encoded)
        resources[logical_id] = {
            "Type": "AWS::IAM::ManagedPolicy", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
            "Properties": {"ManagedPolicyName": {"Fn::Sub": "${EnvironmentName}-" + suffix + "-boundary"},
                           "PolicyDocument": symbolic},
        }
    source_name = {"Fn::Sub": "${EnvironmentName}-xp-source"}
    resources["RenewableSourceRole"] = {
        "Type": "AWS::IAM::Role", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
        "Properties": {
            "RoleName": source_name, "Path": "/platform-bootstrap/", "MaxSessionDuration": 3600,
            "PermissionsBoundary": {"Ref": ids["xp-source"]},
            "AssumeRolePolicyDocument": document([{
                "Effect": "Allow", "Action": "sts:AssumeRole",
                "Principal": {"AWS": {"Ref": "TrustedOperatorRoleArn"}},
            }]),
            "Policies": [{"PolicyName": "assume-platform-roles",
                          "PolicyDocument": _symbolic(boundaries["xp-source"])}],
            "Tags": [{"Key": "managed-by", "Value": "cloudformation"},
                     {"Key": "platform.aws.goodnotes.io/environment", "Value": {"Ref": "EnvironmentName"}}],
        },
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "PENDING REVIEW: external renewable source role and seven immutable-to-provider permission ceilings. No users, keys or EKS resources.",
        "Metadata": {"ReviewStatus": "PENDING_SECURITY_APPROVAL", "Owner": "ManagementPlaneOperator",
                     "NoAutomaticDeployment": True, "Compiler": "scripts/eks_lifecycle/prepare_identity_boundaries.py"},
        "Parameters": {
            "EnvironmentName": {"Type": "String", "MinLength": 3, "MaxLength": 52,
                                "AllowedPattern": "^[a-z][a-z0-9-]*[a-z0-9]$"},
            "TargetRegion": {"Type": "String", "Default": "us-east-1", "AllowedValues": ["us-east-1"]},
            "TrustedOperatorRoleArn": {"Type": "String", "Description": "Explicitly approved stable upstream role; no IAM user or STS session ARN.",
                                       "AllowedPattern": "^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$"},
        },
        "Resources": resources,
        "Outputs": {
            "SourceRoleArn": {"Value": {"Fn::GetAtt": ["RenewableSourceRole", "Arn"]}},
            "BootstrapBoundaryArn": {"Value": {"Ref": ids["xp-bootstrap"]}},
        },
    }


def review_pack(environment: str, operator_arn: str) -> dict[str, Any]:
    match = ROLE_ARN_RE.fullmatch(operator_arn)
    if not match:
        raise ToolError("explicit stable upstream IAM role ARN required")
    account = match["account"]
    contract = role_contract(environment, account)
    if operator_arn in (contract.source_role_arn, contract.provider_role_arn, contract.deployment_role_arn):
        raise ToolError("upstream must be distinct from all platform identities")
    docs = boundary_documents(environment, account)
    policy_prefix = f"arn:aws:iam::{account}:policy/{environment}-"
    return {
        "reviewStatus": "PENDING_SECURITY_APPROVAL",
        "sessionMode": "on-demand-60m",
        "approvedBy": None,
        "approvedAt": None,
        "sourceRole": {"PermissionsBoundary": policy_prefix + "xp-source-boundary",
                       "AssumeRolePolicyDocument": document([{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                             "Principal": {"AWS": operator_arn}}])},
        "boundaries": {policy_prefix + suffix + "-boundary": body for suffix, body in docs.items()},
        "contract": contract.__dict__,
        "sourceTemplateSha256": template_digest(compile_template()),
        "bootstrapTemplateSha256": template_digest(load_yaml(ROOT / "cloudformation.yaml")),
    }


def check_template() -> None:
    if canonical(compile_template()) != canonical(load_yaml(TEMPLATE)):
        raise ToolError("boundary template is stale; regenerate and re-review")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("template", "check", "review-pack"))
    parser.add_argument("--environment")
    parser.add_argument("--operator-role-arn")
    args = parser.parse_args(argv)
    try:
        if args.mode == "check":
            check_template()
            print("BOUNDARY TEMPLATE MATCH: seven policies and one source role; pending security approval")
        elif args.mode == "template":
            print(json.dumps(compile_template(), indent=2))
        else:
            if not args.environment or not args.operator_role_arn:
                raise ToolError("review-pack requires environment and explicitly chosen upstream role")
            print(json.dumps(review_pack(args.environment, args.operator_role_arn), indent=2))
    except (ToolError, ValueError, KeyError) as error:
        print(f"identity preparation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
