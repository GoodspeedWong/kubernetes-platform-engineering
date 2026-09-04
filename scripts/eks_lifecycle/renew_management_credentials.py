#!/usr/bin/env python3
"""One-shot management sessions; the historical renew entry point is disabled.

IAM verification helpers retain their import path. Prefer open_management_session.py.
Source credentials stay on the host; only bounded target-role sessions are published.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote

from common import EKS_ROOT, ToolError, load_yaml, require_tool

SOURCE_NAMESPACE = "crossplane-system"
REMOTE_SECRET_NAME = "eks-platform-aws-session"
ACKNOWLEDGEMENT = "I-APPROVE-ONE-SHOT-60-MINUTE-SESSION-AND-PROVIDER-ROLLOUT"
SESSION_MODE = "on-demand-60m"
MAX_SESSION_SECONDS = 3600
SESSION_PROGRESS_STAGES = (
    "SESSION_PUBLICATION_GATE_VERIFIED",
    "SESSION_IAM_VERIFIED",
    "SESSION_SOURCE_EXPORTED",
    "SESSION_TARGETS_ASSUMED",
    "SESSION_SECRET_PUBLISHED",
)
TAG_PREFIX = "platform.aws.goodnotes.io/"
ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(?P<account>[0-9]{12}):role/(?P<name>[A-Za-z0-9+=,.@_/-]+)$")
BOUNDARY_RE = re.compile(r"^arn:aws:iam::[0-9]{12}:policy/[A-Za-z0-9+=,.@_/-]+$")
CHILD_ROLES = ("eks-control", "fargate-pod", "ec2-node", "karpenter", "cilium")
# These are Provider object names, not package repository basenames. Preserve the
# installed shared providers and the separately declared SQS/EventBridge owners.
PROVIDERS = (
    "provider-helm", "provider-kubernetes",
    "crossplane-contrib-provider-aws-ec2",
    "crossplane-contrib-provider-aws-eks",
    "crossplane-contrib-provider-aws-iam",
    "upbound-provider-aws-sqs",
    "upbound-provider-aws-cloudwatchevents",
)
AUTH_ROOT = EKS_ROOT / "management-aws-auth"
REVIEW_TEMPLATES = {
    "sourceTemplateSha256": AUTH_ROOT / "source-and-boundaries.template.yaml",
    "bootstrapTemplateSha256": AUTH_ROOT / "cloudformation.yaml",
}


@dataclass(frozen=True)
class BootstrapContract:
    environment: str
    region: str
    context: str
    source_role_arn: str
    provider_role_arn: str
    deployment_role_arn: str
    boundary_arn: str

    @property
    def provider_secret_name(self) -> str:
        return REMOTE_SECRET_NAME


@dataclass(frozen=True)
class TargetSessions:
    execution: dict[str, Any]
    deployment: dict[str, Any]
    deadline: datetime


def validate_contract(contract: BootstrapContract) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,50}[a-z0-9]", contract.environment):
        raise ToolError("invalid environment name")
    if contract.region != "us-east-1" or contract.context != "kind-kube-nebula-a":
        raise ToolError("only us-east-1 / kind-kube-nebula-a is reviewed")
    arns = (contract.source_role_arn, contract.provider_role_arn, contract.deployment_role_arn)
    roles = [ROLE_ARN_RE.fullmatch(x) for x in arns]
    if not all(roles) or len({x.group("account") for x in roles}) != 1 or len(set(arns)) != 3:
        raise ToolError("three distinct stable same-account IAM role ARNs are required")
    for role, suffix in zip(roles[1:], ("xp-aws", "eks-deploy")):
        if role.group("name") != f"{contract.environment}-{suffix}":
            raise ToolError("target role does not match environment")
    account = roles[0].group("account")
    if not BOUNDARY_RE.fullmatch(contract.boundary_arn) or f"::{account}:" not in contract.boundary_arn:
        raise ToolError("explicit same-account bootstrap boundary required")
    return account


def public_plan(contract: BootstrapContract) -> dict[str, Any]:
    validate_contract(contract)
    return {"mode": "plan", "environment": contract.environment, "region": contract.region,
            "managementContext": contract.context,
            "providerSecret": f"{SOURCE_NAMESPACE}/{REMOTE_SECRET_NAME}",
            "remoteSecret": f"{SOURCE_NAMESPACE}/{REMOTE_SECRET_NAME}",
            "accessKeyCreated": False, "credentialMaterialPrinted": False,
            "awsMutation": False, "kubernetesMutation": False,
            "sessionMode": SESSION_MODE, "maxWindowSeconds": MAX_SESSION_SECONDS,
            "automaticRenewal": False, "sourceCredentialsPublished": False,
            "requiredProviderNames": list(PROVIDERS),
            "requires": ["complete reviewed IAM/boundary documents", "manual dedicated source login",
                         "on-demand runtime approval", "opted-in provider rollout window"]}


def _clean_env() -> dict[str, str]:
    # Ambient admin credentials must never override the selected source profile.
    return {k: v for k, v in os.environ.items() if not k.startswith("AWS_")} | {
        "AWS_EC2_METADATA_DISABLED": "true", "AWS_PAGER": "", "AWS_CLI_AUTO_PROMPT": "off",
        "AWS_MAX_ATTEMPTS": "1"}


def _run_json(command: list[str], *, input_text: str | None = None,
              env: dict[str, str] | None = None) -> Any:
    try:
        result = subprocess.run(command, input=input_text, text=True, capture_output=True,
                                check=False, timeout=45, env=env or _clean_env())
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolError(f"{command[0]} unavailable or timed out; output suppressed") from error
    # Error streams may echo Secret payloads, not just access key IDs.
    if result.returncode:
        raise ToolError(f"{command[0]} failed (exit {result.returncode}); output suppressed")
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as error:
        raise ToolError(f"{command[0]} returned invalid JSON; output suppressed") from error


def _aws(profile: str, region: str, *args: str) -> Any:
    operation = "unknown"
    if (
        len(args) >= 2
        and re.fullmatch(r"[a-z0-9-]+", args[0])
        and re.fullmatch(r"[a-z0-9-]+", args[1])
    ):
        operation = f"{args[0]}:{args[1]}"
    try:
        return _run_json(
            ["aws", "--profile", profile, "--region", region, *args, "--output", "json"]
        )
    except ToolError as error:
        raise ToolError(
            f"AWS read-only operation {operation} failed; output suppressed"
        ) from error


def _report_session_progress(
    progress: Callable[[str], None] | None,
    stage: str,
) -> None:
    if stage not in SESSION_PROGRESS_STAGES:
        raise ToolError("unreviewed management-session progress stage")
    if progress is not None:
        progress(stage)


def canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return sorted((canonical(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def policy_document(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except json.JSONDecodeError as error:
            raise ToolError("invalid encoded policy document") from error
    if not isinstance(value, dict) or value.get("Version") != "2012-10-17" or not value.get("Statement"):
        raise ToolError("review requires a complete nonempty policy document")
    return value


def expect_document(actual: Any, expected: Any, label: str) -> None:
    if canonical(policy_document(actual)) != canonical(policy_document(expected)):
        raise ToolError(f"IAM drift detected: {label}; refusing publication")


def template_digest(template: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(template, sort_keys=True).encode()).hexdigest()


def verify_review_approval(contract: BootstrapContract, review: dict[str, Any]) -> None:
    """Reject draft/mixed/stale review packs before any AWS call.

    This is an operator attestation, not a cryptographic approval service. The
    reviewed file and repository checkout must be protected by the operator.
    """
    if review.get("reviewStatus") != "APPROVED":
        raise ToolError("explicit security approval required; draft review pack cannot run")
    reviewer = review.get("approvedBy")
    if (not isinstance(reviewer, str) or not reviewer.strip()
            or any(marker in reviewer for marker in ("__REPLACE", "<", ">", "\n", "\r"))):
        raise ToolError("review must identify its approving reviewer")
    try:
        approved = datetime.fromisoformat(review["approvedAt"].replace("Z", "+00:00"))
        if approved.tzinfo is None or approved > datetime.now(timezone.utc):
            raise ValueError("invalid approval time")
    except (KeyError, AttributeError, ValueError, TypeError) as error:
        raise ToolError("review requires a past timezone-qualified approval time") from error
    if review.get("contract") != contract.__dict__:
        raise ToolError("review contract differs from requested identity/environment")
    for field, path in REVIEW_TEMPLATES.items():
        if review.get(field) != template_digest(load_yaml(path)):
            raise ToolError("review template digest is stale; re-review before publication")


def resolve_template(contract: BootstrapContract) -> dict[str, Any]:
    account = validate_contract(contract)
    template = load_yaml(EKS_ROOT / "management-aws-auth/cloudformation.yaml")
    values = {"EnvironmentName": contract.environment, "TargetRegion": contract.region,
              "TrustedSourcePrincipalArn": contract.source_role_arn,
              "PermissionsBoundaryArn": contract.boundary_arn, "MaxSessionDurationSeconds": 3600,
              "AWS::Partition": "aws", "AWS::AccountId": account}

    def render(value: Any) -> Any:
        if isinstance(value, list):
            return [render(v) for v in value]
        if not isinstance(value, dict):
            return value
        if set(value) == {"Ref"}:
            return values[value["Ref"]]
        if set(value) == {"Fn::Sub"}:
            return re.sub(r"\$\{([^}]+)\}", lambda m: str(values[m[1]]), value["Fn::Sub"])
        if set(value) == {"Fn::GetAtt"}:
            name, attribute = value["Fn::GetAtt"]
            if attribute != "Arn":
                raise ToolError("unsupported template attribute")
            return f"arn:aws:iam::{account}:role/{values[name]}"
        return {k: render(v) for k, v in value.items()}

    for name, resource in template["Resources"].items():
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            values[name] = f"arn:aws:iam::{account}:policy/" + render(resource["Properties"]["ManagedPolicyName"])
        elif resource["Type"] == "AWS::IAM::Role":
            values[name] = render(resource["Properties"]["RoleName"])
    return render(template)


def verify_aws_identity(contract: BootstrapContract, audit_profile: str, review: dict[str, Any]) -> None:
    """Read full trust, inline/attached policy bodies and boundaries on every open."""
    account = validate_contract(contract)
    verify_review_approval(contract, review)
    def read(*args: str) -> Any:
        return _aws(audit_profile, contract.region, *args)
    if read("sts", "get-caller-identity").get("Account") != account:
        raise ToolError("audit profile account mismatch")
    rendered = resolve_template(contract)["Resources"]
    boundaries = review.get("boundaries", {})
    required = {contract.boundary_arn} | {
        f"arn:aws:iam::{account}:policy/{contract.environment}-{suffix}-boundary" for suffix in CHILD_ROLES}
    source = review.get("sourceRole", {})
    source_boundary = source.get("PermissionsBoundary")
    if not BOUNDARY_RE.fullmatch(source_boundary or ""):
        raise ToolError("review must include a source-role boundary")
    required.add(source_boundary)
    if set(boundaries) != required:
        raise ToolError("review must contain exactly all source/bootstrap/child boundaries")
    managed = {f"arn:aws:iam::{account}:policy/{r['Properties']['ManagedPolicyName']}": r["Properties"]["PolicyDocument"]
               for r in rendered.values() if r["Type"] == "AWS::IAM::ManagedPolicy"}
    if set(managed) & set(boundaries):
        raise ToolError("bootstrap policies cannot double as externally reviewed boundaries")
    for arn, expected in {**managed, **boundaries}.items():
        if not BOUNDARY_RE.fullmatch(arn) or f"::{account}:" not in arn:
            raise ToolError("reviewed policy must belong to target account")
        policy = read("iam", "get-policy", "--policy-arn", arn)["Policy"]
        if policy.get("Arn") != arn:
            raise ToolError("managed policy ARN mismatch")
        body = read("iam", "get-policy-version", "--policy-arn", arn,
                    "--version-id", policy["DefaultVersionId"])["PolicyVersion"]["Document"]
        expect_document(body, expected, "managed policy or boundary")
    source_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                     "Resource": [contract.provider_role_arn, contract.deployment_role_arn]}]}
    expected_roles = [(contract.source_role_arn, {
        "AssumeRolePolicyDocument": source.get("AssumeRolePolicyDocument"),
        "PermissionsBoundary": source_boundary,
        "Policies": [{"PolicyName": "assume-platform-roles", "PolicyDocument": source_policy}],
    })] + [(arn, rendered[name]["Properties"]) for arn, name in (
        (contract.provider_role_arn, "CrossplaneAWSProviderRole"), (contract.deployment_role_arn, "EKSDeploymentRole"))]
    for arn, expected in expected_roles:
        name = arn.rsplit("/", 1)[1]
        actual = read("iam", "get-role", "--role-name", name)["Role"]
        if (actual.get("Arn") != arn or actual.get("MaxSessionDuration") != 3600
                or actual.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") != expected["PermissionsBoundary"]):
            raise ToolError("role ARN, session duration or boundary drift")
        expect_document(actual.get("AssumeRolePolicyDocument"), expected["AssumeRolePolicyDocument"], "complete trust")
        attached = read("iam", "list-attached-role-policies", "--role-name", name).get("AttachedPolicies", [])
        if {p["PolicyArn"] for p in attached} != set(expected.get("ManagedPolicyArns", [])):
            raise ToolError("attached policy inventory drift")
        inline = {p["PolicyName"]: p["PolicyDocument"] for p in expected["Policies"]}
        if set(read("iam", "list-role-policies", "--role-name", name).get("PolicyNames", [])) != set(inline):
            raise ToolError("inline policy inventory drift")
        for policy_name, body in inline.items():
            expect_document(read("iam", "get-role-policy", "--role-name", name,
                                 "--policy-name", policy_name)["PolicyDocument"], body, "inline policy body")


def validate_session(session: dict[str, Any], now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"):
        if not isinstance(session.get(field), str) or not session[field] or any(c in session[field] for c in "\r\n"):
            raise ToolError("complete temporary credentials with expiry required")
    if not session["AccessKeyId"].startswith("ASIA"):
        raise ToolError("long-lived access keys are forbidden")
    try:
        expiry = datetime.fromisoformat(session["Expiration"].replace("Z", "+00:00"))
        ttl = (expiry - now).total_seconds()
    except (ValueError, TypeError) as error:
        raise ToolError("invalid credential expiry") from error
    if not 600 <= ttl <= MAX_SESSION_SECONDS:
        raise ToolError("temporary session needs 10 to 60 minutes remaining")
    return expiry


def session_environment(session: dict[str, Any]) -> dict[str, str]:
    return _clean_env() | {"AWS_ACCESS_KEY_ID": session["AccessKeyId"],
                          "AWS_SECRET_ACCESS_KEY": session["SecretAccessKey"], "AWS_SESSION_TOKEN": session["SessionToken"]}


def verify_caller(contract: BootstrapContract, session: dict[str, Any], arn: str) -> None:
    validate_session(session)
    account = validate_contract(contract)
    caller = _run_json(["aws", "--region", contract.region, "sts", "get-caller-identity",
                        "--output", "json"], env=session_environment(session))
    prefix = f"arn:aws:sts::{account}:assumed-role/{arn.rsplit('/', 1)[1]}/"
    if caller.get("Account") != account or not caller.get("Arn", "").startswith(prefix):
        raise ToolError("exported/assumed session identity mismatch")


def verify_session(contract: BootstrapContract, session: dict[str, Any]) -> TargetSessions:
    """Assume each target ONCE; do not give the source chain to a Provider SDK."""
    verify_caller(contract, session, contract.source_role_arn)
    deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_SESSION_SECONDS)
    targets = []
    for arn in (contract.provider_role_arn, contract.deployment_role_arn):
        # Reserve time for request latency; verify AWS's actual expiry afterwards.
        duration = int((deadline - datetime.now(timezone.utc)).total_seconds()) - 30
        if not 900 <= duration <= MAX_SESSION_SECONDS:
            raise ToolError("insufficient time to issue a bounded management session")
        assumed = _run_json(["aws", "--region", contract.region, "sts", "assume-role", "--role-arn", arn,
            "--role-session-name", "eks-manual-session", "--duration-seconds", str(duration),
            "--output", "json"], env=session_environment(session))
        target = assumed.get("Credentials", {})
        if validate_session(target) > deadline:
            raise ToolError("AWS returned a target session beyond the approved deadline")
        verify_caller(contract, target, arn)
        targets.append(target)
    result = TargetSessions(*targets, deadline)
    validate_targets(result)
    return result


def validate_targets(sessions: TargetSessions) -> tuple[datetime, datetime]:
    if not isinstance(sessions, TargetSessions) or sessions.deadline.tzinfo is None:
        raise ToolError("bounded execution and deployment sessions required; source publication forbidden")
    expiries = [validate_session(s) for s in (sessions.execution, sessions.deployment)]
    if max(expiries) > sessions.deadline or sessions.execution["AccessKeyId"] == sessions.deployment["AccessKeyId"]:
        raise ToolError("distinct target sessions within the approved deadline required")
    return min(expiries), max(expiries)


def session_labels(environment: str) -> dict[str, str]:
    return {TAG_PREFIX + "environment": environment,
            TAG_PREFIX + "managed-by": "on-demand-session-publisher"}


def secret_document(contract: BootstrapContract, sessions: TargetSessions) -> dict[str, Any]:
    first, last = validate_targets(sessions)
    credentials = ""
    for profile, session in (("default", sessions.execution), ("eks-deployment", sessions.deployment)):
        credentials += f"[{profile}]\n" + "\n".join(("aws_access_key_id=" + session["AccessKeyId"],
            "aws_secret_access_key=" + session["SecretAccessKey"], "aws_session_token=" + session["SessionToken"])) + "\n"
    config = f"[default]\nregion={contract.region}\n[profile eks-deployment]\nregion={contract.region}\n"
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {
        "name": REMOTE_SECRET_NAME, "namespace": SOURCE_NAMESPACE,
        "labels": session_labels(contract.environment),
        "annotations": {TAG_PREFIX + "session-mode": SESSION_MODE,
                        TAG_PREFIX + "expires-at": first.isoformat(),
                        TAG_PREFIX + "all-expires-at": last.isoformat(),
                        TAG_PREFIX + "deadline": sessions.deadline.isoformat()},
    }, "data": {k: base64.b64encode(v.encode()).decode() for k, v in {"credentials": credentials, "config": config}.items()}}


def verify_explicit_provider_rbac() -> None:
    # Re-check live effective permissions before every changed-session publication.
    # A new package/revision needs an explicit inventory and permission review.
    import manage_provider_rbac
    manage_provider_rbac.audit(manage_provider_rbac.inventory())


def verify_direct_session_runtime(contract: BootstrapContract) -> None:
    """Refuse the old in-cluster source->target chain and unreviewed runtimes."""
    base = ["kubectl", "--context", contract.context]
    runtimes = {"eks-remote-auth": "runtime-config.yaml", "eks-aws-session": "aws-session-runtime.yaml"}
    for name, filename in runtimes.items():
        actual = _run_json(base + ["get", "deploymentruntimeconfigs.pkg.crossplane.io", name, "-o", "json"])
        expected = load_yaml(EKS_ROOT / "management-auth" / filename)
        if canonical(actual.get("spec")) != canonical(expected["spec"]):
            raise ToolError("direct-session DeploymentRuntimeConfig differs from reviewed source")
    providers = _run_json(base + ["get", "providers.pkg.crossplane.io", "-o", "json"]).get("items", [])
    by_name = {p["metadata"]["name"]: p for p in providers}
    for name in PROVIDERS:
        wanted = "eks-remote-auth" if name in ("provider-helm", "provider-kubernetes") else "eks-aws-session"
        if by_name.get(name, {}).get("spec", {}).get("runtimeConfigRef", {}).get("name") != wanted:
            raise ToolError("all seven Providers must reference the reviewed direct-session runtimes")
    configs = _run_json(base + ["get", "clusterproviderconfigs.aws.m.upbound.io", "-o", "json"]).get("items", [])
    matching = []
    for config in configs:
        spec = config.get("spec", {})
        ref = spec.get("credentials", {}).get("secretRef", {})
        if ref.get("name") == REMOTE_SECRET_NAME and ref.get("namespace") == SOURCE_NAMESPACE:
            matching.append(spec)
            if (spec.get("assumeRoleChain") or spec.get("profile")
                    or spec.get("credentials", {}).get("source") != "Secret" or ref.get("key") != "credentials"
                    or spec.get("skip_metadata_api_check") is not True):
                raise ToolError("AWS ProviderConfig must consume the execution session directly without a role chain")
    if not matching:
        raise ToolError("no direct-session AWS ClusterProviderConfig is installed")


def session_metadata(context: str) -> dict[str, Any] | None:
    current = _run_json(["kubectl", "--context", context, "--namespace", SOURCE_NAMESPACE,
        "get", "secrets", "--field-selector", f"metadata.name={REMOTE_SECRET_NAME}",
        "-o", r'jsonpath={"{\"items\":["}{range .items[*]}{"{\"metadata\":"}{.metadata}{"}"}{end}{"]}"}'])
    items = current.get("items", [])
    if len(items) > 1:
        raise ToolError("ambiguous session metadata")
    return items[0]["metadata"] if items else None


def metadata_expiries(metadata: dict[str, Any], environment: str) -> tuple[datetime, datetime]:
    if metadata.get("labels") != session_labels(environment):
        raise ToolError("refusing an unowned, legacy-source or differently scoped Secret")
    annotations = metadata.get("annotations", {})
    if annotations.get(TAG_PREFIX + "session-mode") != SESSION_MODE:
        raise ToolError("session metadata does not attest on-demand mode")
    try:
        first, last, deadline = [datetime.fromisoformat(annotations[TAG_PREFIX + key].replace("Z", "+00:00"))
                                for key in ("expires-at", "all-expires-at", "deadline")]
        if any(t.tzinfo is None for t in (first, last, deadline)) or not first <= last <= deadline:
            raise ValueError("invalid interval")
    except (KeyError, AttributeError, TypeError, ValueError) as error:
        raise ToolError("invalid session expiry metadata") from error
    return first, last


def require_closed_window(contract: BootstrapContract, metadata: dict[str, Any] | None) -> None:
    if metadata is not None:
        _, last = metadata_expiries(metadata, contract.environment)
        if last > datetime.now(timezone.utc):
            raise ToolError("previous session is still active; no implicit renewal or early replacement")


def reviewed_provider_deployments(contract: BootstrapContract) -> dict[str, dict[str, Any]]:
    """Resolve consumers through Provider -> current revision -> owned Deployment.

    DeploymentRuntimeConfig metadata labels replace the package controller's
    optional labels, so a provider-name label is not a stable identity. The
    Provider status and controller ownerReference are the authoritative chain.
    """
    base = ["kubectl", "--context", contract.context, "--namespace", SOURCE_NAMESPACE]
    providers = _run_json(
        ["kubectl", "--context", contract.context, "get", "providers.pkg.crossplane.io", "-o", "json"]
    ).get("items", [])
    by_name = {item.get("metadata", {}).get("name"): item for item in providers}
    revisions: dict[str, str] = {}
    for name in PROVIDERS:
        revision = by_name.get(name, {}).get("status", {}).get("currentRevision")
        if not isinstance(revision, str) or not revision or revision in revisions:
            raise ToolError("reviewed Provider currentRevision inventory is incomplete or ambiguous")
        revisions[revision] = name
    deployments = _run_json(base + ["get", "deployments", "-l",
        "platform.aws.goodnotes.io/session-renewal=enabled", "-o", "json"]).get("items", [])
    result: dict[str, dict[str, Any]] = {}
    for deployment in deployments:
        owners = [owner for owner in deployment.get("metadata", {}).get("ownerReferences", [])
                  if owner.get("kind") == "ProviderRevision" and owner.get("controller") is True]
        if (len(owners) != 1 or owners[0].get("name") not in revisions
                or deployment.get("metadata", {}).get("name") != owners[0].get("name")):
            raise ToolError("session consumer lacks an exact reviewed ProviderRevision owner")
        name = revisions[owners[0]["name"]]
        if name in result:
            raise ToolError("multiple session consumers resolve to one reviewed Provider")
        result[name] = deployment
    if len(deployments) != len(PROVIDERS) or set(result) != set(PROVIDERS):
        raise ToolError("exactly one deployment per reviewed provider must opt into manual publication")
    return result


def verify_publication_gate(contract: BootstrapContract) -> list[dict[str, Any]]:
    # Restart all credential consumers, but never silently affect unapproved shared
    # runtimes. The label is the opt-in; ownerReferences establish exact identity.
    deployments = reviewed_provider_deployments(contract)
    verify_explicit_provider_rbac()
    verify_direct_session_runtime(contract)
    return list(deployments.values())


def publish_session(contract: BootstrapContract, sessions: TargetSessions) -> None:
    base = ["kubectl", "--context", contract.context, "--namespace", SOURCE_NAMESPACE]
    deployments = verify_publication_gate(contract)
    # The permission audit can take time. Revalidate expiry after it, before writing.
    document = secret_document(contract, sessions)
    metadata = session_metadata(contract.context)
    require_closed_window(contract, metadata)
    operation = "create"
    if metadata is not None:
        document["metadata"]["resourceVersion"] = metadata["resourceVersion"]
        operation = "replace"
    payload = json.dumps(document)
    for extra in (["--dry-run=server"], []):
        validate_targets(sessions)
        _run_json(base + [operation, "-f", "-", *extra, "-o", 'jsonpath={"true"}'], input_text=payload)
    # Do not rely on SDK file caching behavior. Opening the manual window must
    # also start the exact reviewed consumers when the shared control plane is
    # normally held at zero replicas; otherwise a published session would look
    # successful without any Provider ever using it.
    for deployment in deployments:
        patch = {"spec": {"replicas": 1, "template": {"metadata": {"annotations": {
            "platform.aws.goodnotes.io/session-refreshed-at": datetime.now(timezone.utc).isoformat()}}}}}
        _run_json(base + ["patch", "deployment", deployment["metadata"]["name"], "--type=merge",
            "-p", json.dumps(patch), "-o", 'jsonpath={"true"}'])


def load_private_review(path: Path) -> dict[str, Any]:
    directory = path.parent.stat()
    if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) & 0o077:
        raise ToolError("owner-only review directory required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 524288):
            raise ToolError("private owner-only regular review file required")
        return json.load(stream)


def open_session(contract: BootstrapContract, profile: str, audit_profile: str,
                 review: dict[str, Any], acknowledgement: str, *,
                 progress: Callable[[str], None] | None = None) -> dict[str, Any]:
    if acknowledgement != ACKNOWLEDGEMENT:
        raise ToolError("explicit one-shot session and rollout acknowledgement required")
    if (not profile or not audit_profile or profile == audit_profile
            or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", p) for p in (profile, audit_profile))):
        raise ToolError("distinct explicit source and audit profiles required")
    validate_contract(contract)
    verify_review_approval(contract, review)
    if review.get("sessionMode") != SESSION_MODE:
        raise ToolError("explicit on-demand-60m runtime review required; legacy renewal approval is not sufficient")
    require_tool("aws")
    require_tool("kubectl")
    # Check readiness before minting credentials, and again before publication.
    verify_publication_gate(contract)
    require_closed_window(contract, session_metadata(contract.context))
    _report_session_progress(progress, "SESSION_PUBLICATION_GATE_VERIFIED")
    verify_aws_identity(contract, audit_profile, review)
    _report_session_progress(progress, "SESSION_IAM_VERIFIED")
    source = _run_json(["aws", "--profile", profile, "--region", contract.region,
                        "configure", "export-credentials", "--format", "process"])
    _report_session_progress(progress, "SESSION_SOURCE_EXPORTED")
    sessions = verify_session(contract, source)
    _report_session_progress(progress, "SESSION_TARGETS_ASSUMED")
    publish_session(contract, sessions)
    _report_session_progress(progress, "SESSION_SECRET_PUBLISHED")
    first, last = validate_targets(sessions)
    return {"status": "session-published", "sessionMode": SESSION_MODE,
            "expiresAt": first.isoformat(), "allSessionsExpireAt": last.isoformat(),
            "deadline": sessions.deadline.isoformat(), "automaticRenewal": False,
            "providerReadinessVerified": False, "runtimeAuthenticationVerified": False}


def renew(contract: BootstrapContract, profile: str, audit_profile: str,
          review: dict[str, Any], acknowledgement: str) -> None:
    raise ToolError("automatic renewal is retired; use an explicitly approved one-shot open")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "open"))
    for flag in ("environment", "source-role-arn", "provider-role-arn", "deployment-role-arn", "boundary-arn"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--context", default="kind-kube-nebula-a")
    parser.add_argument("--profile")
    parser.add_argument("--audit-profile")
    parser.add_argument("--review", type=Path)
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args(argv)
    try:
        contract = BootstrapContract(**{key: getattr(args, key) for key in BootstrapContract.__dataclass_fields__})
        if args.mode == "plan":
            print(json.dumps(public_plan(contract), indent=2))
        else:
            if not args.profile or not args.audit_profile or not args.review:
                raise ToolError("open requires source/audit profiles and reviewed policy file")
            print(json.dumps(open_session(contract, args.profile, args.audit_profile,
                                          load_private_review(args.review), args.acknowledge), indent=2))
    except KeyboardInterrupt:
        print("opening interrupted; issued sessions may remain until expiry; do not retry blindly", file=sys.stderr)
        return 130
    except ToolError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError, OSError):
        print("opening failed; inspect metadata and rollout state; issued sessions may remain until expiry", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
