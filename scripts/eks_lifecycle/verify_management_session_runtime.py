#!/usr/bin/env python3
"""Verify an A05 session without printing or persisting credential material."""

from __future__ import annotations

import argparse
import base64
import configparser
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import renew_management_credentials as credentials
from common import ToolError, require_tool


EXPIRED_CODES = {"ExpiredToken", "ExpiredTokenException", "RequestExpired"}
NOT_FOUND_CODES = {"NoSuchEntity", "ResourceNotFoundException"}
ERROR_CODE_RE = re.compile(r"An error occurred \(([^)]+)\)")
ACCESS_KEY_RE = re.compile(r"ASIA[A-Z0-9]{16}")
FORBIDDEN_LOG_MARKERS = (
    "ExpiredToken",
    "AccessDenied",
    "NoCredentialProviders",
    "failed to refresh cached credentials",
    "could not find default credentials",
    'secrets "eks-platform-aws-session" not found',
)


@dataclass(frozen=True)
class PublishedSessions:
    execution: dict[str, str]
    deployment: dict[str, str]
    metadata: dict[str, Any]


def _kube(contract: credentials.BootstrapContract, *args: str) -> Any:
    return credentials._run_json(
        ["kubectl", "--context", contract.context, *args, "-o", "json"]
    )


def _decode(value: str, label: str) -> str:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise ToolError(f"invalid encoded {label}; output suppressed") from error


def _parse_profile_file(value: str) -> dict[str, dict[str, str]]:
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(value)
    except configparser.Error as error:
        raise ToolError("invalid published credential profile file") from error
    if parser.sections() != ["default", "eks-deployment"]:
        raise ToolError("published credential profiles differ from reviewed contract")
    result: dict[str, dict[str, str]] = {}
    required = {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
    for profile in parser.sections():
        values = dict(parser[profile])
        if set(values) != required:
            raise ToolError("published credential profile fields differ from reviewed contract")
        if not ACCESS_KEY_RE.fullmatch(values["aws_access_key_id"]):
            raise ToolError("published credentials are not temporary STS credentials")
        if any(not item or "\n" in item or "\r" in item for item in values.values()):
            raise ToolError("invalid published credential value")
        result[profile] = values
    if result["default"]["aws_access_key_id"] == result["eks-deployment"]["aws_access_key_id"]:
        raise ToolError("execution and deployment sessions must be distinct")
    return result


def _validate_config(value: str, region: str) -> None:
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(value)
    except configparser.Error as error:
        raise ToolError("invalid published AWS config file") from error
    if parser.sections() != ["default", "profile eks-deployment"]:
        raise ToolError("published AWS config profiles differ from reviewed contract")
    for section in parser.sections():
        if dict(parser[section]) != {"region": region}:
            raise ToolError("published AWS config is not region-only")


def read_published_sessions(contract: credentials.BootstrapContract) -> PublishedSessions:
    secret = _kube(
        contract,
        "--namespace",
        credentials.SOURCE_NAMESPACE,
        "get",
        "secret",
        credentials.REMOTE_SECRET_NAME,
    )
    if secret.get("type") != "Opaque" or set(secret.get("data", {})) != {"credentials", "config"}:
        raise ToolError("published session Secret shape differs from reviewed contract")
    credentials.metadata_expiries(secret["metadata"], contract.environment)
    profiles = _parse_profile_file(_decode(secret["data"]["credentials"], "credentials"))
    _validate_config(_decode(secret["data"]["config"], "config"), contract.region)
    return PublishedSessions(profiles["default"], profiles["eks-deployment"], secret["metadata"])


def _session_env(session: dict[str, str]) -> dict[str, str]:
    return credentials._clean_env() | {
        "AWS_ACCESS_KEY_ID": session["aws_access_key_id"],
        "AWS_SECRET_ACCESS_KEY": session["aws_secret_access_key"],
        "AWS_SESSION_TOKEN": session["aws_session_token"],
    }


def _aws(
    contract: credentials.BootstrapContract,
    session: dict[str, str],
    *args: str,
    accepted_errors: set[str] | None = None,
) -> tuple[Any | None, str | None]:
    command = ["aws", "--region", contract.region, *args, "--output", "json"]
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
            env=_session_env(session),
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolError("AWS runtime probe unavailable or timed out; output suppressed") from error
    if result.returncode:
        match = ERROR_CODE_RE.search(result.stderr or "")
        code = match.group(1) if match else None
        if code and accepted_errors and code in accepted_errors:
            return None, code
        raise ToolError("AWS runtime probe failed; output suppressed")
    try:
        return json.loads(result.stdout), None
    except json.JSONDecodeError as error:
        raise ToolError("AWS runtime probe returned invalid JSON; output suppressed") from error


def _verify_caller(
    contract: credentials.BootstrapContract,
    session: dict[str, str],
    role_arn: str,
) -> str:
    caller, _ = _aws(contract, session, "sts", "get-caller-identity")
    account = credentials.validate_contract(contract)
    role_name = role_arn.rsplit("/", 1)[1]
    expected = f"arn:aws:sts::{account}:assumed-role/{role_name}/"
    if caller.get("Account") != account or not caller.get("Arn", "").startswith(expected):
        raise ToolError("published runtime caller identity differs from reviewed role")
    return role_arn


def _verify_deployments(contract: credentials.BootstrapContract) -> list[str]:
    document = _kube(
        contract,
        "--namespace",
        credentials.SOURCE_NAMESPACE,
        "get",
        "deployments",
        "-l",
        "platform.aws.goodnotes.io/session-renewal=enabled",
    )
    items = document.get("items", [])
    by_provider = {
        item.get("metadata", {}).get("labels", {}).get("pkg.crossplane.io/provider"): item
        for item in items
    }
    if len(items) != len(credentials.PROVIDERS) or set(by_provider) != set(credentials.PROVIDERS):
        raise ToolError("runtime deployment inventory differs from reviewed providers")
    for provider, item in by_provider.items():
        desired = item.get("spec", {}).get("replicas", 1)
        status = item.get("status", {})
        if (
            desired != 1
            or status.get("availableReplicas", 0) != 1
            or status.get("updatedReplicas", 0) != 1
            or status.get("observedGeneration", 0) < item["metadata"].get("generation", 0)
        ):
            raise ToolError(f"reviewed Provider runtime is not exactly 1/1 available: {provider}")
        refreshed = (
            item.get("spec", {})
            .get("template", {})
            .get("metadata", {})
            .get("annotations", {})
            .get("platform.aws.goodnotes.io/session-refreshed-at")
        )
        if not refreshed:
            raise ToolError("Provider runtime lacks the explicit session rollout marker")
    return sorted(by_provider)


def _verify_runtime_logs(contract: credentials.BootstrapContract, providers: list[str]) -> None:
    deployments = _kube(
        contract,
        "--namespace",
        credentials.SOURCE_NAMESPACE,
        "get",
        "deployments",
        "-l",
        "platform.aws.goodnotes.io/session-renewal=enabled",
    ).get("items", [])
    names = {
        item["metadata"]["labels"]["pkg.crossplane.io/provider"]: item["metadata"]["name"]
        for item in deployments
    }
    for provider in providers:
        try:
            result = subprocess.run(
                [
                    "kubectl",
                    "--context",
                    contract.context,
                    "--namespace",
                    credentials.SOURCE_NAMESPACE,
                    "logs",
                    "deployment/" + names[provider],
                    "--all-containers=true",
                    "--tail=200",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
                env={k: v for k, v in os.environ.items() if not k.startswith("AWS_")},
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise ToolError("Provider runtime log probe unavailable; output suppressed") from error
        if result.returncode or any(marker.lower() in result.stdout.lower() for marker in FORBIDDEN_LOG_MARKERS):
            raise ToolError(f"Provider runtime log gate failed: {provider}; output suppressed")


def verify_active(contract: credentials.BootstrapContract) -> dict[str, Any]:
    require_tool("aws")
    require_tool("kubectl")
    bundle = read_published_sessions(contract)
    first, _ = credentials.metadata_expiries(bundle.metadata, contract.environment)
    if first <= datetime.now(timezone.utc):
        raise ToolError("published session is not active")
    credentials.verify_direct_session_runtime(contract)
    providers = _verify_deployments(contract)
    _verify_runtime_logs(contract, providers)
    callers = [
        _verify_caller(contract, bundle.execution, contract.provider_role_arn),
        _verify_caller(contract, bundle.deployment, contract.deployment_role_arn),
    ]
    read_probes = [
        ("ec2", ("ec2", "describe-vpcs", "--max-results", "5"), set()),
        ("eks", ("eks", "list-clusters", "--max-results", "1"), set()),
        ("iam", ("iam", "get-role", "--role-name", contract.environment + "-eks-control"), NOT_FOUND_CODES),
        ("sqs", ("sqs", "list-queues", "--max-results", "1"), set()),
        ("cloudwatchevents", ("events", "list-rules", "--limit", "1"), set()),
    ]
    for _, command, accepted in read_probes:
        _aws(contract, bundle.execution, *command, accepted_errors=accepted)
    _aws(
        contract,
        bundle.deployment,
        "eks",
        "describe-cluster",
        "--name",
        contract.environment + "-cluster",
        accepted_errors=NOT_FOUND_CODES,
    )
    return {
        "status": "active-runtime-verified",
        "sessionMode": credentials.SESSION_MODE,
        "providerReadinessVerified": True,
        "runtimeAuthenticationVerified": True,
        "providers": providers,
        "callerRoles": callers,
        "readOnlyAwsServicesVerified": [item[0] for item in read_probes],
        "targetEksDescribeAuthorized": True,
        "credentialMaterialPrinted": False,
    }


def verify_expired(contract: credentials.BootstrapContract) -> dict[str, Any]:
    require_tool("aws")
    require_tool("kubectl")
    bundle = read_published_sessions(contract)
    _, last = credentials.metadata_expiries(bundle.metadata, contract.environment)
    if last > datetime.now(timezone.utc):
        raise ToolError("published sessions have not all expired")
    errors = []
    for session in (bundle.execution, bundle.deployment):
        _, code = _aws(
            contract,
            session,
            "sts",
            "get-caller-identity",
            accepted_errors=EXPIRED_CODES,
        )
        if code not in EXPIRED_CODES:
            raise ToolError("expired session unexpectedly authenticated")
        errors.append(code)
    return {
        "status": "real-expiry-verified",
        "sessionMode": credentials.SESSION_MODE,
        "expiredCredentialRequestsRejected": len(errors),
        "automaticRenewalObserved": False,
        "runtimeAuthenticationVerified": False,
        "credentialMaterialPrinted": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("active", "expired"))
    parser.add_argument("--review", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        review = credentials.load_private_review(args.review)
        contract = credentials.BootstrapContract(**review["contract"])
        credentials.verify_review_approval(contract, review)
        result = verify_active(contract) if args.mode == "active" else verify_expired(contract)
        print(json.dumps(result, indent=2))
        return 0
    except (ToolError, ValueError, KeyError, TypeError, AttributeError, OSError):
        print("runtime session verification failed closed; sensitive output suppressed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
