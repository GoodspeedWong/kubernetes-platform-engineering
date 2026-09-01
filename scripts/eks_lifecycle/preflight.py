#!/usr/bin/env python3
"""Fail-closed preflight for local implementation or explicit online read-only checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from common import (
    EKS_ROOT,
    LOCK_FILE,
    REPO_ROOT,
    ToolError,
    assert_deployment_safe,
    load_yaml,
    require_tool,
    run_checked,
)
import provider_maintenance


REQUIRED_LOCAL_TOOLS = ("python3", "crossplane", "helm", "kubectl", "yq")
REMOTE_AUTH_PROVIDERS = {
    "provider-kubernetes": "providerKubernetes",
    "provider-helm": "providerHelm",
}
REMOTE_AUTH_RUNTIME_CONFIG = "eks-remote-auth"


def _condition_true(resource: dict[str, Any], condition_type: str) -> bool:
    return any(
        condition.get("type") == condition_type and condition.get("status") == "True"
        for condition in resource.get("status", {}).get("conditions", [])
    )


def _resources_by_name(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("metadata", {}).get("name", ""): item
        for item in document.get("items", [])
        if item.get("metadata", {}).get("name")
    }


def validate_management_auth_bundle(lock: dict[str, Any]) -> dict[str, object]:
    auth_root = EKS_ROOT / "management-auth"
    providers_result = run_checked(
        [
            "yq",
            "eval-all",
            "-o=json",
            "[.]",
            str(auth_root / "providers.yaml"),
        ]
    )
    providers = json.loads(providers_result.stdout)
    if not isinstance(providers, list):
        raise ToolError("management-auth/providers.yaml must contain a document list")
    by_name = {
        item.get("metadata", {}).get("name", ""): item
        for item in providers
        if isinstance(item, dict) and item.get("kind") == "Provider"
    }
    reviewed = provider_maintenance.contract(lock)
    expected_by_name = {
        item["metadata"]["name"]: item
        for item in provider_maintenance.provider_documents(reviewed)
    }
    if by_name != expected_by_name:
        raise ToolError("management-auth Providers differ from the reviewed maintenance inventory")

    runtime = load_yaml(auth_root / "runtime-config.yaml")
    if runtime.get("kind") != "DeploymentRuntimeConfig":
        raise ToolError("management-auth runtime-config must be a DeploymentRuntimeConfig")
    pod_spec = (
        runtime.get("spec", {})
        .get("deploymentTemplate", {})
        .get("spec", {})
        .get("template", {})
        .get("spec", {})
    )
    containers = pod_spec.get("containers", [])
    if len(containers) != 1 or containers[0].get("name") != "package-runtime":
        raise ToolError("management-auth runtime must patch only package-runtime")
    volumes = pod_spec.get("volumes", [])
    secret_volumes = [item.get("secret", {}) for item in volumes if "secret" in item]
    if len(secret_volumes) != 1:
        raise ToolError("management-auth runtime must reference one external Secret")
    secret = secret_volumes[0]
    if secret.get("secretName") != "eks-platform-aws-session":
        raise ToolError("management-auth references an unexpected credential Secret")
    if {item.get("key") for item in secret.get("items", [])} != {
        "credentials",
        "config",
    }:
        raise ToolError("management-auth credential Secret keys are incomplete")

    aws_runtime = load_yaml(auth_root / "aws-session-runtime.yaml")
    if (
        aws_runtime.get("kind") != "DeploymentRuntimeConfig"
        or aws_runtime.get("metadata", {}).get("name") != "eks-aws-session"
    ):
        raise ToolError("management-auth AWS runtime identity is invalid")
    aws_pod_spec = (
        aws_runtime.get("spec", {})
        .get("deploymentTemplate", {})
        .get("spec", {})
        .get("template", {})
        .get("spec", {})
    )
    aws_containers = aws_pod_spec.get("containers", [])
    if len(aws_containers) != 1 or aws_containers[0].get("name") != "package-runtime":
        raise ToolError("management-auth AWS runtime must patch only package-runtime")
    aws_env = {
        item.get("name"): item.get("value")
        for item in aws_containers[0].get("env", [])
    }
    if aws_env != {"AWS_EC2_METADATA_DISABLED": "true"}:
        raise ToolError("management-auth AWS runtime permits an unreviewed credential source")
    if aws_pod_spec.get("volumes") or aws_containers[0].get("volumeMounts"):
        raise ToolError("AWS Provider runtime must not mount source or target credentials")

    session_consumers = [
        provider["name"]
        for provider in reviewed["providers"]
        if provider["runtimeConfig"] != "default"
    ]
    return {
        "providers": sorted(by_name),
        "runtimeConfigs": ["eks-aws-session", REMOTE_AUTH_RUNTIME_CONFIG],
        "sessionConsumers": sorted(session_consumers),
        "credentialSecretValuesRead": False,
    }


def evaluate_online_runtime(
    lock: dict[str, Any],
    providers_document: dict[str, Any],
    revisions_document: dict[str, Any],
    deployments_document: dict[str, Any],
) -> dict[str, object]:
    providers = _resources_by_name(providers_document)
    revisions = _resources_by_name(revisions_document)
    deployments = _resources_by_name(deployments_document)
    errors: list[str] = []
    revision_names: dict[str, str] = {}

    for provider_name, lock_key in REMOTE_AUTH_PROVIDERS.items():
        provider = providers.get(provider_name)
        if provider is None:
            errors.append(f"missing Provider {provider_name}")
            continue
        expected_package = lock["packages"][lock_key]["reference"]
        actual_package = provider.get("spec", {}).get("package")
        if actual_package != expected_package:
            errors.append(
                f"{provider_name} package is {actual_package!r}, expected locked {expected_package!r}"
            )
        runtime_name = (
            provider.get("spec", {}).get("runtimeConfigRef", {}).get("name")
        )
        if runtime_name != REMOTE_AUTH_RUNTIME_CONFIG:
            errors.append(
                f"{provider_name} runtimeConfigRef is {runtime_name!r}, expected {REMOTE_AUTH_RUNTIME_CONFIG!r}"
            )
        if not _condition_true(provider, "Installed"):
            errors.append(f"{provider_name} is not Installed=True")
        if not _condition_true(provider, "Healthy"):
            errors.append(f"{provider_name} is not Healthy=True")
        revision_name = provider.get("status", {}).get("currentRevision", "")
        if not revision_name:
            errors.append(f"{provider_name} has no currentRevision")
            continue
        revision_names[provider_name] = revision_name
        revision = revisions.get(revision_name)
        if revision is None:
            errors.append(f"active ProviderRevision is missing: {revision_name}")
            continue
        if revision.get("spec", {}).get("desiredState") != "Active":
            errors.append(f"ProviderRevision {revision_name} is not Active")
        revision_runtime = (
            revision.get("spec", {}).get("runtimeConfigRef", {}).get("name")
        )
        if revision_runtime != REMOTE_AUTH_RUNTIME_CONFIG:
            errors.append(
                f"ProviderRevision {revision_name} runtimeConfigRef is {revision_runtime!r}"
            )
        for condition_type in ("RevisionHealthy", "RuntimeHealthy"):
            if not _condition_true(revision, condition_type):
                errors.append(f"{revision_name} is not {condition_type}=True")
        deployment = deployments.get(revision_name)
        if deployment is None:
            errors.append(f"provider controller Deployment is missing: {revision_name}")
            continue
        desired = deployment.get("spec", {}).get("replicas", 1)
        available = deployment.get("status", {}).get("availableReplicas", 0)
        if available < desired:
            errors.append(
                f"provider controller Deployment unavailable: {revision_name}:{available}/{desired}"
            )

    for core_name in ("crossplane", "crossplane-rbac-manager"):
        deployment = deployments.get(core_name)
        if deployment is None:
            errors.append(f"required Crossplane controller Deployment is missing: {core_name}")
            continue
        desired = deployment.get("spec", {}).get("replicas", 1)
        available = deployment.get("status", {}).get("availableReplicas", 0)
        if available < desired:
            errors.append(
                f"Crossplane controller Deployment unavailable: {core_name}:{available}/{desired}"
            )

    if errors:
        raise ToolError("U0 remote-auth runtime gate failed: " + "; ".join(errors))
    return {
        "providers": sorted(REMOTE_AUTH_PROVIDERS),
        "providerRevisions": revision_names,
        "requiredDeploymentsAvailable": True,
    }


def offline_checks(deployment_inputs: list[Path]) -> dict[str, object]:
    tools = {name: require_tool(name) for name in REQUIRED_LOCAL_TOOLS}
    lock = load_yaml(LOCK_FILE)
    if lock.get("policy", {}).get("floatingVersionsAllowed") is not False:
        raise ToolError("version lock must explicitly forbid floating versions")
    schema_script = REPO_ROOT / "scripts" / "eks_lifecycle" / "prepare_schemas.py"
    run_checked([sys.executable, str(schema_script), "--verify"])
    remote_auth = validate_management_auth_bundle(lock)
    for path in deployment_inputs:
        assert_deployment_safe(path.resolve())
    return {
        "mode": "offline",
        "tools": tools,
        "schemaCache": "verified",
        "remoteAuth": remote_auth,
        "deploymentInputs": len(deployment_inputs),
        "awsMutation": False,
        "kubernetesMutation": False,
    }


def online_read_only_checks(context: str) -> dict[str, object]:
    require_tool("kubectl")
    if not context:
        raise ToolError("--context is required with --online-read-only")
    current = run_checked(["kubectl", "config", "current-context"]).stdout.strip()
    lock = load_yaml(LOCK_FILE)
    providers_result = run_checked(
        [
            "kubectl",
            "--context",
            context,
            "get",
            "providers.pkg.crossplane.io",
            *REMOTE_AUTH_PROVIDERS,
            "-o",
            "json",
        ]
    )
    providers_document = json.loads(providers_result.stdout)
    provider_names = _resources_by_name(providers_document)
    revisions = [
        provider_names[name].get("status", {}).get("currentRevision", "")
        for name in REMOTE_AUTH_PROVIDERS
        if name in provider_names
    ]
    if len(revisions) != len(REMOTE_AUTH_PROVIDERS) or not all(revisions):
        raise ToolError("remote-auth Providers do not all expose a currentRevision")
    revisions_result = run_checked(
        [
            "kubectl",
            "--context",
            context,
            "get",
            "providerrevisions.pkg.crossplane.io",
            *revisions,
            "-o",
            "json",
        ]
    )
    deployments_result = run_checked(
        [
            "kubectl",
            "--context",
            context,
            "get",
            "deployments",
            "-n",
            "crossplane-system",
            "crossplane",
            "crossplane-rbac-manager",
            *revisions,
            "-o",
            "json",
        ]
    )
    runtime = evaluate_online_runtime(
        lock,
        providers_document,
        json.loads(revisions_result.stdout),
        json.loads(deployments_result.stdout),
    )
    final_current = run_checked(["kubectl", "config", "current-context"]).stdout.strip()
    if final_current != current:
        raise ToolError("kubectl current-context changed during read-only preflight")
    return {
        "mode": "online-read-only",
        "requestedContext": context,
        "originalCurrentContext": current,
        "runtime": runtime,
        "secretReads": False,
        "contextChanged": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate local EKS platform prerequisites without changing Kubernetes or AWS."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true", help="run local-only checks (default)")
    mode.add_argument(
        "--online-read-only",
        action="store_true",
        help="read controller Deployment status from one explicit context",
    )
    parser.add_argument("--context", help="explicit kubeconfig context for online read-only mode")
    parser.add_argument(
        "--deployment-input",
        action="append",
        type=Path,
        default=[],
        help="reject test placeholders in a proposed deployment input",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.online_read_only:
            if args.deployment_input:
                raise ToolError("deployment input validation belongs to offline mode")
            report = online_read_only_checks(args.context or "")
        else:
            if args.context:
                raise ToolError("--context is only valid with --online-read-only")
            report = offline_checks(args.deployment_input)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (json.JSONDecodeError, ToolError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
