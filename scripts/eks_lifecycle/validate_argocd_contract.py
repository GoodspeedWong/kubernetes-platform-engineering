#!/usr/bin/env python3
"""Validate P8 network approval and namespace-scoped Argo CD ownership contracts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from common import EKS_ROOT, LOCK_FILE, ToolError, load_yaml


RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"
GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


def require_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolError(f"{path} must be an object")
    return value


def resources_by_name(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    resources: dict[str, dict[str, Any]] = {}
    for item in document.get("items", []):
        if not isinstance(item, dict):
            continue
        annotations = item.get("metadata", {}).get("annotations", {})
        if not isinstance(annotations, dict):
            continue
        name = annotations.get(RESOURCE_NAME)
        if not isinstance(name, str):
            continue
        if name in resources:
            raise ToolError(f"duplicate composition resource name: {name}")
        resources[name] = item
    return resources


def expect(actual: Any, expected: Any, path: str) -> None:
    if actual != expected:
        raise ToolError(f"{path} must be {expected!r}; got {actual!r}")


def manifest(resource: dict[str, Any], path: str) -> dict[str, Any]:
    return require_mapping(
        require_mapping(
            require_mapping(resource.get("spec"), f"{path}.spec").get("forProvider"),
            f"{path}.spec.forProvider",
        ).get("manifest"),
        f"{path}.manifest",
    )


def object_key(value: dict[str, Any]) -> tuple[str, str, str, str]:
    api_version = str(value.get("apiVersion", ""))
    group = api_version.split("/", 1)[0] if "/" in api_version else ""
    metadata = require_mapping(value.get("metadata"), "remote manifest metadata")
    return (
        group,
        str(value.get("kind", "")),
        str(metadata.get("namespace", "<cluster>")),
        str(metadata.get("name", "")),
    )


def validate_argocd_contract(
    foundation_render: dict[str, Any], *, expect_bootstrap: bool | None = None
) -> dict[str, Any]:
    resources = resources_by_name(foundation_render)
    approval = require_mapping(resources.get("network-uat-approval"), "network-uat-approval")
    expect(approval["spec"].get("managementPolicies"), ["Observe"], "approval policies")
    approval_manifest = manifest(approval, "network-uat-approval")
    expect(approval_manifest.get("kind"), "ConfigMap", "approval kind")
    expect(
        approval_manifest.get("metadata", {}).get("namespace"),
        "kube-system",
        "approval namespace",
    )
    approval_query = approval["spec"].get("readiness", {}).get("celQuery", "")
    for binding in (
        "platform.aws.goodnotes.io/environment",
        "platform.aws.goodnotes.io/cluster",
        "foundation-uid",
        "foundation-generation",
        "kube-system-uid",
        "evidence-sha256",
        "^[0-9a-f]{64}$",
    ):
        if binding not in approval_query:
            raise ToolError(f"network approval CEL lacks binding {binding}")

    release = require_mapping(resources.get("argocd-release"), "argocd-release")
    provider = require_mapping(release["spec"].get("forProvider"), "argocd provider")
    expect(
        provider.get("chart"),
        {
            "name": "argo-cd",
            "repository": "oci://ghcr.io/argoproj/argo-helm",
            "digest": load_yaml(LOCK_FILE)["charts"]["argoCD"]["manifestDigest"],
            "version": "10.4.0",
        },
        "Argo CD chart",
    )
    expect(provider.get("namespace"), "argocd", "Argo CD namespace")
    expect(provider.get("skipCreateNamespace"), False, "Argo CD namespace creation")
    expect(provider.get("skipCRDs"), False, "Argo CD CRD ownership")
    expect(provider.get("wait"), True, "Argo CD Helm wait")
    if "valuesFrom" in provider:
        raise ToolError("Argo CD platform values must not import an unreviewed values Secret")
    expect(
        provider.get("values"),
        load_yaml(EKS_ROOT / "values" / "argocd.yaml"),
        "Argo CD reviewed values",
    )

    apps_namespace = manifest(
        require_mapping(resources.get("gitops-apps-namespace"), "apps namespace"),
        "apps namespace",
    )
    expect(object_key(apps_namespace), ("", "Namespace", "<cluster>", "apps"), "apps namespace")

    role = manifest(
        require_mapping(resources.get("argocd-apps-role"), "argocd apps Role"),
        "argocd apps Role",
    )
    expect(role.get("kind"), "Role", "business manager kind")
    expect(role.get("metadata", {}).get("namespace"), "apps", "business Role namespace")
    allowed_resources = {
        ("apps", "deployments"),
        ("apps", "replicasets"),
        ("", "configmaps"),
        ("", "serviceaccounts"),
        ("", "services"),
        ("", "events"),
        ("", "pods"),
        ("batch", "jobs"),
        ("networking.k8s.io", "networkpolicies"),
    }
    actual_resources: set[tuple[str, str]] = set()
    for index, rule in enumerate(role.get("rules", [])):
        if not isinstance(rule, dict):
            raise ToolError(f"business Role rule {index} must be an object")
        if "*" in rule.get("apiGroups", []) or "*" in rule.get("resources", []) or "*" in rule.get("verbs", []):
            raise ToolError("business Role must not contain wildcard permissions")
        for group in rule.get("apiGroups", []):
            for resource_name in rule.get("resources", []):
                actual_resources.add((group, resource_name))
    if actual_resources != allowed_resources:
        raise ToolError(f"unexpected business Role resources: {sorted(actual_resources)}")

    binding = manifest(
        require_mapping(resources.get("argocd-apps-rolebinding"), "argocd apps RoleBinding"),
        "argocd apps RoleBinding",
    )
    expect(binding.get("metadata", {}).get("namespace"), "apps", "RoleBinding namespace")
    expect(
        binding.get("subjects"),
        [
            {
                "kind": "ServiceAccount",
                "name": "argocd-application-controller",
                "namespace": "argocd",
            }
        ],
        "RoleBinding subject",
    )

    project = manifest(
        require_mapping(resources.get("argocd-project"), "argocd-project"),
        "argocd-project",
    )
    project_spec = require_mapping(project.get("spec"), "AppProject spec")
    expect(
        project_spec.get("clusterResourceBlacklist"),
        [{"group": "*", "kind": "*"}],
        "AppProject cluster resource deny",
    )
    expect(
        project_spec.get("destinations"),
        [{"namespace": "apps", "server": "https://kubernetes.default.svc"}],
        "AppProject destination",
    )
    expected_whitelist = {
        ("", "ConfigMap"),
        ("", "Service"),
        ("", "ServiceAccount"),
        ("apps", "Deployment"),
        ("batch", "Job"),
        ("networking.k8s.io", "NetworkPolicy"),
    }
    actual_whitelist = {
        (item.get("group"), item.get("kind"))
        for item in project_spec.get("namespaceResourceWhitelist", [])
        if isinstance(item, dict)
    }
    if actual_whitelist != expected_whitelist:
        raise ToolError(f"unexpected AppProject namespace whitelist: {sorted(actual_whitelist)}")
    source_repositories = project_spec.get("sourceRepos")
    if not isinstance(source_repositories, list) or len(source_repositories) > 1:
        raise ToolError("AppProject sourceRepos must be empty or one exact repository")

    has_bootstrap = "gitops-bootstrap" in resources
    if expect_bootstrap is not None and has_bootstrap != expect_bootstrap:
        raise ToolError(
            f"bootstrap Application presence must be {expect_bootstrap}; got {has_bootstrap}"
        )
    if not has_bootstrap:
        expect(source_repositories, [], "empty Git configuration")
    else:
        application = manifest(resources["gitops-bootstrap"], "gitops-bootstrap")
        app_metadata = require_mapping(application.get("metadata"), "Application metadata")
        expect(
            app_metadata.get("finalizers"),
            ["resources-finalizer.argocd.argoproj.io/foreground"],
            "Application foreground finalizer",
        )
        credentials_name = app_metadata.get("annotations", {}).get(
            "platform.aws.goodnotes.io/repository-credentials-secret"
        )
        if not isinstance(credentials_name, str) or not credentials_name:
            raise ToolError("Application must name its externally provisioned repository Secret")
        app_spec = require_mapping(application.get("spec"), "Application spec")
        expect(app_spec.get("project"), "business", "Application project")
        expect(
            app_spec.get("destination"),
            {"namespace": "apps", "server": "https://kubernetes.default.svc"},
            "Application destination",
        )
        source = require_mapping(app_spec.get("source"), "Application source")
        if source_repositories != [source.get("repoURL")]:
            raise ToolError("Application source must equal the AppProject's sole source repository")
        if not GIT_REVISION_RE.fullmatch(str(source.get("targetRevision", ""))):
            raise ToolError("Application targetRevision must be an exact commit SHA")
        if not source.get("path"):
            raise ToolError("Application source path must be non-empty")
        options = set(app_spec.get("syncPolicy", {}).get("syncOptions", []))
        required_options = {
            "CreateNamespace=false",
            "PruneLast=true",
            "PrunePropagationPolicy=foreground",
            "RespectIgnoreDifferences=true",
        }
        if options != required_options:
            raise ToolError(f"unexpected Application sync options: {sorted(options)}")

    inventory: dict[tuple[str, str, str, str], str] = {}
    for resource_name, resource in resources.items():
        if resource.get("kind") != "Object" or resource_name == "network-uat-approval":
            continue
        value = manifest(resource, resource_name)
        key = object_key(value)
        if not key[3]:
            raise ToolError(f"remote object {resource_name} lacks metadata.name")
        if key in inventory:
            raise ToolError(
                f"duplicate remote owner identity {key}: {inventory[key]} and {resource_name}"
            )
        inventory[key] = resource_name

    return {
        "applicationConfigured": has_bootstrap,
        "businessNamespace": "apps",
        "clusterScopedBusinessPermissions": 0,
        "networkApprovalPolicy": "Observe",
        "remoteOwnerIdentities": len(inventory),
        "sourceRepositories": len(source_repositories),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--foundation-render", type=Path, required=True)
    parser.add_argument(
        "--expect-bootstrap", choices=("true", "false"), help="assert Application presence"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        expected = None if args.expect_bootstrap is None else args.expect_bootstrap == "true"
        print(
            json.dumps(
                validate_argocd_contract(
                    load_yaml(args.foundation_render), expect_bootstrap=expected
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
