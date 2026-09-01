#!/usr/bin/env python3
"""Run local, non-mutating structural checks for the EKS platform bundle."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from common import EKS_ROOT, LOCK_FILE, REPO_ROOT, ToolError, load_yaml, output_directory, run_checked
import render as high_fidelity_render
import render_foundation
import render_cluster
import validate_argocd_contract
import validate_cilium_contract
import validate_spot_contract
import validate_chart_digests
import prepare_identity_boundaries
import manage_provider_rbac
import provider_maintenance
import renew_management_credentials


def floating_values(value: object, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            findings.extend(floating_values(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(floating_values(child, f"{path}[{index}]"))
    elif isinstance(value, str) and value.lower() in {"latest", "@latest"}:
        findings.append(path)
    return findings


def trailing_whitespace(paths: list[Path]) -> list[str]:
    findings = []
    for root in paths:
        if not root.exists():
            continue
        files = [root] if root.is_file() else [path for path in root.rglob("*") if path.is_file()]
        for path in files:
            if any(part in {"__pycache__", ".cache"} for part in path.parts):
                continue
            try:
                lines = path.read_text().splitlines()
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(lines, start=1):
                if line.rstrip() != line:
                    findings.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    return findings


def run_validation(strict: bool, report_directory: Path) -> dict[str, object]:
    lock = load_yaml(LOCK_FILE)
    floating = floating_values(lock)
    if floating:
        raise ToolError(f"floating version values found at: {', '.join(floating)}")
    schema_script = REPO_ROOT / "scripts" / "eks_lifecycle" / "prepare_schemas.py"
    run_checked([sys.executable, str(schema_script), "--verify"])
    prepare_identity_boundaries.check_template()
    rbac_inventory = manage_provider_rbac.inventory()
    if (
        (manage_provider_rbac.ROOT / "permissions.yaml").read_bytes()
        != manage_provider_rbac.rendered_bytes(rbac_inventory)
    ):
        raise ToolError("explicit Provider RBAC differs from inventory")
    provider_contract = provider_maintenance.contract(lock)
    if (
        provider_maintenance.PROVIDERS_FILE.read_bytes()
        != provider_maintenance.rendered_bytes(provider_contract)
    ):
        raise ToolError("management Provider bundle differs from inventory")
    if load_yaml(EKS_ROOT.parent / "crossplane/values.yaml").get("rbacManager", {}).get("deploy") is not False:
        raise ToolError("automatic RBAC manager must remain disabled")
    direct = load_yaml(EKS_ROOT / "management-aws-auth/provider-config.template.yaml")["spec"]
    if direct.get("assumeRoleChain") or direct.get("profile"):
        raise ToolError("manual target credentials must not use a Provider-side role chain or alternate profile")
    if (renew_management_credentials.SESSION_MODE != "on-demand-60m"
            or renew_management_credentials.MAX_SESSION_SECONDS != 3600):
        raise ToolError("manual authentication contract must remain bounded to 60 minutes")
    rendered = run_checked(
        ["kubectl", "kustomize", str(EKS_ROOT / "dependencies")]
    ).stdout
    if rendered.count("kind: Provider") != 2 or rendered.count("@sha256:") != 2:
        raise ToolError("dependency entry must render exactly two digest-pinned Providers")
    kustomize_entries = (
        EKS_ROOT,
        EKS_ROOT / "environment",
        EKS_ROOT / "cluster",
        EKS_ROOT / "foundation",
        EKS_ROOT / "dependencies",
        EKS_ROOT / "catalog",
        EKS_ROOT / "examples",
        EKS_ROOT / "instances",
        EKS_ROOT / "management-auth",
        EKS_ROOT / "management-rbac",
        EKS_ROOT / "management-rbac-maintenance",
        EKS_ROOT / "lifecycle-policy",
        REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-network",
    )
    kustomize_outputs = {
        str(path.relative_to(REPO_ROOT)): run_checked(
            ["kubectl", "kustomize", str(path)]
        ).stdout
        for path in kustomize_entries
    }
    if kustomize_outputs[str(EKS_ROOT.relative_to(REPO_ROOT))].count(
        "kind: CompositeResourceDefinition"
    ) != 3:
        raise ToolError("module root must contain exactly three XRD definitions")
    if kustomize_outputs[str((EKS_ROOT / "instances").relative_to(REPO_ROOT))]:
        raise ToolError("instances entry must remain empty")
    with output_directory(None, "eks-openapi-audit-") as schema_output:
        openapi = high_fidelity_render.write_required_schema_bundle(schema_output)
        openapi_count = len(
            json.loads(openapi.read_text())["components"]["schemas"]
        )
    if openapi_count < 41:
        raise ToolError("render OpenAPI bundle omits locked custom kinds")
    foundation = load_yaml(EKS_ROOT / "tests" / "fixtures" / "p5" / "foundation-valid.yaml")
    crds_ready = load_yaml(
        EKS_ROOT
        / "tests"
        / "fixtures"
        / "p6"
        / "observed-karpenter-crds-ready.yaml"
    )
    foundation_render = render_foundation.render(foundation, crds_ready)
    spot_contract = validate_spot_contract.validate_spot_contract(
        foundation_render, {"us-east-1a", "us-east-1b"}
    )
    cluster = load_yaml(EKS_ROOT / "tests" / "fixtures" / "p4" / "cluster-valid.yaml")
    cluster_observed = load_yaml(
        EKS_ROOT / "tests" / "fixtures" / "p4" / "observed-oidc-ready.yaml"
    )
    cluster_render = render_cluster.render(cluster, cluster_observed)
    cilium_contract = validate_cilium_contract.validate_cilium_contract(
        foundation_render, cluster_render
    )
    argocd_observed = load_yaml(
        EKS_ROOT / "tests" / "fixtures" / "p8" / "observed-network-approved.yaml"
    )
    argocd_observed.update(
        load_yaml(
            EKS_ROOT
            / "tests"
            / "fixtures"
            / "p8"
            / "observed-argocd-prerequisites-ready.yaml"
        )
    )
    argocd_render = render_foundation.render(foundation, argocd_observed)
    for rendered_foundation in (foundation_render, argocd_render):
        validate_chart_digests.validate(rendered_foundation, lock)
    argocd_contract = validate_argocd_contract.validate_argocd_contract(
        argocd_render, expect_bootstrap=False
    )
    ownership = load_yaml(EKS_ROOT / "ownership-contract.yaml")
    owner_ids = [str(item.get("id", "")) for item in ownership.get("resources", [])]
    if not owner_ids or len(owner_ids) != len(set(owner_ids)) or "" in owner_ids:
        raise ToolError("ownership contract contains empty or duplicate resource IDs")
    planned_names = ownership.get("plannedCompositionResourceNames", {})
    for owner, names in planned_names.items():
        if not isinstance(names, list) or len(names) != len(set(names)):
            raise ToolError(f"owner {owner} contains duplicate composition resource names")
    sensitive_findings: list[str] = []
    pem = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
    access_key = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
    for path in EKS_ROOT.rglob("*"):
        if not path.is_file() or "tests" in path.parts or "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if pem.search(text) or access_key.search(text):
            sensitive_findings.append(str(path.relative_to(REPO_ROOT)))
    if sensitive_findings:
        raise ToolError(
            f"sensitive credential-shaped literals found: {', '.join(sensitive_findings)}"
        )
    whitespace = trailing_whitespace([EKS_ROOT, REPO_ROOT / "scripts" / "eks_lifecycle"])
    if whitespace:
        raise ToolError(f"trailing whitespace found: {', '.join(whitespace[:10])}")
    report = {
        "strict": strict,
        "floatingVersions": 0,
        "schemaFiles": 37,
        "spotOnlyNodePools": spot_contract["nodePoolCount"],
        "ciliumContracts": 1 if cilium_contract["cniOwner"] == "cilium" else 0,
        "argocdContracts": 1
        if argocd_contract["clusterScopedBusinessPermissions"] == 0
        else 0,
        "dependencyProviders": 2,
        "duplicateOwnerIds": 0,
        "embeddedValidationPolicy": "error-on-missing-schemas",
        "feeCreatingRuntimeInstances": 0,
        "kustomizeEntrypoints": len(kustomize_entries),
        "openapiRenderSchemas": openapi_count,
        "onDemandNodePools": 0,
        "sensitiveLiterals": 0,
        "identityBoundaryPolicies": 7,
        "explicitProviderRbacDocuments": len(manage_provider_rbac.render(rbac_inventory)),
        "managementProviders": len(provider_contract["providers"]),
        "managementSessionConsumers": sum(
            provider["runtimeConfig"] != manage_provider_rbac.RUNTIME_DEFAULT
            for provider in provider_contract["providers"]
        ),
        "managementSessionSecretReaders": sum(
            provider["sessionReader"] for provider in provider_contract["providers"]
        ),
        "automaticRbacManagerDisabled": True,
        "managementSessionMode": renew_management_credentials.SESSION_MODE,
        "managementAutomaticRenewal": False,
        "identityPreparationReview": "PENDING_SECURITY_APPROVAL",
        "trailingWhitespace": 0,
        "awsMutation": False,
        "kubernetesMutation": False,
    }
    (report_directory / "p1-static-validation.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the EKS lifecycle bundle locally.")
    parser.add_argument("--strict", action="store_true", help="treat every finding as an error")
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        with output_directory(args.output_dir, "eks-static-") as report_directory:
            report = run_validation(args.strict, report_directory)
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, ToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
