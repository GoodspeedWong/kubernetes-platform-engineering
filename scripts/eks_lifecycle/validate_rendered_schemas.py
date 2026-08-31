#!/usr/bin/env python3
"""Strictly validate rendered Crossplane resources and embedded remote manifests."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import (
    EKS_ROOT,
    LOCK_FILE,
    REPO_ROOT,
    SCHEMA_DIRECTORY,
    ToolError,
    load_yaml,
    output_directory,
    require_tool,
    run_checked,
)
import render_foundation


NETWORK_XRD = (
    REPO_ROOT
    / "kind-goodnotes-k8s-demo"
    / "crossplane-platform-aws-network"
    / "xrd.yaml"
)
XRD_PATHS = (
    EKS_ROOT / "environment" / "xrd.yaml",
    NETWORK_XRD,
    EKS_ROOT / "cluster" / "xrd.yaml",
    EKS_ROOT / "foundation" / "xrd.yaml",
)
RESOURCE_NAME = "krm.kcl.dev/composition-resource-name"
BUILTIN_GVKS = {
    ("v1", "ConfigMap"),
    ("v1", "Namespace"),
    ("rbac.authorization.k8s.io/v1", "Role"),
    ("rbac.authorization.k8s.io/v1", "RoleBinding"),
}


def schema_validation_contract(lock: dict[str, Any]) -> dict[str, Any]:
    management = lock.get("targets", {}).get("managementPlane", {})
    contract = management.get("schemaValidation", {})
    if not isinstance(contract, dict) or contract.get("mode") != "source-cache":
        raise ToolError("schema validation must use the locked source-cache mode")
    required = (
        "cliVersion",
        "cacheIdentity",
        "sourceModule",
        "sourceVersion",
        "sourceModuleSum",
        "coreCRDCount",
        "coreCRDsSha256",
    )
    if any(contract.get(key) in (None, "") for key in required):
        raise ToolError("schema validation source-cache lock is incomplete")
    if str(contract["cliVersion"]) != str(management.get("crossplaneCLI")):
        raise ToolError("schema validator CLI version differs from the management lock")
    if str(contract["sourceVersion"]) != str(management.get("crossplaneCore")):
        raise ToolError("schema source version differs from the Crossplane core lock")
    render_engine = management.get("renderEngine", {})
    if (
        contract["sourceModule"] != render_engine.get("module")
        or contract["sourceModuleSum"] != render_engine.get("moduleSum")
    ):
        raise ToolError("schema and render engines must use the same source module")
    if len(str(contract["coreCRDsSha256"])) != 64:
        raise ToolError("core CRD source digest must be SHA-256 pinned")
    return contract


def resolve_core_crds(contract: dict[str, Any]) -> tuple[Path, str, int]:
    module_cache = Path(
        run_checked([require_tool("go"), "env", "GOMODCACHE"]).stdout.strip()
    )
    source = (
        module_cache
        / f"{contract['sourceModule']}@{contract['sourceVersion']}"
        / "cluster"
        / "crds"
    )
    files = sorted(source.glob("*.yaml"))
    if not source.is_dir() or not files:
        raise ToolError(
            "locked Crossplane source CRDs are missing; build the renderer first"
        )
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    actual = digest.hexdigest()
    expected_count = int(contract["coreCRDCount"])
    if len(files) != expected_count or actual != contract["coreCRDsSha256"]:
        raise ToolError(
            "Crossplane core CRD source differs from the locked count or digest"
        )
    return source, actual, len(files)


def write_core_schema_cache(
    destination: Path, identity: str, source: Path
) -> Path:
    cache_path = destination / identity.replace(":", "@")
    cache_path.mkdir(parents=True, exist_ok=True)
    package = cache_path / "package.yaml"
    payload = b""
    for path in sorted(source.glob("*.yaml")):
        payload += path.read_bytes().rstrip() + b"\n---\n"
    if not payload:
        raise ToolError("refusing to create an empty Crossplane schema cache")
    package.write_bytes(payload)
    return package


def write_documents(path: Path, documents: list[dict[str, Any]]) -> None:
    if not documents:
        raise ToolError(f"refusing to write an empty validation input: {path}")
    payload = "\n---\n".join(
        json.dumps(item, indent=2, sort_keys=True) for item in documents
    )
    path.write_text(payload + "\n")


def assert_keys(
    value: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    path: str,
) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing or unknown:
        raise ToolError(
            f"{path} has missing keys {sorted(missing)} or unknown keys {sorted(unknown)}"
        )


def validate_string_map(value: object, path: str) -> None:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise ToolError(f"{path} must be a string map")


def validate_metadata(metadata: object, *, namespaced: bool, path: str) -> None:
    if not isinstance(metadata, dict):
        raise ToolError(f"{path}.metadata must be an object")
    allowed = {"name", "namespace", "labels", "annotations", "finalizers"}
    required = {"name", "namespace"} if namespaced else {"name"}
    assert_keys(metadata, allowed=allowed, required=required, path=f"{path}.metadata")
    if not isinstance(metadata["name"], str) or not metadata["name"]:
        raise ToolError(f"{path}.metadata.name must be non-empty")
    if namespaced and (
        not isinstance(metadata["namespace"], str) or not metadata["namespace"]
    ):
        raise ToolError(f"{path}.metadata.namespace must be non-empty")
    for field in ("labels", "annotations"):
        if field in metadata:
            validate_string_map(metadata[field], f"{path}.metadata.{field}")
    if "finalizers" in metadata and (
        not isinstance(metadata["finalizers"], list)
        or any(not isinstance(item, str) for item in metadata["finalizers"])
    ):
        raise ToolError(f"{path}.metadata.finalizers must be a string list")


def validate_builtin_manifest(document: dict[str, Any]) -> None:
    api_version = str(document.get("apiVersion", ""))
    kind = str(document.get("kind", ""))
    identity = (api_version, kind)
    if identity not in BUILTIN_GVKS:
        raise ToolError(f"no locked builtin validator for {api_version}, Kind={kind}")
    name = str(document.get("metadata", {}).get("name", ""))
    path = f"{kind}/{name or '<missing>'}"
    if kind == "Namespace":
        assert_keys(
            document,
            allowed={"apiVersion", "kind", "metadata"},
            required={"apiVersion", "kind", "metadata"},
            path=path,
        )
        validate_metadata(document["metadata"], namespaced=False, path=path)
        return
    if kind == "ConfigMap":
        assert_keys(
            document,
            allowed={"apiVersion", "kind", "metadata", "data", "binaryData", "immutable"},
            required={"apiVersion", "kind", "metadata"},
            path=path,
        )
        validate_metadata(document["metadata"], namespaced=True, path=path)
        for field in ("data", "binaryData"):
            if field in document:
                validate_string_map(document[field], f"{path}.{field}")
        if "immutable" in document and not isinstance(document["immutable"], bool):
            raise ToolError(f"{path}.immutable must be boolean")
        return
    if kind == "Role":
        assert_keys(
            document,
            allowed={"apiVersion", "kind", "metadata", "rules"},
            required={"apiVersion", "kind", "metadata", "rules"},
            path=path,
        )
        validate_metadata(document["metadata"], namespaced=True, path=path)
        rules = document["rules"]
        if not isinstance(rules, list) or not rules:
            raise ToolError(f"{path}.rules must be a non-empty list")
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ToolError(f"{path}.rules[{index}] must be an object")
            assert_keys(
                rule,
                allowed={"apiGroups", "resources", "resourceNames", "verbs", "nonResourceURLs"},
                required={"verbs"},
                path=f"{path}.rules[{index}]",
            )
            for field, value in rule.items():
                if not isinstance(value, list) or any(
                    not isinstance(item, str) for item in value
                ):
                    raise ToolError(f"{path}.rules[{index}].{field} must be a string list")
        return
    assert_keys(
        document,
        allowed={"apiVersion", "kind", "metadata", "roleRef", "subjects"},
        required={"apiVersion", "kind", "metadata", "roleRef", "subjects"},
        path=path,
    )
    validate_metadata(document["metadata"], namespaced=True, path=path)
    role_ref = document["roleRef"]
    if not isinstance(role_ref, dict):
        raise ToolError(f"{path}.roleRef must be an object")
    assert_keys(
        role_ref,
        allowed={"apiGroup", "kind", "name"},
        required={"apiGroup", "kind", "name"},
        path=f"{path}.roleRef",
    )
    subjects = document["subjects"]
    if not isinstance(subjects, list) or not subjects:
        raise ToolError(f"{path}.subjects must be a non-empty list")
    for index, subject in enumerate(subjects):
        if not isinstance(subject, dict):
            raise ToolError(f"{path}.subjects[{index}] must be an object")
        assert_keys(
            subject,
            allowed={"apiGroup", "kind", "name", "namespace"},
            required={"kind", "name"},
            path=f"{path}.subjects[{index}]",
        )
        if any(not isinstance(value, str) for value in subject.values()):
            raise ToolError(f"{path}.subjects[{index}] values must be strings")


def split_builtin_manifests(
    documents: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    builtins: list[dict[str, Any]] = []
    custom: list[dict[str, Any]] = []
    for document in documents:
        target = (
            builtins
            if (str(document.get("apiVersion", "")), str(document.get("kind", "")))
            in BUILTIN_GVKS
            else custom
        )
        target.append(document)
    for document in builtins:
        validate_builtin_manifest(document)
    return builtins, custom


def strict_validate(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size == 0:
        raise ToolError(f"validation input is missing or empty: {path}")
    contract = schema_validation_contract(load_yaml(LOCK_FILE))
    version = run_checked([require_tool("crossplane"), "version", "--client"]).stdout
    if f"Client Version: {contract['cliVersion']}" not in version:
        raise ToolError("installed Crossplane CLI differs from the schema validation lock")
    source, digest, count = resolve_core_crds(contract)
    extensions = ",".join(
        [str(SCHEMA_DIRECTORY), *(str(item) for item in XRD_PATHS)]
    )
    with tempfile.TemporaryDirectory(prefix="eks-crossplane-schema-cache-") as temporary:
        cache = Path(temporary)
        write_core_schema_cache(cache, str(contract["cacheIdentity"]), source)
        result = run_checked(
            [
                require_tool("crossplane"),
                "resource",
                "validate",
                extensions,
                str(path),
                f"--crossplane-image={contract['cacheIdentity']}",
                f"--cache-dir={cache}",
                "--error-on-missing-schemas",
                "--skip-success-results",
            ],
            timeout=300,
        )
    return {
        "coreCRDCount": count,
        "coreCRDsSha256": digest,
        "diagnostic": result.stdout.strip(),
        "path": str(path),
        "strict": True,
    }


def merge_observed(*documents: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for document in documents:
        overlap = set(result) & set(document)
        if overlap:
            raise ToolError(f"duplicate observed resource keys: {sorted(overlap)}")
        result.update(copy.deepcopy(document))
    return result


def foundation_inputs() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    fixtures = EKS_ROOT / "tests" / "fixtures" / "p8"
    instance = load_yaml(fixtures / "foundation-gitops-valid.yaml")
    observed = merge_observed(
        load_yaml(fixtures / "observed-network-approved.yaml"),
        load_yaml(fixtures / "observed-argocd-prerequisites-ready.yaml"),
        load_yaml(fixtures / "observed-project-ready.yaml"),
    )
    rendered = render_foundation.render(instance, observed)
    resources = [
        item
        for item in rendered.get("items", [])
        if isinstance(item, dict)
        and item.get("metadata", {}).get("annotations", {}).get(RESOURCE_NAME)
    ]
    embedded: list[dict[str, Any]] = []
    for resource in resources:
        if resource.get("kind") != "Object":
            continue
        manifest = resource.get("spec", {}).get("forProvider", {}).get("manifest")
        if not isinstance(manifest, dict) or not manifest.get("kind"):
            name = resource.get("metadata", {}).get("annotations", {}).get(RESOURCE_NAME)
            raise ToolError(f"Object/{name} has no embedded manifest")
        embedded.append(copy.deepcopy(manifest))
    if not embedded:
        raise ToolError("foundation render produced no embedded remote manifests")
    return resources, embedded


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        action="append",
        default=[],
        help="additional multi-document render output to validate",
    )
    parser.add_argument(
        "--foundation-embedded",
        action="store_true",
        help="render the full P8 foundation stage and validate wrappers plus embedded CRs",
    )
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        lock = load_yaml(LOCK_FILE)
        contract = schema_validation_contract(lock)
        if not args.input and not args.foundation_embedded:
            raise ToolError("provide --input or --foundation-embedded")
        with output_directory(args.output_dir, "eks-schema-validation-") as destination:
            targets = [path.resolve() for path in args.input]
            embedded_count = 0
            builtin_count = 0
            wrapper_count = 0
            if args.foundation_embedded:
                wrappers, embedded = foundation_inputs()
                wrapper_path = destination / "foundation-wrappers.yaml"
                write_documents(wrapper_path, wrappers)
                targets.append(wrapper_path)
                builtins, custom = split_builtin_manifests(embedded)
                if builtins:
                    builtin_path = destination / "foundation-embedded-builtins.yaml"
                    write_documents(builtin_path, builtins)
                if custom:
                    embedded_path = destination / "foundation-embedded-custom.yaml"
                    write_documents(embedded_path, custom)
                    targets.append(embedded_path)
                wrapper_count = len(wrappers)
                embedded_count = len(embedded)
                builtin_count = len(builtins)
            validations = [strict_validate(path) for path in targets]
            report = {
                "builtinContractValidated": builtin_count,
                "coreCRDCount": validations[0]["coreCRDCount"] if validations else 0,
                "coreCRDsSha256": (
                    validations[0]["coreCRDsSha256"] if validations else ""
                ),
                "embeddedRemoteManifests": embedded_count,
                "schemaValidationMode": contract["mode"],
                "missingSchemas": 0,
                "validatedFiles": len(validations),
                "wrapperResources": wrapper_count,
            }
            (destination / "schema-validation.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n"
            )
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (KeyError, OSError, ToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
