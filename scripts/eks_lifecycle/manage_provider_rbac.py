#!/usr/bin/env python3
"""Offline RBAC rendering and explicit, fail-closed shared-cluster migration."""
from __future__ import annotations

import argparse
import copy
import json
import re

from common import EKS_ROOT, ToolError, load_yaml
import harden_management_kind as maintenance

ROOT = EKS_ROOT / "management-rbac"
MAINTENANCE_ROOT = EKS_ROOT / "management-rbac-maintenance"
NS = "crossplane-system"
SESSION = "eks-platform-aws-session"
LEGACY_LOCAL_ADMIN = "crossplane-local-runtime-cluster-admin"
ACK = "I-APPROVE-EXPLICIT-PROVIDER-RBAC"
LABELS = {"platform.aws.goodnotes.io/managed-by": "platform-rbac-operator"}
READ = ["get", "list", "watch"]
WRITE = ["get", "list", "watch", "create", "update", "patch", "delete"]
AWS_SERVICES = {
    "aws",
    "cloudwatchevents",
    "ec2",
    "eks",
    "iam",
    "rds",
    "s3",
    "sqs",
}
REMOTE_AUTH_SERVICES = {"helm", "kubernetes"}
SESSION_READER_SERVICES = {"cloudwatchevents", "ec2", "eks", "iam", "sqs"}
RUNTIME_AWS = "eks-aws-session"
RUNTIME_REMOTE = "eks-remote-auth"
RUNTIME_DEFAULT = "default"
PACKAGE_DIGEST = re.compile(r"^.+@sha256:([a-f0-9]{64})$")


def inventory() -> dict:
    result = load_yaml(ROOT / "inventory.yaml")
    if result.get("schemaVersion") != 2 or result.get("context") != maintenance.CONTEXT or result.get("namespace") != NS:
        raise ToolError("unreviewed inventory context/schema")
    providers = result["providers"]
    if {p.get("service") for p in providers} != AWS_SERVICES | REMOTE_AUTH_SERVICES:
        raise ToolError("reviewed Provider service inventory is incomplete")
    for field in ("name", "revision", "package", "lockKey", "service"):
        if len({p[field] for p in providers}) != len(providers):
            raise ToolError("duplicate provider identity")
    for provider in providers:
        service = provider["service"]
        if service not in AWS_SERVICES | REMOTE_AUTH_SERVICES:
            raise ToolError("new Provider service requires a renderer review")
        digest = PACKAGE_DIGEST.fullmatch(provider["package"])
        if digest is None:
            raise ToolError("Provider package must use an immutable sha256 digest")
        expected_revision = f"{provider['name']}-{digest.group(1)[:12]}"
        if provider["revision"] != expected_revision:
            raise ToolError("Provider revision does not match its package digest")
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", provider.get("version", "")):
            raise ToolError("Provider version must be an explicit release")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]+", provider["lockKey"]):
            raise ToolError("Provider lock key is invalid")
        if not isinstance(provider["sessionReader"], bool):
            raise ToolError("sessionReader must be explicit")
        expected_runtime = (
            RUNTIME_AWS
            if service in SESSION_READER_SERVICES
            else RUNTIME_REMOTE
            if service in REMOTE_AUTH_SERVICES
            else RUNTIME_DEFAULT
        )
        if provider["runtimeConfig"] != expected_runtime:
            raise ToolError("Provider runtime does not match the reviewed service boundary")
        if provider["sessionReader"] != (service in SESSION_READER_SERVICES):
            raise ToolError("session Secret reader does not match the reviewed service boundary")
    if sum(p["runtimeConfig"] != RUNTIME_DEFAULT for p in providers) != 7:
        raise ToolError("exactly seven Provider runtimes must consume an on-demand session")
    return result


def groups(service: str) -> list[str]:
    if service == "aws":
        return ["aws.upbound.io", "aws.m.upbound.io"]
    if service in AWS_SERVICES:
        return [f"{service}.aws.upbound.io", f"{service}.aws.m.upbound.io"]
    return [f"{service}.crossplane.io", f"{service}.m.crossplane.io"]


def rule(api_groups: list[str], resources: list[str], verbs: list[str], names: list[str] | None = None) -> dict:
    result = {"apiGroups": api_groups, "resources": resources, "verbs": verbs}
    if names:
        result["resourceNames"] = names
    return result


def role(name: str, rules: list[dict], namespaced: bool = False) -> dict:
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role" if namespaced else "ClusterRole",
            "metadata": {"name": name, "labels": LABELS, **({"namespace": NS} if namespaced else {})}, "rules": rules}


def binding(name: str, subjects: list[str], namespaced: bool = False) -> dict:
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding" if namespaced else "ClusterRoleBinding",
            "metadata": {"name": name, "labels": LABELS, **({"namespace": NS} if namespaced else {})},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role" if namespaced else "ClusterRole", "name": name},
            "subjects": [{"kind": "ServiceAccount", "name": subject, "namespace": NS} for subject in subjects]}


def render(contract: dict) -> list[dict]:
    documents = []
    core_groups = set(contract["coreApiGroups"])
    subjects = [p["revision"] for p in contract["providers"]]
    for provider in contract["providers"]:
        service = provider["service"]
        api_groups = groups(service)
        core_groups.update(api_groups)
        rules = [rule(api_groups, ["*"], WRITE)]
        if service in AWS_SERVICES - {"aws"}:
            rules.extend([
                rule(groups("aws"), ["providerconfigs", "clusterproviderconfigs"], READ),
                rule(groups("aws"), ["providerconfigusages", "providerconfigusages/status", "providerconfigusages/finalizers"], WRITE),
            ])
        name = "eks-platform-provider-" + service
        documents.extend([role(name, rules), binding(name, [provider["revision"]])])
    # No core Secret rule, ServiceAccount-token rule, pod-creation or RBAC escalation in Provider roles.
    documents.extend([
        role("eks-platform-provider-discovery", [rule(["apiextensions.k8s.io"], ["customresourcedefinitions"], READ)]),
        binding("eks-platform-provider-discovery", subjects),
        role("eks-platform-provider-runtime", [rule([""], ["configmaps", "events"], WRITE),
                                                rule(["coordination.k8s.io"], ["leases"], WRITE)], True),
        binding("eks-platform-provider-runtime", subjects, True),
        role("eks-platform-session-reader", [rule([""], ["secrets"], ["get"], [SESSION])], True),
        binding("eks-platform-session-reader", [p["revision"] for p in contract["providers"] if p["sessionReader"]], True),
        role("eks-platform-core-composition", [rule(sorted(core_groups), ["*"], WRITE)]),
        binding("eks-platform-core-composition", ["crossplane"]),
    ])
    return documents


def rendered_bytes(contract: dict) -> bytes:
    result = maintenance.run(["yq", "eval", "-P", ".", "-"],
                             "\n---\n".join(json.dumps(d) for d in render(contract)).encode())
    return b"# Generated by scripts/eks_lifecycle/manage_provider_rbac.py; do not hand edit.\n" + result


def render_core() -> dict:
    """Preserve unrelated dirty manifest chunks, including TLS placeholders."""
    root = EKS_ROOT.parent / "crossplane"
    values = load_yaml(root / "values.yaml")
    if values.get("rbacManager", {}).get("deploy") is not False:
        raise ToolError("automatic RBAC must be explicitly disabled in Helm values")
    fresh = maintenance.run(["helm", "template", "crossplane", "crossplane-stable/crossplane",
                             "--version", "2.2.1", "--namespace", NS, "--include-crds",
                             "-f", str(root / "values.yaml")]).decode()
    def chunks(text: str) -> list[tuple[dict, str]]:
        result = []
        for chunk in re.split(r"(?m)^---\s*$", text):
            if not chunk.strip():
                continue
            parsed = json.loads(maintenance.run(["yq", "eval", "-o=json", ".", "-"], chunk.encode()))
            if parsed:
                result.append((parsed, chunk))
        return result
    def identity(doc: dict) -> tuple:
        return doc["kind"], doc["metadata"].get("namespace"), doc["metadata"]["name"]
    def normalized(doc: dict) -> dict:
        candidate = copy.deepcopy(doc)
        if candidate.get("kind") == "Deployment":
            spec = candidate["spec"]["template"]["spec"]
            for container in spec.get("containers", []) + spec.get("initContainers", []):
                for resources in container.get("resources", {}).values():
                    if "cpu" in resources:
                        resources["cpu"] = str(resources["cpu"])
                    if resources.get("memory") == "1Gi":
                        resources["memory"] = "1024Mi"
        return candidate
    desired = {identity(doc): (doc, raw) for doc, raw in chunks(fresh)}
    retained = []
    removed = 0
    for doc, raw in chunks((root / "manifest.yaml").read_text()):
        key = identity(doc)
        if ("# Source: crossplane/templates/rbac-manager-" in raw
                or key == ("ClusterRole", None, "crossplane:system:aggregate-to-crossplane")):
            if key in desired:
                raise ToolError("unexpected retained automatic RBAC document")
            removed += 1
            continue
        if key not in desired:
            raise ToolError("unrelated manifest removal refused")
        candidate, candidate_raw = desired.pop(key)
        if key == ("ClusterRole", None, "crossplane"):
            if candidate.get("aggregationRule"):
                raise ToolError("rendered core RBAC still aggregated")
            retained.append(candidate_raw)
        else:
            if normalized(candidate) != normalized(doc):
                raise ToolError("unrelated existing manifest differs; refusing overwrite")
            retained.append(raw)
    if desired:
        raise ToolError("unexpected new baseline documents")
    (root / "manifest.yaml").write_text("---\n" + "\n---\n".join(s.strip("\n") for s in retained) + "\n")
    return {"automaticRbacDocumentsRemovedFromSource": removed, "unrelatedDocumentsPreserved": True}


def verify_inventory(contract: dict) -> None:
    actual = maintenance.kube(["get", "providers.pkg.crossplane.io"])["items"]
    if {p["metadata"]["name"] for p in actual} != {p["name"] for p in contract["providers"]}:
        raise ToolError("installed Provider inventory changed; explicit review required")
    by_name = {p["metadata"]["name"]: p for p in actual}
    for expected in contract["providers"]:
        provider = by_name[expected["name"]]
        if provider["spec"]["package"] != expected["package"] or provider["status"]["currentRevision"] != expected["revision"]:
            raise ToolError("Provider package/revision differs from reviewed inventory")
        deployment = maintenance.kube(["get", "deployment", expected["revision"], "-n", NS])
        if deployment["spec"]["template"]["spec"]["serviceAccountName"] != expected["revision"]:
            raise ToolError("Provider uses an unreviewed ServiceAccount")


def retired_targets(contract: dict) -> list[tuple[str, str, str | None]]:
    result = [("deployment", "crossplane-rbac-manager", NS),
              ("clusterrolebinding", "crossplane-rbac-manager", None),
              ("clusterrole", "crossplane-rbac-manager", None),
              ("serviceaccount", "rbac-manager", NS),
              ("clusterrolebinding", LEGACY_LOCAL_ADMIN, None)]
    for provider in contract["providers"]:
        name = "crossplane:provider:" + provider["revision"] + ":system"
        result.extend([("clusterrolebinding", name, None), ("clusterrole", name, None)])
    return result


def can_i(account: str, verb: str, resource: str, namespace: str = NS, name: str = "", group: str = "") -> bool:
    base_resource, _, subresource = resource.partition("/")
    review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": {
        "user": f"system:serviceaccount:{NS}:{account}",
        "groups": ["system:authenticated", "system:serviceaccounts", f"system:serviceaccounts:{NS}"],
        "resourceAttributes": {"verb": verb, "group": group, "resource": base_resource,
                               "subresource": subresource, "namespace": namespace, "name": name}}}
    status = maintenance.kube(["create", "-f", "-"], review).get("status", {})
    if "allowed" not in status or status.get("evaluationError"):
        raise ToolError("authorization review incomplete")
    return status["allowed"] is True


def audit(contract: dict, *, permission_probes: bool = True) -> dict:
    verify_inventory(contract)
    for resource, name, namespace in retired_targets(contract):
        options = ["-n", namespace] if namespace else []
        found = maintenance.kube(["get", resource, *options, "--field-selector", f"metadata.name={name}"])["items"]
        if found:
            raise ToolError("legacy automatic RBAC entry remains")
    for desired in render(contract):
        meta = desired["metadata"]
        options = ["-n", meta["namespace"]] if "namespace" in meta else []
        actual = maintenance.kube(["get", desired["kind"], meta["name"], *options])
        for key in ("rules", "roleRef", "subjects"):
            if key in desired and actual.get(key) != desired[key]:
                raise ToolError("explicit RBAC document drift")
        if actual.get("aggregationRule") or actual["metadata"].get("ownerReferences"):
            raise ToolError("explicit RBAC has another owner")
    core = maintenance.kube(["get", "clusterrole", "crossplane"])
    if core.get("aggregationRule"):
        raise ToolError("core still depends on old automatic aggregation")
    if not permission_probes:
        return {"explicitRbacDocumentsVerified": len(render(contract)), "permissionProbesRun": False}
    count = 0
    for provider in contract["providers"]:
        account, service = provider["revision"], provider["service"]
        probes = [
            ("get", "secrets", NS, SESSION, "", provider["sessionReader"]),
            ("get", "secrets", NS, "unreviewed-secret", "", False),
            ("list", "secrets", NS, "", "", False),
            ("create", "deployments", NS, "", "apps", False),
            ("create", "serviceaccounts/token", NS, "crossplane", "", False),
            ("patch", "clusterrolebindings", "", "test-only", "rbac.authorization.k8s.io", False),
            ("create", "leases", NS, "", "coordination.k8s.io", True),
        ]
        if service in AWS_SERVICES:
            probes.extend([
                ("patch", "clusters", "", "test-only", "eks.aws.upbound.io", service == "eks"),
                ("patch", "providerconfigs", "", "test-only", "aws.upbound.io", service == "aws"),
            ])
        for verb, resource, namespace, name, group, expected in probes:
            if can_i(account, verb, resource, namespace, name, group) != expected:
                raise ToolError(f"permission matrix mismatch for reviewed service {service}")
            count += 1
    for account in ("default", "rbac-manager", "function-kcl-01ce52d97135"):
        if can_i(account, "get", "secrets", NS, SESSION):
            raise ToolError("unrelated runtime can read the session Secret")
        count += 1
    return {"explicitRbacDocumentsVerified": len(render(contract)), "authorizationChecksPassed": count,
            "automaticRbacManagerRemoved": True, "awsCredentialPublication": False}


def migrate(contract: dict) -> dict:
    maintenance.stopped_controllers()
    verify_inventory(contract)
    maintenance.verify_workloads()
    protection = json.loads(maintenance.read_private("protection.json"))
    for saved in protection["objects"]:
        obj = maintenance.kube(["get", saved["resource"], saved["name"]])
        annotations = obj["metadata"].get("annotations", {})
        if obj["metadata"]["uid"] != saved["uid"] or annotations.get(maintenance.MARKER) != protection["token"] or annotations.get(maintenance.PAUSE) != "true":
            raise ToolError("shared workload protection missing")
    targets = retired_targets(contract)
    for desired in render(contract):
        meta = desired["metadata"]
        options = ["-n", meta["namespace"]] if "namespace" in meta else []
        existing = maintenance.kube(["get", desired["kind"], *options,
                                     "--field-selector", "metadata.name=" + meta["name"]])["items"]
        if existing:
            raise ToolError("explicit RBAC target already exists; refusing first-time takeover")
    backup = []
    revision_names = {
        item["metadata"]["name"]
        for item in maintenance.kube(["get", "providerrevisions.pkg.crossplane.io"])["items"]
    }
    for resource, name, namespace in targets:
        options = ["-n", namespace] if namespace else []
        obj = maintenance.kube(["get", resource, name, *options])
        if name.startswith("crossplane:provider:"):
            revision = name[len("crossplane:provider:"):-len(":system")]
            if not any(o["kind"] == "ProviderRevision" and o["name"] == revision for o in obj["metadata"].get("ownerReferences", [])):
                raise ToolError("legacy role/binding has unexpected owner")
            if resource == "clusterrolebinding" and obj.get("subjects") != [{
                "kind": "ServiceAccount", "name": revision, "namespace": NS
            }]:
                raise ToolError("legacy binding has additional consumers")
        if name == LEGACY_LOCAL_ADMIN:
            expected_role = {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin",
            }
            subjects = obj.get("subjects", [])
            if (
                obj.get("roleRef") != expected_role
                or not subjects
                or any(
                    subject.get("kind") != "ServiceAccount"
                    or subject.get("namespace") != NS
                    or subject.get("name") not in revision_names
                    for subject in subjects
                )
            ):
                raise ToolError("legacy local admin binding has unexpected consumers")
        backup.append(obj)
    backup.append(maintenance.kube(["get", "clusterrole", "crossplane"]))
    maintenance.save_new("rbac-migration.before.json", json.dumps(backup).encode())
    # Rendered maintenance root holds the core at zero and never starts business workloads.
    maintenance.run(["kubectl", "--context", maintenance.CONTEXT, "apply", "--dry-run=server", "-k", str(MAINTENANCE_ROOT)])
    maintenance.run(["kubectl", "--context", maintenance.CONTEXT, "apply", "-k", str(MAINTENANCE_ROOT)])
    for (resource, name, namespace), original in zip(targets, backup):
        options = ["-n", namespace] if namespace else []
        current = maintenance.kube(["get", resource, name, *options])
        if current["metadata"]["uid"] != original["metadata"]["uid"]:
            raise ToolError("legacy target replaced; deletion refused")
        maintenance.run(["kubectl", "--context", maintenance.CONTEXT, "--request-timeout=30s",
                         "delete", resource, name, *options, "--wait=false"])
    return {"retiredExactObjects": len(targets), "recoverySnapshotSaved": True, **maintenance.verify_workloads()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("render", "render-core", "audit", "migrate"))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--acknowledge")
    parser.add_argument("--run-id", default="a05-20260831-rbac")
    args = parser.parse_args()
    try:
        contract = inventory()
        if args.mode == "render":
            output = rendered_bytes(contract)
            if args.check:
                if (ROOT / "permissions.yaml").read_bytes() != output:
                    raise ToolError("generated RBAC differs from reviewed inventory")
            else:
                (ROOT / "permissions.yaml").write_bytes(output)
            print(json.dumps({"renderedDocuments": len(render(contract)), "offline": True}))
        elif args.mode == "render-core":
            print(json.dumps(render_core(), sort_keys=True))
        elif args.mode == "audit":
            print(json.dumps(audit(contract), sort_keys=True))
        else:
            if args.acknowledge != ACK or not re.fullmatch(r"a05-[0-9]{8}-[a-z0-9-]{1,32}", args.run_id):
                raise ToolError("explicit migration acknowledgement/run-id required")
            maintenance.STATE = maintenance.STATE.parent / args.run_id
            print(json.dumps(migrate(contract), sort_keys=True))
        return 0
    except (ToolError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "failed", "errorType": type(exc).__name__,
                          "message": str(exc) if isinstance(exc, ToolError) else "output suppressed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
