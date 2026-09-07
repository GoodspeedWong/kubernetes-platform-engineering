"""Offline binding of 63 audited definitions to current locked local manifests."""

from __future__ import annotations

import copy
import json
import subprocess

from common import ToolError, load_yaml
import run_u0_management_preflight as u0
import u1_environment_identity as identity


def key(document):
    meta = document["metadata"]
    return (
        document["apiVersion"],
        document["kind"],
        meta.get("namespace", ""),
        meta["name"],
    )


def payload_digest(document):
    return identity.spec_digest(
        {
            k: v
            for k, v in document.items()
            if k not in {"apiVersion", "kind", "metadata", "status"}
        }
    )


def with_server_defaults(document):
    result = copy.deepcopy(document)
    kind = result["kind"]
    spec = result.get("spec", {})
    if kind in {"Provider", "Function"}:
        spec.setdefault("ignoreCrossplaneConstraints", False)
        spec.setdefault("skipDependencyResolution", False)
    elif kind == "CompositeResourceDefinition":
        # The independently reviewed v1-stored XRD retained this default when
        # served through v2. Never apply it to another field or another kind.
        spec.setdefault("defaultCompositeDeletePolicy", "Background")
    elif kind in {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}:
        constraints = spec.get(
            "matchConstraints"
            if kind == "ValidatingAdmissionPolicy"
            else "matchResources"
        )
        if constraints is not None:
            constraints.setdefault("matchPolicy", "Equivalent")
            constraints.setdefault("namespaceSelector", {})
            constraints.setdefault("objectSelector", {})
            for name in ("resourceRules", "excludeResourceRules"):
                for rule in constraints.get(name, []):
                    rule.setdefault("scope", "*")
    return result


def render_local(archive):
    documents = []
    for root in u0.APPLY_KUSTOMIZATIONS:
        rendered = subprocess.run(
            ["kubectl", "kustomize", str(root)], capture_output=True, timeout=30
        )
        if rendered.returncode:
            raise ToolError("local continuation kustomize render failed")
        parsed = subprocess.run(
            ["yq", "eval-all", "-o=json", "-I=0", "[.]", "-"],
            input=rendered.stdout,
            capture_output=True,
            timeout=30,
        )
        if parsed.returncode:
            raise ToolError("local continuation YAML decoding failed")
        documents.extend(json.loads(parsed.stdout))
    documents.extend(
        [
            u0.provider_maintenance.provider_config("eks-dev-spot"),
            load_yaml(archive / "platform-release.approved.yaml"),
            load_yaml(archive / "node-image.approved.yaml"),
            *u0.function_documents(),
        ]
    )
    result = {}
    for document in documents:
        identity_key = key(document)
        if identity_key in result and not identity.strict_equal(
            result[identity_key], document
        ):
            raise ToolError("conflicting local permanent definitions")
        result[identity_key] = document
    return result


def verify_local(archive, saved):
    documents = render_local(archive)
    evidence = {
        (x["apiVersion"], x["kind"], x["namespace"], x["name"]): x for x in saved
    }
    if len(saved) != 63 or len(evidence) != 63 or set(evidence) != set(documents):
        raise ToolError(
            "local continuation permanent definition inventory differs from audited 63"
        )
    for identity_key, desired in documents.items():
        record = evidence[identity_key]
        if (
            payload_digest(desired) != record["expectedPayloadSha256"]
            or payload_digest(with_server_defaults(desired))
            != record["actualPayloadSha256"]
        ):
            raise ToolError(
                "audited definition content/defaults differ from locked local code"
            )
    return documents
