"""Strict U1 intent validation, separate from bounded Crossplane runtime fields.

No cluster, AWS, filesystem, or credential access. Callers must independently
validate and pin the referenced Composition and immutable revision documents.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from common import ToolError

COMPOSITION_NAME = "xeksenvironments.platform.aws.goodnotes.io"
CHILDREN = {
    "XNetwork": "-network",
    "XEKSCluster": "-cluster",
    "XClusterFoundation": "-foundation",
}
COMPOSITE_LABEL = "crossplane.io/composite"


def strict_equal(actual: Any, expected: Any) -> bool:
    # Python otherwise treats True == 1; that must not relax reviewed intent.
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(
            strict_equal(actual[k], expected[k]) for k in actual
        )
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(
            strict_equal(a, b) for a, b in zip(actual, expected)
        )
    return actual == expected


def spec_digest(spec: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            spec, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


@dataclass(frozen=True)
class RuntimeReferences:
    composition: str | None
    revision: str | None


@dataclass(frozen=True)
class CompositionPin:
    composition_name: str
    composition_uid: str
    revision_name: str
    revision_uid: str
    spec_sha256: str


def validate_root(
    root: dict[str, Any], expected: dict[str, Any], *, expected_uid: str | None
) -> RuntimeReferences:
    """Accept only exact reviewed intent plus explicitly bounded runtime fields."""
    error = "U1 environment identity or reviewed intent changed"
    try:
        metadata = root["metadata"]
        wanted = expected["metadata"]
        name = wanted["name"]
        if (
            root["apiVersion"] != expected["apiVersion"]
            or root["kind"] != expected["kind"]
            or metadata["name"] != name
            or not isinstance(metadata.get("uid"), str)
            or not metadata["uid"]
            or (expected_uid is not None and metadata["uid"] != expected_uid)
            or type(metadata.get("generation")) is not int
            or metadata["generation"] < 1
            or metadata.get("namespace", "") != ""
            or metadata.get("deletionTimestamp") is not None
            or metadata.get("ownerReferences", []) != []
            or not isinstance(metadata.get("finalizers", []), list)
            or len(metadata.get("finalizers", [])) > 1
            or any(
                value != "composite.apiextensions.crossplane.io"
                for value in metadata.get("finalizers", [])
            )
            or not strict_equal(
                metadata.get("annotations", {}), wanted.get("annotations", {})
            )
        ):
            raise ToolError(error)
        labels = copy.deepcopy(metadata.get("labels", {}))
        if COMPOSITE_LABEL in labels and labels.pop(COMPOSITE_LABEL) != name:
            raise ToolError(error)
        if not strict_equal(labels, wanted.get("labels", {})):
            raise ToolError(error)
        spec = copy.deepcopy(root["spec"])
        runtime = spec.get("crossplane", {})
        if not isinstance(runtime, dict):
            raise ToolError(error)
        if any(
            key in runtime and runtime[key] is None
            for key in ("compositionRef", "compositionRevisionRef")
        ):
            raise ToolError("U1 root runtime reference cannot be null")
        composition = runtime.pop("compositionRef", None)
        revision = runtime.pop("compositionRevisionRef", None)
        references = runtime.pop("resourceRefs", [])
        if not strict_equal(spec, expected["spec"]):
            raise ToolError(error)
        if composition is not None and composition != {"name": COMPOSITION_NAME}:
            raise ToolError("U1 root Composition reference differs")
        if revision is not None and (
            composition is None
            or not isinstance(revision, dict)
            or set(revision) != {"name"}
            or not isinstance(revision["name"], str)
            or not revision["name"].startswith(COMPOSITION_NAME + "-")
            or len(revision["name"]) <= len(COMPOSITION_NAME) + 1
        ):
            raise ToolError("U1 root CompositionRevision reference differs")
        if not isinstance(references, list) or len(references) > len(CHILDREN):
            raise ToolError("U1 root child reference inventory differs")
        seen: set[str] = set()
        for reference in references:
            if (
                not isinstance(reference, dict)
                or set(reference) - {"apiVersion", "kind", "name", "namespace"}
                or reference.get("apiVersion") != expected["apiVersion"]
                or reference.get("kind") not in CHILDREN
                or reference.get("name") != name + CHILDREN[reference["kind"]]
                or reference.get("namespace", "") != ""
                or reference["kind"] in seen
                or revision is None
            ):
                raise ToolError("U1 root child reference identity differs")
            seen.add(reference["kind"])
        return RuntimeReferences(
            composition["name"] if composition else None,
            revision["name"] if revision else None,
        )
    except (KeyError, TypeError, AttributeError, ValueError) as cause:
        raise ToolError(error) from cause


def validate_binding(
    composition: dict[str, Any],
    revision: dict[str, Any],
    expected_spec: dict[str, Any],
    *,
    revision_name: str,
    previous: CompositionPin | None = None,
) -> CompositionPin:
    """Verify full locked content and ownership, not just a name or field manager."""
    error = "U1 Composition or immutable revision differs from locked content"
    try:
        comp_meta, rev_meta = composition["metadata"], revision["metadata"]
        rev_spec = copy.deepcopy(revision["spec"])
        sequence = rev_spec.pop("revision")
        owner = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "Composition",
            "name": COMPOSITION_NAME,
            "uid": comp_meta["uid"],
            "controller": True,
        }
        owners = rev_meta.get("ownerReferences", [])
        if (
            composition["apiVersion"] != "apiextensions.crossplane.io/v1"
            or composition["kind"] != "Composition"
            or revision["apiVersion"] != "apiextensions.crossplane.io/v1"
            or revision["kind"] != "CompositionRevision"
            or comp_meta["name"] != COMPOSITION_NAME
            or rev_meta["name"] != revision_name
            or comp_meta.get("namespace", "") != ""
            or rev_meta.get("namespace", "") != ""
            or not isinstance(comp_meta["uid"], str)
            or not comp_meta["uid"]
            or not isinstance(rev_meta["uid"], str)
            or not rev_meta["uid"]
            or comp_meta.get("deletionTimestamp") is not None
            or rev_meta.get("deletionTimestamp") is not None
            or type(sequence) is not int
            or sequence < 1
            or not isinstance(owners, list)
            or len(owners) != 1
            or any(not strict_equal(owners[0].get(k), v) for k, v in owner.items())
            or not strict_equal(composition["spec"], expected_spec)
            or not strict_equal(rev_spec, expected_spec)
        ):
            raise ToolError(error)
        pin = CompositionPin(
            COMPOSITION_NAME,
            comp_meta["uid"],
            revision_name,
            rev_meta["uid"],
            spec_digest(expected_spec),
        )
        if previous is not None and pin != previous:
            raise ToolError("U1 pinned CompositionRevision identity changed")
        return pin
    except (KeyError, TypeError, AttributeError, ValueError) as cause:
        raise ToolError(error) from cause
