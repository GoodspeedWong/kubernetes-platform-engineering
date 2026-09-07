#!/usr/bin/env python3
"""U1-only protection of shared Crossplane owners; never accesses their workloads.

This is intentionally separate from the historical A05/U0 workload-snapshot
hardener. A new reviewed U1 window selects this policy; old recovery state is
never converted or silently accepted. Only two owned pause annotations may be
written on the three known XRs and their 73 local-provider Objects.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re

from common import ToolError
import harden_management_kind as legacy
import u1_environment_identity as identity
from u1_management_scope import SHARED_PROTECTION_POLICY

ACK = "I-APPROVE-U1-SHARED-CROSSPLANE-PROTECTION"
OBJECT_RESOURCE = "objects.kubernetes.crossplane.io"
XR_NAMES = dict(
    zip(legacy.XR_TYPES, ("keycloak-poc", "trading-openclaw-data", "trading-openclaw"))
)
RUN_RE = re.compile(r"a05-[0-9]{8}-u1c?-[0-9]{2}")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]")


def assert_stopped():
    # The parent U1 runner additionally verifies the locked names/UIDs. This
    # helper refuses incomplete parking even when invoked for recovery only.
    items = legacy.kube(["get", "deployment", "-n", legacy.NAMESPACE])["items"]
    if len(items) != 14 or any(
        type(value) is not int or value != 0
        for item in items
        for value in (
            item.get("spec", {}).get("replicas", 1),
            item.get("status", {}).get("replicas", 0),
        )
    ):
        raise ToolError("U1 shared protection requires 14 fully stopped controllers")


def fingerprint(document):
    """Bind intent/ownership without persisting potentially secret Object content."""
    value = copy.deepcopy(document)
    value.pop("status", None)
    meta = value["metadata"]
    for field in ("resourceVersion", "generation", "managedFields"):
        meta.pop(field, None)
    annotations = meta.setdefault("annotations", {})
    for field in (legacy.PAUSE, legacy.MARKER):
        annotations.pop(field, None)
    return identity.spec_digest(value)


def collect():
    selected = []
    owners = []
    for resource, name in XR_NAMES.items():
        items = legacy.kube(["get", resource])["items"]
        if len(items) != 1 or items[0]["metadata"]["name"] != name:
            raise ToolError("U1 shared XR inventory differs")
        item = items[0]
        owners.append(
            {
                "apiVersion": item["apiVersion"],
                "kind": item["kind"],
                "name": name,
                "uid": item["metadata"]["uid"],
                "controller": True,
            }
        )
        selected.append((resource, item))
    objects = legacy.kube(["get", OBJECT_RESOURCE])["items"]
    if len(objects) != 73:
        raise ToolError("U1 shared Object inventory differs")
    for item in sorted(objects, key=lambda x: x["metadata"]["name"]):
        refs = item["metadata"].get("ownerReferences", [])
        if (
            len(refs) != 1
            or not any(
                all(identity.strict_equal(refs[0].get(k), v) for k, v in owner.items())
                for owner in owners
            )
            or item.get("spec", {}).get("providerConfigRef", {}).get("name")
            != "crossplane-local"
        ):
            raise ToolError("U1 shared Object owner or local target differs")
        selected.append((OBJECT_RESOURCE, item))
    seen_names, seen_uids = set(), set()
    for resource, item in selected:
        meta = item["metadata"]
        if (
            not isinstance(meta.get("name"), str)
            or NAME_RE.fullmatch(meta["name"]) is None
            or any(
                not isinstance(meta.get(k), str) or not meta[k]
                for k in ("uid", "resourceVersion")
            )
            or meta.get("deletionTimestamp") is not None
            or (resource, meta["name"]) in seen_names
            or meta["uid"] in seen_uids
        ):
            raise ToolError("U1 shared object identity is unsafe")
        seen_names.add((resource, meta["name"]))
        seen_uids.add(meta["uid"])
    return selected


def read_state():
    state = json.loads(legacy.read_private("protection.json"))
    if (
        not isinstance(state, dict)
        or set(state) != {"schemaVersion", "policy", "token", "objects"}
        or type(state["schemaVersion"]) is not int
        or state["schemaVersion"] != 1
        or state["policy"] != SHARED_PROTECTION_POLICY
        or not isinstance(state["token"], str)
        or re.fullmatch(r"[0-9a-f]{32}", state["token"]) is None
        or not isinstance(state["objects"], list)
        or len(state["objects"]) != 76
    ):
        raise ToolError(
            "U1 protection state differs; historical A05 state cannot be adopted"
        )
    seen = set()
    for saved in state["objects"]:
        if (
            not isinstance(saved, dict)
            or set(saved) != {"resource", "name", "uid", "sha256"}
            or saved["resource"] not in (*XR_NAMES, OBJECT_RESOURCE)
            or not isinstance(saved["name"], str)
            or NAME_RE.fullmatch(saved["name"]) is None
            or not isinstance(saved["uid"], str)
            or not saved["uid"]
            or not isinstance(saved["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", saved["sha256"]) is None
            or (saved["resource"], saved["name"]) in seen
        ):
            raise ToolError("U1 protection target evidence is malformed")
        seen.add((saved["resource"], saved["name"]))
    if any((resource, name) not in seen for resource, name in XR_NAMES.items()):
        raise ToolError("U1 protection state omitted a shared owner")
    return state


def check(item, saved, token, *, phase):
    if phase not in {"protected", "restored", "restoring"}:
        raise ToolError("U1 shared protection phase is unsupported")
    if item["metadata"]["uid"] != saved["uid"] or fingerprint(item) != saved["sha256"]:
        raise ToolError("U1 protected shared object identity or intent changed")
    annotations = item["metadata"].get("annotations", {})
    owned = (
        annotations.get(legacy.PAUSE) == "true"
        and annotations.get(legacy.MARKER) == token
    )
    absent = legacy.PAUSE not in annotations and legacy.MARKER not in annotations
    if not (
        owned
        if phase == "protected"
        else absent if phase == "restored" else owned or absent
    ):
        raise ToolError("U1 shared protection annotations changed ownership")
    return owned


def verify(state, *, phase):
    actual = {(r, d["metadata"]["name"]): d for r, d in collect()}
    if set(actual) != {(s["resource"], s["name"]) for s in state["objects"]}:
        raise ToolError("U1 protected shared inventory changed")
    for saved in state["objects"]:
        check(
            actual[(saved["resource"], saved["name"])],
            saved,
            state["token"],
            phase=phase,
        )


def report(**fields):
    return {
        "policy": SHARED_PROTECTION_POLICY,
        "existingKindWorkloadsAccessed": False,
        **fields,
    }


def protect():
    assert_stopped()
    selected = collect()
    token = legacy.secrets.token_hex(16)
    for _, item in selected:
        legacy.pause_patch(
            item, token
        )  # Reject preexisting protection before any write.
    state = {
        "schemaVersion": 1,
        "policy": SHARED_PROTECTION_POLICY,
        "token": token,
        "objects": [
            {
                "resource": resource,
                "name": item["metadata"]["name"],
                "uid": item["metadata"]["uid"],
                "sha256": fingerprint(item),
            }
            for resource, item in selected
        ],
    }
    legacy.save_new("protection.json", json.dumps(state).encode())
    descriptor = os.open(legacy.STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    for saved in state["objects"]:
        item = legacy.kube(["get", saved["resource"], saved["name"]])
        check(item, saved, token, phase="restored")
        legacy.kube(
            [
                "patch",
                saved["resource"],
                saved["name"],
                "--type=json",
                "-p",
                json.dumps(legacy.pause_patch(item, token)),
            ]
        )
    verify(state, phase="protected")
    return report(protectedXRs=3, protectedObjects=73)


def verify_protected():
    verify(read_state(), phase="protected")
    return report(protectedObjectsVerified=76)


def restore():
    assert_stopped()
    state = read_state()
    verify(state, phase="restoring")  # Validate all targets before first restoration.
    for saved in reversed(state["objects"]):
        item = legacy.kube(["get", saved["resource"], saved["name"]])
        if not check(item, saved, state["token"], phase="restoring"):
            continue  # Unwritten target or safely completed partial restore.
        legacy.kube(
            [
                "patch",
                saved["resource"],
                saved["name"],
                "--type=json",
                "-p",
                json.dumps(legacy.pause_patch(item, state["token"], restore=True)),
            ]
        )
    verify(state, phase="restored")
    return report(restoredObjects=76)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("protect", "verify", "restore"))
    parser.add_argument("--acknowledge", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    if args.acknowledge != ACK or RUN_RE.fullmatch(args.run_id) is None:
        parser.error(
            "explicit U1 protection acknowledgement and U1 run identity required"
        )
    legacy.STATE = legacy.STATE.parent / args.run_id
    try:
        print(
            json.dumps(
                {"protect": protect, "verify": verify_protected, "restore": restore}[
                    args.mode
                ]()
            )
        )
        return 0
    except (ToolError, OSError, ValueError, KeyError, TypeError):
        print(
            json.dumps(
                {
                    "status": "failed",
                    "recovery": "preserve private state; separately review recovery-only",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
