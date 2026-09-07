"""Pure, single-field amendment rules. No files, commands, credentials or APIs."""

from __future__ import annotations

import copy
import ipaddress
from dataclasses import asdict

from common import ToolError
import u1_environment_identity as identity

FIELD = "/spec/parameters/access/publicAccessCidrs"
CHECKS = {
    "controllersStopped": 14,
    "controllerPods": 0,
    "sessionSecretAbsent": True,
    "roots": 1,
    "childXRs": 0,
    "awsManagedResources": 0,
    "nonAwsObjects": 73,
    "sharedObjectsUnchanged": 76,
    "businessWorkloadsUnchanged": 89,
    "permanentDefinitionsUnchanged": 63,
    "sameCompositionPin": True,
}


def cidrs(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 2:
        raise ToolError("CIDR amendment requires one or two distinct public IPv4 /32s")
    try:
        for item in value:
            if not isinstance(item, str):
                raise ValueError()
            network = ipaddress.ip_network(item, strict=True)
            if (
                network.version != 4
                or network.prefixlen != 32
                or not network.network_address.is_global
                or network.network_address.is_multicast
                or str(network) != item
            ):
                raise ValueError()
    except (ValueError, TypeError) as error:
        raise ToolError("CIDR amendment contains a non-canonical public /32") from error
    if value != sorted(set(value)):
        raise ToolError("CIDR amendment list must be sorted and deduplicated")
    return value


def candidate(before, addresses):
    after = copy.deepcopy(before)
    after["spec"]["parameters"]["access"]["publicAccessCidrs"] = list(cidrs(addresses))
    if identity.strict_equal(after, before):
        raise ToolError("CIDR amendment must not be a no-op")
    return after


def verify_delta(before, after):
    wanted = candidate(
        before, after["spec"]["parameters"]["access"]["publicAccessCidrs"]
    )
    if not identity.strict_equal(wanted, after):
        raise ToolError("amendment changes intent outside the single CIDR field")


def verify_root(root, intent, uid, pin):
    refs = identity.validate_root(root, intent, expected_uid=uid)
    if (
        refs.composition != pin.composition_name
        or refs.revision != pin.revision_name
        or root["spec"]["crossplane"].get("resourceRefs", []) != []
        or root["metadata"].get("labels", {}).get(identity.COMPOSITE_LABEL)
        != intent["metadata"]["name"]
        or not isinstance(root["metadata"].get("resourceVersion"), str)
        or not root["metadata"]["resourceVersion"]
    ):
        raise ToolError("CIDR amendment requires the pinned, childless, versioned root")


def patch_for(root, before, after, uid, pin):
    verify_delta(before, after)
    verify_root(root, before, uid, pin)
    # Full metadata/spec tests protect more than a cached UID or old CIDR list.
    return [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": root["metadata"]["resourceVersion"],
        },
        {"op": "test", "path": "/metadata", "value": copy.deepcopy(root["metadata"])},
        {"op": "test", "path": "/spec", "value": copy.deepcopy(root["spec"])},
        {
            "op": "replace",
            "path": FIELD,
            "value": copy.deepcopy(
                after["spec"]["parameters"]["access"]["publicAccessCidrs"]
            ),
        },
    ]


def verify_readback(before_root, after_root, before, after, uid, pin, *, dry_run=False):
    patch_for(before_root, before, after, uid, pin)
    verify_root(after_root, after, uid, pin)
    old, new = copy.deepcopy(before_root), copy.deepcopy(after_root)
    old["spec"]["parameters"]["access"]["publicAccessCidrs"] = after["spec"][
        "parameters"
    ]["access"]["publicAccessCidrs"]
    if new["metadata"]["generation"] != old["metadata"]["generation"] + 1:
        raise ToolError("CIDR amendment generation did not advance exactly once")
    if (
        not dry_run
        and new["metadata"]["resourceVersion"] == old["metadata"]["resourceVersion"]
    ):
        raise ToolError("CIDR amendment resourceVersion did not change")
    for item in (old, new):
        item.pop("status", None)
        for field in ("managedFields", "resourceVersion", "generation"):
            item["metadata"].pop(field, None)
    if not identity.strict_equal(old, new):
        raise ToolError(
            "CIDR write changed other root metadata, runtime fields or intent"
        )


def verify_observation(observation, intent, uid, pin, egress, actor):
    if set(observation) != {
        "observedAt",
        "root",
        "compositionPin",
        "checks",
        "egress",
        "actor",
    }:
        raise ToolError("CIDR observation schema differs")
    for actual, expected in (
        (observation["checks"], CHECKS),
        (observation["compositionPin"], asdict(pin)),
        (observation["egress"], egress),
        (observation["actor"], actor),
    ):
        if not identity.strict_equal(actual, expected):
            raise ToolError("CIDR parked/actor/dual-egress observation differs")
    verify_root(observation["root"], intent, uid, pin)
