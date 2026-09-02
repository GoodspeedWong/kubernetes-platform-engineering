#!/usr/bin/env python3
"""Validate XNetwork topology and immutable transitions without contacting AWS."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

from common import ToolError, load_yaml


REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
NETWORK_CLASSES = {"shared", "application", "data"}
EGRESS_MODES = {"None", "SingleNAT"}
IMMUTABLE_FIELDS = (
    "cidrBlock",
    "networkClass",
    "privateSubnets",
    "publicSubnets",
    "region",
)


def require_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolError(f"{path} must be an object")
    return value


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolError(f"{path} must be a non-empty string")
    return value


def normalized_provider_ref(parameters: dict[str, Any]) -> dict[str, str]:
    raw = parameters.get("providerConfigRef", {})
    reference = require_mapping(raw, "spec.parameters.providerConfigRef")
    extra = set(reference) - {"kind", "name"}
    if extra:
        raise ToolError("spec.parameters.providerConfigRef supports only kind and name")
    kind = reference.get("kind", "ClusterProviderConfig")
    name = reference.get("name", "default")
    if kind != "ClusterProviderConfig":
        raise ToolError("spec.parameters.providerConfigRef.kind must be ClusterProviderConfig")
    require_string(name, "spec.parameters.providerConfigRef.name")
    if len(name) > 63 or not DNS_LABEL_RE.fullmatch(name):
        raise ToolError("spec.parameters.providerConfigRef.name must be a DNS label")
    return {"kind": kind, "name": name}


def normalized_egress(parameters: dict[str, Any]) -> str:
    raw = parameters.get("egress", {})
    egress = require_mapping(raw, "spec.parameters.egress")
    if set(egress) - {"mode"}:
        raise ToolError("spec.parameters.egress supports only mode")
    mode = egress.get("mode", "None")
    if mode not in EGRESS_MODES:
        raise ToolError(f"unsupported egress mode: {mode}")
    return str(mode)


def normalized_environment_ref(parameters: dict[str, Any]) -> dict[str, str] | None:
    raw = parameters.get("environmentRef")
    if raw is None:
        return None
    reference = require_mapping(raw, "spec.parameters.environmentRef")
    if set(reference) != {"kind", "name"}:
        raise ToolError("spec.parameters.environmentRef must contain exactly kind and name")
    if reference.get("kind") != "XEKSEnvironment":
        raise ToolError("spec.parameters.environmentRef.kind must be XEKSEnvironment")
    name = require_string(reference.get("name"), "spec.parameters.environmentRef.name")
    if len(name) > 52 or not DNS_LABEL_RE.fullmatch(name):
        raise ToolError("spec.parameters.environmentRef.name must be a DNS label of at most 52 characters")
    return {"kind": "XEKSEnvironment", "name": name}


def validate_subnets(
    parameters: dict[str, Any], region: str, *, application: bool = False
) -> list[ipaddress.IPv4Network]:
    try:
        vpc = ipaddress.ip_network(
            require_string(parameters.get("cidrBlock"), "spec.parameters.cidrBlock"),
            strict=True,
        )
    except ValueError as error:
        raise ToolError(f"invalid VPC CIDR: {error}") from error
    if vpc.version != 4 or not 16 <= vpc.prefixlen <= 24:
        raise ToolError("VPC CIDR must be IPv4 with a /16 through /24 prefix")

    parsed: list[ipaddress.IPv4Network] = []
    zones: dict[str, dict[str, str]] = {}
    for visibility in ("publicSubnets", "privateSubnets"):
        subnets = require_mapping(parameters.get(visibility), f"spec.parameters.{visibility}")
        if set(subnets) != {"a", "b"}:
            raise ToolError(f"spec.parameters.{visibility} must contain exactly a and b")
        zones[visibility] = {}
        for slot in ("a", "b"):
            path = f"spec.parameters.{visibility}.{slot}"
            subnet = require_mapping(subnets.get(slot), path)
            if set(subnet) != {"availabilityZone", "cidrBlock"}:
                raise ToolError(f"{path} must contain exactly availabilityZone and cidrBlock")
            zone = require_string(subnet.get("availabilityZone"), f"{path}.availabilityZone")
            if not zone.startswith(region) or zone == region:
                raise ToolError(f"availability zone {zone} does not belong to region {region}")
            zones[visibility][slot] = zone
            try:
                network = ipaddress.ip_network(
                    require_string(subnet.get("cidrBlock"), f"{path}.cidrBlock"),
                    strict=True,
                )
            except ValueError as error:
                raise ToolError(f"invalid subnet CIDR: {error}") from error
            if network.version != 4 or not 20 <= network.prefixlen <= 28:
                raise ToolError("subnet CIDRs must be IPv4 with a /20 through /28 prefix")
            if visibility == "privateSubnets" and application and network.prefixlen != 20:
                raise ToolError(
                    "application private subnet CIDRs must use /20 for Cilium ENI and upgrade headroom"
                )
            if not network.subnet_of(vpc):
                raise ToolError(f"subnet {network} is outside VPC {vpc}")
            parsed.append(network)
        if zones[visibility]["a"] == zones[visibility]["b"]:
            raise ToolError(f"{visibility} must span two availability zones")

    if zones["publicSubnets"] != zones["privateSubnets"]:
        raise ToolError("public/private subnet slots must use the same two availability zones")
    for index, left in enumerate(parsed):
        for right in parsed[index + 1 :]:
            if left.overlaps(right):
                raise ToolError(f"subnet CIDRs overlap: {left} and {right}")
    return parsed


def validate_network(
    instance: dict[str, Any], old_instance: dict[str, Any] | None = None
) -> dict[str, Any]:
    if instance.get("apiVersion") != "platform.aws.goodnotes.io/v1alpha1":
        raise ToolError("instance apiVersion must be platform.aws.goodnotes.io/v1alpha1")
    if instance.get("kind") != "XNetwork":
        raise ToolError("instance kind must be XNetwork")
    metadata = require_mapping(instance.get("metadata"), "metadata")
    name = require_string(metadata.get("name"), "metadata.name")
    if len(name) > 63:
        raise ToolError("metadata.name must be at most 63 characters")
    spec = require_mapping(instance.get("spec"), "spec")
    parameters = require_mapping(spec.get("parameters"), "spec.parameters")
    required = set(IMMUTABLE_FIELDS)
    missing = sorted(required - set(parameters))
    if missing:
        raise ToolError(f"spec.parameters is missing required fields: {', '.join(missing)}")
    allowed = required | {"deletionPolicy", "egress", "environmentRef", "providerConfigRef"}
    extra = sorted(set(parameters) - allowed)
    if extra:
        raise ToolError(f"spec.parameters has unsupported fields: {', '.join(extra)}")

    old_parameters: dict[str, Any] | None = None
    if old_instance is not None:
        old_parameters = require_mapping(
            require_mapping(old_instance.get("spec"), "old spec").get("parameters"),
            "old spec.parameters",
        )
        for field in IMMUTABLE_FIELDS:
            if parameters.get(field) != old_parameters.get(field):
                raise ToolError(f"immutable network topology field changed: {field}")

    network_class = parameters.get("networkClass")
    if network_class not in NETWORK_CLASSES:
        raise ToolError(f"unsupported networkClass: {network_class}")
    region = require_string(parameters.get("region"), "spec.parameters.region")
    if not REGION_RE.fullmatch(region):
        raise ToolError("spec.parameters.region is not a valid AWS region shape")
    validate_subnets(parameters, region, application=network_class == "application")
    provider = normalized_provider_ref(parameters)
    egress_mode = normalized_egress(parameters)
    environment = normalized_environment_ref(parameters)
    if environment is not None and network_class != "application":
        raise ToolError("environmentRef is supported only for application networks")
    if egress_mode == "SingleNAT" and environment is None:
        raise ToolError("SingleNAT requires environmentRef")
    deletion_policy = parameters.get("deletionPolicy", "Delete")
    if deletion_policy not in {"Delete", "Orphan"}:
        raise ToolError("deletionPolicy must be Delete or Orphan")

    if old_parameters is not None:
        if provider != normalized_provider_ref(old_parameters):
            raise ToolError("immutable network topology field changed: providerConfigRef")
        if egress_mode != normalized_egress(old_parameters):
            raise ToolError("immutable network topology field changed: egress")
        if environment != normalized_environment_ref(old_parameters):
            raise ToolError("immutable network topology field changed: environmentRef")

    return {
        "network": name,
        "networkClass": network_class,
        "egressMode": egress_mode,
        "discoveryValue": environment["name"] if environment else None,
        "providerConfigRef": provider,
        "awsMutation": False,
        "kubernetesMutation": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate an XNetwork fixture offline.")
    parser.add_argument("--instance", type=Path, required=True)
    parser.add_argument("--old-instance", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        instance = load_yaml(args.instance)
        old_instance = load_yaml(args.old_instance) if args.old_instance else None
        print(json.dumps(validate_network(instance, old_instance), indent=2, sort_keys=True))
        return 0
    except (OSError, ToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
