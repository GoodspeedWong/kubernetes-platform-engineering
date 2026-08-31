"""Fail closed if a foundation Release leaves the approved OCI digest path."""
from __future__ import annotations

from typing import Any

from common import ToolError

CHART_KEYS = {"karpenter-crd": "karpenterCRD", "karpenter": "karpenter", "cilium": "cilium", "argo-cd": "argoCD"}


def validate(document: dict[str, Any], lock: dict[str, Any]) -> int:
    count = 0
    for item in document.get("items", []):
        if item.get("kind") != "Release" or not item.get("apiVersion", "").startswith("helm."):
            continue
        provider = item["spec"]["forProvider"]
        chart = provider.get("chart", {})
        key = CHART_KEYS.get(chart.get("name"))
        if key is None:
            raise ToolError("unreviewed foundation chart")
        expected = lock["charts"][key]
        repository = expected["reference"].rsplit("/", 1)[0]
        if (chart.get("repository") != repository or chart.get("digest") != expected["manifestDigest"]
                or chart.get("url") or provider.get("insecureSkipTLSVerify") or provider.get("plainHTTP")):
            raise ToolError("foundation chart must use its reviewed OCI repository/digest with TLS")
        count += 1
    return count
