"""Pure Standard Spot quota validation shared by U1 snapshots and live gates.

The quota limit is not account-wide available headroom or a capacity guarantee.
This module does not issue AWS calls or authorize a session.
"""

from __future__ import annotations

from common import ToolError

SERVICE_CODE = "ec2"
QUOTA_CODE = "L-34B43A08"
QUOTA_NAME = "All Standard (A, C, D, H, I, M, R, T, Z) Spot Instance Requests"
USAGE_CLASS = "Standard/Spot"
MINIMUM_VCPUS = 16  # Locked U1 environment NodePool limit, not free capacity.
IDENTITY = {
    "serviceCode": SERVICE_CODE,
    "quotaCode": QUOTA_CODE,
    "quotaName": QUOTA_NAME,
    "usageClass": USAGE_CLASS,
}


def validate_value(value: object) -> None:
    if type(value) not in (int, float) or not MINIMUM_VCPUS <= value < float("inf"):
        raise ToolError("U1 quota must be finite and at least the reviewed vCPU limit")


def validate_snapshot(quota: object) -> None:
    if (
        not isinstance(quota, dict)
        or set(quota) != set(IDENTITY) | {"value"}
        or any(quota.get(key) != value for key, value in IDENTITY.items())
    ):
        raise ToolError("U1 Standard Spot quota identity is missing or differs")
    validate_value(quota["value"])


def from_aws_response(response: object) -> dict:
    """Validate the actual API identity before producing a v2 snapshot field."""
    quota = response.get("Quota") if isinstance(response, dict) else None
    usage = quota.get("UsageMetric") if isinstance(quota, dict) else None
    if (
        not isinstance(quota, dict)
        or quota.get("ServiceCode") != SERVICE_CODE
        or quota.get("QuotaCode") != QUOTA_CODE
        or quota.get("QuotaName") != QUOTA_NAME
        or quota.get("GlobalQuota") is not False
        or not isinstance(usage, dict)
        or usage.get("MetricNamespace") != "AWS/Usage"
        or usage.get("MetricName") != "ResourceCount"
        or usage.get("MetricDimensions")
        != {
            "Class": USAGE_CLASS,
            "Resource": "vCPU",
            "Service": "EC2",
            "Type": "Resource",
        }
    ):
        raise ToolError(
            "AWS response does not identify the regional Standard Spot quota"
        )
    result = {**IDENTITY, "value": quota.get("Value")}
    validate_snapshot(result)
    return result
