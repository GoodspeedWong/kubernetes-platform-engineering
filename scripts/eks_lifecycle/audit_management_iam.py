#!/usr/bin/env python3
"""Run the reviewed management IAM integrity checks without opening a session."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from common import ToolError, require_tool
import renew_management_credentials as credentials


ACKNOWLEDGEMENT = "I-APPROVE-READ-ONLY-MANAGEMENT-IAM-AUDIT"
PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


def public_plan() -> dict[str, object]:
    return {
        "mode": "plan",
        "awsApiCalls": False,
        "awsResourceMutation": False,
        "kubernetesApiCalls": False,
        "platformTargetRoleSessionsIssued": False,
        "sessionSecretPublished": False,
        "requiredAwsOperations": [
            "sts:GetCallerIdentity",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy",
        ],
    }


def run_audit(
    review_path: Path,
    audit_profile: str,
    acknowledgement: str,
) -> dict[str, object]:
    if acknowledgement != ACKNOWLEDGEMENT:
        raise ToolError("explicit read-only management IAM audit acknowledgement required")
    if not audit_profile or not PROFILE_RE.fullmatch(audit_profile):
        raise ToolError("explicit valid audit profile required")
    review = credentials.load_private_review(review_path)
    try:
        contract = credentials.BootstrapContract(**review["contract"])
    except (KeyError, TypeError) as error:
        raise ToolError("management-session review contract is malformed") from error
    credentials.validate_contract(contract)
    credentials.verify_review_approval(contract, review)
    require_tool("aws")
    credentials.verify_aws_identity(contract, audit_profile, review)
    return {
        "status": "READ_ONLY_MANAGEMENT_IAM_AUDIT_PASS",
        "awsApiCalls": True,
        "awsResourceMutation": False,
        "kubernetesApiCalls": False,
        "platformTargetRoleSessionsIssued": False,
        "sessionSecretPublished": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run"))
    parser.add_argument("--review", type=Path)
    parser.add_argument("--audit-profile")
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args(argv)
    try:
        if args.mode == "plan":
            if args.review or args.audit_profile or args.acknowledge:
                raise ToolError("plan does not accept review, profile, or acknowledgement")
            result = public_plan()
        else:
            if args.review is None:
                raise ToolError("private approved management-session review required")
            result = run_audit(
                args.review,
                args.audit_profile or "",
                args.acknowledge,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except ToolError as error:
        print(f"management IAM audit failed closed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "management IAM audit failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
