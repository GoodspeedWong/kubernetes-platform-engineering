#!/usr/bin/env python3
"""Manually open one bounded management session, or inspect metadata; never renew."""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import renew_management_credentials as credentials
from common import ToolError


def status(environment: str) -> dict:
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,50}[a-z0-9]", environment):
        raise ToolError("explicit valid environment required")
    metadata = credentials.session_metadata("kind-kube-nebula-a")
    result = {"mode": "status", "automaticRenewal": False, "metadataOnly": True,
              "runtimeAuthenticationVerified": False}
    if metadata is None:
        return result | {"status": "not-published"}
    first, last = credentials.metadata_expiries(metadata, environment)
    now = datetime.now(timezone.utc)
    if now >= last:
        state = "expired"
    elif now >= first:
        state = "partially-expired"
    elif (first - now).total_seconds() <= 900:
        state = "expiring"
    else:
        state = "active"
    return result | {"status": state, "expiresAt": first.isoformat(), "allSessionsExpireAt": last.isoformat(),
                     "remainingSeconds": max(0, int((first - now).total_seconds()))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "open", "status"))
    parser.add_argument("--environment")
    parser.add_argument("--profile")
    parser.add_argument("--audit-profile")
    parser.add_argument("--review", type=Path)
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args(argv)
    try:
        if args.mode == "plan":
            result = {"mode": "plan", "sessionMode": credentials.SESSION_MODE,
                      "maxWindowSeconds": credentials.MAX_SESSION_SECONDS,
                      "automaticRenewal": False, "startsProcess": False,
                      "sourceCredentialsPublished": False, "awsMutation": False, "kubernetesMutation": False,
                      "requiredProviderNames": list(credentials.PROVIDERS),
                      "runtimeAuthenticationVerified": False}
        elif args.mode == "status":
            result = status(args.environment or "")
        else:
            if args.review is None:
                raise ToolError("private approved review file required")
            review = credentials.load_private_review(args.review)
            contract = credentials.BootstrapContract(**review["contract"])
            if args.environment is not None and args.environment != contract.environment:
                raise ToolError("environment differs from approved contract")
            result = credentials.open_session(contract, args.profile, args.audit_profile, review, args.acknowledge)
        print(json.dumps(result, indent=2))
        return 0
    except KeyboardInterrupt:
        print("opening interrupted; issued sessions may remain until expiry; inspect before retrying", file=sys.stderr)
        return 130
    except (ToolError, ValueError, KeyError, TypeError, AttributeError, OSError):
        print("session command failed closed; check review, IAM, runtime, expiry and metadata; no automatic retry", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
