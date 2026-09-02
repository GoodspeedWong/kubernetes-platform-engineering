#!/usr/bin/env python3
"""Stop the seven reviewed consumers and remove one owned A05 session Secret."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import renew_management_credentials as credentials
from common import ToolError, require_tool


ACKNOWLEDGEMENT = "I-APPROVE-CLOSE-ON-DEMAND-SESSION"


def _kube(contract: credentials.BootstrapContract, *args: str, body: Any | None = None) -> Any:
    return credentials._run_json(
        ["kubectl", "--context", contract.context, *args, "-o", "json"],
        input_text=json.dumps(body) if body is not None else None,
    )


def _deployments(contract: credentials.BootstrapContract) -> dict[str, dict[str, Any]]:
    return credentials.reviewed_provider_deployments(contract)


def _delete_secret(contract: credentials.BootstrapContract) -> None:
    try:
        result = subprocess.run(
            [
                "kubectl",
                "--context",
                contract.context,
                "--namespace",
                credentials.SOURCE_NAMESPACE,
                "delete",
                "secret",
                credentials.REMOTE_SECRET_NAME,
                "--wait=true",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
            env=credentials._clean_env(),
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolError("kubectl unavailable or timed out; output suppressed") from error
    if result.returncode:
        raise ToolError(f"kubectl failed (exit {result.returncode}); output suppressed")


def close_session(
    contract: credentials.BootstrapContract,
    acknowledgement: str,
) -> dict[str, Any]:
    if acknowledgement != ACKNOWLEDGEMENT:
        raise ToolError("explicit close acknowledgement required")
    require_tool("kubectl")
    metadata = credentials.session_metadata(contract.context)
    if metadata is None:
        raise ToolError("owned session Secret is not published")
    _, last = credentials.metadata_expiries(metadata, contract.environment)
    deployments = _deployments(contract)
    for item in deployments.values():
        meta = item["metadata"]
        patch = [
            {"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
            {"op": "replace", "path": "/spec/replicas", "value": 0},
        ]
        _kube(
            contract,
            "--namespace",
            credentials.SOURCE_NAMESPACE,
            "patch",
            "deployment",
            meta["name"],
            "--type=json",
            "-p",
            json.dumps(patch),
        )
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        current = _deployments(contract)
        if all(
            item.get("spec", {}).get("replicas") == 0
            and item.get("status", {}).get("replicas", 0) == 0
            for item in current.values()
        ):
            break
        time.sleep(2)
    else:
        raise ToolError("reviewed Provider runtimes did not stop before Secret removal")

    current = credentials.session_metadata(contract.context)
    if current is None or current.get("uid") != metadata.get("uid"):
        raise ToolError("session Secret ownership changed during close")
    scrubbed = _kube(
        contract,
        "--namespace",
        credentials.SOURCE_NAMESPACE,
        "get",
        "secret",
        credentials.REMOTE_SECRET_NAME,
    )
    if scrubbed["metadata"]["uid"] != metadata["uid"]:
        raise ToolError("session Secret ownership changed before scrub")
    if scrubbed.get("data"):
        scrub = [
            {
                "op": "test",
                "path": "/metadata/uid",
                "value": scrubbed["metadata"]["uid"],
            },
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": scrubbed["metadata"]["resourceVersion"],
            },
            {"op": "replace", "path": "/data", "value": {}},
        ]
        _kube(
            contract,
            "--namespace",
            credentials.SOURCE_NAMESPACE,
            "patch",
            "secret",
            credentials.REMOTE_SECRET_NAME,
            "--type=json",
            "-p",
            json.dumps(scrub),
        )
        scrubbed = _kube(
            contract,
            "--namespace",
            credentials.SOURCE_NAMESPACE,
            "get",
            "secret",
            credentials.REMOTE_SECRET_NAME,
        )
    if scrubbed["metadata"]["uid"] != metadata["uid"] or scrubbed.get("data"):
        raise ToolError("session Secret was not scrubbed; deletion refused")
    _delete_secret(contract)
    if credentials.session_metadata(contract.context) is not None:
        raise ToolError("session Secret still exists after exact deletion")
    return {
        "status": "session-closed",
        "providersStopped": len(deployments),
        "clusterCredentialMaterialRemoved": True,
        "awsSessionRevoked": False,
        "awsSessionsExpireAt": last.isoformat(),
        "awsMutation": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--acknowledge", default="")
    args = parser.parse_args(argv)
    try:
        review = credentials.load_private_review(args.review)
        contract = credentials.BootstrapContract(**review["contract"])
        credentials.verify_review_approval(contract, review)
        print(json.dumps(close_session(contract, args.acknowledge), indent=2))
        return 0
    except (ToolError, ValueError, KeyError, TypeError, AttributeError, OSError):
        print("session close failed closed; inspect metadata and Provider state", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
