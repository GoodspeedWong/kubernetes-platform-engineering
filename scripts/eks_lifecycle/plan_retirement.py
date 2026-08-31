#!/usr/bin/env python3
"""Print exactly one evidence-gated retirement transition; never mutate anything."""

from __future__ import annotations

import argparse
import json
import sys

from common import EKS_ROOT, ToolError, load_yaml


STAGES = (
    "Active",
    "DrainWorkloads",
    "RemoveGitOps",
    "DrainCapacity",
    "RemoveFoundation",
    "DeleteReady",
)
INVENTORY = EKS_ROOT / "lifecycle-inventory.yaml"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plan only the next EKS retirement transition; never execute deletion."
    )
    parser.add_argument("--current-stage", choices=STAGES, required=True)
    parser.add_argument(
        "--target-stage",
        choices=STAGES,
        help="optional assertion; it must be exactly the next stage",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    current = STAGES.index(args.current_stage)
    if current == len(STAGES) - 1:
        if args.target_stage and args.target_stage != args.current_stage:
            print("ERROR: DeleteReady has no next stage", file=sys.stderr)
            return 1
        print(
            json.dumps(
                {
                    "execute": False,
                    "currentStage": args.current_stage,
                    "complete": True,
                    "nextStage": None,
                    "note": "Delete the root XR only after protection is observed disabled; the Composition is not called during XR deletion.",
                },
                indent=2,
            )
        )
        return 0
    next_stage = STAGES[current + 1]
    if args.target_stage and args.target_stage != next_stage:
        print(
            f"ERROR: only the next stage is plannable: {args.current_stage} -> {next_stage}",
            file=sys.stderr,
        )
        return 1
    try:
        inventory = load_yaml(INVENTORY)["spec"]["stages"][next_stage]
    except (OSError, KeyError, TypeError, ToolError) as error:
        print(f"ERROR: invalid retirement inventory: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "execute": False,
                "currentStage": args.current_stage,
                "nextStage": next_stage,
                "transition": {"from": args.current_stage, "to": next_stage},
                "inventorySha256": inventory["inventorySha256"],
                "remove": inventory["remove"],
                "retain": inventory["retain"],
                "requiredEvidence": inventory["requiredEvidence"],
                "blockers": [
                    "fresh evidence ConfigMap has not been inspected by this read-only planner",
                    "stage must be advanced by the restricted lifecycle approver identity",
                    "stop on business PDB, Spot capacity, finalizer, hook, ENI, or remote-auth uncertainty",
                ],
                "readyToAdvance": False,
                "requiresFreshEvidence": True,
                "compositionRunsDuringDeletion": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
