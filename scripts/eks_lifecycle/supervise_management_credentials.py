#!/usr/bin/env python3
"""Retired continuous-renewal entry point; never launches a process or calls AWS."""
import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run"))
    args, _ = parser.parse_known_args(argv)
    if args.mode == "plan":
        print(json.dumps({"mode": "retired", "replacement": "open_management_session.py",
                          "automaticRenewal": False, "automaticRestart": False,
                          "startsProcess": False, "awsMutation": False, "kubernetesMutation": False,
                          "alertDeliveryVerified": False}, indent=2))
        return 0
    print("continuous renewal is retired; explicitly open a one-shot management session", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
