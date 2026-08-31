#!/usr/bin/env python3
"""Compatibility entry point: the unsafe long-lived key workflow was removed.

Use plan or open. The former apply/renew modes and source-user flags fail closed.
"""
from renew_management_credentials import main

if __name__ == "__main__":
    raise SystemExit(main())
