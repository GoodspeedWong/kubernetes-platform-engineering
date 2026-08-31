from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))
from renew_management_credentials import public_plan
from test_security_remediation import contract


class ManagementCredentialBootstrapTests(unittest.TestCase):
    def test_plan_is_offline_and_contains_no_credentials(self):
        result = public_plan(contract())
        self.assertFalse(result["awsMutation"])
        self.assertFalse(result["kubernetesMutation"])
        self.assertFalse(result["accessKeyCreated"])
        self.assertEqual(result["providerSecret"], result["remoteSecret"])

    def test_old_apply_mode_is_removed(self):
        script = ROOT / "scripts/eks_lifecycle/bootstrap_management_credentials.py"
        result = subprocess.run([sys.executable, str(script), "apply"], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("invalid choice", result.stderr)
        for name in ("bootstrap_management_credentials.py", "renew_management_credentials.py"):
            source = (ROOT / "scripts/eks_lifecycle" / name).read_text()
            self.assertNotIn('"create-access-key"', source)

    def test_cli_plan_uses_no_aws_profile(self):
        script = ROOT / "scripts/eks_lifecycle/bootstrap_management_credentials.py"
        args = [sys.executable, str(script), "plan"]
        for key, value in contract().__dict__.items():
            args += ["--" + key.replace("_", "-"), value]
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(json.loads(result.stdout)["kubernetesMutation"])


if __name__ == "__main__":
    unittest.main()
