"""The old persistent supervisor must stay retired, including its legacy CLI."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))
import renew_management_credentials as credentials
import supervise_management_credentials as supervision
from common import ToolError
from test_security_remediation import contract


class RetiredSupervisionTests(unittest.TestCase):
    def test_retired_plan_never_starts_a_process(self):
        output = io.StringIO()
        with patch.object(subprocess, "Popen") as start, contextlib.redirect_stdout(output):
            self.assertEqual(0, supervision.main(["plan"]))
        plan = json.loads(output.getvalue())
        self.assertEqual("retired", plan["mode"])
        for flag in ("startsProcess", "automaticRenewal", "automaticRestart", "alertDeliveryVerified"):
            self.assertFalse(plan[flag])
        start.assert_not_called()

    def test_run_with_old_or_new_ack_never_starts_or_reads_review(self):
        for ack in ("I-ACCEPT-TEMPORARY-SESSION-RENEWAL-AND-PROVIDER-ROLLOUT", credentials.ACKNOWLEDGEMENT):
            with patch.object(subprocess, "Popen") as start, patch.object(credentials, "load_private_review") as read:
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(1, supervision.main(["run", "--review", "/unused.json", "--acknowledge", ack]))
            start.assert_not_called()
            read.assert_not_called()

    def test_legacy_renew_function_refuses_even_with_new_approval(self):
        with patch.object(credentials, "_run_json") as run:
            with self.assertRaisesRegex(ToolError, "retired"):
                credentials.renew(contract(), "source", "audit", {}, credentials.ACKNOWLEDGEMENT)
        run.assert_not_called()

    def test_old_cli_renew_is_invalid_in_both_entry_points(self):
        for name in ("bootstrap_management_credentials.py", "renew_management_credentials.py"):
            result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/eks_lifecycle" / name), "renew"],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("invalid choice", result.stderr)

    def test_private_review_rejects_shared_and_symlinked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.json"
            path.write_text("{}")
            path.chmod(0o600)
            self.assertEqual({}, credentials.load_private_review(path))
            path.chmod(0o644)
            with self.assertRaises(ToolError):
                credentials.load_private_review(path)
            link = Path(directory) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                credentials.load_private_review(link)
            path.chmod(0o600)
            Path(directory).chmod(0o755)
            with self.assertRaises(ToolError):
                credentials.load_private_review(path)


if __name__ == "__main__":
    unittest.main()
