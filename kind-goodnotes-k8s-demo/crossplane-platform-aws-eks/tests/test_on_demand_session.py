from __future__ import annotations

import base64
import configparser
import contextlib
import io
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))
import open_management_session as manual
import prepare_identity_boundaries as preparation
import audit_management_iam as iam_audit
import renew_management_credentials as credentials
from common import EKS_ROOT, ToolError, load_yaml
from test_security_remediation import ACCOUNT, contract, inventory, session, target_sessions


def review():
    return inventory()[0] | {"sessionMode": credentials.SESSION_MODE}


def metadata(first_seconds=1800, last_seconds=1800):
    result = credentials.secret_document(contract(), target_sessions())["metadata"]
    now = datetime.now(timezone.utc)
    for key, seconds in (("expires-at", first_seconds), ("all-expires-at", last_seconds), ("deadline", max(last_seconds, 0) + 60)):
        result["annotations"][credentials.TAG_PREFIX + key] = (now + timedelta(seconds=seconds)).isoformat()
    return result | {"resourceVersion": "42"}


class OnDemandSessionTests(unittest.TestCase):
    def test_plan_is_offline_and_unambiguously_one_shot(self):
        output = io.StringIO()
        with patch.object(credentials, "_run_json") as run, contextlib.redirect_stdout(output):
            self.assertEqual(0, manual.main(["plan"]))
        result = json.loads(output.getvalue())
        self.assertEqual(3600, result["maxWindowSeconds"])
        for key in ("automaticRenewal", "startsProcess", "awsMutation", "sourceCredentialsPublished"):
            self.assertFalse(result[key])
        run.assert_not_called()

    def test_target_profiles_are_sdk_files_without_source_or_refresh_configuration(self):
        bundle = target_sessions()
        document = credentials.secret_document(contract(), bundle)
        shared = configparser.ConfigParser()
        shared.read_string(base64.b64decode(document["data"]["credentials"]).decode())
        config = configparser.ConfigParser()
        config.read_string(base64.b64decode(document["data"]["config"]).decode())
        self.assertEqual(["default", "eks-deployment"], shared.sections())
        self.assertEqual(bundle.execution["AccessKeyId"], shared["default"]["aws_access_key_id"])
        self.assertEqual(bundle.deployment["AccessKeyId"], shared["eks-deployment"]["aws_access_key_id"])
        for profile in config.sections():
            self.assertEqual({"region"}, set(config[profile]))
        combined = str(dict(shared)) + str(dict(config))
        for forbidden in ("credential_process", "source_profile", "role_arn", "web_identity_token_file"):
            self.assertNotIn(forbidden, combined)

    def test_source_session_cannot_be_passed_to_secret_writer(self):
        with self.assertRaises(ToolError):
            credentials.secret_document(contract(), session())

    def test_identical_target_keys_are_rejected(self):
        s = session()
        bundle = credentials.TargetSessions(s, s, datetime.now(timezone.utc) + timedelta(hours=1))
        with self.assertRaises(ToolError):
            credentials.validate_targets(bundle)

    def test_targets_must_not_outlive_deadline(self):
        bundle = target_sessions()
        bad = credentials.TargetSessions(bundle.execution, bundle.deployment, datetime.now(timezone.utc) + timedelta(minutes=20))
        with self.assertRaises(ToolError):
            credentials.validate_targets(bad)

    def test_90_minute_and_naive_target_expiry_rejected(self):
        for expiry in ((datetime.now(timezone.utc) + timedelta(minutes=90)).isoformat(), "2030-01-01T00:00:00"):
            with self.assertRaises(ToolError):
                credentials.validate_session(session() | {"Expiration": expiry})

    def test_assume_role_happens_exactly_once_for_each_target_on_host(self):
        bundle = target_sessions()
        by_role = {contract().provider_role_arn: bundle.execution, contract().deployment_role_arn: bundle.deployment}
        by_key = {session()["AccessKeyId"]: contract().source_role_arn} | {s["AccessKeyId"]: arn for arn, s in by_role.items()}
        def reply(command, *, env):
            if "assume-role" in command:
                self.assertEqual(session()["AccessKeyId"], env["AWS_ACCESS_KEY_ID"])
                self.assertNotIn("--profile", command)
                duration = int(command[command.index("--duration-seconds") + 1])
                self.assertTrue(900 <= duration < 3600)
                return {"Credentials": by_role[command[command.index("--role-arn") + 1]]}
            role = by_key[env["AWS_ACCESS_KEY_ID"]].rsplit("/", 1)[-1]
            return {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/test"}
        with patch.object(credentials, "_run_json", side_effect=reply) as run:
            actual = credentials.verify_session(contract(), session())
        self.assertEqual(bundle.execution, actual.execution)
        self.assertEqual(bundle.deployment, actual.deployment)
        self.assertEqual(2, sum("assume-role" in c.args[0] for c in run.call_args_list))
        self.assertEqual(3, sum("get-caller-identity" in c.args[0] for c in run.call_args_list))

    def test_wrong_source_identity_never_assumes_target(self):
        with patch.object(credentials, "_run_json", return_value={"Account": ACCOUNT, "Arn": "wrong"}) as run:
            with self.assertRaises(ToolError):
                credentials.verify_session(contract(), session())
        self.assertEqual(1, run.call_count)

    def test_bad_target_identity_never_publishes(self):
        with patch.object(credentials, "verify_caller", side_effect=[None, ToolError("wrong role")]):
            with patch.object(credentials, "_run_json", return_value={"Credentials": target_sessions().execution}) as run:
                with self.assertRaises(ToolError):
                    credentials.verify_session(contract(), session())
        self.assertEqual(1, run.call_count)

    def test_manual_open_exports_only_once_and_returns_without_sleep_or_loop(self):
        progress = []
        with patch.object(credentials, "require_tool"), patch.object(credentials, "verify_publication_gate") as gate:
            with patch.object(credentials, "session_metadata", return_value=None), patch.object(credentials, "verify_aws_identity") as audit:
                with patch.object(credentials, "_run_json", return_value=session()) as run:
                    with patch.object(credentials, "verify_session", return_value=target_sessions()) as assume, patch.object(credentials, "publish_session") as publish:
                        result = credentials.open_session(
                            contract(),
                            "source",
                            "audit",
                            review(),
                            credentials.ACKNOWLEDGEMENT,
                            progress=progress.append,
                        )
        gate.assert_called_once_with(contract())
        audit.assert_called_once()
        run.assert_called_once()
        self.assertIn("export-credentials", run.call_args.args[0])
        assume.assert_called_once()
        publish.assert_called_once()
        self.assertFalse(result["automaticRenewal"])
        self.assertFalse(result["runtimeAuthenticationVerified"])
        self.assertNotIn("test-only", json.dumps(result))
        self.assertEqual(list(credentials.SESSION_PROGRESS_STAGES), progress)

    def test_read_only_iam_audit_has_explicit_boundary_and_never_opens_session(self):
        self.assertFalse(iam_audit.public_plan()["awsApiCalls"])
        with (
            patch.object(credentials, "load_private_review", return_value=review()),
            patch.object(iam_audit, "require_tool") as require,
            patch.object(credentials, "verify_aws_identity") as verify,
            patch.object(credentials, "open_session") as open_session,
        ):
            result = iam_audit.run_audit(
                Path("review.json"),
                "audit-only",
                iam_audit.ACKNOWLEDGEMENT,
            )
        require.assert_called_once_with("aws")
        verify.assert_called_once_with(contract(), "audit-only", review())
        open_session.assert_not_called()
        self.assertTrue(result["awsApiCalls"])
        self.assertFalse(result["awsResourceMutation"])
        self.assertFalse(result["kubernetesApiCalls"])
        self.assertFalse(result["platformTargetRoleSessionsIssued"])
        self.assertFalse(result["sessionSecretPublished"])

    def test_read_only_iam_audit_requires_ack_before_loading_review(self):
        with (
            patch.object(credentials, "load_private_review") as load,
            self.assertRaisesRegex(ToolError, "acknowledgement"),
        ):
            iam_audit.run_audit(Path("review.json"), "audit-only", "")
        load.assert_not_called()

    def test_aws_read_failure_reports_only_safe_operation(self):
        with (
            patch.object(credentials, "_run_json", side_effect=ToolError("private stderr")),
            self.assertRaisesRegex(ToolError, "iam:get-role") as raised,
        ):
            credentials._aws("audit-only", "us-east-1", "iam", "get-role")
        self.assertNotIn("private stderr", str(raised.exception))

    def test_pending_review_and_legacy_runtime_approval_never_call_external_tools(self):
        pending = review() | {"reviewStatus": "PENDING_SECURITY_APPROVAL"}
        legacy = review()
        legacy.pop("sessionMode")
        for item in (pending, legacy):
            with patch.object(credentials, "_run_json") as run, patch.object(credentials, "verify_publication_gate") as gate:
                with self.assertRaises(ToolError):
                    credentials.open_session(contract(), "source", "audit", item, credentials.ACKNOWLEDGEMENT)
            run.assert_not_called()
            gate.assert_not_called()

    def test_missing_ack_and_same_or_bad_profiles_rejected_before_any_tool(self):
        for source, audit, ack in (("source", "audit", ""), ("same", "same", credentials.ACKNOWLEDGEMENT),
                                   ("-bad", "audit", credentials.ACKNOWLEDGEMENT)):
            with patch.object(credentials, "_run_json") as run, self.assertRaises(ToolError):
                credentials.open_session(contract(), source, audit, review(), ack)
            run.assert_not_called()

    def test_active_window_blocks_new_aws_calls_and_publication(self):
        with patch.object(credentials, "require_tool"), patch.object(credentials, "verify_publication_gate"):
            with patch.object(credentials, "session_metadata", return_value=metadata()), patch.object(credentials, "_run_json") as run:
                with patch.object(credentials, "verify_aws_identity") as audit, patch.object(credentials, "publish_session") as publish:
                    with self.assertRaisesRegex(ToolError, "still active"):
                        credentials.open_session(contract(), "source", "audit", review(), credentials.ACKNOWLEDGEMENT)
        run.assert_not_called()
        audit.assert_not_called()
        publish.assert_not_called()

    def test_iam_drift_prevents_export(self):
        with patch.object(credentials, "require_tool"), patch.object(credentials, "verify_publication_gate"):
            with patch.object(credentials, "session_metadata", return_value=None), patch.object(credentials, "verify_aws_identity", side_effect=ToolError("drift")):
                with patch.object(credentials, "_run_json") as run, self.assertRaises(ToolError):
                    credentials.open_session(contract(), "source", "audit", review(), credentials.ACKNOWLEDGEMENT)
        run.assert_not_called()

    def test_publication_failure_is_not_retried_or_reported_as_success(self):
        with patch.object(credentials, "require_tool"), patch.object(credentials, "verify_publication_gate"):
            with patch.object(credentials, "session_metadata", return_value=None), patch.object(credentials, "verify_aws_identity"):
                with patch.object(credentials, "_run_json", return_value=session()), patch.object(credentials, "verify_session", return_value=target_sessions()):
                    with patch.object(credentials, "publish_session", side_effect=ToolError("uncertain")) as publish, self.assertRaises(ToolError):
                        credentials.open_session(contract(), "source", "audit", review(), credentials.ACKNOWLEDGEMENT)
        publish.assert_called_once()

    def test_sdk_cli_retries_disabled_and_admin_environment_removed(self):
        with patch.dict("os.environ", {"AWS_ACCESS_KEY_ID": "admin", "AWS_PROFILE": "admin", "AWS_MAX_ATTEMPTS": "99"}):
            clean = credentials._clean_env()
        self.assertNotIn("AWS_ACCESS_KEY_ID", clean)
        self.assertNotIn("AWS_PROFILE", clean)
        self.assertEqual("1", clean["AWS_MAX_ATTEMPTS"])

    def test_status_reports_absent_active_warning_partial_and_expired_without_aws(self):
        cases = [(None, "not-published"), (metadata(), "active"), (metadata(800, 800), "expiring"),
                 (metadata(-10, 10), "partially-expired"), (metadata(-20, -10), "expired")]
        for item, state in cases:
            with patch.object(credentials, "session_metadata", return_value=item) as read, patch.object(credentials, "_aws") as aws:
                result = manual.status(contract().environment)
            self.assertEqual(state, result["status"])
            self.assertTrue(result["metadataOnly"])
            self.assertFalse(result["runtimeAuthenticationVerified"])
            self.assertNotIn("test-only", json.dumps(result))
            read.assert_called_once()
            aws.assert_not_called()

    def test_partial_expiry_does_not_allow_early_reopen(self):
        with self.assertRaises(ToolError):
            credentials.require_closed_window(contract(), metadata(-10, 10))
        credentials.require_closed_window(contract(), metadata(-20, -10))

    def test_foreign_legacy_and_missing_or_naive_metadata_rejected(self):
        foreign = metadata() | {"labels": {}}
        legacy = metadata()
        legacy["labels"][credentials.TAG_PREFIX + "managed-by"] = "temporary-session-renewer"
        missing = metadata()
        missing["annotations"].pop(credentials.TAG_PREFIX + "all-expires-at")
        naive = metadata()
        naive["annotations"][credentials.TAG_PREFIX + "deadline"] = "2030-01-01T00:00:00"
        for item in (foreign, legacy, missing, naive):
            with self.assertRaises(ToolError):
                credentials.metadata_expiries(item, contract().environment)

    def test_metadata_query_does_not_request_secret_data_in_output(self):
        with patch.object(credentials, "_run_json", return_value={"items": []}) as run:
            self.assertIsNone(credentials.session_metadata(contract().context))
        command = run.call_args.args[0]
        self.assertIn("metadata", command[-1])
        self.assertNotIn(".data", command[-1])

    def test_cli_environment_mismatch_fails_before_open(self):
        with patch.object(credentials, "load_private_review", return_value=review()), patch.object(credentials, "open_session") as open_session:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, manual.main(["open", "--review", "/unused", "--environment", "different-env"]))
        open_session.assert_not_called()

    def test_review_generator_selects_manual_mode_but_does_not_self_approve(self):
        item = preparation.review_pack("eks-dev-spot", f"arn:aws:iam::{ACCOUNT}:role/upstream")
        self.assertEqual(credentials.SESSION_MODE, item["sessionMode"])
        self.assertEqual("PENDING_SECURITY_APPROVAL", item["reviewStatus"])
        self.assertIsNone(item["approvedBy"])

    @staticmethod
    def runtime_replies():
        files = ("runtime-config.yaml", "aws-session-runtime.yaml")
        runtimes = [load_yaml(EKS_ROOT / "management-auth" / name) for name in files]
        providers = {"items": [{"metadata": {"name": name}, "spec": {"runtimeConfigRef": {
            "name": "eks-remote-auth" if name in ("provider-helm", "provider-kubernetes") else "eks-aws-session"}}}
                              for name in credentials.PROVIDERS]}
        config = load_yaml(EKS_ROOT / "management-aws-auth/provider-config.template.yaml")
        return runtimes + [providers, {"items": [config]}]

    def test_direct_runtime_gate_accepts_reviewed_sources(self):
        with patch.object(credentials, "_run_json", side_effect=self.runtime_replies()):
            credentials.verify_direct_session_runtime(contract())

    def test_old_assume_chain_wrong_key_or_alternate_profile_blocks_publication(self):
        for mode in ("chain", "key", "profile", "metadata"):
            replies = self.runtime_replies()
            spec = replies[-1]["items"][0]["spec"]
            if mode == "chain":
                spec["assumeRoleChain"] = [{"roleARN": contract().provider_role_arn}]
            elif mode == "key":
                spec["credentials"]["secretRef"]["key"] = "config"
            elif mode == "profile":
                spec["profile"] = "eks-deployment"
            else:
                spec["skip_metadata_api_check"] = False
            with patch.object(credentials, "_run_json", side_effect=replies), self.assertRaises(ToolError):
                credentials.verify_direct_session_runtime(contract())

    def test_missing_direct_provider_config_blocks_open(self):
        replies = self.runtime_replies()
        replies[-1] = {"items": []}
        with patch.object(credentials, "_run_json", side_effect=replies), self.assertRaises(ToolError):
            credentials.verify_direct_session_runtime(contract())

    def test_runtime_drift_and_wrong_provider_binding_fail_closed(self):
        for mode in ("runtime", "provider"):
            replies = self.runtime_replies()
            if mode == "runtime":
                replies[0]["spec"]["deploymentTemplate"]["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "AWS_ROLE_ARN", "value": "unapproved"})
            else:
                replies[2]["items"][0]["spec"]["runtimeConfigRef"]["name"] = "default"
            with patch.object(credentials, "_run_json", side_effect=replies), self.assertRaises(ToolError):
                credentials.verify_direct_session_runtime(contract())

    def test_no_hidden_loop_scheduler_or_login_in_session_entry_points(self):
        for filename in ("open_management_session.py", "renew_management_credentials.py", "supervise_management_credentials.py"):
            text = (ROOT / "scripts/eks_lifecycle" / filename).read_text()
            for forbidden in ("while True:", "time.sleep(", '"sso", "login"', "KeepAlive"):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
