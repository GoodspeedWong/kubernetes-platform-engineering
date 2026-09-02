from __future__ import annotations

import base64
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import call, patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/eks_lifecycle"))
import close_management_session as closer
import renew_management_credentials as credentials
import verify_management_session_runtime as runtime
from common import ToolError
from test_security_remediation import contract


def target_sessions() -> credentials.TargetSessions:
    now = datetime.now(timezone.utc)
    execution = {
        "AccessKeyId": "ASIA" + "A" * 16,
        "SecretAccessKey": "execution-secret-test-only",
        "SessionToken": "execution-token-test-only",
        "Expiration": (now + timedelta(minutes=30)).isoformat(),
    }
    deployment = {
        "AccessKeyId": "ASIA" + "B" * 16,
        "SecretAccessKey": "deployment-secret-test-only",
        "SessionToken": "deployment-token-test-only",
        "Expiration": (now + timedelta(minutes=31)).isoformat(),
    }
    return credentials.TargetSessions(execution, deployment, now + timedelta(minutes=32))


def published_secret() -> dict:
    document = credentials.secret_document(contract(), target_sessions())
    document["metadata"].update({"uid": "secret-uid", "resourceVersion": "42"})
    return document


def published_bundle(*, expired: bool = False) -> runtime.PublishedSessions:
    secret = published_secret()
    if expired:
        now = datetime.now(timezone.utc)
        for key, seconds in (("expires-at", -20), ("all-expires-at", -10), ("deadline", -5)):
            secret["metadata"]["annotations"][credentials.TAG_PREFIX + key] = (
                now + timedelta(seconds=seconds)
            ).isoformat()
    profiles = runtime._parse_profile_file(
        base64.b64decode(secret["data"]["credentials"]).decode()
    )
    return runtime.PublishedSessions(
        profiles["default"], profiles["eks-deployment"], secret["metadata"]
    )


def deployments(replicas: int) -> dict[str, dict]:
    return {
        provider: {
            "metadata": {
                "name": "runtime-" + str(index),
                "uid": "uid-" + str(index),
                "resourceVersion": str(index + 10),
                "labels": {"pkg.crossplane.io/provider": provider},
            },
            "spec": {"replicas": replicas},
            "status": {"replicas": replicas},
        }
        for index, provider in enumerate(credentials.PROVIDERS)
    }


class RuntimeSessionTests(unittest.TestCase):
    def test_published_secret_has_only_two_distinct_temporary_target_profiles(self):
        secret = published_secret()
        with patch.object(runtime, "_kube", return_value=secret):
            bundle = runtime.read_published_sessions(contract())
        self.assertTrue(bundle.execution["aws_access_key_id"].startswith("ASIA"))
        self.assertTrue(bundle.deployment["aws_access_key_id"].startswith("ASIA"))
        self.assertNotEqual(
            bundle.execution["aws_access_key_id"], bundle.deployment["aws_access_key_id"]
        )

    def test_profile_parser_rejects_source_or_refresh_configuration(self):
        value = base64.b64decode(published_secret()["data"]["credentials"]).decode()
        with self.assertRaises(ToolError):
            runtime._parse_profile_file(value + "source_profile=forbidden\n")

    def test_active_verification_checks_two_callers_and_read_only_service_set(self):
        bundle = published_bundle()
        with patch.object(runtime, "read_published_sessions", return_value=bundle):
            with patch.object(credentials, "verify_direct_session_runtime") as direct:
                with patch.object(runtime, "_verify_deployments", return_value=deployments(1)):
                    with patch.object(runtime, "_verify_runtime_logs") as logs:
                        with patch.object(runtime, "_verify_caller", side_effect=[contract().provider_role_arn, contract().deployment_role_arn]) as caller:
                            with patch.object(runtime, "_aws", return_value=({}, None)) as aws:
                                result = runtime.verify_active(contract())
        direct.assert_called_once_with(contract())
        logs.assert_called_once()
        self.assertEqual(2, caller.call_count)
        self.assertEqual(6, aws.call_count)
        self.assertTrue(result["runtimeAuthenticationVerified"])
        self.assertEqual(
            ["ec2", "eks", "iam", "sqs", "cloudwatchevents"],
            result["readOnlyAwsServicesVerified"],
        )

    def test_expired_verification_requires_both_real_aws_rejections(self):
        bundle = published_bundle(expired=True)
        with patch.object(runtime, "read_published_sessions", return_value=bundle):
            with patch.object(runtime, "_aws", return_value=(None, "ExpiredToken")) as aws:
                result = runtime.verify_expired(contract())
        self.assertEqual(2, aws.call_count)
        self.assertEqual(2, result["expiredCredentialRequestsRejected"])
        self.assertFalse(result["automaticRenewalObserved"])

    def test_expiry_mode_refuses_before_deadline_without_calling_aws(self):
        with patch.object(runtime, "read_published_sessions", return_value=published_bundle()):
            with patch.object(runtime, "_aws") as aws, self.assertRaises(ToolError):
                runtime.verify_expired(contract())
        aws.assert_not_called()

    def test_successful_empty_aws_query_response_is_an_empty_object(self):
        result = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(runtime.subprocess, "run", return_value=result):
            document, error = runtime._aws(
                contract(), published_bundle().execution, "sqs", "list-queues"
            )
        self.assertEqual({}, document)
        self.assertIsNone(error)


class CloseSessionTests(unittest.TestCase):
    def test_close_stops_exact_consumers_then_scrubs_and_deletes_owned_secret(self):
        metadata = published_secret()["metadata"]
        calls: list[tuple[str, ...]] = []

        def kube(_contract, *args, body=None):
            calls.append(args)
            if "get" in args and "secret" in args:
                return {"metadata": metadata, "data": {}}
            return {}

        with patch.object(credentials, "session_metadata", side_effect=[metadata, metadata, None]):
            with patch.object(closer, "_deployments", side_effect=[deployments(1), deployments(0)]):
                with patch.object(closer, "_kube", side_effect=kube):
                    result = closer.close_session(contract(), closer.ACKNOWLEDGEMENT)
        self.assertEqual(7, result["providersStopped"])
        self.assertTrue(result["clusterCredentialMaterialRemoved"])
        self.assertFalse(result["awsSessionRevoked"])
        operations = [args[2] for args in calls]
        self.assertEqual(["patch"] * 8 + ["get", "delete"], operations)

    def test_close_requires_explicit_ack_before_reading_cluster(self):
        with patch.object(credentials, "session_metadata") as read:
            with self.assertRaises(ToolError):
                closer.close_session(contract(), "")
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
