from __future__ import annotations

import copy
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from test_u1_authorization import snapshot
from test_u1_bootstrap import contract
import run_u1_bootstrap as bootstrap
import u1_continuation_operations as continuation
import u1_spot_quota as quota
import validate_u1_authorization as authorization
from common import ToolError


def aws_response(value=32.0):
    # Independent AWS-shaped fixture: do not derive its identity from production
    # constants, or an accidental On-Demand edit could keep all tests green.
    return {
        "Quota": {
            "ServiceCode": "ec2",
            "QuotaCode": "L-34B43A08",
            "QuotaName": "All Standard (A, C, D, H, I, M, R, T, Z) Spot Instance Requests",
            "GlobalQuota": False,
            "Value": value,
            "UsageMetric": {
                "MetricNamespace": "AWS/Usage",
                "MetricName": "ResourceCount",
                "MetricDimensions": {
                    "Class": "Standard/Spot",
                    "Resource": "vCPU",
                    "Service": "EC2",
                    "Type": "Resource",
                },
            },
        }
    }


def legacy_snapshot():
    document = snapshot(observed_at=datetime.now(timezone.utc) - timedelta(days=3))
    document["schemaVersion"] = 1
    document["spotQuota"] = {"quotaCode": "L-1216C47A", "value": 16.0}
    return document


class SpotQuotaTests(unittest.TestCase):
    def test_correct_aws_response_round_trips_to_snapshot(self):
        original = aws_response()
        result = quota.from_aws_response(original)
        self.assertEqual(snapshot()["spotQuota"], result)
        self.assertEqual(aws_response(), original)

    def test_threshold_accepts_int_or_float_but_not_available_headroom(self):
        for value in (16, 16.0, 32.0):
            with self.subTest(value=value):
                self.assertEqual(
                    value, quota.from_aws_response(aws_response(value))["value"]
                )

    def test_invalid_values_fail_both_live_and_snapshot(self):
        for value in (
            True,
            False,
            "32",
            None,
            {},
            [],
            0,
            -1,
            15.99,
            float("nan"),
            float("inf"),
            -float("inf"),
        ):
            with self.subTest(value=value):
                with self.assertRaises(ToolError):
                    quota.from_aws_response(aws_response(value))
                candidate = snapshot()["spotQuota"] | {"value": value}
                with self.assertRaises(ToolError):
                    quota.validate_snapshot(candidate)

    def test_on_demand_response_cannot_pass_even_with_large_limit(self):
        response = aws_response(10000)
        response["Quota"].update(
            QuotaCode="L-1216C47A", QuotaName="Running On-Demand Standard instances"
        )
        response["Quota"]["UsageMetric"]["MetricDimensions"][
            "Class"
        ] = "Standard/OnDemand"
        with self.assertRaises(ToolError):
            quota.from_aws_response(response)

    def test_each_live_identity_field_is_required(self):
        for key in (
            "ServiceCode",
            "QuotaCode",
            "QuotaName",
            "GlobalQuota",
            "UsageMetric",
            "Value",
        ):
            candidate = aws_response()
            del candidate["Quota"][key]
            with self.subTest(key=key), self.assertRaises(ToolError):
                quota.from_aws_response(candidate)

    def test_live_identity_cannot_be_spoofed_by_correct_code_alone(self):
        for field, value in (
            ("ServiceCode", "fargate"),
            ("QuotaName", "GPU Spot requests"),
            ("QuotaCode", "L-1216C47A"),
            ("GlobalQuota", True),
            ("GlobalQuota", 0),
        ):
            candidate = aws_response()
            candidate["Quota"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ToolError):
                quota.from_aws_response(candidate)

    def test_usage_metric_identity_is_required(self):
        for field, value in (
            ("MetricNamespace", "Other"),
            ("MetricName", "Other"),
            ("MetricDimensions", {}),
            ("MetricDimensions", None),
        ):
            candidate = aws_response()
            candidate["Quota"]["UsageMetric"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ToolError):
                quota.from_aws_response(candidate)
        for field, value in (
            ("Class", "Standard/OnDemand"),
            ("Resource", "Count"),
            ("Service", "Other"),
            ("Type", "Other"),
        ):
            candidate = aws_response()
            candidate["Quota"]["UsageMetric"]["MetricDimensions"][field] = value
            with self.subTest(field=field), self.assertRaises(ToolError):
                quota.from_aws_response(candidate)

    def test_malformed_live_envelopes_fail_closed(self):
        for value in (
            None,
            [],
            True,
            {},
            {"Quota": None},
            {"Quota": []},
            {"Quota": aws_response()["Quota"] | {"UsageMetric": []}},
        ):
            with self.subTest(value=value), self.assertRaises(ToolError):
                quota.from_aws_response(value)

    def test_snapshot_identity_fields_exact_and_mandatory(self):
        original = snapshot()["spotQuota"]
        for field in original:
            missing = original.copy()
            del missing[field]
            with self.subTest(field=field), self.assertRaises(ToolError):
                quota.validate_snapshot(missing)
        for bad in (
            None,
            [],
            original | {"extra": True},
            original | {"quotaCode": "L-1216C47A"},
            original | {"serviceCode": "other"},
            original | {"quotaName": "other"},
            original | {"usageClass": "Standard/OnDemand"},
        ):
            with self.subTest(bad=bad), self.assertRaises(ToolError):
                quota.validate_snapshot(bad)

    def test_v2_snapshot_passes_both_active_and_archived_readers(self):
        candidate = snapshot()
        authorization._validate_snapshot(candidate, allow_stale=False)
        self.assertTrue(authorization._validate_archived_snapshot(candidate))

    def test_legacy_archive_is_preserved_but_not_spot_proof(self):
        candidate = legacy_snapshot()
        before = copy.deepcopy(candidate)
        self.assertFalse(authorization._validate_archived_snapshot(candidate))
        self.assertEqual(before, candidate)

    def test_stale_exception_never_enables_v1_for_active_validation(self):
        for allow_stale in (False, True):
            with self.subTest(allow_stale=allow_stale), self.assertRaises(ToolError):
                authorization._validate_snapshot(
                    legacy_snapshot(), allow_stale=allow_stale
                )

    def test_archived_reader_rejects_malformed_legacy_records(self):
        for changed in (
            {"quotaCode": "L-34B43A08"},
            {"value": float("inf")},
            {"value": True},
            {"value": 8},
            {"extra": "unreviewed"},
        ):
            candidate = legacy_snapshot()
            candidate["spotQuota"].update(changed)
            with self.subTest(changed=changed), self.assertRaises(ToolError):
                authorization._validate_archived_snapshot(candidate)

    def test_v2_archive_cannot_downgrade_bad_spot_identity(self):
        candidate = snapshot()
        candidate["spotQuota"]["quotaCode"] = "L-1216C47A"
        with self.assertRaises(ToolError):
            authorization._validate_archived_snapshot(candidate)

    def test_unknown_or_bool_schema_and_non_objects_rejected(self):
        for version in (True, 2.0, "2", 3):
            candidate = snapshot()
            candidate["schemaVersion"] = version
            for reader in (
                lambda x: authorization._validate_snapshot(x, allow_stale=True),
                authorization._validate_archived_snapshot,
            ):
                with self.subTest(version=version), self.assertRaises(ToolError):
                    reader(candidate)
        for candidate in (None, [], True):
            with self.assertRaises(ToolError):
                authorization._validate_snapshot(candidate, allow_stale=False)
            with self.assertRaises(ToolError):
                authorization._validate_archived_snapshot(candidate)


class RuntimeSpotGateTests(unittest.TestCase):
    def setUp(self):
        # Any accidental real subprocess is a test failure, including AWS/Kube.
        guard = patch.object(
            bootstrap.subprocess, "run", side_effect=AssertionError("offline only")
        )
        guard.start()
        self.addCleanup(guard.stop)
        self.contract = contract()

    def operations(self, continuing):
        return (
            continuation.RealOperations(
                {
                    "evidence": {
                        "rootUid": "root-uid",
                        "pin": None,
                        "proof": {"core-readonly-evidence": {"controllers": []}},
                    }
                }
            )
            if continuing
            else bootstrap.RealOperations()
        )

    def baseline(self, continuing, response):
        ops = self.operations(continuing)
        observed = []

        def aws(_contract, _profile, service, operation, *args):
            observed.append((service, operation, args))
            if (service, operation) == ("sts", "get-caller-identity"):
                return {"Account": self.contract.account_id}
            if (service, operation) == ("service-quotas", "get-service-quota"):
                self.assertEqual(
                    ("--service-code", "ec2", "--quota-code", "L-34B43A08"), args
                )
                return response
            if (service, operation) == ("ec2", "describe-images"):
                return {
                    "Images": [
                        {
                            "ImageId": self.contract.node_image_id,
                            "State": "available",
                            "Architecture": "x86_64",
                            "RootDeviceType": "ebs",
                        }
                    ]
                }
            raise AssertionError("unexpected operation")

        with ExitStack() as stack:
            for method in ("_assert_stopped", "_assert_catalogs"):
                stack.enter_context(patch.object(ops, method))
            stack.enter_context(patch.object(ops, "_aws_json", side_effect=aws))
            stack.enter_context(
                patch.object(
                    ops,
                    "public_egress",
                    return_value={
                        "host": self.contract.expected_host_public_ip,
                        "kind": self.contract.expected_kind_public_ip,
                    },
                )
            )
            stack.enter_context(
                patch.object(ops, "verify_eks_release_availability", return_value={})
            )
            stack.enter_context(
                patch.object(
                    ops,
                    "aws_conflicts",
                    return_value={k: 0 for k in authorization.TARGET_CONFLICT_KEYS},
                )
            )
            mutations = [
                stack.enter_context(patch.object(ops, method))
                for method in (
                    "protect",
                    "open_session",
                    "start_controllers",
                    "create_environment",
                )
            ]
            if continuing:
                reader = MagicMock()
                reader.get.side_effect = lambda path, **kw: (
                    [
                        {
                            "metadata": {
                                "name": self.contract.environment,
                                "uid": "root-uid",
                            }
                        }
                    ]
                    if path.endswith("/xeksenvironments")
                    else []
                )
                metadata = stack.enter_context(
                    patch.object(continuation, "ReadOnlyMetadata")
                )
                metadata.return_value.__enter__.return_value = reader
                for method in (
                    "_assert_shared",
                    "_assert_managed",
                    "_assert_permanent",
                    "observe_root",
                ):
                    stack.enter_context(patch.object(ops, method))
                stack.enter_context(
                    patch.object(ops, "_session_present", return_value=False)
                )
            else:
                stack.enter_context(
                    patch.object(
                        bootstrap.credentials, "session_metadata", return_value=None
                    )
                )
                stack.enter_context(
                    patch.object(
                        ops, "_lifecycle_inventory", return_value=([], ["object"] * 73)
                    )
                )
                stack.enter_context(patch.object(ops, "_record_non_aws_baseline"))
            try:
                return ops.baseline(self.contract, self.contract.audit_profile)
            finally:
                for mutation in mutations:
                    mutation.assert_not_called()
                self.assertIn(
                    (
                        "service-quotas",
                        "get-service-quota",
                        ("--service-code", "ec2", "--quota-code", "L-34B43A08"),
                    ),
                    observed,
                )

    def test_both_live_baselines_report_verified_spot_identity(self):
        for continuing in (False, True):
            with self.subTest(continuing=continuing):
                result = self.baseline(continuing, aws_response())
                self.assertEqual(snapshot()["spotQuota"], result["spotQuota"])
                self.assertTrue(result["spotQuotaAtLeastNodePoolLimit"])

    def test_both_live_baselines_reject_on_demand_before_mutations(self):
        response = aws_response(9999)
        response["Quota"]["QuotaCode"] = "L-1216C47A"
        for continuing in (False, True):
            with self.subTest(continuing=continuing), self.assertRaises(ToolError):
                self.baseline(continuing, response)

    def test_both_live_baselines_reject_invalid_limits(self):
        for continuing in (False, True):
            for value in (True, 15, float("nan"), float("inf")):
                with self.subTest(
                    continuing=continuing, value=value
                ), self.assertRaises(ToolError):
                    self.baseline(continuing, aws_response(value))

    def test_both_adapters_use_one_inherited_quota_gate(self):
        self.assertIs(
            bootstrap.RealOperations.verify_spot_quota,
            continuation.RealOperations.verify_spot_quota,
        )


if __name__ == "__main__":
    unittest.main()
