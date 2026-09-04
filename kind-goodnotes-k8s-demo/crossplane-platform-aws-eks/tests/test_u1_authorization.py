from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "eks_lifecycle"))

from common import ToolError  # noqa: E402
import validate_u1_authorization as u1  # noqa: E402


CODE_STATE = {
    "gitCommit": "1" * 40,
    "roots": [
        "scripts/eks_lifecycle",
        "kind-goodnotes-k8s-demo/crossplane-platform-aws-eks",
        "kind-goodnotes-k8s-demo/crossplane-platform-aws-network",
    ],
    "trackedNonMarkdownFiles": 201,
    "aggregateSha256": "2" * 64,
    "untrackedNonMarkdownFiles": 0,
    "markdownDriftExcluded": True,
}


def snapshot(*, observed_at: datetime | None = None) -> dict:
    return {
        "schemaVersion": 1,
        "observedAt": (observed_at or datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
        "profile": "warlock-cli-codex-admin",
        "accountId": "123456789012",
        "partition": "aws",
        "region": "us-east-1",
        "environment": "eks-dev-spot",
        "hostPublicEgressIp": "203.0.113.10",
        "kindPublicEgressIp": "203.0.113.10",
        "availabilityZones": ["us-east-1a", "us-east-1b"],
        "targetNameConflicts": {
            key: 0 for key in sorted(u1.TARGET_CONFLICT_KEYS)
        },
        "serviceLinkedRoles": {
            "AWSServiceRoleForAmazonEKS": True,
            "AWSServiceRoleForAmazonEKSForFargate": True,
            "AWSServiceRoleForEC2Spot": True,
        },
        "providerBootstrapRoles": {
            "upstream": True,
            "source": True,
            "execution": True,
            "deployment": True,
        },
        "spotQuota": {"quotaCode": "L-1216C47A", "value": 32.0},
        "nodeImage": {
            "imageId": "ami-0123456789abcdef0",
            "state": "available",
            "architecture": "x86_64",
            "rootDeviceType": "ebs",
        },
        "eksRelease": {
            "clusterVersion": "1.35",
            "clusterType": "eks",
            "status": "STANDARD_SUPPORT",
            "defaultPlatformVersion": "eks.21",
            "kubernetesPatchVersion": "1.35.6",
            "coreDNSAddonVersion": "v1.14.3-eksbuild.3",
            "coreDNSArchitectures": ["amd64", "arm64"],
            "coreDNSComputeTypes": [
                "ec2",
                "hybrid",
                "fargate",
                "auto",
                "local-cluster",
            ],
            "coreDNSPlatformVersions": ["*"],
            "coreDNSRequiresConfiguration": False,
            "coreDNSRequiresIamPermissions": False,
        },
        "awsMutation": False,
        "kubernetesMutation": False,
    }


def environment(bundle: str = "u1-bootstrap-2026-09-04") -> bytes:
    return f"""apiVersion: platform.aws.goodnotes.io/v1alpha1
kind: XEKSEnvironment
metadata:
  name: eks-dev-spot
  labels:
    platform.aws.goodnotes.io/environment: eks-dev-spot
    platform.aws.goodnotes.io/managed-by: crossplane
  annotations:
    platform.aws.goodnotes.io/authorization-bundle: {bundle}
    platform.aws.goodnotes.io/do-not-apply-outside-runner: \"true\"
spec:
  crossplane:
    compositionUpdatePolicy: Manual
  parameters:
    class: dev
    region: us-east-1
    providerConfigRef:
      kind: ClusterProviderConfig
      name: eks-dev-spot
    kubernetesVersion: \"1.35\"
    platformReleaseRef:
      kind: EnvironmentConfig
      name: platform-release
    nodeImageRef:
      kind: EnvironmentConfig
      name: node-image
    network:
      cidrBlock: 10.50.0.0/16
      publicSubnets:
        a: {{availabilityZone: us-east-1a, cidrBlock: 10.50.0.0/24}}
        b: {{availabilityZone: us-east-1b, cidrBlock: 10.50.1.0/24}}
      privateSubnets:
        a: {{availabilityZone: us-east-1a, cidrBlock: 10.50.16.0/20}}
        b: {{availabilityZone: us-east-1b, cidrBlock: 10.50.32.0/20}}
    compute:
      class: spot-general
      limits: {{cpu: \"16\", memory: 64Gi}}
    access:
      adminPrincipalArn: arn:aws:iam::123456789012:role/human-admin
      deploymentPrincipalArn: arn:aws:iam::123456789012:role/eks-dev-spot-eks-deploy
      publicAccessCidrs: [203.0.113.10/32]
    lifecycle:
      retirementStage: Active
      deletionProtection: true
""".encode()


CATALOG = b"""apiVersion: apiextensions.crossplane.io/v1beta1
kind: EnvironmentConfig
metadata:
  name: {name}
data:
  schemaVersion: 1
  kubernetes: "1.35"
  crossplane:
    core: v2.2.1
    cli: v2.3.0
  cilium:
    chart: "1.20.1"
    app: "1.20.1"
  karpenter:
    crdChart: "1.14.1"
    controllerChart: "1.14.1"
    app: "1.14.1"
  argoCD:
    chart: "10.4.0"
    app: v3.5.1
  coreDNSAddon: v1.14.3-eksbuild.3
"""

NODE_CATALOG = b"""apiVersion: apiextensions.crossplane.io/v1beta1
kind: EnvironmentConfig
metadata:
  name: node-image
data:
  schemaVersion: 1
  region: us-east-1
  kubernetes: \"1.35\"
  images:
    amd64:
      family: AL2023
      release: v20260728
      releaseVersion: 1.35.6-20260728
      alias: al2023@v20260728
      amiId: ami-0123456789abcdef0
      status: reviewed-candidate
"""


def cost_plan() -> dict:
    return {
        "schemaVersion": 1,
        "currency": "USD",
        "maximumEnvironmentAgeDays": 7,
        "warningThresholdUsd": 50,
        "softStopThresholdUsd": 70,
        "hardStop": False,
        "automaticBudgetAction": False,
        "billingOwner": "GoodspeedWong",
        "cleanupOwner": "GoodspeedWong",
        "resourcesRemainBillableAfterWindow": True,
        "failureAction": "park controllers, remove the session, preserve the environment, and require explicit retirement",
        "budgetEnforcement": "manual observation; AWS billing data may be delayed",
    }


def authorization(status: str = u1.PENDING_STATUS) -> dict:
    approved = status == u1.APPROVED_STATUS
    now = datetime.now(timezone.utc)
    return {
        "schemaVersion": u1.SCHEMA_VERSION,
        "bundle": "u1-bootstrap-2026-09-04",
        "windowId": "u1b-20260904-01",
        "singleUse": True,
        "generatedAt": (now - timedelta(minutes=9)).isoformat(),
        "reviewStatus": status,
        "approvedBy": "operator" if approved else None,
        "approvedAt": (now - timedelta(minutes=5)).isoformat() if approved else None,
        "authorizationType": u1.AUTHORIZATION_TYPE,
        "requiresSeparateApprovedManagementSessionReview": True,
        "preparationEvidence": {
            "u0ManagementStatus": "U0_MANAGEMENT_PREFLIGHT_PASS",
            "u0AdmissionStatus": "U0_ADMISSION_PREFLIGHT_PASS",
            "u0AdmissionWindowId": "u0a-20260904-02",
            "u0AdmissionResultSha256": "3" * 64,
            "accountReadinessPassed": 19,
            "accountReadinessTotal": 20,
            "deferredAccountItem": "A15TargetPrivateNodePathInU1",
            "projectDoneTasks": 122,
            "projectTotalTasks": 153,
            "awsResourceMutation": False,
        },
        "requestedU1Window": {
            "purpose": "Create exactly one reviewed EKS environment and stop at the first U1 bootstrap checkpoint",
            "maximumSessionSeconds": u1.MAX_SESSION_SECONDS,
            "maximumExecutionSeconds": u1.MAX_EXECUTION_SECONDS,
            "stsSessionIssuanceAllowed": True,
            "directAwsCliMutationAllowed": False,
            "crossplaneAwsResourceMutationAllowed": True,
            "kubernetesMutationAllowed": True,
            "persistentEnvironmentAllowed": True,
            "automaticRetryAllowed": False,
            "u1TasksWithPossibleSideEffects": [
                "U1-01",
                "U1-02",
                "U1-03",
                "U1-04",
                "U1-05",
            ],
            "kubernetesMutationScope": list(u1.KUBERNETES_MUTATION_SCOPE),
            "awsMutationScope": list(u1.AWS_MUTATION_SCOPE),
            "credentialHandling": dict(u1.CREDENTIAL_HANDLING),
            "cleanupBehavior": dict(u1.CLEANUP_BEHAVIOR),
            "allowed": list(u1.ALLOWED_ACTIONS),
            "forbidden": list(u1.FORBIDDEN_ACTIONS),
        },
        "decisions": {
            key: True if approved else None for key in sorted(u1.DECISION_KEYS)
        },
        "reviewedInputs": {},
        "executionCode": dict(CODE_STATE),
    }


class U1AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "u1-bootstrap-2026-09-04"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)
        self.claim_root = Path(self.temporary.name).resolve() / "claims"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_bundle(
        self,
        document: dict,
        *,
        snapshot_document: dict | None = None,
        environment_payload: bytes | None = None,
        platform_payload: bytes | None = None,
        resource_contract: dict | None = None,
    ) -> Path:
        payloads = {
            "REVIEW_SUMMARY.md": b"private U1 review\n",
            "aws-readonly-snapshot.json": (
                json.dumps(snapshot_document or snapshot(), indent=2, sort_keys=True)
                + "\n"
            ).encode(),
            "cost-and-cleanup-plan.json": (
                json.dumps(cost_plan(), indent=2, sort_keys=True) + "\n"
            ).encode(),
            "environment.approved.yaml": environment_payload or environment(document["bundle"]),
            "expected-resource-contract.json": (
                json.dumps(
                    resource_contract or u1.EXPECTED_RESOURCE_CONTRACT,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode(),
            "node-image.approved.yaml": NODE_CATALOG,
            "platform-release.approved.yaml": platform_payload
            or CATALOG.replace(b"{name}", b"platform-release"),
        }
        document["reviewedInputs"] = {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in payloads.items()
            if name != "REVIEW_SUMMARY.md"
        }
        payloads["authorization-contract.json"] = (
            json.dumps(document, indent=2, sort_keys=True) + "\n"
        ).encode()
        for name, payload in payloads.items():
            path = self.directory / name
            path.write_bytes(payload)
            os.chmod(path, 0o600)
        checksum = self.directory / "SHA256SUMS"
        checksum.write_text(
            "".join(
                f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
                for name in sorted(payloads)
            )
        )
        os.chmod(checksum, 0o600)
        return self.directory / "authorization-contract.json"

    def validate(self, path: Path, *, approved: bool = False):
        with patch.object(u1, "execution_code_state", return_value=dict(CODE_STATE)):
            return u1.validate_authorization(path, require_approved=approved)

    def test_pending_plan_is_local_only_and_not_executable(self) -> None:
        path = self.write_bundle(authorization())
        result = self.validate(path)
        self.assertFalse(result["approved"])
        self.assertTrue(result["crossplaneAwsResourceMutationAllowed"])
        self.assertFalse(result["directAwsCliMutationAllowed"])
        self.assertFalse(result["awsApiCalls"])
        self.assertFalse(result["kubernetesApiCalls"])
        with self.assertRaisesRegex(ToolError, "not approved"):
            self.validate(path, approved=True)

    def test_approved_exact_scope_passes(self) -> None:
        path = self.write_bundle(authorization(u1.APPROVED_STATUS))
        result = self.validate(path, approved=True)
        self.assertTrue(result["approved"])
        self.assertEqual("eks-dev-spot", result["environment"])
        self.assertEqual(8, result["checksumsVerified"])
        self.assertEqual(12, len(u1.DECISION_KEYS))

    def test_gitops_or_second_capacity_class_cannot_enter_manifest(self) -> None:
        payload = environment().replace(
            b"    lifecycle:\n",
            b"    gitOps: {}\n    lifecycle:\n",
        )
        path = self.write_bundle(authorization(), environment_payload=payload)
        with self.assertRaisesRegex(ToolError, "Git bootstrap"):
            self.validate(path)

        payload = environment().replace(b"class: spot-general", b"class: on-demand")
        path = self.write_bundle(authorization(), environment_payload=payload)
        with self.assertRaisesRegex(ToolError, "intent differs"):
            self.validate(path)

    def test_public_cidr_must_match_snapshot_exactly(self) -> None:
        payload = environment().replace(b"203.0.113.10/32", b"203.0.113.11/32")
        path = self.write_bundle(authorization(), environment_payload=payload)
        with self.assertRaisesRegex(ToolError, "public endpoint CIDR"):
            self.validate(path)

    def test_distinct_host_and_kind_egress_require_two_exact_slash32s(self) -> None:
        snapshot_document = snapshot()
        snapshot_document["kindPublicEgressIp"] = "203.0.113.12"
        payload = environment().replace(
            b"publicAccessCidrs: [203.0.113.10/32]",
            b"publicAccessCidrs: [203.0.113.10/32, 203.0.113.12/32]",
        )
        path = self.write_bundle(
            authorization(),
            snapshot_document=snapshot_document,
            environment_payload=payload,
        )
        result = self.validate(path)
        self.assertFalse(result["approved"])

    def test_snapshot_conflict_staleness_and_quota_fail_closed(self) -> None:
        for mode in ("conflict", "stale", "quota", "kind-ip"):
            item = snapshot()
            if mode == "conflict":
                item["targetNameConflicts"]["vpcs"] = 1
            elif mode == "stale":
                item["observedAt"] = (
                    datetime.now(timezone.utc) - timedelta(days=2)
                ).isoformat()
            elif mode == "quota":
                item["spotQuota"]["value"] = 8
            else:
                item["kindPublicEgressIp"] = "203.0.113.12"
            path = self.write_bundle(authorization(), snapshot_document=item)
            with self.subTest(mode=mode), self.assertRaises(ToolError):
                self.validate(path)

    def test_snapshot_requires_ipv4_exact_roles_and_finite_quota(self) -> None:
        cases = []
        ipv6 = snapshot()
        ipv6["hostPublicEgressIp"] = "2001:db8::1"
        ipv6["kindPublicEgressIp"] = "2001:db8::1"
        cases.append(ipv6)
        roles = snapshot()
        roles["serviceLinkedRoles"]["unreviewed"] = True
        cases.append(roles)
        quota = snapshot()
        quota["spotQuota"]["value"] = float("nan")
        cases.append(quota)
        for index, snapshot_document in enumerate(cases):
            path = self.write_bundle(
                authorization(), snapshot_document=snapshot_document
            )
            with self.subTest(index=index), self.assertRaises(ToolError):
                self.validate(path)

    def test_node_catalog_ami_must_match_snapshot(self) -> None:
        path = self.write_bundle(authorization())
        node_path = self.directory / "node-image.approved.yaml"
        node_path.write_bytes(
            NODE_CATALOG.replace(
                b"ami-0123456789abcdef0", b"ami-0fedcba9876543210"
            )
        )
        os.chmod(node_path, 0o600)
        with self.assertRaisesRegex(ToolError, "node image catalog"):
            self.validate(path)

    def test_platform_release_and_eks_snapshot_must_match_locked_runtime(self) -> None:
        changed = CATALOG.replace(
            b"{name}", b"platform-release"
        ).replace(b"v1.14.3-eksbuild.3", b"v1.14.3-eksbuild.16")
        path = self.write_bundle(authorization(), platform_payload=changed)
        with self.assertRaisesRegex(ToolError, "platform release data"):
            self.validate(path)

        release = snapshot()
        release["eksRelease"]["status"] = "UNSUPPORTED"
        path = self.write_bundle(authorization(), snapshot_document=release)
        with self.assertRaisesRegex(ToolError, "EKS/CoreDNS release snapshot"):
            self.validate(path)

    def test_scope_or_resource_contract_drift_fails(self) -> None:
        document = authorization(u1.APPROVED_STATUS)
        document["requestedU1Window"]["allowed"].append("create another cluster")
        path = self.write_bundle(document)
        with self.assertRaisesRegex(ToolError, "allowlist"):
            self.validate(path, approved=True)

        resources = json.loads(json.dumps(u1.EXPECTED_RESOURCE_CONTRACT))
        resources["requiredCapacityType"] = "on-demand"
        path = self.write_bundle(authorization(), resource_contract=resources)
        with self.assertRaisesRegex(ToolError, "resource contract"):
            self.validate(path)

    def test_u0_evidence_and_every_decision_are_required(self) -> None:
        for mode in ("u0", "decision"):
            document = authorization(u1.APPROVED_STATUS)
            if mode == "u0":
                document["preparationEvidence"]["u0AdmissionStatus"] = "FAILED"
            else:
                document["decisions"][next(iter(document["decisions"]))] = False
            path = self.write_bundle(document)
            with self.subTest(mode=mode), self.assertRaises(ToolError):
                self.validate(path, approved=True)

    def test_checksum_tamper_extra_file_and_permissions_fail(self) -> None:
        path = self.write_bundle(authorization())
        candidate = self.directory / "environment.approved.yaml"
        candidate.write_bytes(candidate.read_bytes() + b"\n")
        with self.assertRaisesRegex(ToolError, "reviewed input changed|checksum differs"):
            self.validate(path)

        self.temporary.cleanup()
        self.setUp()
        path = self.write_bundle(authorization())
        extra = self.directory / "extra.json"
        extra.write_text("{}\n")
        os.chmod(extra, 0o600)
        with self.assertRaisesRegex(ToolError, "unreviewed file"):
            self.validate(path)

        extra.unlink()
        os.chmod(path, 0o640)
        with self.assertRaisesRegex(ToolError, "owner-only regular"):
            self.validate(path)

    def test_claim_is_atomic_owner_only_and_cannot_be_reused(self) -> None:
        path = self.write_bundle(authorization(u1.APPROVED_STATUS))
        with patch.object(u1, "execution_code_state", return_value=dict(CODE_STATE)):
            claimed = u1.claim_authorization(
                path,
                u1.CLAIM_ACKNOWLEDGEMENT,
                claim_root=self.claim_root,
            )
            verified = u1.verify_claim(path, claim_root=self.claim_root)
            with self.assertRaisesRegex(ToolError, "already claimed"):
                u1.claim_authorization(
                    path,
                    u1.CLAIM_ACKNOWLEDGEMENT,
                    claim_root=self.claim_root,
                )
        receipt = self.claim_root / "u1b-20260904-01.json"
        self.assertTrue(claimed["claimed"])
        self.assertTrue(verified["claimActive"])
        self.assertEqual(0o700, stat.S_IMODE(self.claim_root.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(receipt.stat().st_mode))

    def test_approval_must_follow_snapshot_and_remain_fresh(self) -> None:
        for mode in ("before-snapshot", "stale", "anonymous"):
            document = authorization(u1.APPROVED_STATUS)
            snap = snapshot()
            if mode == "before-snapshot":
                snap["observedAt"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
                document["approvedAt"] = (
                    datetime.now(timezone.utc) - timedelta(minutes=2)
                ).isoformat()
            elif mode == "stale":
                document["approvedAt"] = (
                    datetime.now(timezone.utc) - timedelta(days=2)
                ).isoformat()
            else:
                document["approvedBy"] = " "
            path = self.write_bundle(document, snapshot_document=snap)
            with self.subTest(mode=mode), self.assertRaises(ToolError):
                self.validate(path, approved=True)


if __name__ == "__main__":
    unittest.main()
