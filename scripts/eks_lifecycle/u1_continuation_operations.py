"""Live adapter for a separately approved same-root continuation (never imported to run by plan).

The baseline is deliberately narrow: one previously created root, no child XR,
no AWS managed/cloud resources, and exactly the independently audited shared
inventory. It does not adopt a partially provisioned environment. New inventory
requires a new contract, not an automatic retry or an inventory exception.
"""

from __future__ import annotations

import json

from common import ToolError
import run_u1_bootstrap as base
import u1_environment_identity as identity
import validate_u1_continuation as authorization
from u1_readonly_metadata import ReadOnlyMetadata
from u1_continuation_definitions import payload_digest, key


def verify_definition(actual: dict, saved: dict, desired: dict | None = None) -> None:
    meta = actual.get("metadata", {})
    if (
        actual.get("apiVersion") != saved["apiVersion"]
        or actual.get("kind") != saved["kind"]
        or meta.get("name") != saved["name"]
        or meta.get("namespace", "") != saved["namespace"]
        or meta.get("uid") != saved["uid"]
        or meta.get("deletionTimestamp") is not None
        or payload_digest(actual) != saved["actualPayloadSha256"]
    ):
        raise ToolError("continuation permanent definition UID/content drift")
    if desired is not None:
        for field in ("annotations", "labels"):
            if any(
                not identity.strict_equal(meta.get(field, {}).get(k), v)
                for k, v in desired["metadata"].get(field, {}).items()
            ):
                raise ToolError(
                    "continuation permanent definition required metadata drift"
                )
    if saved["kind"] in {
        "ClusterRole",
        "ClusterRoleBinding",
        "Role",
        "RoleBinding",
    } and meta.get("ownerReferences"):
        raise ToolError("continuation explicit RBAC acquired another owner")
    if saved["kind"] == "ValidatingAdmissionPolicy" and actual.get("status", {}).get(
        "typeChecking", {}
    ).get("expressionWarnings"):
        raise ToolError("continuation admission policy has expression warnings")


def verify_shared(actual: dict, saved: dict) -> None:
    meta = actual.get("metadata", {})
    annotations = meta.get("annotations", {})
    if (
        meta.get("uid") != saved["uid"]
        or meta.get("name") != saved["name"]
        or meta.get("deletionTimestamp") is not None
        or "crossplane.io/paused" in annotations
        or "platform.aws.goodnotes.io/a05-maintenance" in annotations
        or not identity.strict_equal(
            meta.get("ownerReferences", []), saved["ownerReferences"]
        )
    ):
        raise ToolError("continuation shared-object identity/protection drift")


class RealOperations(base.RealOperations):
    def __init__(self, reviewed: dict):
        super().__init__()
        self.reviewed = reviewed
        self.evidence = reviewed["evidence"]
        self.proof = self.evidence["proof"]
        self._root_composition_pin = self.evidence["pin"]
        self.controller_uids = {
            x["name"]: x["uid"]
            for x in self.proof["core-readonly-evidence"]["controllers"]
        }

    def _verify_claim(self, contract):
        authorization.verify_claim(contract.authorization_path)

    def _kube(self, contract, *args, body=None):
        # The adapter never invokes a root/definition mutation, including dry-run.
        # Inherited lifecycle operations can only patch exact controller replicas.
        read_args = args[2:] if args[:2] == ("--namespace", base.NAMESPACE) else args
        # Namespaced reads outside crossplane-system are permitted for audited
        # permanent RBAC; they remain exact GETs with no input body.
        if args[:1] == ("--namespace",) and len(args) > 2:
            read_args = args[2:]
        is_read = bool(read_args) and read_args[0] == "get" and body is None
        if not is_read:
            if (
                len(args) != 8
                or args[:4] != ("--namespace", base.NAMESPACE, "patch", "deployment")
                or args[4] not in self.controller_uids
                or args[5:7] != ("--type=json", "-p")
                or body is not None
            ):
                raise ToolError(
                    "continuation Kubernetes write outside controller scaling"
                )
            patch = json.loads(args[7])
            if (
                len(patch) != 3
                or patch[0]
                != {
                    "op": "test",
                    "path": "/metadata/uid",
                    "value": self.controller_uids[args[4]],
                }
                or patch[1].get("op") != "test"
                or patch[1].get("path") != "/metadata/resourceVersion"
                or patch[2].get("op") != "replace"
                or patch[2].get("path") != "/spec/replicas"
                or type(patch[2].get("value")) is not int
                or patch[2]["value"] not in (0, 1)
            ):
                raise ToolError(
                    "continuation controller write differs from UID-bound scale contract"
                )
        return super()._kube(contract, *args, body=body)

    def dry_run_environment(self, _contract):
        raise ToolError(
            "continuation never creates or reapplies the existing root, even dry-run"
        )

    def create_environment(self, _contract):
        raise ToolError("continuation cannot create a root")

    def observe_root(self, contract):
        root = self._kube(
            contract,
            "get",
            "xeksenvironment.platform.aws.goodnotes.io",
            contract.environment,
        )
        meta = self._assert_environment_identity(
            contract, root, expected_uid=self.evidence["rootUid"]
        )
        return {
            "name": contract.environment,
            "uid": meta["uid"],
            "generation": meta["generation"],
        }

    def _assert_controller_identity(self, contract, *, allow_tagged_functions=False):
        deployments = super()._assert_controller_identity(
            contract, allow_tagged_functions=False
        )
        if {
            n: d.get("metadata", {}).get("uid") for n, d in deployments.items()
        } != self.controller_uids:
            raise ToolError("continuation controller UID inventory changed")
        return deployments

    def _deployment_map(self, contract):
        deployments = super()._deployment_map(contract)
        # Also used during recovery: never scale a replacement controller.
        if set(deployments) != set(self.controller_uids) or any(
            deployments[n].get("metadata", {}).get("uid") != uid
            for n, uid in self.controller_uids.items()
        ):
            raise ToolError("continuation refuses replacement/missing controller")
        return deployments

    def _assert_permanent(self, contract):
        for saved in self.proof["permanent-definitions-evidence"]["documents"]:
            group, version = saved["apiVersion"].split("/")
            options = ("--namespace", saved["namespace"]) if saved["namespace"] else ()
            live = self._kube(
                contract,
                *options,
                "get",
                f"{saved['kind'].lower()}.{version}.{group}",
                saved["name"],
            )
            verify_definition(live, saved, self.evidence["definitions"][key(live)])
        runtime = self.proof["runtime-and-final-checks"]
        core = self._kube(contract, "get", "clusterrole", "crossplane")
        if (
            core["metadata"]["uid"] != runtime["coreRbac"]["uid"]
            or core.get("aggregationRule")
            or identity.spec_digest(core.get("rules"))
            != runtime["coreRbac"]["rulesSha256"]
        ):
            raise ToolError("continuation core RBAC drift")
        base.u0_runner.provider_rbac.audit(
            base.u0_runner.provider_rbac.inventory(), permission_probes=False
        )
        for saved in runtime["packageRuntimePins"]:
            kind = saved["kind"].lower()
            package = self._kube(
                contract, "get", f"{kind}.pkg.crossplane.io", saved["name"]
            )
            revision = self._kube(
                contract, "get", f"{kind}revision.pkg.crossplane.io", saved["revision"]
            )
            deployment = self._kube(
                contract,
                "--namespace",
                base.NAMESPACE,
                "get",
                "deployment",
                saved["revision"],
            )

            def owns(child, owner_kind, owner_name, owner_uid):
                refs = child.get("metadata", {}).get("ownerReferences", [])
                return len(refs) == 1 and all(
                    identity.strict_equal(refs[0].get(k), v)
                    for k, v in {
                        "kind": owner_kind,
                        "name": owner_name,
                        "uid": owner_uid,
                        "controller": True,
                        "apiVersion": "pkg.crossplane.io/v1",
                    }.items()
                )

            if (
                package["metadata"]["uid"] != saved["uid"]
                or package.get("spec", {}).get("package") != saved["package"]
                or package.get("status", {}).get("currentRevision") != saved["revision"]
                or revision["metadata"]["uid"] != saved["revisionUid"]
                or revision.get("spec", {}).get("package") != saved["package"]
                or revision.get("spec", {}).get("desiredState") != "Active"
                or deployment["metadata"]["uid"] != saved["deploymentUid"]
                or deployment["spec"]["template"]["spec"].get("serviceAccountName")
                != saved["revision"]
                or not owns(revision, saved["kind"], saved["name"], saved["uid"])
                or not owns(
                    deployment,
                    saved["kind"] + "Revision",
                    saved["revision"],
                    saved["revisionUid"],
                )
            ):
                raise ToolError("continuation package/runtime owner chain drift")
        for saved in runtime["generatedCrdBindings"]:
            crd = self._kube(contract, "get", "customresourcedefinition", saved["name"])
            schemas = [
                v["schema"]["openAPIV3Schema"]
                for v in crd["spec"]["versions"]
                if v["name"] == "v1alpha1"
            ]
            refs = crd["metadata"].get("ownerReferences", [])
            if (
                crd["metadata"]["uid"] != saved["uid"]
                or len(schemas) != 1
                or len(refs) != 1
                or refs[0].get("uid") != saved["xrdUid"]
                or refs[0].get("kind") != "CompositeResourceDefinition"
                or refs[0].get("controller") is not True
                or identity.spec_digest(
                    schemas[0]["properties"]["spec"]["properties"]["parameters"]
                )
                != saved["parameterSchemaSha256"]
                or identity.spec_digest(schemas[0].get("x-kubernetes-validations", []))
                != saved["rootCelSha256"]
            ):
                raise ToolError("continuation generated CRD schema/owner drift")

    def _assert_shared(self, contract, reader):
        expected = self.proof["shared-object-evidence"]["sharedObjects"]
        if len(expected) != 76:
            raise ToolError("continuation shared inventory is incomplete")
        for resource in {s["resource"] for s in expected}:
            # Query metadata through discovery-backed kubectl raw API paths.
            plural, group = resource.split(".", 1)
            version = (
                "v1alpha2"
                if resource == "objects.kubernetes.crossplane.io"
                else "v1alpha1"
            )
            actual = reader.get(f"/apis/{group}/{version}/{plural}", many=True)
            by_name = {x["metadata"]["name"]: x for x in actual}
            wanted = {s["name"]: s for s in expected if s["resource"] == resource}
            if set(by_name) != set(wanted) or len(actual) != len(wanted):
                raise ToolError("continuation shared inventory drift")
            for name, saved in wanted.items():
                verify_shared(by_name[name], saved)
        if not identity.strict_equal(
            base.u0_runner.hardening.workload_state(),
            self.proof["business-workload-evidence"]["workloads"],
        ):
            raise ToolError("continuation business workload UID/replica/schedule drift")

    def _assert_managed(self, contract, reader):
        inventory = self.proof["managed-inventory-evidence"]
        discovered = base.u0_runner._run_names(
            [
                "kubectl",
                "--context",
                contract.bootstrap.context,
                "api-resources",
                "--categories=managed",
                "-o",
                "name",
            ]
        )
        if set(discovered) != set(inventory["managedApiEndpoints"]):
            raise ToolError("continuation managed API discovery drift")
        identities = set()
        expected_objects = {
            s["name"]: s["uid"]
            for s in self.proof["shared-object-evidence"]["sharedObjects"]
            if s["resource"] == "objects.kubernetes.crossplane.io"
        }
        for resource, endpoint in inventory["managedApiEndpoints"].items():
            items = reader.get(endpoint, many=True)
            if resource == "objects.kubernetes.crossplane.io":
                if {
                    x["metadata"]["name"]: x["metadata"]["uid"] for x in items
                } != expected_objects or len(items) != 73:
                    raise ToolError("continuation non-AWS Object baseline drift")
                for x in items:
                    identities.add(
                        (
                            "kubernetes.crossplane.io/v1alpha2",
                            "Object",
                            "",
                            x["metadata"]["name"],
                        )
                    )
            elif items:
                raise ToolError(
                    "continuation starting inventory contains an unreviewed managed resource"
                )
        self._baseline_non_aws_identities = identities

    def _session_present(self, contract, reader):
        return (
            reader.get(
                f"/api/v1/namespaces/{base.NAMESPACE}/secrets/{base.credentials.REMOTE_SECRET_NAME}",
                optional=True,
            )
            is not None
        )

    def baseline(self, contract, audit_profile):
        with ReadOnlyMetadata(contract.bootstrap.context) as reader:
            self._assert_stopped(contract)
            if self._session_present(contract, reader):
                raise ToolError("continuation baseline contains a session Secret")
            root = self.observe_root(contract)
            xrs = []
            for resource in base.u0_runner.XR_RESOURCES:
                plural, group = resource.split(".", 1)
                for item in reader.get(f"/apis/{group}/v1alpha1/{plural}", many=True):
                    xrs.append(
                        (resource, item["metadata"]["name"], item["metadata"]["uid"])
                    )
            if xrs != [
                (
                    "xeksenvironments.platform.aws.goodnotes.io",
                    contract.environment,
                    self.evidence["rootUid"],
                )
            ]:
                raise ToolError(
                    "continuation requires exactly the reviewed root and zero children"
                )
            self._assert_shared(contract, reader)
            self._assert_managed(contract, reader)
            self._assert_permanent(contract)
            self._assert_catalogs(contract)
        egress = self.public_egress(contract)
        caller = (
            self._aws_json(contract, audit_profile, "sts", "get-caller-identity") or {}
        )
        if caller.get("Account") != contract.account_id:
            raise ToolError("continuation audit account differs")
        release = self.verify_eks_release_availability(contract, audit_profile)
        conflicts = self.aws_conflicts(contract, audit_profile)
        if not identity.strict_equal(
            conflicts, {k: 0 for k in authorization.create.TARGET_CONFLICT_KEYS}
        ):
            raise ToolError(
                "continuation zero-cloud starting baseline differs; no adoption allowed"
            )
        quota = (
            self._aws_json(
                contract,
                audit_profile,
                "service-quotas",
                "get-service-quota",
                "--service-code",
                "ec2",
                "--quota-code",
                "L-1216C47A",
            )
            or {}
        )
        value = quota.get("Quota", {}).get("Value")
        if type(value) not in (int, float) or not 16 <= value < float("inf"):
            raise ToolError("continuation Spot quota differs")
        images = (
            self._aws_json(
                contract,
                audit_profile,
                "ec2",
                "describe-images",
                "--image-ids",
                contract.node_image_id,
            )
            or {}
        )
        items = images.get("Images", [])
        if len(items) != 1 or any(
            items[0].get(k) != v
            for k, v in {
                "ImageId": contract.node_image_id,
                "State": "available",
                "Architecture": "x86_64",
                "RootDeviceType": "ebs",
            }.items()
        ):
            raise ToolError("continuation reviewed AMI unavailable")
        # Repeat parked root/shared checks immediately before the first mutation.
        with ReadOnlyMetadata(contract.bootstrap.context) as reader:
            self._assert_stopped(contract)
            self.observe_root(contract)
            self._assert_shared(contract, reader)
            if self._session_present(contract, reader):
                raise ToolError("continuation session appeared during baseline")
        return {
            "sameRootUid": True,
            "root": root,
            "controllersStopped": 14,
            "sharedObjects": 76,
            "awsManagedResources": 0,
            "targetConflicts": conflicts,
            "hostEgressMatched": egress["host"] == contract.expected_host_public_ip,
            "kindEgressMatched": egress["kind"] == contract.expected_kind_public_ip,
            **release,
        }

    def protect(self, contract):
        # Verify the independently reviewed shared identities immediately before
        # the existing UID-tested hardener saves a NEW run-specific token.
        self._verify_claim(contract)
        with ReadOnlyMetadata(contract.bootstrap.context) as reader:
            self._assert_shared(contract, reader)
        super().protect(contract)

    def cleanup(self, contract, *, expected_environment_uid):
        if expected_environment_uid != self.evidence["rootUid"]:
            raise ToolError("continuation cleanup requires contract-bound root UID")
        result = super().cleanup(
            contract, expected_environment_uid=expected_environment_uid
        )
        with ReadOnlyMetadata(contract.bootstrap.context) as reader:
            self._assert_shared(contract, reader)
        return result
