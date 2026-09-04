#!/usr/bin/env python3
"""Run or recover one authorized U0 management-plane preflight window.

Plan mode is local-only. Run mode claims one reviewed authorization before the
first API call, protects the shared Crossplane objects, installs only reviewed
management definitions/catalogs, pins the three existing Functions to reviewed
digests, opens the separately approved A05 session, starts exactly 14 locked
controllers, performs read-only verification, and always attempts cleanup. It
never applies the XEKSEnvironment candidate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import EKS_ROOT, LOCK_FILE, REPO_ROOT, ToolError, find_placeholders, load_yaml
import close_management_session as close_session_tool
import harden_management_kind as hardening
import manage_provider_rbac as provider_rbac
import preflight
import provider_maintenance
import renew_management_credentials as credentials
import validate_u0_authorization as authorization_tool
import verify_management_session_runtime as runtime_verifier


RUN_ACKNOWLEDGEMENT = "I-APPROVE-EXECUTE-ONE-U0-MANAGEMENT-PREFLIGHT"
RECOVER_ACKNOWLEDGEMENT = "I-APPROVE-U0-RECOVERY-ONLY"
HARDENING_ACKNOWLEDGEMENT = hardening.ACK
SESSION_ACKNOWLEDGEMENT = credentials.ACKNOWLEDGEMENT
CLOSE_ACKNOWLEDGEMENT = close_session_tool.ACKNOWLEDGEMENT
NAMESPACE = credentials.SOURCE_NAMESPACE

FUNCTION_LOCKS = {
    "function-kcl": "functionKCL",
    "function-auto-ready": "functionAutoReady",
    "function-patch-and-transform": "functionPatchAndTransform",
}
APPLY_KUSTOMIZATIONS = (
    EKS_ROOT / "dependencies",
    EKS_ROOT / "management-auth",
    EKS_ROOT / "management-rbac",
    EKS_ROOT.parent / "crossplane-platform-aws-network",
    EKS_ROOT,
    EKS_ROOT / "lifecycle-policy",
)
XR_RESOURCES = (
    "xnetworks.platform.aws.goodnotes.io",
    "xeksclusters.platform.aws.goodnotes.io",
    "xclusterfoundations.platform.aws.goodnotes.io",
    "xeksenvironments.platform.aws.goodnotes.io",
)
AWS_MANAGED_MARKERS = (".aws.upbound.io/", ".aws.m.upbound.io/")
JOURNAL_EVENTS = {
    "CLAIMED",
    "BASELINE_REJECTED_NO_MUTATION",
    "BASELINE_VERIFIED",
    "PROTECTION_STARTED",
    "PROTECTED",
    "DEFINITIONS_STARTED",
    "DEFINITIONS_APPLIED",
    "SESSION_STARTED",
    "SESSION_OPENED",
    "CONTROLLERS_STARTED",
    "VERIFIED",
    "CLEANUP_STARTED",
    "CLEANUP_COMPLETE",
    "FAILED_CLEANUP_COMPLETE",
    "RECOVERY_STARTED",
    "RECOVERY_COMPLETE",
    "RECOVERY_REQUIRED",
}


@dataclass(frozen=True)
class U0Contract:
    authorization_path: Path
    session_review_path: Path
    authorization: dict[str, Any] = field(repr=False)
    session_review: dict[str, Any] = field(repr=False)
    bootstrap: credentials.BootstrapContract = field(repr=False)
    bundle_directory: Path = field(repr=False)
    environment_candidate: dict[str, Any] = field(repr=False)
    provider_config_name: str
    controller_names: tuple[str, ...]
    run_id: str


def _package_digest(reference: Any, label: str) -> str:
    if not isinstance(reference, str):
        raise ToolError(f"{label} package reference is missing")
    match = re.fullmatch(r".+@sha256:([0-9a-f]{64})", reference)
    if match is None:
        raise ToolError(f"{label} package is not digest pinned")
    return match.group(1)


def function_package_contracts() -> dict[str, dict[str, str]]:
    packages = load_yaml(LOCK_FILE).get("packages", {})
    result: dict[str, dict[str, str]] = {}
    for name, lock_key in FUNCTION_LOCKS.items():
        locked = packages.get(lock_key, {})
        reference = locked.get("reference")
        version = locked.get("version")
        digest = _package_digest(reference, name)
        if not isinstance(version, str) or not re.fullmatch(
            r"v[0-9]+\.[0-9]+\.[0-9]+", version
        ):
            raise ToolError(f"{name} package version is invalid")
        repository = reference.rsplit("@sha256:", 1)[0]
        result[name] = {
            "digestReference": reference,
            "taggedReference": f"{repository}:{version}",
            "revision": f"{name}-{digest[:12]}",
            "version": version,
        }
    return result


def function_documents() -> list[dict[str, Any]]:
    documents = []
    for name, reviewed in function_package_contracts().items():
        documents.append(
            {
                "apiVersion": "pkg.crossplane.io/v1",
                "kind": "Function",
                "metadata": {
                    "name": name,
                    "annotations": {
                        "platform.aws.goodnotes.io/version": reviewed["version"]
                    },
                    "labels": {
                        "platform.aws.goodnotes.io/managed-by": "platform-bootstrap",
                        "platform.aws.goodnotes.io/resource-role": "shared-function",
                    },
                },
                "spec": {
                    "package": reviewed["digestReference"],
                    "packagePullPolicy": "IfNotPresent",
                    "revisionActivationPolicy": "Automatic",
                    "revisionHistoryLimit": 1,
                    "runtimeConfigRef": {
                        "apiVersion": "pkg.crossplane.io/v1beta1",
                        "kind": "DeploymentRuntimeConfig",
                        "name": "default",
                    },
                },
            }
        )
    return documents


def controller_inventory() -> tuple[str, ...]:
    reviewed = provider_rbac.inventory()
    provider_names = [item["revision"] for item in reviewed["providers"]]
    function_names = [
        item["revision"] for item in function_package_contracts().values()
    ]
    result = tuple(sorted(("crossplane", *provider_names, *function_names)))
    if len(result) != 14 or len(set(result)) != 14:
        raise ToolError("reviewed U0 controller inventory must contain exactly 14 deployments")
    return result


def _session_contract(
    path: Path,
    *,
    recovery_only: bool = False,
) -> tuple[dict[str, Any], credentials.BootstrapContract]:
    review = credentials.load_private_review(path)
    try:
        contract = credentials.BootstrapContract(**review["contract"])
    except (KeyError, TypeError) as error:
        raise ToolError("A05 session review contract is malformed") from error
    credentials.validate_contract(contract)
    if not recovery_only:
        credentials.verify_review_approval(contract, review)
    if review.get("sessionMode") != credentials.SESSION_MODE:
        raise ToolError("A05 review does not approve the on-demand-60m session")
    return review, contract


def load_contract(
    authorization_path: Path,
    session_review_path: Path,
    *,
    require_approved: bool,
    allow_stale_approved: bool = False,
    recovery_only: bool = False,
) -> U0Contract:
    authorization_path = Path(os.path.abspath(authorization_path.expanduser()))
    session_review_path = Path(os.path.abspath(session_review_path.expanduser()))
    authorization = authorization_tool.validate_authorization(
        authorization_path,
        require_approved=require_approved,
        allow_stale_approved=allow_stale_approved,
    )
    authorization.pop("_authorizationSha256", None)
    session_review, bootstrap = _session_contract(
        session_review_path,
        recovery_only=recovery_only,
    )
    bundle_directory = authorization_path.parent
    environment_candidate = load_yaml(bundle_directory / "environment.candidate.yaml")
    if (
        environment_candidate.get("kind") != "XEKSEnvironment"
        or environment_candidate.get("metadata", {}).get("name") != bootstrap.environment
    ):
        raise ToolError("U0 environment candidate differs from the approved A05 environment")
    parameters = environment_candidate.get("spec", {}).get("parameters", {})
    if parameters.get("region") != bootstrap.region:
        raise ToolError("U0 environment candidate region differs from the A05 review")
    provider_ref = parameters.get("providerConfigRef", {})
    provider_config_name = provider_ref.get("name")
    if not isinstance(provider_config_name, str):
        raise ToolError("U0 environment candidate must name one ProviderConfig")
    provider_config = provider_maintenance.provider_config(provider_config_name)
    if find_placeholders(provider_config):
        raise ToolError("rendered U0 ProviderConfig contains a placeholder")
    window_id = authorization["windowId"]
    match = re.fullmatch(r"u0-([0-9]{8})-([0-9]{2})", window_id)
    if match is None:
        raise ToolError("U0 window identity is invalid")
    run_id = f"a05-{match.group(1)}-u0-{match.group(2)}"
    return U0Contract(
        authorization_path=authorization_path,
        session_review_path=session_review_path,
        authorization=authorization,
        session_review=session_review,
        bootstrap=bootstrap,
        bundle_directory=bundle_directory,
        environment_candidate=environment_candidate,
        provider_config_name=provider_config_name,
        controller_names=controller_inventory(),
        run_id=run_id,
    )


def public_plan(contract: U0Contract) -> dict[str, Any]:
    return {
        "mode": "plan",
        "bundle": contract.authorization["bundle"],
        "windowId": contract.authorization["windowId"],
        "reviewStatus": contract.authorization["reviewStatus"],
        "approved": contract.authorization["approved"],
        "separateA05ReviewVerified": True,
        "controllerDeployments": len(contract.controller_names),
        "sharedXRsToProtect": 3,
        "ownedObjectsToProtect": 73,
        "kustomizationApplyEntrypoints": len(APPLY_KUSTOMIZATIONS),
        "catalogManifests": 2,
        "functionPackagePins": len(FUNCTION_LOCKS),
        "environmentCandidateApplyAllowed": False,
        "environmentCandidateServerDryRunOnly": True,
        "awsResourceMutationAllowed": False,
        "awsApiCalls": False,
        "kubernetesApiCalls": False,
        "localClaimCreated": False,
        "mutationPerformed": False,
    }


class Journal:
    def __init__(self, path: Path):
        self.path = path

    @classmethod
    def create(cls, window_id: str) -> "Journal":
        root = authorization_tool._claim_root(authorization_tool.CLAIM_ROOT, create=False)
        path = root / f"{window_id}.state.jsonl"
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError as error:
            raise ToolError("U0 execution journal already exists; use recovery") from error
        except OSError as error:
            raise ToolError("U0 execution journal could not be created safely") from error
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.flush()
            os.fsync(stream.fileno())
        return cls(path)

    @classmethod
    def existing(cls, window_id: str) -> "Journal | None":
        root = authorization_tool._claim_root(authorization_tool.CLAIM_ROOT, create=False)
        path = root / f"{window_id}.state.jsonl"
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ToolError("U0 execution journal is unsafe")
        return cls(path)

    def append(self, event: str) -> None:
        if event not in JOURNAL_EVENTS:
            raise ToolError("unreviewed U0 journal event")
        payload = (
            json.dumps(
                {
                    "event": event,
                    "recordedAt": datetime.now(timezone.utc).isoformat(),
                },
                sort_keys=True,
            )
            + "\n"
        ).encode()
        try:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW,
            )
        except OSError as error:
            raise ToolError("U0 execution journal is unavailable") from error
        with os.fdopen(descriptor, "ab") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ToolError("U0 execution journal changed ownership or mode")
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())


def _run_suppressed(
    command: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 120,
) -> None:
    try:
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=credentials._clean_env(),
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolError(f"{command[0]} unavailable or timed out; output suppressed") from error
    if result.returncode:
        raise ToolError(f"{command[0]} failed ({result.returncode}); output suppressed")


def _run_names(command: list[str], *, timeout: int = 60) -> list[str]:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=credentials._clean_env(),
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolError(f"{command[0]} read-only inventory unavailable; output suppressed") from error
    if result.returncode:
        raise ToolError(f"{command[0]} read-only inventory failed; output suppressed")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


class RealOperations:
    def _kube(self, contract: U0Contract, *args: str, body: Any | None = None) -> Any:
        return credentials._run_json(
            [
                "kubectl",
                "--context",
                contract.bootstrap.context,
                *args,
                "-o",
                "json",
            ],
            input_text=json.dumps(body) if body is not None else None,
        )

    def _deployment_map(self, contract: U0Contract) -> dict[str, dict[str, Any]]:
        document = self._kube(
            contract,
            "--namespace",
            NAMESPACE,
            "get",
            "deployments",
        )
        return {
            item.get("metadata", {}).get("name", ""): item
            for item in document.get("items", [])
            if item.get("metadata", {}).get("name")
        }

    def _assert_controller_identity(
        self,
        contract: U0Contract,
        *,
        allow_tagged_functions: bool = False,
    ) -> dict[str, dict[str, Any]]:
        deployments = self._deployment_map(contract)
        if set(deployments) != set(contract.controller_names):
            raise ToolError("live controller Deployment inventory differs from the reviewed 14")
        provider_rbac.verify_inventory(provider_rbac.inventory())
        reviewed_functions = function_package_contracts()
        functions = self._kube(contract, "get", "functions.pkg.crossplane.io")
        by_name = {
            item.get("metadata", {}).get("name", ""): item
            for item in functions.get("items", [])
        }
        if set(by_name) != set(FUNCTION_LOCKS):
            raise ToolError("live Function inventory differs from the reviewed three")
        for name, reviewed in reviewed_functions.items():
            function = by_name[name]
            spec = function.get("spec", {})
            package = spec.get("package")
            tagged = package == reviewed["taggedReference"]
            if package != reviewed["digestReference"] and not (
                allow_tagged_functions and tagged
            ):
                raise ToolError("live Function package/revision differs from the lock")
            if tagged and (
                spec.get("packagePullPolicy") != "IfNotPresent"
                or function.get("status", {}).get("currentIdentifier")
                != reviewed["taggedReference"]
                or function.get("status", {}).get("resolvedPackage")
                != reviewed["taggedReference"]
            ):
                raise ToolError("legacy tagged Function is not safe for digest migration")
            expected_revision = reviewed["revision"]
            if function.get("status", {}).get("currentRevision") != expected_revision:
                raise ToolError("live Function package/revision differs from the lock")
            owners = [
                owner
                for owner in deployments[expected_revision]
                .get("metadata", {})
                .get("ownerReferences", [])
                if owner.get("kind") == "FunctionRevision"
                and owner.get("controller") is True
            ]
            if len(owners) != 1 or owners[0].get("name") != expected_revision:
                raise ToolError("Function controller lacks its reviewed revision owner")
        return deployments

    def _assert_no_runtime_instances(
        self,
        contract: U0Contract,
        *,
        require_all_apis: bool = False,
    ) -> int:
        base = ["kubectl", "--context", contract.bootstrap.context]
        discovered = set(
            _run_names(
                base
                + [
                    "api-resources",
                    "--api-group=platform.aws.goodnotes.io",
                    "-o",
                    "name",
                ]
            )
        )
        installed = [resource for resource in XR_RESOURCES if resource in discovered]
        if require_all_apis and set(installed) != set(XR_RESOURCES):
            raise ToolError("reviewed EKS lifecycle APIs are not all installed")
        xrs: list[str] = []
        for resource in installed:
            xrs.extend(_run_names(base + ["get", resource, "-o", "name"]))
        if xrs:
            raise ToolError("U0 management preflight found an environment-owned XR instance")
        managed = _run_names(base + ["get", "managed", "--all-namespaces", "-o", "name"])
        if any(marker in name for name in managed for marker in AWS_MANAGED_MARKERS):
            raise ToolError("U0 management preflight found an existing AWS managed resource")
        return len(managed)

    def _wait_lifecycle_apis(self, contract: U0Contract) -> None:
        base = ["kubectl", "--context", contract.bootstrap.context]
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            authorization_tool.verify_claim(contract.authorization_path)
            discovered = set(
                _run_names(
                    base
                    + [
                        "api-resources",
                        "--api-group=platform.aws.goodnotes.io",
                        "-o",
                        "name",
                    ]
                )
            )
            if set(XR_RESOURCES).issubset(discovered):
                return
            time.sleep(2)
        raise ToolError("reviewed EKS lifecycle APIs were not established in time")

    def _assert_stopped(
        self,
        contract: U0Contract,
        *,
        allow_tagged_functions: bool = False,
    ) -> None:
        deployments = self._assert_controller_identity(
            contract,
            allow_tagged_functions=allow_tagged_functions,
        )
        for name in contract.controller_names:
            item = deployments[name]
            if (
                item.get("spec", {}).get("replicas", 1) != 0
                or item.get("status", {}).get("replicas", 0) != 0
            ):
                raise ToolError("reviewed controller is not fully stopped")

    def baseline(self, contract: U0Contract) -> dict[str, Any]:
        self._assert_stopped(contract, allow_tagged_functions=True)
        if credentials.session_metadata(contract.bootstrap.context) is not None:
            raise ToolError("U0 baseline contains a published session Secret")
        managed_count = self._assert_no_runtime_instances(contract)
        return {
            "controllersStopped": 14,
            "sessionSecretAbsent": True,
            "awsManagedResources": 0,
            "nonAwsManagedResources": managed_count,
        }

    def _harden(self, contract: U0Contract, mode: str) -> None:
        if mode not in {"protect", "restore"}:
            raise ToolError("U0 hardening mode is not reviewed")
        _run_suppressed(
            [
                sys.executable,
                str(REPO_ROOT / "scripts/eks_lifecycle/harden_management_kind.py"),
                mode,
                "--acknowledge",
                HARDENING_ACKNOWLEDGEMENT,
                "--run-id",
                contract.run_id,
            ],
            timeout=240,
        )

    def protect(self, contract: U0Contract) -> None:
        authorization_tool.verify_claim(contract.authorization_path)
        self._harden(contract, "protect")

    def _apply_kustomization(
        self,
        contract: U0Contract,
        root: Path,
        *,
        dry_run: bool,
    ) -> None:
        authorization_tool.verify_claim(contract.authorization_path)
        if root.resolve() not in {item.resolve() for item in APPLY_KUSTOMIZATIONS}:
            raise ToolError("U0 kustomization path is not reviewed")
        command = [
            "kubectl",
            "--context",
            contract.bootstrap.context,
            "apply",
        ]
        if dry_run:
            command.append("--dry-run=server")
        command.extend(["-k", str(root)])
        _run_suppressed(command)

    def _apply_document(
        self,
        contract: U0Contract,
        document: dict[str, Any],
        *,
        dry_run: bool,
    ) -> None:
        authorization_tool.verify_claim(contract.authorization_path)
        kind = document.get("kind")
        if kind not in {
            "ClusterProviderConfig",
            "EnvironmentConfig",
            "Function",
            "XEKSEnvironment",
        }:
            raise ToolError("U0 apply document kind is not reviewed")
        if kind == "Function":
            reviewed = {
                item["metadata"]["name"]: item for item in function_documents()
            }
            if document != reviewed.get(document.get("metadata", {}).get("name")):
                raise ToolError("U0 Function document differs from the reviewed digest pin")
        if kind == "EnvironmentConfig":
            authorization_tool.validate_catalog_candidate(
                document,
                str(document.get("metadata", {}).get("name", "catalog")),
            )
        if kind == "XEKSEnvironment" and not dry_run:
            raise ToolError("U0 forbids persisting the environment candidate")
        command = [
            "kubectl",
            "--context",
            contract.bootstrap.context,
            "apply",
        ]
        if dry_run:
            command.append("--dry-run=server")
        command.extend(["-f", "-"])
        _run_suppressed(command, input_text=json.dumps(document))

    def apply_definitions(self, contract: U0Contract) -> None:
        provider_config = provider_maintenance.provider_config(
            contract.provider_config_name
        )
        catalogs = [
            load_yaml(contract.bundle_directory / "platform-release.candidate.yaml"),
            load_yaml(contract.bundle_directory / "node-image.candidate.yaml"),
        ]
        functions = function_documents()
        documents = [provider_config, *catalogs, *functions]
        if any(find_placeholders(document) for document in documents):
            raise ToolError("U0 reviewed apply document contains a placeholder")

        # Validate the complete admission surface before the first declaration write.
        for root in APPLY_KUSTOMIZATIONS:
            self._apply_kustomization(contract, root, dry_run=True)
        for document in documents:
            self._apply_document(contract, document, dry_run=True)

        for root in APPLY_KUSTOMIZATIONS:
            self._apply_kustomization(contract, root, dry_run=False)
        for document in documents:
            self._apply_document(contract, document, dry_run=False)
        self._assert_controller_identity(contract, allow_tagged_functions=False)
        self._assert_no_runtime_instances(contract)

    def open_session(
        self,
        contract: U0Contract,
        profile: str,
        audit_profile: str,
    ) -> None:
        credentials.open_session(
            contract.bootstrap,
            profile,
            audit_profile,
            contract.session_review,
            SESSION_ACKNOWLEDGEMENT,
        )

    def _patch_replicas(
        self,
        contract: U0Contract,
        replicas: int,
        *,
        require_active_claim: bool,
    ) -> None:
        deployments = self._deployment_map(contract)
        reviewed = set(contract.controller_names)
        missing = reviewed - set(deployments)
        if missing:
            raise ToolError("reviewed controller Deployment is missing during scaling")
        other_names = sorted(reviewed - {"crossplane"})
        names = (
            [*other_names, "crossplane"]
            if replicas == 1
            else ["crossplane", *other_names]
        )
        for name in names:
            if require_active_claim:
                authorization_tool.verify_claim(contract.authorization_path)
            item = deployments[name]
            metadata = item["metadata"]
            if item.get("spec", {}).get("replicas", 1) == replicas:
                continue
            patch = [
                {"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
                {
                    "op": "test",
                    "path": "/metadata/resourceVersion",
                    "value": metadata["resourceVersion"],
                },
                {"op": "replace", "path": "/spec/replicas", "value": replicas},
            ]
            self._kube(
                contract,
                "--namespace",
                NAMESPACE,
                "patch",
                "deployment",
                name,
                "--type=json",
                "-p",
                json.dumps(patch),
            )

    def start_controllers(self, contract: U0Contract) -> None:
        self._patch_replicas(contract, 1, require_active_claim=True)

    def _wait_replicas(
        self,
        contract: U0Contract,
        replicas: int,
        *,
        deadline_seconds: int,
        require_active_claim: bool,
    ) -> None:
        deadline = time.monotonic() + deadline_seconds
        while time.monotonic() < deadline:
            if require_active_claim:
                authorization_tool.verify_claim(contract.authorization_path)
            deployments = self._deployment_map(contract)
            if set(contract.controller_names) == set(deployments):
                ready = True
                for name in contract.controller_names:
                    item = deployments[name]
                    desired = item.get("spec", {}).get("replicas", 1)
                    if replicas == 0:
                        observed = item.get("status", {}).get("replicas", 0)
                        ready = ready and desired == 0 and observed == 0
                    else:
                        available = item.get("status", {}).get("availableReplicas", 0)
                        ready = ready and desired == 1 and available >= 1
                if ready:
                    return
            time.sleep(2)
        raise ToolError("reviewed controllers did not reach the requested bounded state")

    def wait_ready(self, contract: U0Contract) -> None:
        self._wait_replicas(
            contract,
            1,
            deadline_seconds=300,
            require_active_claim=True,
        )

    def verify(self, contract: U0Contract) -> dict[str, Any]:
        authorization_tool.verify_claim(contract.authorization_path)
        self._assert_controller_identity(contract, allow_tagged_functions=False)
        runtime = runtime_verifier.verify_active(contract.bootstrap)
        online = preflight.online_read_only_checks(contract.bootstrap.context)
        self._wait_lifecycle_apis(contract)
        self._apply_document(
            contract,
            contract.environment_candidate,
            dry_run=True,
        )
        self._assert_no_runtime_instances(contract, require_all_apis=True)
        return {
            "runtimeAuthenticationVerified": runtime.get(
                "runtimeAuthenticationVerified", False
            ),
            "onlinePreflight": online.get("mode") == "online-read-only",
            "environmentCandidatePersisted": False,
            "awsResourceMutation": False,
        }

    def _protection_state(self, contract: U0Contract) -> bool:
        path = hardening.STATE.parent / contract.run_id / "protection.json"
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ToolError("U0 protection recovery state is unsafe")
        return True

    def cleanup(self, contract: U0Contract) -> dict[str, Any]:
        self._patch_replicas(contract, 0, require_active_claim=False)
        self._wait_replicas(
            contract,
            0,
            deadline_seconds=180,
            require_active_claim=False,
        )
        if credentials.session_metadata(contract.bootstrap.context) is not None:
            close_session_tool.close_session(
                contract.bootstrap,
                CLOSE_ACKNOWLEDGEMENT,
            )
        if self._protection_state(contract):
            self._harden(contract, "restore")
        self._assert_stopped(contract, allow_tagged_functions=True)
        if credentials.session_metadata(contract.bootstrap.context) is not None:
            raise ToolError("session Secret remains after U0 cleanup")
        return {
            "controllersStopped": 14,
            "sessionSecretAbsent": True,
            "sharedProtectionRestored": True,
            "awsResourceMutation": False,
        }


def execute(
    contract: U0Contract,
    profile: str,
    audit_profile: str,
    acknowledgement: str,
    *,
    operations: RealOperations | None = None,
) -> dict[str, Any]:
    if acknowledgement != RUN_ACKNOWLEDGEMENT:
        raise ToolError("explicit U0 execution acknowledgement required")
    if not profile or not audit_profile or profile == audit_profile:
        raise ToolError("distinct explicit source and audit profiles are required")
    # Revalidate both approvals immediately before the irreversible local claim.
    contract = load_contract(
        contract.authorization_path,
        contract.session_review_path,
        require_approved=True,
    )
    authorization_tool.claim_authorization(
        contract.authorization_path,
        authorization_tool.CLAIM_ACKNOWLEDGEMENT,
    )
    journal = Journal.create(contract.authorization["windowId"])
    journal.append("CLAIMED")
    ops = operations or RealOperations()
    protection_attempted = False
    session_attempted = False
    controllers_attempted = False
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None
    verified: dict[str, Any] = {}
    try:
        authorization_tool.verify_claim(contract.authorization_path)
        ops.baseline(contract)
        journal.append("BASELINE_VERIFIED")

        protection_attempted = True
        journal.append("PROTECTION_STARTED")
        ops.protect(contract)
        journal.append("PROTECTED")

        authorization_tool.verify_claim(contract.authorization_path)
        journal.append("DEFINITIONS_STARTED")
        ops.apply_definitions(contract)
        journal.append("DEFINITIONS_APPLIED")

        authorization_tool.verify_claim(contract.authorization_path)
        session_attempted = True
        journal.append("SESSION_STARTED")
        ops.open_session(contract, profile, audit_profile)
        journal.append("SESSION_OPENED")

        authorization_tool.verify_claim(contract.authorization_path)
        controllers_attempted = True
        ops.start_controllers(contract)
        ops.wait_ready(contract)
        journal.append("CONTROLLERS_STARTED")

        verified = ops.verify(contract)
        if (
            verified.get("runtimeAuthenticationVerified") is not True
            or verified.get("onlinePreflight") is not True
            or verified.get("environmentCandidatePersisted") is not False
            or verified.get("awsResourceMutation") is not False
        ):
            raise ToolError("U0 verification result is incomplete")
        journal.append("VERIFIED")
    except BaseException as error:  # cleanup also runs for KeyboardInterrupt
        failure = error
    finally:
        if protection_attempted or session_attempted or controllers_attempted:
            try:
                journal.append("CLEANUP_STARTED")
                ops.cleanup(contract)
                journal.append(
                    "FAILED_CLEANUP_COMPLETE" if failure else "CLEANUP_COMPLETE"
                )
            except BaseException as error:  # preserve recovery evidence
                cleanup_failure = error
                try:
                    journal.append("RECOVERY_REQUIRED")
                except BaseException:
                    pass
    if cleanup_failure is not None:
        raise ToolError("U0 cleanup is incomplete; run recovery before any retry") from cleanup_failure
    if failure is not None:
        if isinstance(failure, KeyboardInterrupt):
            raise failure
        if not (protection_attempted or session_attempted or controllers_attempted):
            try:
                journal.append("BASELINE_REJECTED_NO_MUTATION")
            except BaseException:
                pass
            raise ToolError(
                "U0 baseline failed after claim; no API mutation was attempted"
            ) from failure
        raise ToolError("U0 preflight failed; bounded cleanup completed") from failure
    return {
        "status": "U0_MANAGEMENT_PREFLIGHT_PASS",
        "windowId": contract.authorization["windowId"],
        "singleUseClaimConsumed": True,
        "controllersRestoredToZero": True,
        "sessionSecretAbsent": True,
        "sharedProtectionRestored": True,
        "environmentCandidatePersisted": False,
        "awsResourceMutation": False,
        "verification": verified,
    }


def recover(
    contract: U0Contract,
    acknowledgement: str,
    *,
    operations: RealOperations | None = None,
) -> dict[str, Any]:
    if acknowledgement != RECOVER_ACKNOWLEDGEMENT:
        raise ToolError("explicit recovery-only acknowledgement required")
    # Recovery deliberately accepts an expired claim but never an absent or
    # mismatched one. It performs no apply, start, AssumeRole, or AWS call.
    authorization_tool.verify_claim(
        contract.authorization_path,
        require_active=False,
    )
    journal = Journal.existing(contract.authorization["windowId"])
    if journal is not None:
        journal.append("RECOVERY_STARTED")
    result = (operations or RealOperations()).cleanup(contract)
    if journal is not None:
        journal.append("RECOVERY_COMPLETE")
    return {
        "status": "U0_RECOVERY_COMPLETE",
        "windowId": contract.authorization["windowId"],
        "controllersRestoredToZero": result["controllersStopped"] == 14,
        "sessionSecretAbsent": result["sessionSecretAbsent"],
        "awsApiCalls": False,
        "awsResourceMutation": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run", "recover"))
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--session-review", type=Path, required=True)
    parser.add_argument("--profile")
    parser.add_argument("--audit-profile")
    parser.add_argument("--acknowledge", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.mode == "plan":
            if args.profile or args.audit_profile or args.acknowledge:
                raise ToolError("plan does not accept profiles or acknowledgement")
            contract = load_contract(
                args.authorization,
                args.session_review,
                require_approved=False,
            )
            result = public_plan(contract)
        elif args.mode == "run":
            if not args.profile or not args.audit_profile:
                raise ToolError("run requires source and audit profiles")
            contract = load_contract(
                args.authorization,
                args.session_review,
                require_approved=True,
            )
            result = execute(
                contract,
                args.profile,
                args.audit_profile,
                args.acknowledge,
            )
        else:
            if args.profile or args.audit_profile:
                raise ToolError("recovery does not accept AWS profiles")
            contract = load_contract(
                args.authorization,
                args.session_review,
                require_approved=True,
                allow_stale_approved=True,
                recovery_only=True,
            )
            result = recover(contract, args.acknowledge)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print(
            "U0 command interrupted; bounded cleanup was attempted; inspect recovery status",
            file=sys.stderr,
        )
        return 130
    except (ToolError, OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "U0 management-preflight command failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
