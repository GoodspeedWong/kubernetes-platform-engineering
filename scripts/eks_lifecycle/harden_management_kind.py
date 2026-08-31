#!/usr/bin/env python3
"""Explicit, recoverable A05 maintenance. Never handles AWS credentials.

Private state is deliberately outside Git. Encryption is additive: this tool
never removes a decryption key, rewrites existing Secrets, or rebuilds KinD.
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import time

from common import EKS_ROOT, ToolError, load_yaml

CONTEXT = "kind-kube-nebula-a"
NODE = "kube-nebula-a-control-plane"
NAMESPACE = "crossplane-system"
PAUSE = "crossplane.io/paused"
MARKER = "platform.aws.goodnotes.io/a05-maintenance"
ACK = "I-APPROVE-A05-SHARED-MAINTENANCE"
STATE = Path.home() / ".local/share/eks-platform/kind-kube-nebula-a/a05-20260830"
NODE_DIR = "/etc/kubernetes/a05-encryption"
CONFIG = NODE_DIR + "/encryption.json"
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
XR_TYPES = (
    "xkeycloaks.platform.k8s.goodnotes.io",
    "xtradingdatastores.platform.trading-openclaw.io",
    "xtradingworkloads.platform.trading-openclaw.io",
)
EXPECTED_XRS = {"keycloak-poc", "trading-openclaw-data", "trading-openclaw"}


def run(args: list[str], payload: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            args, input=payload, capture_output=True, timeout=45, check=False
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ToolError(f"{args[0]} unavailable/timed out; output suppressed") from exc
    if result.returncode:
        raise ToolError(f"{args[0]} failed ({result.returncode}); output suppressed")
    return result.stdout


def kube(args: list[str], body: dict | None = None) -> dict:
    output = run(
        ["kubectl", "--context", CONTEXT, "--request-timeout=30s", *args, "-o", "json"],
        json.dumps(body).encode() if body is not None else None,
    )
    return json.loads(output)


def private_directory(path: Path) -> None:
    # Refuse symlink traversal, including existing ancestors of our fixed path.
    for part in reversed((path, *path.parents)):
        if part.is_symlink():
            raise ToolError("private state path contains a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ToolError("private state directory must be owned by caller and mode 0700")


def save_new(name: str, value: bytes) -> None:
    private_directory(STATE)
    fd = os.open(STATE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def read_private(name: str) -> bytes:
    private_directory(STATE)
    path = STATE / name
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ToolError("unsafe private state file")
    return path.read_bytes()


def stopped_controllers() -> None:
    deployments = kube(["get", "deployment", "-n", NAMESPACE])["items"]
    if not deployments or any(d["spec"].get("replicas", 1) != 0 for d in deployments):
        raise ToolError("all shared controllers must be stopped before pause/restore")


def workload_state() -> dict:
    state = {}
    for kind in ("deployment", "statefulset", "cronjob"):
        for item in kube(["get", kind, "-A"])["items"]:
            meta = item["metadata"]
            if meta["namespace"] == NAMESPACE:
                continue
            field = "suspend" if kind == "cronjob" else "replicas"
            state[f"{kind}/{meta['namespace']}/{meta['name']}"] = {
                "uid": meta["uid"], field: item["spec"].get(field, False if kind == "cronjob" else 1)
            }
    return state


def pause_patch(item: dict, token: str, restore: bool = False) -> list[dict]:
    meta = item["metadata"]
    annotations = meta.get("annotations", {})
    operations = [
        {"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
    ]
    pause_path = "/metadata/annotations/" + PAUSE.replace("/", "~1")
    marker_path = "/metadata/annotations/" + MARKER.replace("/", "~1")
    if restore:
        if annotations.get(MARKER) != token or annotations.get(PAUSE) != "true":
            raise ToolError("maintenance annotation drift; manual inspection required")
        operations.extend([
            {"op": "remove", "path": marker_path},
            {"op": "remove", "path": pause_path},
        ])
    else:
        if PAUSE in annotations or MARKER in annotations:
            raise ToolError("existing pause/maintenance annotation; refusing takeover")
        if "annotations" not in meta:
            operations.append({"op": "add", "path": "/metadata/annotations", "value": {}})
        operations.extend([
            {"op": "add", "path": pause_path, "value": "true"},
            {"op": "add", "path": marker_path, "value": token},
        ])
    # Never copy unrelated annotations into process arguments: last-applied
    # annotations can contain embedded Secret manifests.
    return operations


def protect() -> dict:
    stopped_controllers()
    selected = []
    for resource in XR_TYPES + ("objects.kubernetes.crossplane.io",):
        for item in kube(["get", resource])["items"]:
            if resource in XR_TYPES and item["metadata"]["name"] not in EXPECTED_XRS:
                raise ToolError("unexpected shared XR")
            if resource not in XR_TYPES and not any(
                owner.get("name") in EXPECTED_XRS
                for owner in item["metadata"].get("ownerReferences", [])
            ):
                raise ToolError("unexpected Object owner")
            selected.append((resource, item))
    if len(selected) != 76:
        raise ToolError("expected exactly three XRs and 73 Objects")
    token = secrets.token_hex(8)
    # Validate all targets before the first change; save only minimal recovery data.
    for _, item in selected:
        pause_patch(item, token)
    snapshot = {"token": token, "workloads": workload_state(), "objects": [
        {"resource": resource, "name": item["metadata"]["name"], "uid": item["metadata"]["uid"]}
        for resource, item in selected
    ]}
    save_new("protection.json", json.dumps(snapshot).encode())
    for resource, item in selected:  # XRs before child Objects.
        kube(["patch", resource, item["metadata"]["name"], "--type=json", "-p",
              json.dumps(pause_patch(item, token))])
    return {"protectedXRs": 3, "protectedObjects": 73, "workloadsChanged": False}


def verify_workloads() -> dict:
    snapshot = json.loads(read_private("protection.json"))
    if workload_state() != snapshot["workloads"]:
        raise ToolError("business workload replicas/schedules changed; inspect before proceeding")
    return {"businessWorkloadStateUnchanged": True}


def restore_protection() -> dict:
    stopped_controllers()
    verify_workloads()
    snapshot = json.loads(read_private("protection.json"))
    for saved in reversed(snapshot["objects"]):
        item = kube(["get", saved["resource"], saved["name"]])
        if item["metadata"]["uid"] != saved["uid"]:
            raise ToolError("protected object was replaced")
        annotations = item["metadata"].get("annotations", {})
        if MARKER not in annotations and PAUSE not in annotations:
            continue  # A safely completed earlier restore, including partial retries.
        kube(["patch", saved["resource"], saved["name"], "--type=json", "-p",
              json.dumps(pause_patch(item, snapshot["token"], restore=True))])
    return {"restoredObjects": len(snapshot["objects"]), **verify_workloads()}


def narrow_local_admin() -> dict:
    stopped_controllers()
    name = "crossplane-local-runtime-cluster-admin"
    current = kube(["get", "clusterrolebinding", name])
    desired = load_yaml(EKS_ROOT.parent / "crossplane-managed-kind/local-cluster/provider-runtime-cluster-admin.yaml")
    expected = [{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io",
                 "name": "system:serviceaccounts:crossplane-system"}]
    if current["subjects"] != expected or current["roleRef"] != desired["roleRef"]:
        raise ToolError("legacy binding differs from reviewed scope")
    for subject in desired["subjects"]:
        if subject.get("kind") != "ServiceAccount" or subject.get("namespace") != NAMESPACE:
            raise ToolError("only exact local Provider service accounts allowed")
        kube(["get", "serviceaccount", subject["name"], "-n", NAMESPACE])
    save_new("legacy-admin-binding.before.json", json.dumps(current).encode())
    operations = [
        {"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/subjects", "value": expected},
        {"op": "replace", "path": "/subjects", "value": desired["subjects"]},
    ]
    kube(["patch", "clusterrolebinding", name, "--type=json", "-p", json.dumps(operations)])
    if kube(["get", "clusterrolebinding", name])["subjects"] != desired["subjects"]:
        raise ToolError("local binding readback mismatch")
    return {"groupWideClusterAdminRemoved": True, "explicitLocalProviderSubjects": 2,
            "globalSecretIsolationComplete": False}


def encrypted_manifest(original: dict) -> dict:
    document = copy.deepcopy(original)
    containers = document["spec"]["containers"]
    if len(containers) != 1 or containers[0]["name"] != "kube-apiserver":
        raise ToolError("unexpected API server manifest")
    container = containers[0]
    if any(arg.startswith("--encryption-provider") for arg in container["command"]):
        raise ToolError("encryption already configured; refusing key replacement")
    if any(v["name"] == "a05-encryption" for v in document["spec"].get("volumes", [])):
        raise ToolError("encryption volume already exists")
    container["command"].append("--encryption-provider-config=" + CONFIG)
    container.setdefault("volumeMounts", []).append({
        "name": "a05-encryption", "mountPath": NODE_DIR, "readOnly": True
    })
    document["spec"].setdefault("volumes", []).append({
        "name": "a05-encryption", "hostPath": {"path": NODE_DIR, "type": "Directory"}
    })
    return document


def encryption_document(key: bytes) -> dict:
    if len(key) != 32:
        raise ToolError("secretbox requires a 32-byte random key")
    return {"apiVersion": "apiserver.config.k8s.io/v1", "kind": "EncryptionConfiguration",
            "resources": [{"resources": ["secrets"], "providers": [
                {"secretbox": {"keys": [{"name": "a05-key-1", "secret": base64.b64encode(key).decode()}]}},
                {"identity": {}},
            ]}]}


def enable_encryption() -> dict:
    verify_workloads()
    original = run(["docker", "exec", NODE, "cat", MANIFEST])
    document = encrypted_manifest(json.loads(run(["yq", "eval", "-o=json", ".", "-"], original)))
    # Recovery material is durable on the FileVault host before any API change.
    save_new("kube-apiserver.before.yaml", original)
    save_new("encryption.json", json.dumps(encryption_document(secrets.token_bytes(32))).encode())
    # JSON is valid YAML and avoids adding an uninstalled Python YAML dependency.
    save_new("kube-apiserver.encrypted.yaml", json.dumps(document, indent=2).encode())
    run(["docker", "exec", NODE, "test", "!", "-e", NODE_DIR])
    run(["docker", "exec", NODE, "mkdir", "-m", "700", NODE_DIR])
    run(["docker", "cp", str(STATE / "encryption.json"), NODE + ":" + CONFIG])
    run(["docker", "exec", NODE, "chown", "0:0", CONFIG])
    run(["docker", "exec", NODE, "chmod", "600", CONFIG])
    # Backup is outside kubelet's manifest directory; never leave two Pod manifests there.
    run(["docker", "exec", NODE, "cp", "-p", MANIFEST, NODE_DIR + "/kube-apiserver.before.yaml"])
    run(["docker", "cp", str(STATE / "kube-apiserver.encrypted.yaml"), NODE + ":" + NODE_DIR + "/apiserver.next"])
    run(["docker", "exec", NODE, "chown", "0:0", NODE_DIR + "/apiserver.next"])
    run(["docker", "exec", NODE, "chmod", "600", NODE_DIR + "/apiserver.next"])
    run(["docker", "exec", NODE, "mv", NODE_DIR + "/apiserver.next", MANIFEST])
    print(json.dumps({"apiServerManifestUpdated": True, "privateRecoveryMaterialSaved": True}), flush=True)
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            pod = kube(["get", "pod", "-n", "kube-system", "kube-apiserver-" + NODE])
            command = pod["spec"]["containers"][0]["command"]
            ready = any(c["type"] == "Ready" and c["status"] == "True" for c in pod["status"].get("conditions", []))
            if "--encryption-provider-config=" + CONFIG in command and ready:
                run(["kubectl", "--context", CONTEXT, "--request-timeout=15s", "get", "--raw=/readyz"])
                return {"apiServerEncryptedConfigurationReady": True, **verify_workloads()}
        except ToolError:
            pass
        time.sleep(3)
    # No automatic removal: encrypted writes may already have occurred.
    raise ToolError("API readiness unconfirmed; KEEP encryption key/config for recovery")


def verify_encryption() -> dict:
    name = "a05-encryption-canary-" + secrets.token_hex(5)
    marker = base64.b64encode(secrets.token_bytes(32)).decode()
    document = {"apiVersion": "v1", "kind": "Secret", "metadata": {
        "name": name, "namespace": NAMESPACE, "labels": {"platform.aws.goodnotes.io/canary": "a05"}},
        "type": "Opaque", "data": {"probe": marker}}
    created = kube(["create", "-f", "-"], document)
    uid = created["metadata"]["uid"]
    try:
        returned = kube(["get", "secret", name, "-n", NAMESPACE])
        if returned["data"]["probe"] != marker:
            raise ToolError("canary API round trip failed")
        etcd_id = run(["docker", "exec", NODE, "crictl", "ps", "--name", "etcd", "-q"]).decode().strip()
        if not etcd_id or "\n" in etcd_id:
            raise ToolError("expected one etcd container")
        raw = run(["docker", "exec", NODE, "crictl", "exec", etcd_id, "etcdctl",
                   "--endpoints=https://127.0.0.1:2379", "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
                   "--cert=/etc/kubernetes/pki/etcd/server.crt", "--key=/etc/kubernetes/pki/etcd/server.key",
                   "get", f"/registry/secrets/{NAMESPACE}/{name}", "--print-value-only"])
        if not raw.startswith(b"k8s:enc:secretbox:v1:a05-key-1:") or base64.b64decode(marker) in raw:
            raise ToolError("canary is not confirmed encrypted in etcd")
        return {"canaryApiReadWrite": True, "etcdSecretboxCiphertextConfirmed": True,
                "existingSecretsRewritten": False}
    finally:
        # Exact unique canary and UID check; no broad deletion or secret dump.
        current = kube(["get", "secret", name, "-n", NAMESPACE])
        if current["metadata"]["uid"] != uid:
            raise ToolError("canary ownership changed; cleanup refused")
        run(["kubectl", "--context", CONTEXT, "--request-timeout=30s", "delete", "secret", name,
             "-n", NAMESPACE, "--wait=false"])


def main() -> int:
    global STATE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("protect", "encrypt", "verify-encryption", "verify-workloads", "restore", "narrow-local-admin"))
    parser.add_argument("--acknowledge", required=True)
    parser.add_argument("--run-id", default="a05-20260830")
    args = parser.parse_args()
    if args.acknowledge != ACK:
        parser.error("explicit shared maintenance acknowledgement required")
    import re
    if not re.fullmatch(r"a05-[0-9]{8}(?:-[a-z0-9-]{1,32})?", args.run_id):
        parser.error("run-id must be a safe, unique A05 maintenance identifier")
    STATE = STATE.parent / args.run_id
    try:
        action = {"protect": protect, "encrypt": enable_encryption,
                  "verify-encryption": verify_encryption, "verify-workloads": verify_workloads,
                  "restore": restore_protection, "narrow-local-admin": narrow_local_admin}[args.mode]
        print(json.dumps(action(), sort_keys=True))
        return 0
    except (ToolError, OSError, ValueError) as exc:
        # No exception payload: YAML/JSON errors may include private file contents.
        print(json.dumps({"status": "failed", "errorType": type(exc).__name__,
                          "recovery": "keep private recovery files; inspect this operation before retrying"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
