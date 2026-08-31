#!/usr/bin/env python3
"""Fetch and verify digest-pinned schemas for the Crossplane EKS platform.

The fetch mode only reads public registries and HTTPS URLs. It never invokes
cluster mutation, package installation, Helm release mutation, or AWS APIs.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
EKS_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-eks"
DEFAULT_LOCK = EKS_ROOT / "versions.lock.yaml"
DEFAULT_MANIFEST = EKS_ROOT / "tests" / "schemas" / "manifest.yaml"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
AUTH_PARAM_RE = re.compile(r'(\w+)="([^"]*)"')


class SchemaError(RuntimeError):
    """Expected validation or download failure."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise SchemaError(f"required tool is missing: {name}")
    return resolved


def run_checked(command: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise SchemaError(f"command failed ({command[0]}): {detail}")
    return result.stdout


def load_yaml(path: Path) -> dict[str, Any]:
    require_tool("yq")
    if not path.is_file():
        raise SchemaError(f"configuration file does not exist: {path}")
    raw = run_checked(["yq", "eval", "-o=json", ".", str(path)])
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SchemaError(f"invalid YAML in {path}: {error}") from error
    if not isinstance(value, dict):
        raise SchemaError(f"expected a YAML mapping in {path}")
    return value


def parse_digest(value: str, label: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise SchemaError(f"{label} must be an exact sha256 digest")
    return value


def verify_descriptor(payload: bytes, digest: str, label: str) -> None:
    expected = parse_digest(digest, label).removeprefix("sha256:")
    actual = sha256_bytes(payload)
    if actual != expected:
        raise SchemaError(f"digest mismatch for {label}: expected {expected}, got {actual}")


def safe_output_path(output_root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise SchemaError(f"unsafe schema output path: {relative}")
    resolved_root = output_root.resolve()
    resolved = (resolved_root / Path(*candidate.parts)).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise SchemaError(f"schema output escapes output directory: {relative}")
    return resolved


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class RegistryClient:
    def __init__(self, registry: str, repository: str, timeout: int = 120) -> None:
        self.registry = registry
        self.repository = repository
        self.timeout = timeout
        self.token: str | None = None

    def _request(self, url: str, accept: str | None = None) -> bytes:
        headers = {"User-Agent": "goodnotes-eks-schema-lock/1"}
        if accept:
            headers["Accept"] = accept
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.read()

    def _authenticate(self, challenge: str) -> None:
        if not challenge.startswith("Bearer "):
            raise SchemaError(f"unsupported registry authentication for {self.registry}")
        params = dict(AUTH_PARAM_RE.findall(challenge[len("Bearer ") :]))
        realm = params.get("realm")
        if not realm or not realm.startswith("https://"):
            raise SchemaError(f"registry {self.registry} returned an unsafe token realm")
        query = {
            key: value
            for key, value in (("service", params.get("service")), ("scope", params.get("scope")))
            if value
        }
        separator = "&" if "?" in realm else "?"
        token_url = f"{realm}{separator}{urllib.parse.urlencode(query)}"
        token_payload = self._request(token_url)
        try:
            token_document = json.loads(token_payload)
            token = token_document.get("token") or token_document.get("access_token")
        except (json.JSONDecodeError, AttributeError) as error:
            raise SchemaError(f"invalid registry token response from {self.registry}") from error
        if not isinstance(token, str) or not token:
            raise SchemaError(f"registry token response from {self.registry} had no token")
        self.token = token

    def get(self, route: str, *, accept: str | None = None) -> bytes:
        url = f"https://{self.registry}/v2/{self.repository}/{route}"
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                return self._request(url, accept)
            except urllib.error.HTTPError as error:
                if error.code == 401 and self.token is None:
                    challenge = error.headers.get("WWW-Authenticate", "")
                    self._authenticate(challenge)
                    continue
                last_error = error
            except (urllib.error.URLError, TimeoutError) as error:
                last_error = error
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
        raise SchemaError(f"registry read failed for {self.registry}/{self.repository}: {last_error}")


def parse_registry_reference(reference: str) -> tuple[str, str, str]:
    normalized = reference.removeprefix("oci://")
    if "@" in normalized:
        image, locator = normalized.rsplit("@", 1)
    else:
        image, separator, locator = normalized.rpartition(":")
        if not separator or "/" not in image:
            raise SchemaError(f"OCI reference has no tag or digest: {reference}")
    if "/" not in image:
        raise SchemaError(f"OCI reference has no repository: {reference}")
    registry, repository = image.split("/", 1)
    if not registry or not repository or not locator:
        raise SchemaError(f"invalid OCI reference: {reference}")
    return registry, repository, locator


MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


def load_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise SchemaError(f"invalid JSON for {label}: {error}") from error
    if not isinstance(value, dict):
        raise SchemaError(f"expected JSON object for {label}")
    return value


def select_platform_manifest(index: dict[str, Any], architecture: str) -> str:
    candidates = []
    for descriptor in index.get("manifests", []):
        platform = descriptor.get("platform", {})
        if platform.get("os") == "linux" and platform.get("architecture") == architecture:
            candidates.append(descriptor.get("digest"))
    if len(candidates) != 1 or not isinstance(candidates[0], str):
        raise SchemaError(f"expected exactly one linux/{architecture} manifest")
    return parse_digest(candidates[0], "platform manifest")


def fetch_xpkg_package(reference: str, architecture: str) -> bytes:
    registry, repository, locator = parse_registry_reference(reference)
    index_digest = parse_digest(locator, "xpkg index")
    client = RegistryClient(registry, repository)
    index_payload = client.get(f"manifests/{index_digest}", accept=MANIFEST_ACCEPT)
    verify_descriptor(index_payload, index_digest, "xpkg index")
    index = load_json(index_payload, "xpkg index")
    media_type = index.get("mediaType", "")
    if media_type.endswith("image.index.v1+json") or media_type.endswith("manifest.list.v2+json"):
        manifest_digest = select_platform_manifest(index, architecture)
        manifest_payload = client.get(f"manifests/{manifest_digest}", accept=MANIFEST_ACCEPT)
        verify_descriptor(manifest_payload, manifest_digest, "xpkg platform manifest")
        manifest = load_json(manifest_payload, "xpkg platform manifest")
    else:
        manifest = index
    base_layers = [
        layer
        for layer in manifest.get("layers", [])
        if layer.get("annotations", {}).get("io.crossplane.xpkg") == "base"
    ]
    if len(base_layers) != 1:
        raise SchemaError("xpkg manifest must contain exactly one base layer")
    layer_digest = parse_digest(base_layers[0].get("digest", ""), "xpkg base layer")
    layer = client.get(f"blobs/{layer_digest}")
    verify_descriptor(layer, layer_digest, "xpkg base layer")
    try:
        with tarfile.open(fileobj=io.BytesIO(layer), mode="r:gz") as archive:
            package = archive.extractfile("package.yaml")
            if package is None:
                raise SchemaError("xpkg base layer has no package.yaml")
            return package.read()
    except tarfile.TarError as error:
        raise SchemaError(f"invalid xpkg base layer: {error}") from error


def fetch_http(url: str, expected_sha256: str) -> bytes:
    if not url.startswith("https://"):
        raise SchemaError(f"only HTTPS downloads are allowed: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "goodnotes-eks-schema-lock/1"})
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                payload = response.read()
            actual = sha256_bytes(payload)
            if actual != expected_sha256:
                raise SchemaError(
                    f"download digest mismatch for {url}: expected {expected_sha256}, got {actual}"
                )
            return payload
        except SchemaError:
            raise
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    raise SchemaError(f"HTTPS download failed for {url}: {last_error}")


def fetch_oci_chart(chart: dict[str, Any]) -> bytes:
    registry, repository, _ = parse_registry_reference(str(chart["reference"]))
    manifest_digest = parse_digest(str(chart["manifestDigest"]), "chart manifest")
    content_digest = parse_digest(f"sha256:{chart['contentSha256']}", "chart content")
    client = RegistryClient(registry, repository)
    manifest_payload = client.get(f"manifests/{manifest_digest}", accept=MANIFEST_ACCEPT)
    verify_descriptor(manifest_payload, manifest_digest, "chart manifest")
    manifest = load_json(manifest_payload, "chart manifest")
    layers = [
        layer
        for layer in manifest.get("layers", [])
        if layer.get("mediaType") == "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
    ]
    if len(layers) != 1 or layers[0].get("digest") != content_digest:
        raise SchemaError("chart manifest does not contain the locked content layer")
    chart_payload = client.get(f"blobs/{content_digest}")
    verify_descriptor(chart_payload, content_digest, "chart content")
    return chart_payload


def extract_crd(document: bytes, crd_name: str, temporary_directory: Path) -> bytes:
    package_path = temporary_directory / "documents.yaml"
    package_path.write_bytes(document)
    expression = (
        'select(.kind == "CustomResourceDefinition" and .metadata.name == '
        f"{json.dumps(crd_name)})"
    )
    rendered = run_checked(
        ["yq", "eval-all", "--no-doc", expression, str(package_path)]
    ).strip()
    if not rendered:
        raise SchemaError(f"CRD was not found in locked source: {crd_name}")
    actual_name = run_checked(
        ["yq", "eval", ".metadata.name", "-"], input_text=rendered
    ).strip()
    if actual_name != crd_name:
        raise SchemaError(f"selected CRD name mismatch: expected {crd_name}, got {actual_name}")
    return (rendered + "\n").encode()


def render_chart(chart_payload: bytes, temporary_directory: Path) -> bytes:
    require_tool("helm")
    chart_path = temporary_directory / "chart.tgz"
    chart_path.write_bytes(chart_payload)
    rendered = run_checked(
        [
            "helm",
            "template",
            "schema-source",
            str(chart_path),
            "--include-crds",
            "--kube-version",
            "1.35.0",
        ]
    )
    return rendered.encode()


def write_source_crds(
    source: dict[str, Any],
    lock: dict[str, Any],
    output_root: Path,
    architecture: str,
) -> list[Path]:
    source_type = source.get("type")
    with tempfile.TemporaryDirectory(prefix="eks-schema-") as temporary:
        temporary_directory = Path(temporary)
        if source_type == "xpkg":
            package_key = source.get("packageKey")
            try:
                package = lock["packages"][package_key]
                reference = package["reference"]
            except (KeyError, TypeError) as error:
                raise SchemaError(f"unknown packageKey in schema manifest: {package_key}") from error
            documents = fetch_xpkg_package(str(reference), architecture)
        elif source_type == "httpChart":
            chart_key = source.get("chartKey")
            try:
                chart = lock["charts"][chart_key]
                url = str(chart["url"])
                digest = str(chart["sha256"])
            except (KeyError, TypeError) as error:
                raise SchemaError(f"unknown chartKey in schema manifest: {chart_key}") from error
            documents = render_chart(fetch_http(url, digest), temporary_directory)
        elif source_type == "ociChart":
            chart_key = source.get("chartKey")
            try:
                chart = lock["charts"][chart_key]
            except (KeyError, TypeError) as error:
                raise SchemaError(f"unknown chartKey in schema manifest: {chart_key}") from error
            documents = render_chart(fetch_oci_chart(chart), temporary_directory)
        elif source_type == "httpCRDs":
            written = []
            for crd in source.get("crds", []):
                payload = fetch_http(str(crd["url"]), str(crd["sha256"]))
                selected = extract_crd(payload, str(crd["name"]), temporary_directory)
                target = safe_output_path(output_root, str(crd["file"]))
                atomic_write(target, selected)
                written.append(target)
            return written
        else:
            raise SchemaError(f"unsupported schema source type: {source_type}")

        written = []
        for crd in source.get("crds", []):
            selected = extract_crd(documents, str(crd["name"]), temporary_directory)
            target = safe_output_path(output_root, str(crd["file"]))
            atomic_write(target, selected)
            written.append(target)
        return written


def expected_output_paths(manifest: dict[str, Any], output_root: Path) -> list[Path]:
    paths = []
    seen = set()
    for source in manifest.get("sources", []):
        for crd in source.get("crds", []):
            path = safe_output_path(output_root, str(crd.get("file", "")))
            if path in seen:
                raise SchemaError(f"duplicate schema output path: {path}")
            seen.add(path)
            paths.append(path)
    if not paths:
        raise SchemaError("schema manifest declares no generated schemas")
    return sorted(paths)


def write_checksums(paths: list[Path], output_root: Path, checksum_path: Path) -> None:
    lines = [f"{sha256_file(path)}  {path.relative_to(output_root).as_posix()}" for path in paths]
    atomic_write(checksum_path, ("\n".join(lines) + "\n").encode())


def read_checksums(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise SchemaError(f"checksum file is missing: {path}")
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise SchemaError(f"invalid checksum line {line_number} in {path}")
        if parts[1] in checksums:
            raise SchemaError(f"duplicate checksum path in {path}: {parts[1]}")
        checksums[parts[1]] = parts[0]
    return checksums


def verify_schemas(paths: list[Path], output_root: Path, checksum_path: Path) -> None:
    checksums = read_checksums(checksum_path)
    expected_names = {path.relative_to(output_root).as_posix() for path in paths}
    if set(checksums) != expected_names:
        missing = sorted(expected_names - set(checksums))
        extra = sorted(set(checksums) - expected_names)
        raise SchemaError(f"checksum inventory mismatch; missing={missing}, extra={extra}")
    for path in paths:
        relative = path.relative_to(output_root).as_posix()
        if not path.is_file():
            raise SchemaError(f"schema file is missing: {relative}")
        actual = sha256_file(path)
        if actual != checksums[relative]:
            raise SchemaError(
                f"schema checksum mismatch for {relative}: expected {checksums[relative]}, got {actual}"
            )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch or verify the digest-pinned schemas used by the EKS lifecycle platform."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fetch", action="store_true", help="download locked public artifacts")
    mode.add_argument("--verify", action="store_true", help="verify the existing cache offline")
    parser.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="override the generated schema directory (checksums stay beside the manifest)",
    )
    parser.add_argument(
        "--checksums",
        type=Path,
        help="override the checksum file path",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        manifest = load_yaml(args.manifest)
        schema_root = args.manifest.resolve().parent
        output_root = (
            args.output_dir.resolve()
            if args.output_dir
            else (schema_root / str(manifest.get("generatedDirectory", "generated"))).resolve()
        )
        checksum_path = (
            args.checksums.resolve()
            if args.checksums
            else (schema_root / str(manifest.get("checksumFile", "checksums.sha256"))).resolve()
        )
        paths = expected_output_paths(manifest, output_root)
        if args.fetch:
            lock = load_yaml(args.lock_file)
            architecture = str(manifest.get("platform", "amd64"))
            if architecture not in {"amd64", "arm64"}:
                raise SchemaError(f"unsupported schema package architecture: {architecture}")
            written: list[Path] = []
            for source in manifest.get("sources", []):
                source_id = source.get("id", "unnamed")
                print(f"FETCH {source_id}")
                written.extend(write_source_crds(source, lock, output_root, architecture))
            if sorted(written) != paths:
                raise SchemaError("fetch did not produce exactly the declared schema inventory")
            write_checksums(paths, output_root, checksum_path)
        verify_schemas(paths, output_root, checksum_path)
        print(f"SCHEMA VERIFY PASS: {len(paths)} files")
        return 0
    except (KeyError, TypeError, ValueError, SchemaError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
