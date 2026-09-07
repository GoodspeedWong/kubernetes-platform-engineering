"""Server-side metadata GETs through a short-lived, owner-only Unix socket.

Unlike kubectl jsonpath, PartialObjectMetadata negotiation does not download
Secret data or embedded managed Object manifests. No fallback representation is
accepted. Constructing this object is inert; entering it starts the local proxy.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from common import ToolError
import run_u1_bootstrap as bootstrap


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: Path):
        super().__init__("localhost", timeout=30)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class ReadOnlyMetadata:
    def __init__(self, context: str):
        if context != "kind-kube-nebula-a":
            raise ToolError("unreviewed metadata context")
        self.context = context
        self.directory = None
        self.process = None

    def __enter__(self):
        # config view is local-only and does not execute an auth plugin. Refuse
        # exec/auth-provider before the proxy can authenticate to any server.
        config = json.loads(
            bootstrap._run_text(
                [
                    "kubectl",
                    "--context",
                    self.context,
                    "config",
                    "view",
                    "--minify",
                    "-o",
                    "json",
                ]
            )
        )
        users, clusters = config.get("users", []), config.get("clusters", [])
        if (
            len(users) != 1
            or len(clusters) != 1
            or set(users[0].get("user", {}))
            - {"client-certificate-data", "client-key-data"}
            or set(users[0].get("user", {}))
            != {"client-certificate-data", "client-key-data"}
            or not clusters[0]["cluster"]
            .get("server", "")
            .startswith("https://127.0.0.1:")
        ):
            raise ToolError(
                "metadata transport requires the local certificate-only KinD context"
            )
        self.directory = tempfile.TemporaryDirectory(
            prefix="u1c-meta-", dir="/private/tmp"
        )
        self.path = Path(self.directory.name) / "api.sock"
        os.chmod(self.directory.name, 0o700)
        try:
            self.process = subprocess.Popen(
                [
                    "kubectl",
                    "--context",
                    self.context,
                    "proxy",
                    "--unix-socket",
                    str(self.path),
                    "--accept-hosts=^localhost$",
                    "--reject-methods=POST,PUT,PATCH,DELETE,CONNECT,TRACE,OPTIONS,HEAD",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=bootstrap._clean_env(),
            )
            end = time.monotonic() + 10
            while not self.path.exists():
                if self.process.poll() is not None or time.monotonic() >= end:
                    raise ToolError("read-only metadata proxy unavailable")
                time.sleep(0.05)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def get(self, path: str, *, many: bool = False, optional: bool = False):
        if not path.startswith(("/api/", "/apis/")) or any(
            x in path for x in ("..", "?", "#", "\n", "\r")
        ):
            raise ToolError("metadata path is not reviewed")
        kind = "PartialObjectMetadataList" if many else "PartialObjectMetadata"
        connection = UnixConnection(self.path)
        try:
            connection.request(
                "GET",
                path,
                headers={"Accept": f"application/json;as={kind};g=meta.k8s.io;v=v1"},
            )
            response = connection.getresponse()
            if response.status == 404 and optional:
                return None
            if response.status != 200:
                raise ToolError(
                    "metadata GET rejected; no representation fallback allowed"
                )
            payload = response.read(16 * 1024 * 1024 + 1)
            if len(payload) > 16 * 1024 * 1024:
                raise ToolError("metadata response exceeds bound")
            document = json.loads(payload)
            if (
                document.get("apiVersion") != "meta.k8s.io/v1"
                or document.get("kind") != kind
            ):
                raise ToolError("server did not return metadata-only representation")
            if set(document) - {"apiVersion", "kind", "metadata", "items"}:
                raise ToolError("unexpected data in metadata representation")
            if many:
                items = document.get("items")
                if items is None:
                    items = (
                        []
                    )  # A verified metadata-list response may encode empty as null.
                if not isinstance(items, list) or any(
                    set(x) - {"apiVersion", "kind", "metadata"} for x in items
                ):
                    raise ToolError("invalid metadata list")
                return items
            return document
        finally:
            connection.close()

    def __exit__(self, *_):
        try:
            if self.process is not None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            if self.directory is not None:
                self.directory.cleanup()
