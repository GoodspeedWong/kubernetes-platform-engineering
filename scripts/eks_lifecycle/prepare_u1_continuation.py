#!/usr/bin/env python3
"""Prepare a NEW unapproved continuation draft from private LOCAL evidence only.

Never refresh an AWS snapshot, record approval, consume a claim or mutate an
existing bundle. A fresh active package must be independently assembled/reviewed
after the separate read-only readiness work; this command always leaves it null.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from common import EKS_ROOT, ToolError
import validate_u1_continuation as auth


def file_reference(path: Path):
    path = Path(os.path.abspath(path.expanduser()))
    return {"path": str(path), "sha256": auth.digest(path)}


def directory_reference(path: Path):
    path = Path(os.path.abspath(path.expanduser()))
    return {
        "path": str(path),
        "files": {p.name: auth.digest(p) for p in sorted(path.iterdir())},
    }


def write_new(path: Path, payload: bytes):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(destination: Path, sources: dict) -> dict:
    destination = Path(os.path.abspath(destination.expanduser()))
    match = auth.BUNDLE_RE.fullmatch(destination.name)
    if match is None or destination.exists():
        raise ToolError(
            "new, distinct continuation directory required; never overwrite a reviewed bundle"
        )
    evidence = auth.source_evidence(sources)
    code = auth.create.execution_code_state()
    window = f"u1c-{''.join(match.groups()[:3])}-{match[4]}"
    source_bytes = (json.dumps(sources, indent=2, sort_keys=True) + "\n").encode()
    document = {
        "schemaVersion": 1,
        "authorizationType": auth.AUTHORIZATION_TYPE,
        "bundle": destination.name,
        "windowId": window,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "reviewStatus": auth.PENDING,
        "approvedBy": None,
        "approvedAt": None,
        "scope": auth.SCOPE,
        "executionCode": code,
        "sourcesSha256": hashlib.sha256(source_bytes).hexdigest(),
        "rootUid": evidence["rootUid"],
        "compositionPin": asdict(evidence["pin"]),
        "sourceCreateWindow": evidence["sourceWindow"],
        "awsReadOnlySnapshot": None,
    }
    summary = f"""# U1 既有 root 续跑：本地审核草案

状态：`{auth.PENDING}`。本包**不授权 active 执行**，没有消费 claim。

- 包：`{destination.name}`；预留的新窗口身份：`{window}`。
- Git commit：`{code['gitCommit']}`。
- execution aggregate：`{code['aggregateSha256']}`；非 Markdown 文件 {code['trackedNonMarkdownFiles']}。
- 绑定既有 root UID：`{evidence['rootUid']}`。
- 原 create 窗口：`{evidence['sourceWindow']}`；旧 `RECOVERY_REQUIRED`、claim、journal 均原样保留。
- 原包是否证明 Standard Spot 配额：`{evidence['archivedSpotQuotaVerified']}`；v1 的 On-Demand 记录不算 Spot 证据。
- Composition：`{evidence['pin'].composition_name}` / UID `{evidence['pin'].composition_uid}`。
- Revision：`{evidence['pin'].revision_name}` / UID `{evidence['pin'].revision_uid}`。
- 内容 SHA-256：`{evidence['pin'].spec_sha256}`。

## 本次产出和证据边界

本地准备只读入历史文件。没有 AWS/Kubernetes API、STS、Session Secret 或 controller 操作。
9 月 6 日独立 Kubernetes 只读停车确认用于绑定身份，不改写旧窗口结果，也不证明当前云库存为零。
`sources.json` 绑定完整原包、create claim/result/journal、独立刷新包、独立 A05 review 和聚合范围外的 core RBAC 源。
所有私有文件 0600，目录 0700；只检查摘要，不将凭据值写入本包。

## 续跑行为

独立 `run_u1_continuation.py` / `validate_u1_continuation.py` 使用 `u1c-*` claim，拒绝旧 create claim。
只观察同一 root，绝不 create/apply/replace/patch/delete root 或永久定义。
初始基线只支持 root=1、child XR=0、AWS managed resource=0、73 个原有非 AWS Object；
AWS 14 类目标库存必须重新证明为零，不自动接管部分已创建资源。
核对 14 个 controller UID、76 个共享对象、89 个业务副本/计划、63 份永久定义、Provider/Function owner chain。
只允许原 owner 层级到首个 U1 checkpoint；Spot-only、Karpenter Fargate-only、Cilium EC2-only 的原 intent 不变。
最长 active 3000 秒，独立 A05 会话最多 3600 秒；失败先终止 active timer，再停车、清 Session、恢复共享对象。
保留 root/cloud，云资源继续计费；7 天/70 USD 只是手工软预算。无自动重试、删除、U1-06/07、U2 或 Git bootstrap。

## 仍需完成，不能用本包绕过

1. 单独批准并获取新的 schema v2 AWS/release/CoreDNS/AMI/Spot quota/IAM/双出口快照。
   spotQuota 必须包含 serviceCode、quotaCode、quotaName、usageClass、value，并通过 Standard Spot 校验。
2. 出口必须仍匹配既有 root 的审核 CIDR；漂移需另审 intent 变更，不能在本轮偷偷改 root。
3. 核对独立 A05 review；真正开启前仍需完整 IAM 审计。此处只有历史 review 的文件绑定。
4. 将完整新证据放入**新包**，绑定最终代码/全部摘要，由唯一维护审核人独立批准 active 窗口。
5. 新窗口内 claim 后、首个 mutation 前再次检查真实基线；失败消费 claim，不自动重试。

本草案 `awsReadOnlySnapshot=null`、approval=null，因此 `validate-approved` 和 `run` 必须失败且不得创建 claim。
仅允许现在运行本地 `plan --authorization <本目录>/authorization-contract.json`。
"""
    # Safe creation, not update. A partially written new draft is deliberately
    # retained after failure for inspection; it is never a runnable approval.
    destination.mkdir(mode=0o700)
    os.chmod(destination, 0o700)
    write_new(destination / "sources.json", source_bytes)
    write_new(
        destination / "authorization-contract.json",
        (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(),
    )
    write_new(destination / "REVIEW_SUMMARY.md", summary.encode())
    checksums = "".join(
        f"{auth.digest(destination / name)}  {name}\n" for name in sorted(auth.FILES)
    )
    write_new(destination / "SHA256SUMS", checksums.encode())
    descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return auth.public_plan(
        auth.validate(
            destination / "authorization-contract.json", require_approved=False
        )
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in (
        "destination",
        "create-bundle",
        "create-claim",
        "create-result",
        "create-journal",
        "refresh-bundle",
        "session-review",
    ):
        parser.add_argument("--" + arg, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        core = EKS_ROOT.parent / "crossplane/manifest.yaml"
        sources = {
            "createBundle": directory_reference(args.create_bundle),
            "refreshBundle": directory_reference(args.refresh_bundle),
            "createClaim": file_reference(args.create_claim),
            "createResult": file_reference(args.create_result),
            "createJournal": file_reference(args.create_journal),
            "sessionReview": file_reference(args.session_review),
            "coreRbacSource": {
                "path": str(core),
                "sha256": hashlib.sha256(core.read_bytes()).hexdigest(),
            },
        }
        print(json.dumps(prepare(args.destination, sources), indent=2))
        return 0
    except (ToolError, OSError, ValueError, KeyError, TypeError, AttributeError):
        print(
            "continuation draft preparation failed closed; private values suppressed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
