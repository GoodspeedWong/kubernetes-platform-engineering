from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
EKS_ROOT = REPO_ROOT / "kind-goodnotes-k8s-demo" / "crossplane-platform-aws-eks"


class P11DocumentationTests(unittest.TestCase):
    def test_five_primary_runbooks_exist_and_are_linked(self) -> None:
        runbooks = (
            "BOOTSTRAP.md",
            "UPGRADE.md",
            "RETIREMENT.md",
            "TROUBLESHOOTING.md",
            "UAT.md",
        )
        readme = (EKS_ROOT / "README.md").read_text()
        for name in runbooks:
            with self.subTest(runbook=name):
                path = EKS_ROOT / name
                self.assertTrue(path.is_file())
                self.assertGreater(len(path.read_text().splitlines()), 20)
                self.assertIn(f"]({name})", readme)

    def test_readme_states_ownership_limits_risks_entries_and_exclusions(self) -> None:
        readme = (EKS_ROOT / "README.md").read_text()
        required = (
            "唯一生命周期 owner",
            "Fargate",
            "AWS 内置网络",
            "CPU 上限为 `16`",
            "内存上限为 `64Gi`",
            "单 NAT",
            "Spot-only",
            "安装入口与运维手册",
            "明确不包含",
            "Managed Node Group",
            "真实创建/扰动/升级/退役 UAT",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, readme)

    def test_bootstrap_separates_definitions_catalog_instances_and_gitops(self) -> None:
        bootstrap = (EKS_ROOT / "BOOTSTRAP.md").read_text()
        required = (
            "U0 定义安装顺序",
            "安装平台 catalog",
            "U1 创建唯一运行实例",
            "目标集群与业务 GitOps",
            "`catalog/`",
            "只允许一个已审核实例",
            "不访问 Kubernetes 或 AWS",
            "AWS_UAT=NOT_RUN",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, bootstrap)
        self.assertIn("resources: []", (EKS_ROOT / "instances/kustomization.yaml").read_text())

    def test_operational_kubectl_commands_pin_context(self) -> None:
        documents = (
            "BOOTSTRAP.md",
            "TROUBLESHOOTING.md",
            "UAT.md",
            "NETWORK_BOOTSTRAP_UAT.md",
        )
        for name in documents:
            for number, line in enumerate((EKS_ROOT / name).read_text().splitlines(), 1):
                stripped = line.strip()
                if not stripped.startswith("kubectl "):
                    continue
                if stripped.startswith("kubectl kustomize "):
                    continue
                with self.subTest(document=name, line=number):
                    self.assertIn("--context", stripped)

    def test_operational_aws_commands_pin_profile_and_region(self) -> None:
        documents = ("BOOTSTRAP.md", "TROUBLESHOOTING.md", "UAT.md")
        for name in documents:
            for number, line in enumerate((EKS_ROOT / name).read_text().splitlines(), 1):
                stripped = line.strip()
                if not stripped.startswith("aws "):
                    continue
                with self.subTest(document=name, line=number):
                    self.assertIn("--profile", stripped)
                    self.assertIn("--region", stripped)

    def test_upgrade_and_retirement_are_gated_and_fail_closed(self) -> None:
        upgrade = (EKS_ROOT / "UPGRADE.md").read_text()
        retirement = (EKS_ROOT / "RETIREMENT.md").read_text()
        for marker in (
            "CompositionRevision",
            "逐 minor",
            "Spot 不足",
            "PDB",
            "强制停止条件",
            "不能用",
        ):
            self.assertIn(marker, upgrade)
        for marker in (
            "DrainWorkloads",
            "RemoveGitOps",
            "DrainCapacity",
            "RemoveFoundation",
            "DeleteReady",
            "finalizer",
            "Launch Template",
            "管理面丢失",
            "禁止强删",
        ):
            self.assertIn(marker, retirement)

    def test_uat_preserves_runtime_boundary_and_cleanup_ownership(self) -> None:
        uat = (EKS_ROOT / "UAT.md").read_text()
        for marker in (
            "U0=FAILED_CLOSED/RECOVERY_COMPLETE",
            "U1–U5=NOT_RUN",
            "AWS_RESOURCE_UAT=NOT_RUN",
            "测试资源与清理责任",
            "创建/清理 owner",
            "未知残留",
            "新的明确授权",
            "超过 15 分钟",
            "InstanceLifecycle=spot",
        ):
            self.assertIn(marker, uat)

    def test_todo_commands_match_implemented_high_fidelity_interfaces(self) -> None:
        todo = (EKS_ROOT / "TODO.md").read_text()
        self.assertNotIn("此刻运行会因文件未实现而失败", todo)
        self.assertIn("render_recursive.py --check", todo)
        self.assertIn("validate_rendered_schemas.py --foundation-embedded", todo)
        self.assertIn("run_m1_validation.py", todo)
        self.assertIn("--required-schemas", todo)
        self.assertIn("禁止同时传", todo)
        self.assertIsNone(
            re.search(r"显式设置锁定的\s*`--crossplane-version`", todo)
        )

    def test_handoff_has_rerun_contract_and_runtime_not_run_markers(self) -> None:
        handoff = (EKS_ROOT / "M1_HANDOFF.md").read_text()
        for marker in (
            "run_m1_validation.py",
            "overall=PASS",
            "testCount>0",
            "S01..S21=PASS",
            "kindApply=NOT_RUN",
            "awsCreate=NOT_RUN",
            "U0 授权清单",
        ):
            self.assertIn(marker, handoff)


if __name__ == "__main__":
    unittest.main()
