import importlib.util
import sys
import unittest
from collections import Counter
from pathlib import Path


MODULE_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = MODULE_ROOT / "scripts" / "sync_github_project.py"
SPEC = importlib.util.spec_from_file_location("github_project_sync", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
SYNC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SYNC
SPEC.loader.exec_module(SYNC)


class GitHubProjectSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = SYNC.load_tasks(
            MODULE_ROOT / "TODO.md",
            MODULE_ROOT / "AWS_ACCOUNT_PREREQUISITES.md",
        )
        cls.by_id = {task.source_id: task for task in cls.tasks}

    def test_expected_task_counts(self):
        self.assertEqual(153, len(self.tasks))
        self.assertEqual(153, len(self.by_id))
        self.assertEqual(
            {
                "M1 Local": 97,
                "AWS Readiness": 20,
                "M2 AWS UAT": 36,
            },
            dict(Counter(task.track for task in self.tasks)),
        )

    def test_initial_status_and_phase_mapping(self):
        self.assertEqual(("P0", "Ready"), self._classified_phase_status("P0-01"))
        self.assertEqual(("P11", "Backlog"), self._classified_phase_status("P11-07"))
        self.assertEqual(("AWS", "Ready"), self._classified_phase_status("A20"))
        self.assertEqual(("U0", "Backlog"), self._classified_phase_status("U0-01"))
        self.assertEqual(("U5", "Backlog"), self._classified_phase_status("U5-05"))

    def test_checked_source_task_is_done(self):
        self.assertTrue(self.by_id["P0-01"].checked)
        self.assertEqual(("P0", "Done"), self._phase_status("P0-01"))

    def test_multiline_descriptions_are_preserved(self):
        self.assertIn("管理面公网访问", self.by_id["P4-01"].description)
        self.assertIn("OIDC、镜像和 Git 来源", self.by_id["A15"].description)

    def test_every_body_has_private_tracking_marker(self):
        for source_id, task in self.by_id.items():
            self.assertIn(
                f"<!-- crossplane-eks-task:{source_id} -->",
                task.body,
            )
            self.assertIn("Do not put account IDs", task.body)

    def test_private_draft_item_type_is_detected(self):
        item = {"content": {"type": "DraftIssue"}}
        self.assertEqual("DraftIssue", SYNC.item_content_type(item))

    def test_private_draft_content_id_is_distinct_from_project_item_id(self):
        item = {
            "id": "PVTI_project-item",
            "content": {"id": "DI_draft-content", "type": "DraftIssue"},
        }
        self.assertEqual("DI_draft-content", SYNC.item_content_id(item))

    def test_missing_draft_content_id_fails_closed(self):
        with self.assertRaisesRegex(SYNC.SyncError, "DI_ content ID"):
            SYNC.item_content_id(
                {"id": "PVTI_project-item", "content": {"type": "DraftIssue"}}
            )

    def test_sensitive_cloud_identity_is_detected(self):
        value = "arn:aws:iam::123456789012:role/example"
        self.assertIsNotNone(SYNC.SENSITIVE_VALUE_RE.search(value))

    def test_matching_metadata_does_not_generate_remote_writes(self):
        task = self.by_id["P0-01"]
        fields = self._fields()
        item = {
            "track": task.track,
            "phase": task.phase,
            "gate": task.gate,
            "requires AWS": task.requires_aws,
            "source ID": task.source_id,
            "status": task.initial_status,
        }
        updates = SYNC.build_metadata_updates(
            [task],
            {task.source_id: "item-id"},
            {task.source_id: item},
            fields,
            set(),
        )
        self.assertEqual([], updates)

    def test_only_missing_metadata_generates_remote_writes(self):
        task = self.by_id["P0-01"]
        fields = self._fields()
        item = {
            "track": task.track,
            "phase": task.phase,
            "source ID": task.source_id,
            "status": task.initial_status,
        }
        updates = SYNC.build_metadata_updates(
            [task],
            {task.source_id: "item-id"},
            {task.source_id: item},
            fields,
            set(),
        )
        self.assertEqual(
            {"Gate", "Requires AWS"},
            {
                next(name for name, field in fields.items() if field["id"] == update.field_id)
                for update in updates
            },
        )

    def _phase_status(self, source_id):
        task = self.by_id[source_id]
        return task.phase, task.initial_status

    @staticmethod
    def _classified_phase_status(source_id):
        _, phase, _, _, initial_status = SYNC.classify_task(source_id)
        return phase, initial_status

    @staticmethod
    def _fields():
        def single_select(name, values):
            return {
                "id": f"field-{name}",
                "name": name,
                "options": [
                    {"id": f"option-{index}", "name": value}
                    for index, value in enumerate(values)
                ],
            }

        return {
            "Status": single_select("Status", SYNC.STATUS_OPTIONS),
            "Track": single_select("Track", SYNC.TRACK_OPTIONS),
            "Phase": single_select("Phase", SYNC.PHASE_OPTIONS),
            "Gate": single_select("Gate", SYNC.GATE_OPTIONS),
            "Requires AWS": single_select(
                "Requires AWS", SYNC.AWS_DEPENDENCY_OPTIONS
            ),
            "Source ID": {"id": "field-Source ID", "name": "Source ID"},
        }


if __name__ == "__main__":
    unittest.main()
