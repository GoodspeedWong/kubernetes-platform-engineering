#!/usr/bin/env python3
"""Synchronize the EKS lifecycle taskbooks to a private GitHub Project.

The Markdown files define task identity and task text. GitHub Project keeps the
execution status. Existing status values are preserved unless a source checkbox
is checked, in which case the Project item is moved to Done.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


MODULE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TODO = MODULE_ROOT / "TODO.md"
DEFAULT_AWS = MODULE_ROOT / "AWS_ACCOUNT_PREREQUISITES.md"
DEFAULT_OWNER = "@me"
DEFAULT_PROJECT_NUMBER = 1

TASK_RE = re.compile(r"^- \[([ xX])\] ((?:P|U)\d+-\d+|A\d+)\s+(.+?)\s*$")
MARKER_RE = re.compile(r"<!-- crossplane-eks-task:([A-Z0-9-]+) -->")
SENSITIVE_VALUE_RE = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"
    r"|(?<![0-9])[0-9]{12}(?![0-9])"
)

TRACK_OPTIONS = ("M1 Local", "AWS Readiness", "M2 AWS UAT")
GATE_OPTIONS = ("M1", "ACCOUNT_READY", "M2")
AWS_DEPENDENCY_OPTIONS = ("No", "Account preparation", "Yes")
PHASE_OPTIONS = (
    "P0",
    "P1",
    "P2",
    "P3",
    "P4",
    "P5",
    "P6",
    "P7",
    "P8",
    "P9",
    "P10",
    "P11",
    "AWS",
    "U0",
    "U1",
    "U2",
    "U3",
    "U4",
    "U5",
)
STATUS_OPTIONS = ("Backlog", "Ready", "In progress", "In review", "Done")


class SyncError(RuntimeError):
    """Raised when local or remote state is unsafe to synchronize."""


@dataclass(frozen=True)
class Task:
    source_id: str
    description: str
    source_file: str
    checked: bool
    track: str
    phase: str
    gate: str
    requires_aws: str
    initial_status: str

    @property
    def title(self) -> str:
        first_clause = re.split(r"[；。]", self.description, maxsplit=1)[0].strip()
        if len(first_clause) > 96:
            first_clause = first_clause[:93].rstrip() + "..."
        return f"[{self.source_id}] {first_clause}"

    @property
    def body(self) -> str:
        return (
            f"{self.description}\n\n"
            "---\n\n"
            "### Tracking metadata\n\n"
            f"- Source file: `{self.source_file}`\n"
            f"- Source ID: `{self.source_id}`\n"
            f"- Track: `{self.track}`\n"
            f"- Phase: `{self.phase}`\n"
            f"- Gate: `{self.gate}`\n"
            f"- AWS account dependency: `{self.requires_aws}`\n\n"
            "Do not put account IDs, credentials, kubeconfigs, tokens, private keys, "
            "or other secrets in this item.\n\n"
            f"<!-- crossplane-eks-task:{self.source_id} -->"
        )


def classify_task(source_id: str) -> tuple[str, str, str, str, str]:
    if source_id.startswith("P"):
        phase = source_id.split("-", maxsplit=1)[0]
        status = "Ready" if phase == "P0" else "Backlog"
        return "M1 Local", phase, "M1", "No", status
    if source_id.startswith("U"):
        phase = source_id.split("-", maxsplit=1)[0]
        return "M2 AWS UAT", phase, "M2", "Yes", "Backlog"
    if source_id.startswith("A"):
        return "AWS Readiness", "AWS", "ACCOUNT_READY", "Account preparation", "Ready"
    raise SyncError(f"unsupported task ID: {source_id}")


def parse_task_file(path: Path) -> list[Task]:
    if not path.is_file():
        raise SyncError(f"task file not found: {path}")

    tasks: list[Task] = []
    current: dict[str, Any] | None = None

    def finish_current() -> None:
        nonlocal current
        if current is None:
            return
        description = " ".join(current["parts"])
        description = re.sub(r"\s+", " ", description).strip()
        track, phase, gate, requires_aws, initial_status = classify_task(
            current["source_id"]
        )
        tasks.append(
            Task(
                source_id=current["source_id"],
                description=description,
                source_file=path.name,
                checked=current["checked"],
                track=track,
                phase=phase,
                gate=gate,
                requires_aws=requires_aws,
                initial_status="Done" if current["checked"] else initial_status,
            )
        )
        current = None

    for line in path.read_text(encoding="utf-8").splitlines():
        match = TASK_RE.match(line)
        if match:
            finish_current()
            current = {
                "checked": match.group(1).lower() == "x",
                "source_id": match.group(2),
                "parts": [match.group(3).strip()],
            }
            continue

        if current is not None and line.startswith(("  ", "\t")) and line.strip():
            current["parts"].append(line.strip())
            continue

        finish_current()

    finish_current()
    return tasks


def load_tasks(todo_path: Path, aws_path: Path) -> list[Task]:
    tasks = parse_task_file(todo_path) + parse_task_file(aws_path)
    ids = [task.source_id for task in tasks]
    duplicates = sorted(task_id for task_id, count in Counter(ids).items() if count > 1)
    if duplicates:
        raise SyncError(f"duplicate task IDs: {', '.join(duplicates)}")
    if not tasks:
        raise SyncError("no task checkboxes discovered")
    sensitive_tasks = sorted(
        task.source_id
        for task in tasks
        if SENSITIVE_VALUE_RE.search(task.description)
    )
    if sensitive_tasks:
        raise SyncError(
            "task text contains values that must not be synchronized: "
            + ", ".join(sensitive_tasks)
        )
    return tasks


def run_gh_json(
    arguments: Sequence[str],
    stdin_payload: dict[str, Any] | None = None,
    retries: int = 0,
) -> Any:
    command = ["gh", *arguments]
    completed: subprocess.CompletedProcess[str] | None = None
    for attempt in range(retries + 1):
        completed = subprocess.run(
            command,
            input=json.dumps(stdin_payload, ensure_ascii=False) if stdin_payload else None,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode == 0:
            break
        detail = completed.stderr.strip() or completed.stdout.strip()
        transient = any(
            marker in detail.casefold()
            for marker in (
                "eof",
                "timeout",
                "connection reset",
                "bad gateway",
                "service unavailable",
                " 502",
                " 503",
                " 504",
            )
        )
        if not transient or attempt == retries:
            raise SyncError(f"command failed ({' '.join(command)}): {detail}")
        delay = 2**attempt
        print(
            f"transient GitHub error; retrying in {delay}s "
            f"({attempt + 1}/{retries})",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(delay)
    if completed is None:
        raise SyncError(f"command did not run: {' '.join(command)}")
    if not completed.stdout.strip():
        return {}
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SyncError(f"non-JSON response from {' '.join(command)}") from exc


def graphql(
    query: str, variables: dict[str, Any], retries: int = 0
) -> dict[str, Any]:
    result = run_gh_json(
        ["api", "graphql", "--input", "-"],
        {"query": query, "variables": variables},
        retries=retries,
    )
    if result.get("errors"):
        raise SyncError(
            f"GraphQL errors: {json.dumps(result['errors'], ensure_ascii=False)}"
        )
    return result.get("data", {})


def project_record(owner: str, project_number: int) -> dict[str, Any]:
    payload = run_gh_json(
        [
            "project",
            "list",
            "--owner",
            owner,
            "--limit",
            "10",
            "--format",
            "json",
        ],
        retries=3,
    )
    for project in payload.get("projects", []):
        if project.get("number") == project_number:
            if project.get("public"):
                raise SyncError("refusing to import private planning tasks into a public Project")
            return project
    raise SyncError(f"private Project #{project_number} not found for {owner}")


def list_fields(owner: str, project_number: int) -> list[dict[str, Any]]:
    payload = run_gh_json(
        [
            "project",
            "field-list",
            str(project_number),
            "--owner",
            owner,
            "--limit",
            "50",
            "--format",
            "json",
        ],
        retries=3,
    )
    return payload.get("fields", [])


def create_field(
    owner: str,
    project_number: int,
    name: str,
    data_type: str,
    options: Iterable[str] = (),
) -> None:
    arguments = [
        "project",
        "field-create",
        str(project_number),
        "--owner",
        owner,
        "--name",
        name,
        "--data-type",
        data_type,
        "--format",
        "json",
    ]
    option_list = list(options)
    if option_list:
        arguments.extend(["--single-select-options", ",".join(option_list)])
    run_gh_json(arguments)


def ensure_fields(owner: str, project_number: int) -> dict[str, dict[str, Any]]:
    specifications = {
        "Track": ("SINGLE_SELECT", TRACK_OPTIONS),
        "Phase": ("SINGLE_SELECT", PHASE_OPTIONS),
        "Gate": ("SINGLE_SELECT", GATE_OPTIONS),
        "Requires AWS": ("SINGLE_SELECT", AWS_DEPENDENCY_OPTIONS),
        "Source ID": ("TEXT", ()),
    }
    existing = {field["name"]: field for field in list_fields(owner, project_number)}
    created_any = False

    for name, (data_type, options) in specifications.items():
        if name not in existing:
            create_field(owner, project_number, name, data_type, options)
            created_any = True

    if created_any:
        existing = {
            field["name"]: field for field in list_fields(owner, project_number)
        }
    required = (
        "Status",
        "Track",
        "Phase",
        "Gate",
        "Requires AWS",
        "Source ID",
    )
    missing = [name for name in required if name not in existing]
    if missing:
        raise SyncError(f"required Project fields missing: {', '.join(missing)}")

    option_fields = (
        ("Track", TRACK_OPTIONS),
        ("Phase", PHASE_OPTIONS),
        ("Gate", GATE_OPTIONS),
        ("Requires AWS", AWS_DEPENDENCY_OPTIONS),
    )
    for name, expected_options in option_fields:
        actual_options = {option["name"] for option in existing[name].get("options", [])}
        missing_options = sorted(set(expected_options) - actual_options)
        if missing_options:
            raise SyncError(f"field {name} lacks options: {', '.join(missing_options)}")

    status_options = {option["name"] for option in existing["Status"].get("options", [])}
    missing_statuses = sorted(set(STATUS_OPTIONS) - status_options)
    if missing_statuses:
        raise SyncError(f"Status field lacks options: {', '.join(missing_statuses)}")
    return existing


def list_items(owner: str, project_number: int) -> list[dict[str, Any]]:
    payload = run_gh_json(
        [
            "project",
            "item-list",
            str(project_number),
            "--owner",
            owner,
            "--limit",
            "250",
            "--format",
            "json",
        ],
        retries=3,
    )
    items = payload.get("items", [])
    total_count = int(payload.get("totalCount", len(items)))
    if total_count > len(items):
        raise SyncError(
            f"Project has {total_count} items but only {len(items)} were returned; "
            "raise the audited item limit before synchronizing"
        )
    return items


def item_body(item: dict[str, Any]) -> str:
    content = item.get("content")
    if isinstance(content, dict):
        return str(content.get("body") or "")
    return str(item.get("body") or "")


def item_title(item: dict[str, Any]) -> str:
    return str(item.get("title") or "")


def item_content_type(item: dict[str, Any]) -> str:
    content = item.get("content")
    if isinstance(content, dict):
        return str(content.get("type") or "")
    return str(item.get("type") or "")


def item_content_id(item: dict[str, Any]) -> str:
    content = item.get("content")
    if not isinstance(content, dict) or content.get("type") != "DraftIssue":
        raise SyncError("tracked Project item is not a private DraftIssue")
    content_id = str(content.get("id") or "")
    if not content_id.startswith("DI_"):
        raise SyncError("tracked DraftIssue is missing its DI_ content ID")
    return content_id


def item_source_id(item: dict[str, Any]) -> str | None:
    match = MARKER_RE.search(item_body(item))
    return match.group(1) if match else None


def indexed_items(items: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for item in items:
        source_id = item_source_id(item)
        if source_id is None:
            continue
        if source_id in index:
            duplicates.append(source_id)
        else:
            index[source_id] = item
    if duplicates:
        raise SyncError(f"duplicate remote Source IDs: {', '.join(sorted(set(duplicates)))}")
    return index


def chunks(values: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def create_draft_items(project_id: str, tasks: Sequence[Task]) -> dict[str, str]:
    created: dict[str, str] = {}
    for batch_number, batch in enumerate(chunks(tasks, 10), start=1):
        declarations = ["$projectId: ID!"]
        mutations: list[str] = []
        variables: dict[str, Any] = {"projectId": project_id}
        for index, task in enumerate(batch):
            declarations.extend(
                [f"$title{index}: String!", f"$body{index}: String!"]
            )
            variables[f"title{index}"] = task.title
            variables[f"body{index}"] = task.body
            mutations.append(
                f"i{index}: addProjectV2DraftIssue(input: {{"
                f"projectId: $projectId, title: $title{index}, body: $body{index}"
                "}) { projectItem { id } }"
            )
        query = f"mutation({', '.join(declarations)}) {{ {' '.join(mutations)} }}"
        data = graphql(query, variables)
        for index, task in enumerate(batch):
            try:
                created[task.source_id] = data[f"i{index}"]["projectItem"]["id"]
            except (KeyError, TypeError) as exc:
                raise SyncError(f"missing create result for {task.source_id}") from exc
        print(
            f"created batch {batch_number}: {len(batch)} items "
            f"({len(created)}/{len(tasks)})",
            flush=True,
        )
    return created


def update_draft_content(item_id: str, task: Task) -> None:
    run_gh_json(
        [
            "project",
            "item-edit",
            "--id",
            item_id,
            "--title",
            task.title,
            "--body",
            task.body,
            "--format",
            "json",
        ],
        retries=3,
    )


@dataclass(frozen=True)
class FieldUpdate:
    item_id: str
    field_id: str
    value_type: str
    value: str


def update_fields(project_id: str, updates: Sequence[FieldUpdate]) -> None:
    for batch_number, batch in enumerate(chunks(updates, 30), start=1):
        declarations = ["$projectId: ID!"]
        mutations: list[str] = []
        variables: dict[str, Any] = {"projectId": project_id}
        for index, update in enumerate(batch):
            declarations.extend(
                [f"$item{index}: ID!", f"$field{index}: ID!", f"$value{index}: String!"]
            )
            variables[f"item{index}"] = update.item_id
            variables[f"field{index}"] = update.field_id
            variables[f"value{index}"] = update.value
            if update.value_type == "single_select":
                value_expression = f"{{singleSelectOptionId: $value{index}}}"
            elif update.value_type == "text":
                value_expression = f"{{text: $value{index}}}"
            else:
                raise SyncError(f"unsupported field update type: {update.value_type}")
            mutations.append(
                f"u{index}: updateProjectV2ItemFieldValue(input: {{"
                f"projectId: $projectId, itemId: $item{index}, fieldId: $field{index}, "
                f"value: {value_expression}"
                "}) { projectV2Item { id } }"
            )
        query = f"mutation({', '.join(declarations)}) {{ {' '.join(mutations)} }}"
        graphql(query, variables, retries=3)
        print(
            f"updated field batch {batch_number}: {len(batch)} values",
            flush=True,
        )


def option_id(field: dict[str, Any], option_name: str) -> str:
    for option in field.get("options", []):
        if option.get("name") == option_name:
            return str(option["id"])
    raise SyncError(f"option {option_name!r} not found in field {field.get('name')!r}")


def normalize_field_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.casefold())


def item_field(item: dict[str, Any], field_name: str) -> Any:
    expected = normalize_field_name(field_name)
    for key, value in item.items():
        if normalize_field_name(str(key)) == expected:
            return value
    return None


def build_metadata_updates(
    tasks: Sequence[Task],
    item_ids: dict[str, str],
    existing_items: dict[str, dict[str, Any]],
    fields: dict[str, dict[str, Any]],
    newly_created: set[str],
) -> list[FieldUpdate]:
    updates: list[FieldUpdate] = []
    for task in tasks:
        item_id = item_ids[task.source_id]
        existing_item = existing_items.get(task.source_id)
        desired_fields = (
            ("Track", "single_select", task.track),
            ("Phase", "single_select", task.phase),
            ("Gate", "single_select", task.gate),
            ("Requires AWS", "single_select", task.requires_aws),
            ("Source ID", "text", task.source_id),
        )
        for field_name, value_type, desired_value in desired_fields:
            current_value = (
                item_field(existing_item, field_name)
                if existing_item is not None
                else None
            )
            if task.source_id not in newly_created and current_value == desired_value:
                continue
            remote_value = (
                option_id(fields[field_name], desired_value)
                if value_type == "single_select"
                else desired_value
            )
            updates.append(
                FieldUpdate(
                    item_id,
                    fields[field_name]["id"],
                    value_type,
                    remote_value,
                )
            )

        current_status = None
        metadata_complete = False
        if existing_item is not None:
            current_status = item_field(existing_item, "Status")
            metadata_complete = (
                item_field(existing_item, "Source ID") == task.source_id
            )
        if (
            task.source_id in newly_created
            or not metadata_complete
            or not current_status
            or (task.checked and current_status != "Done")
        ):
            updates.append(
                FieldUpdate(
                    item_id,
                    fields["Status"]["id"],
                    "single_select",
                    option_id(fields["Status"], task.initial_status),
                )
            )
    return updates


def command_plan(tasks: Sequence[Task]) -> int:
    track_counts = Counter(task.track for task in tasks)
    phase_counts = Counter(task.phase for task in tasks)
    print(f"tasks: {len(tasks)}")
    for track in TRACK_OPTIONS:
        print(f"  {track}: {track_counts[track]}")
    print("phases:")
    for phase in PHASE_OPTIONS:
        if phase_counts[phase]:
            print(f"  {phase}: {phase_counts[phase]}")
    print("sample:")
    for task in tasks[:3]:
        print(f"  {task.title}")
    return 0


def command_sync(
    tasks: Sequence[Task], owner: str, project_number: int, limit: int | None
) -> int:
    project = project_record(owner, project_number)
    fields = ensure_fields(owner, project_number)
    remote_items = list_items(owner, project_number)
    remote_index = indexed_items(remote_items)

    selected_tasks = list(tasks[:limit] if limit is not None else tasks)
    task_ids = {task.source_id for task in selected_tasks}
    all_source_ids = {task.source_id for task in tasks}
    unknown = sorted(
        source_id for source_id in remote_index if source_id not in all_source_ids
    )
    if unknown:
        raise SyncError(f"remote items have unknown Source IDs: {', '.join(unknown)}")

    changed_content = 0
    for task in selected_tasks:
        item = remote_index.get(task.source_id)
        if item is None:
            continue
        if item_title(item) != task.title or item_body(item) != task.body:
            update_draft_content(item_content_id(item), task)
            changed_content += 1

    missing_tasks = [task for task in selected_tasks if task.source_id not in remote_index]
    created = create_draft_items(str(project["id"]), missing_tasks) if missing_tasks else {}

    item_ids = {
        source_id: str(item["id"])
        for source_id, item in remote_index.items()
        if source_id in task_ids
    }
    item_ids.update(created)
    missing_ids = sorted(task_ids - set(item_ids))
    if missing_ids:
        raise SyncError(f"no Project item ID for: {', '.join(missing_ids)}")

    updates = build_metadata_updates(
        selected_tasks,
        item_ids,
        remote_index,
        fields,
        set(created),
    )
    update_fields(str(project["id"]), updates)
    print(
        f"SYNC COMPLETE: selected={len(selected_tasks)} created={len(created)} "
        f"content_updated={changed_content} field_updates={len(updates)}"
    )
    return 0


def command_audit(
    tasks: Sequence[Task],
    owner: str,
    project_number: int,
    expect_initial_status: bool,
) -> int:
    project_record(owner, project_number)
    ensure_fields(owner, project_number)
    items = list_items(owner, project_number)
    index = indexed_items(items)
    expected = {task.source_id: task for task in tasks}

    problems: list[str] = []
    missing = sorted(set(expected) - set(index))
    unknown = sorted(set(index) - set(expected))
    if missing:
        problems.append(f"missing Source IDs: {', '.join(missing)}")
    if unknown:
        problems.append(f"unknown Source IDs: {', '.join(unknown)}")

    statuses: Counter[str] = Counter()
    for source_id in sorted(set(expected) & set(index)):
        task = expected[source_id]
        item = index[source_id]
        status = item_field(item, "Status")
        statuses[str(status or "<unset>")] += 1
        checks = {
            "private DraftIssue type": item_content_type(item) == "DraftIssue",
            "title": item_title(item) == task.title,
            "body": item_body(item) == task.body,
            "Track": item_field(item, "Track") == task.track,
            "Phase": item_field(item, "Phase") == task.phase,
            "Gate": item_field(item, "Gate") == task.gate,
            "Requires AWS": item_field(item, "Requires AWS")
            == task.requires_aws,
            "Source ID": item_field(item, "Source ID") == task.source_id,
            "Status": status in STATUS_OPTIONS,
        }
        if expect_initial_status:
            checks["initial Status"] = status == task.initial_status
        failed = [name for name, passed in checks.items() if not passed]
        if failed:
            problems.append(f"{source_id}: invalid {', '.join(failed)}")

    if problems:
        for problem in problems:
            print(f"AUDIT FAIL: {problem}", file=sys.stderr)
        return 1

    print(
        f"AUDIT PASS: source_tasks={len(tasks)} project_items={len(index)} "
        f"project_total_items={len(items)}"
    )
    print("status:")
    for status in STATUS_OPTIONS:
        if statuses[status]:
            print(f"  {status}: {statuses[status]}")
    return 0


def command_set_status(
    tasks: Sequence[Task],
    owner: str,
    project_number: int,
    source_id: str,
    status: str,
) -> int:
    task_ids = {task.source_id for task in tasks}
    if source_id not in task_ids:
        raise SyncError(f"unknown source task: {source_id}")
    project = project_record(owner, project_number)
    fields = ensure_fields(owner, project_number)
    index = indexed_items(list_items(owner, project_number))
    if source_id not in index:
        raise SyncError(f"Project item is missing for {source_id}; run sync first")
    update_fields(
        str(project["id"]),
        [
            FieldUpdate(
                str(index[source_id]["id"]),
                fields["Status"]["id"],
                "single_select",
                option_id(fields["Status"], status),
            )
        ],
    )
    refreshed = indexed_items(list_items(owner, project_number))
    actual = item_field(refreshed[source_id], "Status")
    if actual != status:
        raise SyncError(f"status readback mismatch for {source_id}: {actual!r}")
    print(f"STATUS UPDATED: {source_id} -> {status}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default=DEFAULT_OWNER)
    parser.add_argument("--project-number", type=int, default=DEFAULT_PROJECT_NUMBER)
    parser.add_argument("--todo", type=Path, default=DEFAULT_TODO)
    parser.add_argument("--aws", type=Path, default=DEFAULT_AWS)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="parse local taskbooks without GitHub access")
    sync_parser = subparsers.add_parser("sync", help="create or update private draft items")
    sync_parser.add_argument(
        "--limit",
        type=int,
        help="synchronize only the first N tasks for a controlled pilot",
    )
    audit_parser = subparsers.add_parser(
        "audit", help="verify complete local-to-Project coverage"
    )
    audit_parser.add_argument(
        "--expect-initial-status",
        action="store_true",
        help="also require the initial status mapping used by the first import",
    )
    status_parser = subparsers.add_parser(
        "set-status", help="update one Project task status and verify readback"
    )
    status_parser.add_argument("source_id")
    status_parser.add_argument("status", choices=STATUS_OPTIONS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        tasks = load_tasks(args.todo, args.aws)
        if args.command == "plan":
            return command_plan(tasks)
        if args.command == "sync":
            if args.limit is not None and args.limit <= 0:
                raise SyncError("--limit must be greater than zero")
            return command_sync(tasks, args.owner, args.project_number, args.limit)
        if args.command == "audit":
            return command_audit(
                tasks,
                args.owner,
                args.project_number,
                args.expect_initial_status,
            )
        if args.command == "set-status":
            return command_set_status(
                tasks,
                args.owner,
                args.project_number,
                args.source_id,
                args.status,
            )
        raise SyncError(f"unsupported command: {args.command}")
    except SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
