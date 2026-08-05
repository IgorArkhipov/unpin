"""Isolated CLI and MCP state-transition scenarios for local provider matrix."""

from __future__ import annotations

import concurrent.futures
import json
import os
import pty
import select
import selectors
import subprocess
import time
from pathlib import Path
from typing import Any

from local_provider_matrix_support import (
    MATRIX,
    REPO_ROOT,
    MatrixFailure,
    copy_fixture_tree,
    digest_path,
    find_item,
    fixture_restore_command,
    fixture_subprocess_environment,
    fixture_toggle_command,
    parse_json_output,
    read_full_inventory,
    read_inventory,
    run_command,
    validate_audit,
    validate_fixture_temporary_root,
    validate_manifest,
    write_json,
)


def shared_source_contract(
    binary: Path,
    fixture_root: Path,
    app_state_root: Path,
    initial_item: dict[str, Any],
) -> dict[str, Any] | None:
    if initial_item.get("kind") != "skill":
        return None
    source_path = initial_item["sourcePath"]
    item_id = initial_item["id"]
    state_path = initial_item["statePath"]
    views = [
        item
        for item in read_full_inventory(binary, fixture_root, app_state_root)["items"]
        if item.get("sourcePath") == source_path
        and item.get("statePath") == state_path
        and item.get("id") != item_id
    ]
    if not views:
        return None
    return {
        "sourcePath": source_path,
        "statePath": state_path,
        "targetId": item_id,
        "counterpartStates": {
            item["id"]: bool(item["enabled"])
            for item in sorted(views, key=lambda item: item["id"])
        },
        "providers": sorted({item["provider"] for item in views}),
    }


def assert_shared_source_state(
    binary: Path,
    fixture_root: Path,
    app_state_root: Path,
    contract: dict[str, Any] | None,
    expected_enabled: bool,
    slug: str,
) -> None:
    if contract is None:
        return

    views = [
        item
        for item in read_full_inventory(binary, fixture_root, app_state_root)["items"]
        if item.get("sourcePath") == contract["sourcePath"]
        and item.get("statePath") == contract["statePath"]
        and item.get("id") != contract["targetId"]
    ]
    counterpart_states = {
        item["id"]: bool(item["enabled"])
        for item in sorted(views, key=lambda item: item["id"])
    }
    if counterpart_states.keys() != contract["counterpartStates"].keys():
        raise MatrixFailure(
            f"{slug} shared-source counterpart inventory changed: "
            f"expected {sorted(contract['counterpartStates'])}, "
            f"got {sorted(counterpart_states)}"
        )
    if any(enabled != expected_enabled for enabled in counterpart_states.values()):
        raise MatrixFailure(
            f"{slug} shared-source counterparts did not match enabled={expected_enabled}: "
            f"{counterpart_states}"
        )


class McpSession:
    def __init__(self, binary: Path, fixture_root: Path, app_state_root: Path) -> None:
        self.command = [
            str(binary),
            "mcp",
            "--fixture-root",
            str(fixture_root),
            "--home-root",
            str(fixture_root),
            "--project-root",
            str(fixture_root),
            "--app-state-root",
            str(app_state_root),
        ]
        self.process: subprocess.Popen[str] | None = None
        self.receipt: dict[str, Any] = {}

    def __enter__(self) -> McpSession:
        self.process = subprocess.Popen(
            self.command,
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=fixture_subprocess_environment(),
        )
        try:
            self._initialize()
        except Exception:
            self.close(check=False)
            raise
        return self

    def _initialize(self) -> None:
        initialized = self.request(
            "initialize",
            request_id="initialize",
            params={
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "unpin-local-matrix", "version": "1"},
            },
        )
        self.notify("notifications/initialized", {})
        tools = self.request("tools/list", request_id="tools-list")
        tool_names = [tool["name"] for tool in tools.get("tools", [])]
        required_tools = {
            "unpin_get_inventory_summary",
            "unpin_list_inventory_groups",
            "unpin_get_inventory_group",
            "unpin_plan_inventory_group",
            "unpin_plan_toggle_item",
            "unpin_apply_toggle_item",
            "unpin_restore_backup",
        }
        if initialized.get("serverInfo", {}).get("name") != "unpin":
            raise MatrixFailure("MCP initialize returned unexpected server identity")
        if not required_tools.issubset(tool_names):
            raise MatrixFailure("MCP tools/list omitted required matrix tools")
        if "unpin_apply_inventory_group" in tool_names:
            raise MatrixFailure(
                "default MCP tools/list exposed conditional inventory group apply"
            )
        self.receipt = {
            "server": initialized["serverInfo"]["name"],
            "protocolVersion": initialized.get("protocolVersion"),
            "toolsDiscovered": tool_names,
            "persistentSession": True,
        }

    def __exit__(self, error_type: Any, error: Any, traceback: Any) -> None:
        self.close(check=error_type is None)

    def _running_process(self) -> subprocess.Popen[str]:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise MatrixFailure("MCP session is not running")
        return self.process

    def _send(self, message: dict[str, Any]) -> None:
        process = self._running_process()
        process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        process.stdin.flush()

    def request(
        self,
        method: str,
        *,
        request_id: str,
        params: dict[str, Any] | None = None,
        timeout_seconds: float = 30,
    ) -> dict[str, Any]:
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            message["params"] = params
        self._send(message)

        process = self._running_process()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise MatrixFailure(
                        f"MCP request {method} timed out after {timeout_seconds}s"
                    )
                line = process.stdout.readline()
                if not line:
                    raise MatrixFailure(
                        f"MCP process exited before responding to {method}"
                    )
                response = json.loads(line)
                if response.get("id") != request_id:
                    continue
                if "error" in response:
                    raise MatrixFailure(f"MCP request {method} failed: {response['error']}")
                return response.get("result") or {}
        finally:
            selector.close()

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def call_tool(
        self, *, request_id: str, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        result = self.request(
            "tools/call",
            request_id=request_id,
            params={"name": name, "arguments": arguments},
        )
        return result["structuredContent"]

    def close(self, *, check: bool) -> None:
        if self.process is None:
            return
        process = self.process
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        try:
            return_code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            if check:
                raise MatrixFailure("MCP process did not exit after stdin closed")
            return
        if check and return_code != 0:
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise MatrixFailure(f"MCP process exited {return_code}: {stderr[-1000:]}")


def matrix_case_roots(
    artifact_root: Path,
    fixture_workspace_root: Path,
    directory: str,
    slug: str,
) -> tuple[Path, Path, Path]:
    case_root = artifact_root / directory / slug
    workspace_root = validate_fixture_temporary_root(
        fixture_workspace_root / directory / slug
    )
    fixture_root = validate_fixture_temporary_root(workspace_root / "fixtures")
    app_state_root = validate_fixture_temporary_root(workspace_root / "state")
    return case_root, fixture_root, app_state_root


def run_cli_scenario(
    binary: Path,
    artifact_root: Path,
    fixture_workspace_root: Path,
    scenario: dict[str, Any],
    canonical_fixture_digest: str,
) -> dict[str, Any]:
    case_root, fixture_root, app_state_root = matrix_case_roots(
        artifact_root,
        fixture_workspace_root,
        "cases",
        scenario["slug"],
    )
    copy_fixture_tree(fixture_root)
    app_state_root.mkdir(parents=True)

    before = read_inventory(binary, fixture_root, app_state_root, scenario)
    initial_item = find_item(before, scenario["id"])
    initial_enabled = bool(initial_item["enabled"])
    shared_contract = shared_source_contract(
        binary, fixture_root, app_state_root, initial_item
    )
    write_json(case_root / "00-inventory-before.json", before)

    no_write_fixture_digest = digest_path(fixture_root)
    no_write_app_state_digest = digest_path(app_state_root)
    plan_process = run_command(
        fixture_toggle_command(binary, fixture_root, app_state_root, scenario),
        check=shared_contract is None,
    )
    plan = parse_json_output(plan_process.stdout)
    write_json(case_root / "01-plan.json", plan)
    if shared_contract is None:
        if plan.get("status") not in {"dry-run", "planned"}:
            raise MatrixFailure(f"{scenario['slug']} dry run did not plan")
    elif (
        plan_process.returncode == 0
        or plan.get("status") != "blocked"
        or "shared-source-crosses-provider-reach" not in json.dumps(plan, sort_keys=True)
    ):
        raise MatrixFailure(
            f"{scenario['slug']} did not block a shared source outside provider reach"
        )
    if (
        digest_path(fixture_root) != canonical_fixture_digest
        or digest_path(fixture_root) != no_write_fixture_digest
        or digest_path(app_state_root) != no_write_app_state_digest
    ):
        raise MatrixFailure(f"{scenario['slug']} dry run changed fixtures")
    if (app_state_root / "backups").exists():
        raise MatrixFailure(f"{scenario['slug']} dry run created a backup")

    if shared_contract is not None:
        result = {
            **scenario,
            "status": "passed",
            "states": {"initial": initial_enabled, "final": initial_enabled},
            "operationTypes": [],
            "backupAuthentication": [],
            "auditEvents": {},
            "fixtureDigestRestored": True,
            "sharedSourceFanout": {
                "asserted": True,
                "providers": shared_contract["providers"],
                "blockedBeforeWrite": True,
            },
        }
        write_json(case_root / "summary.json", result)
        return result

    first = parse_json_output(
        run_command(
            fixture_toggle_command(
                binary,
                fixture_root,
                app_state_root,
                scenario,
                plan_fingerprint=plan["planFingerprint"],
            )
        ).stdout
    )
    write_json(case_root / "02-apply-first.json", first)
    if first.get("status") != "applied":
        raise MatrixFailure(f"{scenario['slug']} first apply failed: {first}")
    first_backup = first["backupId"]

    after_first = read_inventory(binary, fixture_root, app_state_root, scenario)
    after_first_enabled = bool(find_item(after_first, scenario["id"])["enabled"])
    write_json(case_root / "03-inventory-after-first.json", after_first)
    if after_first_enabled == initial_enabled:
        raise MatrixFailure(f"{scenario['slug']} first apply did not invert state")

    second_plan = parse_json_output(
        run_command(
            fixture_toggle_command(binary, fixture_root, app_state_root, scenario)
        ).stdout
    )
    write_json(case_root / "04-plan-second.json", second_plan)
    second = parse_json_output(
        run_command(
            fixture_toggle_command(
                binary,
                fixture_root,
                app_state_root,
                scenario,
                plan_fingerprint=second_plan["planFingerprint"],
            )
        ).stdout
    )
    write_json(case_root / "05-apply-second.json", second)
    if second.get("status") != "applied":
        raise MatrixFailure(f"{scenario['slug']} second apply failed: {second}")
    second_backup = second["backupId"]

    after_second = read_inventory(binary, fixture_root, app_state_root, scenario)
    after_second_enabled = bool(find_item(after_second, scenario["id"])["enabled"])
    write_json(case_root / "06-inventory-after-second.json", after_second)
    if after_second_enabled != initial_enabled:
        raise MatrixFailure(f"{scenario['slug']} second apply did not restore initial state")

    restore_second_plan = parse_json_output(
        run_command(
            fixture_restore_command(
                binary, fixture_root, app_state_root, second_backup
            )
        ).stdout
    )
    write_json(case_root / "07-plan-restore-second.json", restore_second_plan)
    restore_second = parse_json_output(
        run_command(
            fixture_restore_command(
                binary,
                fixture_root,
                app_state_root,
                second_backup,
                plan_fingerprint=restore_second_plan["plan"]["planFingerprint"],
            )
        ).stdout
    )
    write_json(case_root / "08-restore-second.json", restore_second)
    if restore_second.get("status") != "restored":
        raise MatrixFailure(f"{scenario['slug']} second backup restore failed")

    after_restore_second = read_inventory(
        binary, fixture_root, app_state_root, scenario
    )
    after_restore_second_enabled = bool(
        find_item(after_restore_second, scenario["id"])["enabled"]
    )
    write_json(case_root / "09-inventory-after-restore-second.json", after_restore_second)
    if after_restore_second_enabled == initial_enabled:
        raise MatrixFailure(f"{scenario['slug']} second backup did not restore inverse state")

    restore_first_plan = parse_json_output(
        run_command(
            fixture_restore_command(
                binary, fixture_root, app_state_root, first_backup
            )
        ).stdout
    )
    write_json(case_root / "10-plan-restore-first.json", restore_first_plan)
    restore_first = parse_json_output(
        run_command(
            fixture_restore_command(
                binary,
                fixture_root,
                app_state_root,
                first_backup,
                plan_fingerprint=restore_first_plan["plan"]["planFingerprint"],
            )
        ).stdout
    )
    write_json(case_root / "11-restore-first.json", restore_first)
    if restore_first.get("status") != "restored":
        raise MatrixFailure(f"{scenario['slug']} first backup restore failed")

    final_inventory = read_inventory(binary, fixture_root, app_state_root, scenario)
    final_enabled = bool(find_item(final_inventory, scenario["id"])["enabled"])
    write_json(case_root / "12-inventory-final.json", final_inventory)
    final_digest = digest_path(fixture_root)
    if final_enabled != initial_enabled or final_digest != canonical_fixture_digest:
        raise MatrixFailure(f"{scenario['slug']} did not recover byte-exact initial state")

    result = {
        **scenario,
        "status": "passed",
        "states": {
            "initial": initial_enabled,
            "afterFirstToggle": after_first_enabled,
            "afterSecondToggle": after_second_enabled,
            "afterRestoreSecond": after_restore_second_enabled,
            "final": final_enabled,
        },
        "operationTypes": sorted(
            {operation["type"] for operation in first.get("operations", [])}
        ),
        "backupAuthentication": [
            validate_manifest(app_state_root, first_backup),
            validate_manifest(app_state_root, second_backup),
        ],
        "auditEvents": validate_audit(app_state_root),
        "fixtureDigestRestored": True,
        "sharedSourceFanout": {
            "asserted": shared_contract is not None,
            "providers": shared_contract["providers"] if shared_contract else [],
        },
    }
    write_json(case_root / "summary.json", result)
    return result


def mcp_call(
    session: McpSession,
    *,
    request_id: str,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    return session.call_tool(request_id=request_id, name=name, arguments=arguments)


def matrix_inventory_group_name(scenario: dict[str, Any]) -> str:
    sanitized = "".join(
        character if character.isascii() and (character.isalnum() or character == "-") else "-"
        for character in str(scenario["slug"]).lower()
    ).strip("-")
    sanitized = sanitized[:50].rstrip("-")
    if not sanitized:
        raise MatrixFailure("matrix scenario slug cannot form an inventory group name")
    return f"matrix-{sanitized}"


def inventory_group_member_selector(item: dict[str, Any]) -> str:
    fields = ("provider", "layer", "kind", "category", "id")
    values = [item.get(field) for field in fields]
    if not all(isinstance(value, str) and value for value in values):
        raise MatrixFailure(
            "inventory group matrix member is missing a full provider/layer/kind/category/id identity"
        )
    return ":".join(values)


def matrix_inventory_group_members(
    inventory: dict[str, Any],
    scenario: dict[str, Any],
) -> list[dict[str, Any]]:
    target = find_item(inventory, scenario["id"])
    if target.get("kind") != "skill":
        return [target]
    shared_views = [
        item
        for item in inventory["items"]
        if item.get("kind") == "skill"
        and item.get("sourcePath") == target.get("sourcePath")
    ]
    return shared_views or [target]


def create_matrix_inventory_group(
    binary: Path,
    case_root: Path,
    fixture_root: Path,
    app_state_root: Path,
    scenario: dict[str, Any],
) -> str:
    group_name = matrix_inventory_group_name(scenario)
    qualified_name = f"personal:{group_name}"
    inventory = read_full_inventory(binary, fixture_root, app_state_root)
    members = matrix_inventory_group_members(inventory, scenario)
    command = [
        str(binary),
        "group",
        "create",
        "--fixture-root",
        str(fixture_root),
        "--home-root",
        str(fixture_root),
        "--project-root",
        str(fixture_root),
        "--app-state-root",
        str(app_state_root),
        "--scope",
        "personal",
        "--name",
        group_name,
    ]
    for item in members:
        command.extend(["--member", inventory_group_member_selector(item)])
    command.append("--json")

    preview = parse_json_output(run_command(command).stdout)
    write_json(case_root / "00-group-create-preview.json", preview)
    if preview.get("status") != "planned" or not preview.get("planFingerprint"):
        raise MatrixFailure(
            f"{scenario['slug']} inventory group definition did not produce a reviewable preview"
        )
    applied = parse_json_output(
        run_command(
            [
                *command,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                preview["planFingerprint"],
            ]
        ).stdout
    )
    write_json(case_root / "00-group-create-apply.json", applied)
    if (
        applied.get("status") != "created"
        or applied.get("result", {}).get("qualifiedName") != qualified_name
    ):
        raise MatrixFailure(
            f"{scenario['slug']} inventory group definition was not created"
        )
    return qualified_name


def run_mcp_scenario(
    binary: Path,
    artifact_root: Path,
    fixture_workspace_root: Path,
    scenario: dict[str, Any],
    canonical_fixture_digest: str,
) -> dict[str, Any]:
    case_root, fixture_root, app_state_root = matrix_case_roots(
        artifact_root,
        fixture_workspace_root,
        "mcp-cases",
        scenario["slug"],
    )
    copy_fixture_tree(fixture_root)
    app_state_root.mkdir(parents=True)

    inventory_group = create_matrix_inventory_group(
        binary,
        case_root,
        fixture_root,
        app_state_root,
        scenario,
    )
    with McpSession(binary, fixture_root, app_state_root) as session:
        write_json(case_root / "00-protocol.json", session.receipt)
        return run_mcp_session(
            session,
            binary,
            case_root,
            fixture_root,
            app_state_root,
            scenario,
            canonical_fixture_digest,
            inventory_group,
        )


def run_mcp_session(
    session: McpSession,
    binary: Path,
    case_root: Path,
    fixture_root: Path,
    app_state_root: Path,
    scenario: dict[str, Any],
    canonical_fixture_digest: str,
    inventory_group: str,
) -> dict[str, Any]:

    initial_inventory = read_inventory(binary, fixture_root, app_state_root, scenario)
    initial_item = find_item(initial_inventory, scenario["id"])
    initial_enabled = bool(initial_item["enabled"])
    shared_contract = shared_source_contract(
        binary, fixture_root, app_state_root, initial_item
    )
    target_enabled = not initial_enabled

    summary = mcp_call(
        session,
        request_id="summary",
        name="unpin_get_inventory_summary",
        arguments={},
    )
    write_json(case_root / "00-write-safety.json", summary)
    if (
        summary["writeSafety"]["writesEnabled"] is not False
        or summary["writeSafety"].get("humanApproval") != "cli-or-tui-required"
    ):
        raise MatrixFailure(
            f"{scenario['slug']} MCP did not preserve CLI/TUI human approval boundary"
        )

    if shared_contract is not None:
        selection = {
            "provider": scenario["provider"],
            "kind": scenario["kind"],
            "layer": scenario["layer"],
            "id": scenario["id"],
            "targetEnabled": target_enabled,
        }
        no_write_fixture_digest = digest_path(fixture_root)
        no_write_app_state_digest = digest_path(app_state_root)
        plan = mcp_call(
            session,
            request_id="plan-shared-source",
            name="unpin_plan_toggle_item",
            arguments=selection,
        )
        write_json(case_root / "01-plan.json", plan)
        if (
            plan.get("status") != "blocked"
            or "shared-source-crosses-provider-reach"
            not in json.dumps(plan, sort_keys=True)
            or digest_path(fixture_root) != canonical_fixture_digest
            or digest_path(fixture_root) != no_write_fixture_digest
            or digest_path(app_state_root) != no_write_app_state_digest
            or (app_state_root / "backups").exists()
        ):
            raise MatrixFailure(
                f"{scenario['slug']} MCP did not block shared source before writes"
            )
        result = {
            **scenario,
            "status": "passed",
            "confirmationBlocked": True,
            "states": {"initial": initial_enabled, "final": initial_enabled},
            "backupAuthentication": [],
            "auditEvents": {},
            "fixtureDigestRestored": True,
            "sharedSourceFanout": {
                "asserted": True,
                "providers": shared_contract["providers"],
                "blockedBeforeWrite": True,
            },
        }
        write_json(case_root / "summary.json", result)
        return result

    no_write_group_fixture_digest = digest_path(fixture_root)
    no_write_group_app_state_digest = digest_path(app_state_root)
    group_list = mcp_call(
        session,
        request_id="inventory-group-list",
        name="unpin_list_inventory_groups",
        arguments={},
    )
    write_json(case_root / "00-inventory-group-list.json", group_list)
    listed_names = {
        group.get("qualifiedName") for group in group_list.get("groups", [])
    }
    if (
        group_list.get("status") != "ok"
        or inventory_group not in listed_names
    ):
        raise MatrixFailure(
            f"{scenario['slug']} MCP inventory group list omitted {inventory_group}"
        )

    group_get = mcp_call(
        session,
        request_id="inventory-group-get",
        name="unpin_get_inventory_group",
        arguments={"group": inventory_group},
    )
    write_json(case_root / "00-inventory-group-get.json", group_get)
    if (
        group_get.get("status") != "ok"
        or group_get.get("group", {}).get("qualifiedName") != inventory_group
    ):
        raise MatrixFailure(
            f"{scenario['slug']} MCP inventory group get returned the wrong definition"
        )

    group_plan = mcp_call(
        session,
        request_id="inventory-group-plan",
        name="unpin_plan_inventory_group",
        arguments={
            "group": inventory_group,
            "targetEnabled": target_enabled,
            "maxMembers": 256,
            "providerReach": {
                "mode": "selected",
                "provider": scenario["provider"],
            },
        },
    )
    write_json(case_root / "01-inventory-group-plan.json", group_plan)
    inspected_member_keys = {
        inventory_group_member_selector(member["identity"])
        for member in group_get.get("group", {}).get("members", [])
    }
    planned_members = group_plan.get("plan", {}).get("members", [])
    planned_member_keys = {
        inventory_group_member_selector(member["identity"])
        for member in planned_members
    }
    if (
        group_plan.get("status") != "preview"
        or group_plan.get("plan", {}).get("disposition") != "preview"
        or group_plan.get("plan", {}).get("mode") != "preview-only"
        or not planned_members
        or planned_member_keys != inspected_member_keys
        or not any(member.get("outcome") == "changed" for member in planned_members)
        or any(
            member.get("outcome")
            not in {"changed", "already-correct", "out-of-provider-reach"}
            or member.get("requestedEnabled") != target_enabled
            for member in planned_members
        )
        or group_plan.get("challenge") is not None
        or group_plan.get("operationId") is not None
        or group_plan.get("plan", {}).get("operationId") is not None
        or digest_path(fixture_root) != no_write_group_fixture_digest
        or digest_path(app_state_root) != no_write_group_app_state_digest
    ):
        raise MatrixFailure(
            f"{scenario['slug']} MCP inventory group plan was not a read-only preview"
        )

    selection = {
        "provider": scenario["provider"],
        "kind": scenario["kind"],
        "layer": scenario["layer"],
        "id": scenario["id"],
        "targetEnabled": target_enabled,
    }
    no_write_fixture_digest = digest_path(fixture_root)
    no_write_app_state_digest = digest_path(app_state_root)
    plan = mcp_call(
        session,
        request_id="plan",
        name="unpin_plan_toggle_item",
        arguments=selection,
    )
    write_json(case_root / "01-plan.json", plan)
    if (
        plan.get("status") != "planned"
        or digest_path(fixture_root) != canonical_fixture_digest
        or digest_path(fixture_root) != no_write_fixture_digest
        or digest_path(app_state_root) != no_write_app_state_digest
    ):
        raise MatrixFailure(f"{scenario['slug']} MCP plan was not a no-write plan")

    unconfirmed = mcp_call(
        session,
        request_id="unconfirmed",
        name="unpin_apply_toggle_item",
        arguments=selection,
    )
    write_json(case_root / "02-unconfirmed-apply.json", unconfirmed)
    if (
        unconfirmed.get("status") != "blocked"
        or "plan fingerprint" not in unconfirmed.get("reason", "")
        or digest_path(fixture_root) != no_write_fixture_digest
        or digest_path(app_state_root) != no_write_app_state_digest
    ):
        raise MatrixFailure(f"{scenario['slug']} MCP apply skipped review gate")

    reviewed_selection = {**selection, "planFingerprint": plan["planFingerprint"]}
    first_handoff = mcp_call(
        session,
        request_id="handoff-first",
        name="unpin_apply_toggle_item",
        arguments=reviewed_selection,
    )
    write_json(case_root / "03-handoff-first.json", first_handoff)
    if (
        first_handoff.get("status") != "human-action-required"
        or first_handoff.get("operation", {}).get("lifecycle")
        != "awaiting-human-action"
        or digest_path(fixture_root) != no_write_fixture_digest
        # A handoff persists its durable operation state under app_state_root,
        # but must not create a provider backup before the CLI/TUI approves it.
        or first_handoff.get("backupId") is not None
    ):
        raise MatrixFailure(
            f"{scenario['slug']} MCP first handoff changed provider state or created a backup"
        )

    first = parse_json_output(
        run_command(
            fixture_toggle_command(
                binary,
                fixture_root,
                app_state_root,
                scenario,
                plan_fingerprint=plan["planFingerprint"],
            )
        ).stdout
    )
    write_json(case_root / "04-cli-apply-first.json", first)
    if first.get("status") != "applied":
        raise MatrixFailure(f"{scenario['slug']} MCP first handoff apply failed")
    first_backup = first["backupId"]
    after_first_enabled = bool(
        find_item(
            read_inventory(binary, fixture_root, app_state_root, scenario),
            scenario["id"],
        )["enabled"]
    )
    if after_first_enabled != target_enabled:
        raise MatrixFailure(f"{scenario['slug']} MCP first apply state mismatch")
    assert_shared_source_state(
        binary,
        fixture_root,
        app_state_root,
        shared_contract,
        after_first_enabled,
        scenario["slug"],
    )

    second_selection = {**selection, "targetEnabled": initial_enabled}
    second_plan = mcp_call(
        session,
        request_id="plan-second",
        name="unpin_plan_toggle_item",
        arguments=second_selection,
    )
    write_json(case_root / "05-plan-second.json", second_plan)
    second_handoff = mcp_call(
        session,
        request_id="handoff-second",
        name="unpin_apply_toggle_item",
        arguments={
            **second_selection,
            "planFingerprint": second_plan["planFingerprint"],
        },
    )
    write_json(case_root / "06-handoff-second.json", second_handoff)
    if second_handoff.get("status") != "human-action-required":
        raise MatrixFailure(f"{scenario['slug']} MCP second handoff failed")
    second = parse_json_output(
        run_command(
            fixture_toggle_command(
                binary,
                fixture_root,
                app_state_root,
                scenario,
                plan_fingerprint=second_plan["planFingerprint"],
            )
        ).stdout
    )
    write_json(case_root / "07-cli-apply-second.json", second)
    if second.get("status") != "applied":
        raise MatrixFailure(f"{scenario['slug']} MCP second handoff apply failed")
    second_backup = second["backupId"]
    after_second_inventory = read_inventory(
        binary, fixture_root, app_state_root, scenario
    )
    write_json(case_root / "08-inventory-after-second.json", after_second_inventory)
    after_second_enabled = bool(
        find_item(after_second_inventory, scenario["id"])["enabled"]
    )
    if after_second_enabled != initial_enabled:
        raise MatrixFailure(f"{scenario['slug']} MCP second apply state mismatch")
    assert_shared_source_state(
        binary,
        fixture_root,
        app_state_root,
        shared_contract,
        after_second_enabled,
        scenario["slug"],
    )

    before_restore_plan = {
        "fixture": digest_path(fixture_root),
        "appState": digest_path(app_state_root),
    }
    restore_second_plan = mcp_call(
        session,
        request_id="plan-restore-second",
        name="unpin_restore_backup",
        arguments={"backupId": second_backup},
    )
    write_json(case_root / "09-plan-restore-second.json", restore_second_plan)
    if (
        restore_second_plan.get("status") != "planned"
        or digest_path(fixture_root) != before_restore_plan["fixture"]
        or digest_path(app_state_root) != before_restore_plan["appState"]
    ):
        raise MatrixFailure(f"{scenario['slug']} MCP restore plan wrote state")

    restore_second_handoff = mcp_call(
        session,
        request_id="handoff-restore-second",
        name="unpin_restore_backup",
        arguments={
            "backupId": second_backup,
            "planFingerprint": restore_second_plan["planFingerprint"],
        },
    )
    write_json(case_root / "10-handoff-restore-second.json", restore_second_handoff)
    if (
        restore_second_handoff.get("status") != "human-action-required"
        or digest_path(fixture_root) != before_restore_plan["fixture"]
        or digest_path(app_state_root) != before_restore_plan["appState"]
    ):
        raise MatrixFailure(f"{scenario['slug']} MCP restore handoff wrote state")
    restore_second = parse_json_output(
        run_command(
            fixture_restore_command(
                binary,
                fixture_root,
                app_state_root,
                second_backup,
                plan_fingerprint=restore_second_plan["planFingerprint"],
            )
        ).stdout
    )
    write_json(case_root / "11-cli-restore-second.json", restore_second)
    if restore_second.get("status") != "restored":
        raise MatrixFailure(f"{scenario['slug']} MCP second backup restore failed")
    after_restore_second = bool(
        find_item(
            read_inventory(binary, fixture_root, app_state_root, scenario),
            scenario["id"],
        )["enabled"]
    )
    if after_restore_second != target_enabled:
        raise MatrixFailure(f"{scenario['slug']} MCP restored wrong intermediate state")
    assert_shared_source_state(
        binary,
        fixture_root,
        app_state_root,
        shared_contract,
        after_restore_second,
        scenario["slug"],
    )

    restore_first_plan = mcp_call(
        session,
        request_id="plan-restore-first",
        name="unpin_restore_backup",
        arguments={"backupId": first_backup},
    )
    write_json(case_root / "12-plan-restore-first.json", restore_first_plan)
    restore_first_handoff = mcp_call(
        session,
        request_id="handoff-restore-first",
        name="unpin_restore_backup",
        arguments={
            "backupId": first_backup,
            "planFingerprint": restore_first_plan["planFingerprint"],
        },
    )
    write_json(case_root / "13-handoff-restore-first.json", restore_first_handoff)
    if restore_first_handoff.get("status") != "human-action-required":
        raise MatrixFailure(f"{scenario['slug']} MCP first restore handoff failed")
    restore_first = parse_json_output(
        run_command(
            fixture_restore_command(
                binary,
                fixture_root,
                app_state_root,
                first_backup,
                plan_fingerprint=restore_first_plan["planFingerprint"],
            )
        ).stdout
    )
    write_json(case_root / "14-cli-restore-first.json", restore_first)
    if restore_first.get("status") != "restored":
        raise MatrixFailure(f"{scenario['slug']} MCP first backup restore failed")
    final_enabled = bool(
        find_item(
            read_inventory(binary, fixture_root, app_state_root, scenario),
            scenario["id"],
        )["enabled"]
    )
    if (
        final_enabled != initial_enabled
        or digest_path(fixture_root) != canonical_fixture_digest
    ):
        raise MatrixFailure(f"{scenario['slug']} MCP cycle did not recover initial state")
    assert_shared_source_state(
        binary,
        fixture_root,
        app_state_root,
        shared_contract,
        final_enabled,
        scenario["slug"],
    )

    result = {
        **scenario,
        "status": "passed",
        "unreviewedApplyBlocked": True,
        "humanActionHandoff": True,
        "states": {
            "initial": initial_enabled,
            "afterFirstToggle": after_first_enabled,
            "afterSecondToggle": after_second_enabled,
            "afterRestoreSecond": after_restore_second,
            "final": final_enabled,
        },
        "mcpWritesEnabled": False,
        "inventoryGroupPreview": True,
        "inventoryGroupQualifiedName": inventory_group,
        "inventoryGroupProvider": scenario["provider"],
        "fixtureDigestRestored": True,
        "backupAuthentication": [
            validate_manifest(app_state_root, first_backup),
            validate_manifest(app_state_root, second_backup),
        ],
        "auditEvents": validate_audit(app_state_root),
        "sharedSourceFanout": {
            "asserted": shared_contract is not None,
            "providers": shared_contract["providers"] if shared_contract else [],
        },
    }
    write_json(case_root / "summary.json", result)
    return result


def drain_pty(master_fd: int, timeout_seconds: float, transcript: bytearray) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        readable, _, _ = select.select([master_fd], [], [], remaining)
        if not readable:
            return
        try:
            chunk = os.read(master_fd, 65536)
        except OSError:
            return
        if not chunk:
            return
        transcript.extend(chunk)
        if len(transcript) > 262144:
            del transcript[:-131072]


def drive_tui_toggle(
    binary: Path,
    fixture_root: Path,
    app_state_root: Path,
    item_id: str,
    *,
    confirm: bool,
) -> None:
    master_fd, slave_fd = pty.openpty()
    environment = fixture_subprocess_environment()
    environment.setdefault("TERM", "xterm-256color")
    process = subprocess.Popen(
        [
            str(binary),
            "tui",
            "--fixture-root",
            str(fixture_root),
            "--app-state-root",
            str(app_state_root),
        ],
        cwd=REPO_ROOT,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=environment,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave_fd)
    transcript = bytearray()
    try:
        drain_pty(master_fd, 0.35, transcript)
        actions = [b"/", item_id.encode("utf-8"), b"\r", b" "]
        actions.extend([b"\r", b"a"] if confirm else [b"a"])
        actions.append(b"q")
        for action in actions:
            if process.poll() is not None:
                break
            os.write(master_fd, action)
            drain_pty(master_fd, 0.15 if action != b"a" else 0.5, transcript)
        try:
            return_code = process.wait(timeout=20)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait(timeout=5)
            raise MatrixFailure("interactive TUI did not exit after scripted actions") from error
        drain_pty(master_fd, 0.05, transcript)
        if return_code != 0:
            tail = transcript[-2000:].decode("utf-8", errors="replace")
            raise MatrixFailure(f"interactive TUI exited {return_code}: {tail}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master_fd)


def backup_ids(app_state_root: Path) -> set[str]:
    root = app_state_root / "backups"
    if not root.is_dir():
        return set()
    return {path.name for path in root.iterdir() if path.is_dir()}


def durable_app_state_snapshot(app_state_root: Path) -> dict[str, str]:
    if not app_state_root.is_dir():
        return {}
    return {
        path.name: digest_path(path)
        for path in sorted(app_state_root.iterdir(), key=lambda item: item.name)
        if path.name not in {"locks", "runtime"}
    }


def new_backup_id(before: set[str], app_state_root: Path, slug: str) -> str:
    created = backup_ids(app_state_root) - before
    if len(created) != 1:
        raise MatrixFailure(f"{slug} TUI expected one new backup, got {sorted(created)}")
    return created.pop()


def run_tui_scenario(
    binary: Path,
    artifact_root: Path,
    fixture_workspace_root: Path,
    scenario: dict[str, Any],
    canonical_fixture_digest: str,
) -> dict[str, Any]:
    case_root, fixture_root, app_state_root = matrix_case_roots(
        artifact_root,
        fixture_workspace_root,
        "tui-cases",
        scenario["slug"],
    )
    copy_fixture_tree(fixture_root)
    app_state_root.mkdir(parents=True)

    before = read_inventory(binary, fixture_root, app_state_root, scenario)
    initial_item = find_item(before, scenario["id"])
    initial_enabled = bool(initial_item["enabled"])
    shared_contract = shared_source_contract(
        binary, fixture_root, app_state_root, initial_item
    )
    write_json(case_root / "00-inventory-before.json", before)

    no_write_fixture_digest = digest_path(fixture_root)
    no_write_app_state = durable_app_state_snapshot(app_state_root)
    drive_tui_toggle(
        binary,
        fixture_root,
        app_state_root,
        scenario["id"],
        confirm=False,
    )
    if (
        digest_path(fixture_root) != no_write_fixture_digest
        or durable_app_state_snapshot(app_state_root) != no_write_app_state
        or backup_ids(app_state_root)
    ):
        raise MatrixFailure(f"{scenario['slug']} TUI applied without confirmation")

    if shared_contract is not None:
        no_write_fixture_digest = digest_path(fixture_root)
        no_write_app_state = durable_app_state_snapshot(app_state_root)
        drive_tui_toggle(
            binary,
            fixture_root,
            app_state_root,
            scenario["id"],
            confirm=True,
        )
        after_blocked = read_inventory(binary, fixture_root, app_state_root, scenario)
        write_json(case_root / "01-inventory-after-blocked.json", after_blocked)
        if (
            bool(find_item(after_blocked, scenario["id"])["enabled"])
            != initial_enabled
            or digest_path(fixture_root) != canonical_fixture_digest
            or digest_path(fixture_root) != no_write_fixture_digest
            or durable_app_state_snapshot(app_state_root) != no_write_app_state
            or backup_ids(app_state_root)
        ):
            raise MatrixFailure(
                f"{scenario['slug']} TUI did not block shared source before writes"
            )
        result = {
            **scenario,
            "status": "passed",
            "confirmationBlocked": True,
            "states": {"initial": initial_enabled, "final": initial_enabled},
            "backupAuthentication": [],
            "auditEvents": {},
            "fixtureDigestRestored": True,
            "sharedSourceFanout": {
                "asserted": True,
                "providers": shared_contract["providers"],
                "blockedBeforeWrite": True,
            },
        }
        write_json(case_root / "summary.json", result)
        return result

    before_first_backups = backup_ids(app_state_root)
    drive_tui_toggle(
        binary,
        fixture_root,
        app_state_root,
        scenario["id"],
        confirm=True,
    )
    first_backup = new_backup_id(before_first_backups, app_state_root, scenario["slug"])
    after_first = read_inventory(binary, fixture_root, app_state_root, scenario)
    after_first_enabled = bool(find_item(after_first, scenario["id"])["enabled"])
    write_json(case_root / "01-inventory-after-first.json", after_first)
    if after_first_enabled == initial_enabled:
        raise MatrixFailure(f"{scenario['slug']} TUI first apply did not invert state")
    assert_shared_source_state(
        binary,
        fixture_root,
        app_state_root,
        shared_contract,
        after_first_enabled,
        scenario["slug"],
    )

    before_second_backups = backup_ids(app_state_root)
    drive_tui_toggle(
        binary,
        fixture_root,
        app_state_root,
        scenario["id"],
        confirm=True,
    )
    second_backup = new_backup_id(before_second_backups, app_state_root, scenario["slug"])
    after_second = read_inventory(binary, fixture_root, app_state_root, scenario)
    after_second_enabled = bool(find_item(after_second, scenario["id"])["enabled"])
    write_json(case_root / "02-inventory-after-second.json", after_second)
    if after_second_enabled != initial_enabled:
        raise MatrixFailure(f"{scenario['slug']} TUI second apply did not restore state")
    assert_shared_source_state(
        binary,
        fixture_root,
        app_state_root,
        shared_contract,
        after_second_enabled,
        scenario["slug"],
    )

    restore_second_plan = parse_json_output(
        run_command(
            fixture_restore_command(
                binary, fixture_root, app_state_root, second_backup
            )
        ).stdout
    )
    restore_second = parse_json_output(
        run_command(
            fixture_restore_command(
                binary,
                fixture_root,
                app_state_root,
                second_backup,
                plan_fingerprint=restore_second_plan["plan"]["planFingerprint"],
            )
        ).stdout
    )
    if restore_second.get("status") != "restored":
        raise MatrixFailure(f"{scenario['slug']} TUI second backup restore failed")
    after_restore_second = read_inventory(
        binary, fixture_root, app_state_root, scenario
    )
    after_restore_second_enabled = bool(
        find_item(after_restore_second, scenario["id"])["enabled"]
    )
    if after_restore_second_enabled == initial_enabled:
        raise MatrixFailure(f"{scenario['slug']} TUI restored wrong intermediate state")
    assert_shared_source_state(
        binary,
        fixture_root,
        app_state_root,
        shared_contract,
        after_restore_second_enabled,
        scenario["slug"],
    )

    restore_first_plan = parse_json_output(
        run_command(
            fixture_restore_command(
                binary, fixture_root, app_state_root, first_backup
            )
        ).stdout
    )
    restore_first = parse_json_output(
        run_command(
            fixture_restore_command(
                binary,
                fixture_root,
                app_state_root,
                first_backup,
                plan_fingerprint=restore_first_plan["plan"]["planFingerprint"],
            )
        ).stdout
    )
    if restore_first.get("status") != "restored":
        raise MatrixFailure(f"{scenario['slug']} TUI first backup restore failed")
    final_inventory = read_inventory(binary, fixture_root, app_state_root, scenario)
    final_enabled = bool(find_item(final_inventory, scenario["id"])["enabled"])
    write_json(case_root / "03-inventory-final.json", final_inventory)
    if (
        final_enabled != initial_enabled
        or digest_path(fixture_root) != canonical_fixture_digest
    ):
        raise MatrixFailure(f"{scenario['slug']} TUI cycle did not recover initial state")
    assert_shared_source_state(
        binary,
        fixture_root,
        app_state_root,
        shared_contract,
        final_enabled,
        scenario["slug"],
    )

    result = {
        **scenario,
        "status": "passed",
        "confirmationBlocked": True,
        "states": {
            "initial": initial_enabled,
            "afterFirstToggle": after_first_enabled,
            "afterSecondToggle": after_second_enabled,
            "afterRestoreSecond": after_restore_second_enabled,
            "final": final_enabled,
        },
        "backupAuthentication": [
            validate_manifest(app_state_root, first_backup),
            validate_manifest(app_state_root, second_backup),
        ],
        "auditEvents": validate_audit(app_state_root),
        "fixtureDigestRestored": True,
        "sharedSourceFanout": {
            "asserted": shared_contract is not None,
            "providers": shared_contract["providers"] if shared_contract else [],
        },
    }
    write_json(case_root / "summary.json", result)
    return result


def run_matrix_cases(
    worker: Any,
    binary: Path,
    artifact_root: Path,
    fixture_workspace_root: Path,
    canonical_fixture_digest: str,
) -> list[dict[str, Any]]:
    worker_count = min(4, len(MATRIX))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        return list(
            executor.map(
                lambda scenario: worker(
                    binary,
                    artifact_root,
                    fixture_workspace_root,
                    scenario,
                    canonical_fixture_digest,
                ),
                MATRIX,
            )
        )
