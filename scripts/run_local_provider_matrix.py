#!/usr/bin/env python3
"""Run Unpin's local provider matrix without mutating live provider state."""

from __future__ import annotations

import collections
import datetime as dt
import html
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from local_provider_matrix_cases import (
    run_cli_scenario,
    run_matrix_cases,
    run_mcp_scenario,
    run_tui_scenario,
)
from local_provider_matrix_finalize import (
    finalize_artifacts,
    tighten_artifact_permissions,
    workspace_identity,
)
from local_provider_matrix_support import (
    DECLARED_EXCEPTIONS,
    FIXTURE_ROOT,
    MATRIX,
    REPO_ROOT,
    SCREENSHOTS,
    MatrixCommandTimeout,
    MatrixFailure,
    digest_path,
    installed_hosts,
    list_command,
    parse_args,
    parse_json_output,
    prepare_artifact_root,
    run_command,
    sanitize_path,
    sha256_file,
    validate_artifact_root,
    validate_fixture_temporary_root,
    write_json,
    write_text,
)

REPOSITORY_TMP_ROOT = (REPO_ROOT / "tmp").resolve()
QUALITY_GATE_TIMEOUT_SECONDS = 1_200


def count_inventory(items: list[dict[str, Any]]) -> dict[str, Any]:
    def count(field: str) -> dict[str, int]:
        return dict(sorted(collections.Counter(item[field] for item in items).items()))

    writable = [item for item in items if item.get("mutability") == "read-write"]
    return {
        "total": len(items),
        "writable": len(writable),
        "byProvider": count("provider"),
        "byKind": count("kind"),
        "byLayer": count("layer"),
        "writableByProvider": dict(
            sorted(collections.Counter(item["provider"] for item in writable).items())
        ),
    }


def digest_paths(paths: list[Path]) -> dict[str, str]:
    return {str(path): digest_path(path) for path in paths}


def live_plan_state_paths(item: dict[str, Any]) -> list[Path]:
    return sorted(
        {
            Path(os.path.abspath(Path(item[field]).expanduser()))
            for field in ("sourcePath", "statePath")
            if item.get(field)
        },
        key=lambda path: path.as_posix(),
    )


def live_item_has_cross_provider_shared_source(
    item: dict[str, Any], inventory: list[dict[str, Any]]
) -> bool:
    if item.get("kind") != "skill":
        return False

    source_path = item.get("sourcePath")
    state_path = item.get("statePath")
    provider = item.get("provider")
    if not all(isinstance(value, str) for value in (source_path, state_path, provider)):
        return False

    return any(
        counterpart.get("provider") != provider
        and counterpart.get("sourcePath") == source_path
        and counterpart.get("statePath") == state_path
        for counterpart in inventory
    )


def inventory_item_paths(item: dict[str, Any]) -> list[Path]:
    return [
        Path(value).expanduser().resolve()
        for field in ("sourcePath", "statePath")
        if (value := item.get(field))
    ]


def is_repository_tmp_path(path: Path) -> bool:
    return path == REPOSITORY_TMP_ROOT or path.is_relative_to(REPOSITORY_TMP_ROOT)


def live_inventory_exclusion_reason(item: dict[str, Any]) -> str | None:
    paths = inventory_item_paths(item)
    if any(path.is_relative_to(FIXTURE_ROOT) for path in paths):
        return "repository-fixture"
    if any(is_repository_tmp_path(path) for path in paths):
        return "repository-tmp"
    return None


def path_class(path: Path, *, artifact_root: Path, home_root: Path) -> str:
    if path.is_relative_to(artifact_root):
        return "artifact-state"
    if path.is_relative_to(REPO_ROOT):
        return "repository"
    if path.is_relative_to(home_root):
        return "home-provider"
    return "external"


def affected_target_path(value: str) -> Path | None:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        return None
    return Path(os.path.abspath(candidate))


def sanitized_live_plan(
    planned: dict[str, Any], *, artifact_root: Path, home_root: Path
) -> dict[str, Any]:
    selection = planned.get("selection") or {}
    target_classes = set()
    for target in planned.get("affectedTargets", []):
        target_path = affected_target_path(target)
        target_classes.add(
            path_class(
                target_path,
                artifact_root=artifact_root,
                home_root=home_root,
            )
            if target_path is not None
            else "logical-config-key"
        )
    return {
        "status": planned.get("status"),
        "reason": planned.get("reason"),
        "writes": planned.get("writes"),
        "targetEnabled": planned.get("targetEnabled"),
        "selection": {
            key: selection.get(key)
            for key in ("provider", "kind", "layer", "mutability", "enabled")
        },
        "affectedTargetClasses": sorted(target_classes),
        "operationTypes": sorted(
            operation.get("type") for operation in planned.get("operations", [])
        ),
    }


def capture_live_inventory(
    binary: Path,
    artifact_root: Path,
    home_root: Path,
    project_root: Path,
    cursor_root: Path,
) -> dict[str, Any]:
    app_state_root = (artifact_root / "live-state").resolve()
    app_state_root.mkdir(parents=True, exist_ok=True)
    process = run_command(
        list_command(
            binary,
            app_state_root=app_state_root,
            home_root=home_root,
            project_root=project_root,
            cursor_root=cursor_root,
        )
    )
    inventory = parse_json_output(process.stdout)

    all_items = inventory["items"]
    items = []
    excluded_items: collections.Counter[str] = collections.Counter()
    for item in all_items:
        if reason := live_inventory_exclusion_reason(item):
            excluded_items[reason] += 1
        else:
            items.append(item)
    plans: list[dict[str, Any]] = []
    provider_state_unchanged = True
    for scenario in MATRIX:
        provider = scenario["provider"]
        kind = scenario["kind"]
        layer = scenario["layer"]
        matches = [
            item
            for item in items
            if item["provider"] == provider
            and item["kind"] == kind
            and item["layer"] == layer
        ]
        if contains := scenario.get("liveIdContains"):
            matches = [item for item in matches if contains in item["id"]]
        if excludes := scenario.get("liveIdExcludes"):
            matches = [item for item in matches if excludes not in item["id"]]
        writable = [item for item in matches if item.get("mutability") == "read-write"]
        cell: dict[str, Any] = {
            "slug": scenario["slug"],
            "provider": provider,
            "kind": kind,
            "layer": layer,
            "surface": scenario["surface"],
            "installed": len(matches),
            "writable": len(writable),
        }
        if not writable:
            cell["status"] = "read-only" if matches else "not-installed"
            plans.append(cell)
            continue

        candidates = sorted(writable, key=lambda item: item["id"])
        if kind == "mcp":
            candidates.sort(
                key=lambda item: (
                    "unpin" in item["id"].lower(),
                    item["id"],
                )
            )
        selected = candidates[0]
        state_paths = live_plan_state_paths(selected)
        selected_baseline = digest_paths(state_paths)
        command: list[str | Path] = [
            binary,
            "toggle",
            "--home-root",
            home_root,
            "--project-root",
            project_root,
        ]
        if cursor_root.exists():
            command.extend(["--cursor-root", cursor_root])
        command.extend(
            [
                "--app-state-root",
                app_state_root,
                "--provider",
                provider,
                "--kind",
                kind,
                "--layer",
                layer,
                "--id",
                selected["id"],
                "--json",
            ]
        )
        planned = parse_json_output(run_command(command, check=False).stdout)
        blocked_for_shared_source = (
            planned.get("status") == "blocked"
            and planned.get("reason")
            == "native toggle blocked: shared-source-crosses-provider-reach"
        )
        plan_selection = planned.get("selection") or {}
        semantic_plan_valid = (
            planned.get("status") in {"dry-run", "planned"}
            and planned.get("writes") in {False, "no writes were performed"}
            and bool(planned.get("operations"))
            and bool(planned.get("affectedTargets"))
            and plan_selection.get("id") == selected["id"]
            and plan_selection.get("provider") == provider
            and plan_selection.get("kind") == kind
            and plan_selection.get("layer") == layer
            and planned.get("targetEnabled") is (not bool(selected["enabled"]))
        )
        affected_targets = [
            target_path
            for target in planned.get("affectedTargets", [])
            if (target_path := affected_target_path(target)) is not None
        ]
        unknown_targets = [
            path
            for path in affected_targets
            if not path.is_relative_to(app_state_root)
            and not any(
                path == known
                or path.is_relative_to(known)
                for known in state_paths
            )
        ]
        current_provider_digests = digest_paths(state_paths)
        provider_digests_unchanged = current_provider_digests == selected_baseline
        changed_path_classes = sorted(
            {
                path_class(
                    path,
                    artifact_root=artifact_root,
                    home_root=home_root,
                )
                for path in state_paths
                if current_provider_digests[str(path)]
                != selected_baseline[str(path)]
            }
        )
        backup_directory_absent = not (app_state_root / "backups").exists()
        unknown_target_classes = sorted(
            {
                path_class(
                    path,
                    artifact_root=artifact_root,
                    home_root=home_root,
                )
                for path in unknown_targets
            }
        )
        unchanged = (
            provider_digests_unchanged
            and backup_directory_absent
            and not unknown_targets
        )
        if blocked_for_shared_source:
            if not live_item_has_cross_provider_shared_source(selected, items):
                raise MatrixFailure(
                    "live shared-source block did not have a physically coupled "
                    f"cross-provider view for {scenario['slug']}"
                )
            if not unchanged:
                raise MatrixFailure(
                    f"live shared-source block changed state for {scenario['slug']}; "
                    f"provider digests unchanged: {provider_digests_unchanged}; "
                    f"changed path classes: {changed_path_classes}; "
                    f"backup directory absent: {backup_directory_absent}; "
                    f"unknown target classes: {unknown_target_classes}"
                )
            provider_state_unchanged = provider_state_unchanged and unchanged
            write_json(
                artifact_root / "raw/live-plans" / f"{scenario['slug']}.json",
                sanitized_live_plan(
                    planned, artifact_root=artifact_root, home_root=home_root
                ),
            )
            cell.update(
                {
                    "status": "blocked-shared-source",
                    "reason": planned["reason"],
                    "stateUnchanged": unchanged,
                    "checkedPathCount": len(state_paths),
                    "selectedPathClasses": sorted(
                        {
                            path_class(
                                path,
                                artifact_root=artifact_root,
                                home_root=home_root,
                            )
                            for path in state_paths
                        }
                    ),
                }
            )
            plans.append(cell)
            continue
        if not semantic_plan_valid or not unchanged:
            raise MatrixFailure(
                f"live dry run failed safety check for {scenario['slug']}; "
                f"semantic plan valid: {semantic_plan_valid}; "
                f"provider digests unchanged: {provider_digests_unchanged}; "
                f"changed path classes: {changed_path_classes}; "
                f"backup directory absent: {backup_directory_absent}; "
                f"unknown target classes: {unknown_target_classes}"
            )
        provider_state_unchanged = provider_state_unchanged and unchanged
        write_json(
            artifact_root / "raw/live-plans" / f"{scenario['slug']}.json",
            sanitized_live_plan(
                planned, artifact_root=artifact_root, home_root=home_root
            ),
        )
        cell.update(
            {
                "status": "planned",
                "stateUnchanged": unchanged,
                "checkedPathCount": len(state_paths),
                "selectedPathClasses": sorted(
                    {
                        path_class(
                            path,
                            artifact_root=artifact_root,
                            home_root=home_root,
                        )
                        for path in state_paths
                    }
                ),
            }
        )
        plans.append(cell)

    summary = {
        **count_inventory(items),
        "excludedRepositoryFixtureItems": excluded_items["repository-fixture"],
        "excludedRepositoryTmpItems": excluded_items["repository-tmp"],
        "warnings": len(inventory.get("warnings", [])),
        "dryRunCells": plans,
        "providerStateUnchanged": provider_state_unchanged,
        "rawInventoryPersisted": False,
    }
    write_json(artifact_root / "raw/live-inventory-summary.json", summary)
    return summary


def run_quality_gates(
    cargo: Path, binary: Path, artifact_root: Path
) -> dict[str, Any]:
    python_sources = [
        Path(__file__).resolve(),
        Path(__file__).with_name("local_provider_matrix_cases.py").resolve(),
        Path(__file__).with_name("local_provider_matrix_finalize.py").resolve(),
        Path(__file__).with_name("local_provider_matrix_support.py").resolve(),
    ]
    gates: list[tuple[str, list[str | Path]]] = [
        ("cargo-fmt", [cargo, "fmt", "--all", "--", "--check"]),
        (
            "cargo-clippy",
            [
                cargo,
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("cargo-test", [cargo, "test", "--workspace", "--all-features"]),
        ("cargo-build", [cargo, "build", "-p", "unpin-cli"]),
        ("cli-help", [binary, "--help"]),
        ("git-diff-check", ["git", "diff", "--check"]),
        (
            "python-compile",
            [
                sys.executable,
                "-c",
                (
                    "import ast,pathlib;"
                    f"paths={list(map(str, python_sources))!r};"
                    "[ast.parse(pathlib.Path(path).read_text(encoding='utf-8')) "
                    "for path in paths]"
                ),
            ],
        ),
        (
            "python-timeout-selfcheck",
            [
                sys.executable,
                "-c",
                (
                    "import pathlib,sys\n"
                    f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})\n"
                    "from local_provider_matrix_support import MatrixFailure, run_command\n"
                    "try:\n"
                    "    run_command([sys.executable, '-c', 'import time; time.sleep(1)'], "
                    "timeout_seconds=0.01)\n"
                    "except MatrixFailure:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise SystemExit('timeout self-check did not fail')\n"
                ),
            ],
        ),
    ]
    results: dict[str, Any] = {}
    for name, command in gates:
        started = dt.datetime.now(dt.timezone.utc)
        try:
            process = run_command(
                command,
                check=False,
                timeout_seconds=QUALITY_GATE_TIMEOUT_SECONDS,
            )
        except MatrixCommandTimeout as error:
            duration = (dt.datetime.now(dt.timezone.utc) - started).total_seconds()
            write_text(
                artifact_root / "raw/verification" / f"{name}.stdout.txt",
                sanitize_path(
                    error.stdout,
                    artifact_root=artifact_root,
                    home_root=Path.home(),
                ),
            )
            write_text(
                artifact_root / "raw/verification" / f"{name}.stderr.txt",
                sanitize_path(
                    error.stderr,
                    artifact_root=artifact_root,
                    home_root=Path.home(),
                ),
            )
            results[name] = {
                "status": "timed-out",
                "exitCode": None,
                "timeoutSeconds": error.timeout_seconds,
                "durationSeconds": round(duration, 3),
            }
            if error.termination_issue is not None:
                results[name]["terminationIssue"] = error.termination_issue
            write_json(artifact_root / "raw/verification.json", results)
            raise
        duration = (dt.datetime.now(dt.timezone.utc) - started).total_seconds()
        write_text(
            artifact_root / "raw/verification" / f"{name}.stdout.txt",
            sanitize_path(
                process.stdout, artifact_root=artifact_root, home_root=Path.home()
            ),
        )
        write_text(
            artifact_root / "raw/verification" / f"{name}.stderr.txt",
            sanitize_path(
                process.stderr, artifact_root=artifact_root, home_root=Path.home()
            ),
        )
        results[name] = {
            "status": "passed" if process.returncode == 0 else "failed",
            "exitCode": process.returncode,
            "durationSeconds": round(duration, 3),
        }
        if name == "cargo-test":
            matches = re.findall(
                r"test result: ok\. (\d+) passed", process.stdout + process.stderr
            )
            results[name]["testsPassed"] = sum(int(match) for match in matches)
        if process.returncode != 0:
            write_json(artifact_root / "raw/verification.json", results)
            raise MatrixFailure(f"quality gate failed: {name}")
    write_json(artifact_root / "raw/verification.json", results)
    return results


def capture_static_surfaces(binary: Path, artifact_root: Path) -> dict[str, Any]:
    tui_state = (artifact_root / "tui-state").resolve()
    tui_state.mkdir(parents=True, exist_ok=True)
    surfaces = {
        "providers": [binary, "providers"],
        "doctor": [binary, "doctor", "--fixture-root", FIXTURE_ROOT],
        "tui": [
            binary,
            "tui",
            "--fixture-root",
            FIXTURE_ROOT,
            "--app-state-root",
            tui_state,
            "--headless",
        ],
    }
    results: dict[str, Any] = {}
    for name, command in surfaces.items():
        process = run_command(command)
        write_text(
            artifact_root / "raw" / f"{name}.txt",
            sanitize_path(
                process.stdout, artifact_root=artifact_root, home_root=Path.home()
            ),
        )
        results[name] = {"status": "passed", "exitCode": process.returncode}
    return results


def state_label(value: bool | None) -> str:
    if value is None:
        return "guarded"
    return "enabled" if value else "disabled"


def matrix_live_status(
    live_summary: dict[str, Any] | None, scenario: dict[str, Any]
) -> str:
    if live_summary is None:
        return "skipped"
    for cell in live_summary["dryRunCells"]:
        if cell["slug"] == scenario["slug"]:
            return cell["status"]
    return "not-installed"


def render_report(
    summary: dict[str, Any], artifact_root: Path, tui_output: str
) -> tuple[str, str, str]:
    cli_results = summary["results"]["cliCases"]
    tui_results = summary["results"]["tuiCases"]
    mcp_results = summary["results"]["mcpCases"]
    live = summary.get("liveInventory")
    matrix = summary["matrix"]
    declared_exceptions = summary["declaredExceptions"]
    screenshots = summary["screenshotsExpected"]
    fanout_counts = {
        label: sum(
            1
            for result in results
            if result.get("sharedSourceFanout", {}).get("asserted") is True
        )
        for label, results in (
            ("CLI", cli_results),
            ("TUI", tui_results),
            ("MCP", mcp_results),
        )
    }
    mcp_unreviewed_blocked = sum(
        result.get("unreviewedApplyBlocked") is True for result in mcp_results
    )
    mcp_handoffs = sum(
        result.get("humanActionHandoff") is True for result in mcp_results
    )
    mcp_writes_disabled = sum(
        result.get("mcpWritesEnabled") is False for result in mcp_results
    )
    live_safety_lines = (
        [
            "- Installed provider inventory was read only.",
            "- Live writable surfaces received dry-run plans only; before/after hashes matched.",
        ]
        if live
        else ["- Installed provider inventory was skipped by request."]
    )

    report_lines = [
        "# Unpin local provider matrix",
        "",
        f"Generated: {summary['generatedAt']}",
        "",
        "## Safety boundary",
        "",
        *live_safety_lines,
        f"- Tested workspace binary SHA-256: `{summary['testedBinary']['sha256']}`.",
        f"- Source binding: Git `{summary['testedBinary']['gitHead']}` with workspace state `{summary['testedBinary']['workspaceStateSha256']}` (dirty: `{str(summary['testedBinary']['workspaceDirty']).lower()}`).",
        "- All apply, re-enable, backup, audit, and restore cycles used isolated copies of committed fixtures.",
        "- No `.env*` file was read or copied.",
        "- Full live inventory was aggregated in memory and not persisted.",
        "",
        "## Installed hosts",
        "",
        "| Host | Surface | Version |",
        "| --- | --- | --- |",
    ]
    for provider, host in summary["installedHosts"].items():
        report_lines.append(
            f"| {provider} | {host['surface']} | {host.get('version') or 'not found'} |"
        )
    if live:
        report_lines.extend(
            [
                "",
                "## Live read-only inventory",
                "",
                f"- Items discovered: **{live['total']}**",
                f"- Writable items discovered: **{live['writable']}**",
                f"- Discovery warnings: **{live['warnings']}**",
                f"- Selected provider state unchanged after every dry-run plan: **{str(live['providerStateUnchanged']).lower()}**",
            ]
        )
    report_lines.extend(
        [
            "",
            "## Executed matrix",
            "",
            f"- CLI cycles: **{len(cli_results)}/{len(matrix)} passed**",
            f"- Interactive TUI cycles: **{len(tui_results)}/{len(matrix)} passed**",
            f"- MCP plan/review/handoff cycles: **{len(mcp_results)}/{len(matrix)} passed**",
            "- CLI and TUI cycles verified plan -> first toggle -> inverse toggle -> restore inverse backup -> restore original backup -> byte-exact fixture recovery.",
            "- TUI cycles drove search, staging, confirmation blocking, two confirmed applies, rediscovery, and backups through a real terminal PTY; CLI restore then proved both backups.",
            f"- MCP cycles kept writes disabled in {mcp_writes_disabled}/{len(matrix)} cases, blocked {mcp_unreviewed_blocked}/{len(matrix)} unreviewed applies, and returned {mcp_handoffs}/{len(matrix)} exact-fingerprint human-action handoffs; CLI completed each reviewed handoff and restore.",
            f"- Shared-source fan-out: {fanout_counts['CLI']} CLI, {fanout_counts['TUI']} TUI, and {fanout_counts['MCP']} MCP-handoff cases proved all provider views disable and return together.",
            "",
            "| Provider | Layer | Kind | Surface | Live | CLI | TUI | MCP |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for scenario in matrix:
        report_lines.append(
            "| {provider} | {layer} | {kind} | {surface} | {live} | passed | passed | passed |".format(
                **scenario, live=matrix_live_status(live, scenario)
            )
        )
    report_lines.extend(
        [
            "",
            "## Explicit non-writable cells",
            "",
            "| Provider | Layer | Kind | Status | Reason |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for cell in declared_exceptions:
        report_lines.append(
            f"| {cell['provider']} | {cell['layer']} | {cell['kind']} | {cell['status']} | {cell['reason']} |"
        )
    report_lines.extend(
        [
            "",
            "## Screenshots",
            "",
            *[f"- [{name}](screenshots/{name})" for name in screenshots],
            "",
            "## Raw evidence",
            "",
            "- `raw/results.json`: CLI cycle summaries.",
            "- `raw/tui-results.json`: interactive TUI cycle summaries.",
            "- `raw/mcp-results.json`: MCP plan/review/handoff summaries plus CLI completion evidence.",
            "- `raw/live-inventory-summary.json`: sanitized installed-library counts and dry-run cells.",
            "- Full live inventory is aggregated in memory and is not persisted.",
            "- `cases/`, `tui-cases/`, and `mcp-cases/`: per-step applies, restores, manifests, and audit logs.",
            "- `raw/verification.json`: format, Clippy, tests, build, help, diff, and runner compile gates.",
            "",
            "Interactive local dashboard: [dashboard.html](dashboard.html).",
            "",
        ]
    )

    provider_sections = []
    provider_display_names = {"opencode": "OpenCode"}
    for provider in ["claude", "codex", "cursor", "pi", "opencode", "zed"]:
        provider_display_name = provider_display_names.get(provider, provider.title())
        rows = []
        for control_plane, results in (("CLI", cli_results), ("TUI", tui_results)):
            for result in results:
                if result["provider"] != provider:
                    continue
                states = result["states"]
                rows.append(
                    "<tr><td>{control}</td><td>{surface}</td><td>{layer}</td><td>{kind}</td>"
                    "<td>{initial}</td><td>{first}</td><td>{second}</td>"
                    "<td>{restore}</td><td>{final}</td></tr>".format(
                        control=control_plane,
                        surface=html.escape(result["surface"]),
                        layer=result["layer"],
                        kind=result["kind"],
                        initial=state_label(states.get("initial")),
                        first=state_label(states.get("afterFirstToggle")),
                        second=state_label(states.get("afterSecondToggle")),
                        restore=state_label(states.get("afterRestoreSecond")),
                        final=state_label(states.get("final")),
                    )
                )
        provider_sections.append(
            f"""
<section class="panel" id="provider-{provider}">
  <div class="eyebrow">{provider.upper()} TOGGLE STATES</div>
  <h2>{provider_display_name} CLI + interactive TUI apply transitions</h2>
  <table><thead><tr><th>Control</th><th>Surface</th><th>Layer</th><th>Kind</th><th>Initial</th><th>Toggle 1</th><th>Toggle 2</th><th>Restore 2</th><th>Final</th></tr></thead>
  <tbody>{''.join(rows)}</tbody></table>
</section>"""
        )

    host_cards = "".join(
        f"<article class='metric'><span>{provider}</span><strong>{html.escape(host.get('version') or 'not found')}</strong><small>{host['surface']}</small></article>"
        for provider, host in summary["installedHosts"].items()
    )
    live_counts = ""
    if live:
        live_counts = "".join(
            f"<tr><td>{provider}</td><td>{count}</td><td>{live['writableByProvider'].get(provider, 0)}</td></tr>"
            for provider, count in live["byProvider"].items()
        )

    matrix_rows = "".join(
        "<tr><td>{provider}</td><td>{layer}</td><td>{kind}</td><td>{surface}</td>"
        "<td><span class='badge {live}'>{live}</span></td><td><span class='badge passed'>passed</span></td>"
        "<td><span class='badge passed'>passed</span></td>"
        "<td><span class='badge passed'>passed</span></td></tr>".format(
            **scenario,
            live=matrix_live_status(live, scenario),
        )
        for scenario in matrix
    )
    exception_rows = "".join(
        f"<tr><td>{cell['provider']}</td><td>{cell['layer']}</td><td>{cell['kind']}</td><td><span class='badge {cell['status']}'>{cell['status']}</span></td><td>{html.escape(cell['reason'])}</td></tr>"
        for cell in declared_exceptions
    )
    verification = summary.get("verification", {})
    gate_cards = "".join(
        f"<article class='metric'><span>{name}</span><strong>{value['status']}</strong><small>{value['durationSeconds']}s</small></article>"
        for name, value in verification.items()
    )
    live_state = (
        str(live["providerStateUnchanged"]).lower() if live else "skipped"
    )
    live_announcement = (
        f"- Live inventory: {live['total']} items discovered read-only; provider state "
        "for each selection remained unchanged after its live dry-run plan."
        if live
        else "- Live inventory: skipped by request."
    )
    evidence_bundle = (
        artifact_root.relative_to(REPO_ROOT)
        if artifact_root.is_relative_to(REPO_ROOT)
        else artifact_root
    )
    binary_short = summary["testedBinary"]["sha256"][:12]
    git_short = summary["testedBinary"]["gitHead"][:12]
    dashboard = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unpin local provider matrix</title>
<style>
:root{{--bg:#08111d;--panel:#101d2d;--panel2:#14253a;--text:#e8f0fa;--muted:#9eb0c5;--cyan:#53d8fb;--green:#54e69a;--amber:#ffc857;--red:#ff6b7a;--border:#29415e}}
*{{box-sizing:border-box}} body{{margin:0;background:radial-gradient(circle at top right,#173454 0,var(--bg) 42%);color:var(--text);font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}}
main{{width:1480px;max-width:calc(100vw - 48px);margin:24px auto 80px}} .panel{{background:linear-gradient(145deg,var(--panel2),var(--panel));border:1px solid var(--border);border-radius:18px;padding:28px;margin:24px 0;box-shadow:0 22px 60px #0007}}
h1{{font-size:42px;margin:8px 0 10px}} h2{{font-size:25px;margin:6px 0 20px}} .eyebrow{{color:var(--cyan);letter-spacing:.16em;font-size:12px;font-weight:700}} .muted{{color:var(--muted)}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:20px}} .metric{{background:#091525;border:1px solid var(--border);border-radius:13px;padding:18px;display:flex;flex-direction:column;min-height:110px}} .metric span,.metric small{{color:var(--muted)}} .metric strong{{font-size:24px;color:var(--green);margin:7px 0}}
table{{width:100%;border-collapse:collapse;background:#0a1624;border-radius:12px;overflow:hidden}} th,td{{padding:11px 13px;border-bottom:1px solid #203750;text-align:left;vertical-align:top}} th{{color:var(--cyan);font-size:12px;text-transform:uppercase;letter-spacing:.08em}} tr:last-child td{{border-bottom:0}}
.badge{{display:inline-block;border-radius:999px;padding:3px 9px;background:#20344c;color:var(--text)}} .passed,.planned{{background:#103f34;color:var(--green)}} .read-only,.unsupported,.not-installed{{background:#453713;color:var(--amber)}} .out-of-scope{{background:#352448;color:#d6afff}}
pre{{white-space:pre-wrap;background:#050c15;border:1px solid var(--border);border-radius:12px;padding:20px;color:#cfe1f4;max-height:none}}
.callout{{border-left:4px solid var(--green);padding:12px 16px;background:#0a211d;border-radius:0 10px 10px 0}} .two{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
</style></head><body><main>
<section class="panel" id="overview"><div class="eyebrow">FRESH LOCAL EVIDENCE</div><h1>Unpin provider matrix</h1><p class="muted">Installed inventory read only. Mutations isolated to fixture copies. Generated {html.escape(summary['generatedAt'])}.</p><p class="muted">Workspace build {git_short} · binary SHA-256 {binary_short}…</p><div class="metrics">{host_cards}</div><p class="callout">CLI {len(cli_results)}/{len(matrix)} passed. Interactive TUI {len(tui_results)}/{len(matrix)} passed. MCP {len(mcp_results)}/{len(matrix)} passed. Live state unchanged: {live_state}.</p></section>
<section class="panel" id="live-library"><div class="eyebrow">INSTALLED LIBRARY</div><h2>Read-only local inventory</h2><p class="muted">Full item names and paths are aggregated in memory and never persisted. Screenshot contains aggregate counts.</p><div class="two"><table><thead><tr><th>Provider</th><th>Items</th><th>Writable</th></tr></thead><tbody>{live_counts}</tbody></table><div class="metrics" style="grid-template-columns:1fr 1fr">{gate_cards}</div></div></section>
<section class="panel" id="coverage-matrix"><div class="eyebrow">SUPPORTED CELLS</div><h2>Provider x scope x item x control plane</h2><p class="callout">Shared-source fan-out proved in {fanout_counts['CLI']} CLI, {fanout_counts['TUI']} TUI, and {fanout_counts['MCP']} MCP-handoff cases: every loading provider stayed visible as disabled and returned to enabled.</p><table><thead><tr><th>Provider</th><th>Layer</th><th>Kind</th><th>Surface</th><th>Live plan</th><th>CLI</th><th>TUI</th><th>MCP</th></tr></thead><tbody>{matrix_rows}</tbody></table><h2 style="margin-top:28px">Explicit non-writable cells</h2><table><thead><tr><th>Provider</th><th>Layer</th><th>Kind</th><th>Status</th><th>Reason</th></tr></thead><tbody>{exception_rows}</tbody></table></section>
<section class="panel" id="tui-library"><div class="eyebrow">TUI CONTROL PLANE</div><h2>Headless library plus interactive terminal cycles</h2><p class="callout">All {len(tui_results)} writable cells passed search, stage, blocked-unconfirmed apply, two confirmed applies, rediscovery, and backup through TUI; CLI restore proved both backups.</p><pre>{html.escape(tui_output)}</pre></section>
{''.join(provider_sections)}
<section class="panel" id="mcp-states"><div class="eyebrow">MCP CONTROL PLANE</div><h2>Plan, review, and human-action handoff</h2><div class="metrics"><article class="metric"><span>Scenarios</span><strong>{len(mcp_results)}/{len(matrix)}</strong><small>passed</small></article><article class="metric"><span>MCP writes</span><strong>0/{mcp_writes_disabled}</strong><small>CLI/TUI approval required</small></article><article class="metric"><span>Exact handoff</span><strong>{mcp_handoffs}/{len(matrix)}</strong><small>reviewed fingerprints</small></article><article class="metric"><span>Recovery</span><strong>byte-exact</strong><small>all fixture trees</small></article></div><p class="callout">Every persistent MCP session completed initialize, initialized notification, tools/list discovery, no-write safety checks, blocked unreviewed apply, and exact-fingerprint handoff for toggles and restores. CLI completed each reviewed handoff, producing authenticated backups, two apply plus two restore audit events, and byte-exact recovery.</p></section>
</main></body></html>"""

    announcement = f"""Unpin local provider matrix refreshed

- Installed hosts: {', '.join(f"{name} {host.get('version') or 'not found'}" for name, host in summary['installedHosts'].items())}
{live_announcement}
- Isolated matrix: {len(cli_results)}/{len(matrix)} CLI, {len(tui_results)}/{len(matrix)} interactive TUI, and {len(mcp_results)}/{len(matrix)} persistent MCP plan/review/handoff cycles passed.
- Tested workspace build: Git {git_short}, binary SHA-256 {binary_short}…; full source binding is in summary.json.
- Shared-source fan-out: {fanout_counts['CLI']} CLI, {fanout_counts['TUI']} TUI, and {fanout_counts['MCP']} MCP-handoff cases proved every loading provider toggles together.
- Coverage: Claude Code, Codex, Cursor, Pi, OpenCode, and Zed across every writable global/project skill, plugin, and MCP cell.
- Zed plugins remain intentionally out of scope; Zed standard Agent Skills and context_servers MCPs are covered globally and per project.
- Safety: all mutations used copied fixtures, authenticated backups, audit evidence, restore, and byte-exact recovery. No live provider state or .env files were mutated/read.

Reproduce with: python3 scripts/run_local_provider_matrix.py
Guide: docs/local-provider-matrix.md
Evidence bundle: {evidence_bundle}
"""
    return "\n".join(report_lines), dashboard, announcement


def build_summary(
    artifact_root: Path,
    tested_binary: dict[str, str],
    hosts: dict[str, Any],
    live_summary: dict[str, Any] | None,
    cli_results: list[dict[str, Any]],
    tui_results: list[dict[str, Any]],
    mcp_results: list[dict[str, Any]],
    verification: dict[str, Any],
    static_surfaces: dict[str, Any],
) -> dict[str, Any]:
    return {
        "runId": artifact_root.name,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "testedBinary": tested_binary,
        "safety": {
            "liveInventoryReadOnly": True,
            "liveProviderStateMutated": False,
            "fixtureMutationOnly": True,
            "isolatedPerScenario": True,
            "envFilesRead": False,
            "rawLiveInventoryPersisted": False,
        },
        "installedHosts": hosts,
        "liveInventory": live_summary,
        "matrix": MATRIX,
        "declaredExceptions": DECLARED_EXCEPTIONS,
        "results": {
            "cliCases": cli_results,
            "tuiCases": tui_results,
            "mcpCases": mcp_results,
        },
        "verification": verification,
        "staticSurfaces": static_surfaces,
        "screenshotsExpected": SCREENSHOTS,
    }


def main() -> int:
    args = parse_args()
    artifact_root = validate_artifact_root(args.artifact_root)
    validate_fixture_temporary_root(artifact_root)
    if args.finalize:
        manifest = finalize_artifacts(artifact_root)
        print(json.dumps({"status": "finalized", "artifactRoot": str(artifact_root), **manifest["counts"]}))
        return 0

    artifact_root = prepare_artifact_root(artifact_root, args.overwrite)
    binary = args.binary.expanduser().resolve()
    # Preserve Cargo's rustup shim name. Resolving the symlink executes rustup
    # directly, so arguments such as `fmt --all` are parsed as rustup options.
    cargo = Path(os.path.abspath(args.cargo.expanduser()))
    home_root = args.home_root.expanduser().resolve()
    project_root = args.project_root.expanduser().resolve()
    cursor_root = args.cursor_root.expanduser().resolve()

    try:
        source_identity = workspace_identity()
        default_binary = (REPO_ROOT / "target/debug/unpin").resolve()
        if binary == default_binary:
            if not cargo.is_file():
                raise MatrixFailure(f"Cargo is unavailable for workspace build: {cargo}")
            run_command([cargo, "build", "-p", "unpin-cli"])
        elif not binary.is_file():
            raise MatrixFailure(f"custom Unpin binary is unavailable: {binary}")
        tested_binary = {
            "source": "workspace-build" if binary == default_binary else "custom",
            "sha256": sha256_file(binary),
            **source_identity,
        }
        hosts = installed_hosts()
        live_summary = None
        if not args.skip_live:
            live_summary = capture_live_inventory(
                binary, artifact_root, home_root, project_root, cursor_root
            )

        canonical_fixture_digest = digest_path(FIXTURE_ROOT)
        cli_results = run_matrix_cases(
            run_cli_scenario,
            binary,
            artifact_root,
            canonical_fixture_digest,
        )
        tui_results = run_matrix_cases(
            run_tui_scenario,
            binary,
            artifact_root,
            canonical_fixture_digest,
        )
        mcp_results = run_matrix_cases(
            run_mcp_scenario,
            binary,
            artifact_root,
            canonical_fixture_digest,
        )
        write_json(artifact_root / "raw/results.json", cli_results)
        write_json(artifact_root / "raw/tui-results.json", tui_results)
        write_json(artifact_root / "raw/mcp-results.json", mcp_results)
        write_json(artifact_root / "raw/scenario-matrix.json", MATRIX)

        static_surfaces = capture_static_surfaces(binary, artifact_root)
        verification = (
            {}
            if args.skip_quality_gates
            else run_quality_gates(cargo, binary, artifact_root)
        )
        summary = build_summary(
            artifact_root,
            tested_binary,
            hosts,
            live_summary,
            cli_results,
            tui_results,
            mcp_results,
            verification,
            static_surfaces,
        )
        write_json(artifact_root / "summary.json", summary)
        tui_output = sanitize_path(
            (artifact_root / "raw/tui.txt").read_text(encoding="utf-8"),
            artifact_root=artifact_root,
            home_root=home_root,
        )
        report, dashboard, announcement = render_report(summary, artifact_root, tui_output)
        write_text(artifact_root / "report.md", report)
        write_text(artifact_root / "dashboard.html", dashboard)
        write_text(artifact_root / "announcement.md", announcement)
        write_json(
            artifact_root / "screenshot-review.json",
            {
                "status": "pending",
                "reviewedBy": None,
                "reviewedAt": None,
                "screenshots": SCREENSHOTS,
                "checksums": {},
                "assertions": {
                    "matchesExpectedSections": False,
                    "noPrivateNamesVisible": False,
                    "noLocalHomePathsVisible": False,
                    "stateLabelsReadable": False,
                },
            },
        )
        tighten_artifact_permissions(artifact_root)
        print(
            json.dumps(
                {
                    "status": "passed",
                    "artifactRoot": str(artifact_root),
                    "cliCases": len(cli_results),
                    "tuiCases": len(tui_results),
                    "mcpCases": len(mcp_results),
                    "liveItems": live_summary["total"] if live_summary else None,
                    "liveStateUnchanged": (
                        live_summary["providerStateUnchanged"] if live_summary else None
                    ),
                    "screenshotsPending": SCREENSHOTS,
                }
            )
        )
        return 0
    except Exception as error:
        write_json(
            artifact_root / "failure.json",
            {
                "status": "failed",
                "error": "matrix run failed; see terminal output",
                "type": type(error).__name__,
                "failedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            },
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
