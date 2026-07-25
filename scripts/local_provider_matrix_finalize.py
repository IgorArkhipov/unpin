"""Workspace binding and final evidence validation for local provider matrix."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from local_provider_matrix_support import (
    MATRIX,
    REPO_ROOT,
    SCREENSHOTS,
    MatrixFailure,
    digest_path,
    is_env_path,
    run_command,
    sha256_file,
    validate_artifact_root,
    write_json,
)


def workspace_identity() -> dict[str, Any]:
    head = run_command(["git", "rev-parse", "HEAD"]).stdout.strip()
    status = run_command(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"]
    ).stdout
    status_paths = [
        line[3:].split(" -> ")[-1].strip('"')
        for line in status.splitlines()
        if len(line) >= 4
    ]
    if any(is_env_path(Path(path)) for path in status_paths):
        raise MatrixFailure("refusing to fingerprint workspace with changed .env files")

    tracked_diff = run_command(
        [
            "git",
            "diff",
            "--binary",
            "HEAD",
            "--",
            ".",
            ":(exclude).env*",
            ":(exclude)**/.env*",
        ]
    ).stdout
    untracked = run_command(
        [
            "git",
            "-c",
            "core.quotePath=false",
            "ls-files",
            "--others",
            "--exclude-standard",
        ]
    ).stdout.splitlines()
    digest = hashlib.sha256()
    digest.update(status.encode())
    digest.update(tracked_diff.encode())
    for relative in sorted(untracked):
        relative_path = Path(relative)
        if is_env_path(relative_path):
            raise MatrixFailure("refusing to fingerprint untracked .env files")
        path = REPO_ROOT / relative_path
        digest.update(relative.encode())
        digest.update(digest_path(path).encode())
    return {
        "gitHead": head,
        "workspaceStateSha256": f"sha256:{digest.hexdigest()}",
        "workspaceDirty": bool(status.strip()),
    }


def scan_publishable_files(artifact_root: Path, files: list[Path]) -> None:
    forbidden = [str(Path.home())]
    for artifact in artifact_root.rglob("*"):
        if is_env_path(artifact.relative_to(artifact_root)):
            raise MatrixFailure(
                f"evidence bundle contains forbidden .env artifact: {artifact}"
            )
    for path in files:
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                raise MatrixFailure(
                    f"publishable artifact contains forbidden local token {token!r}: {path}"
                )


def tighten_artifact_permissions(artifact_root: Path) -> None:
    artifact_root.chmod(0o700)
    for path in artifact_root.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(0o700 if path.is_dir() else 0o600)


def finalize_artifacts(artifact_root: Path) -> dict[str, Any]:
    root = validate_artifact_root(artifact_root)
    required = [
        root / "summary.json",
        root / "report.md",
        root / "dashboard.html",
        root / "announcement.md",
        root / "raw/results.json",
        root / "raw/tui-results.json",
        root / "raw/mcp-results.json",
    ]
    missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
    if missing:
        raise MatrixFailure(f"cannot finalize; missing artifacts: {missing}")

    summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
    if summary.get("liveInventory") is None or not summary.get("verification"):
        raise MatrixFailure(
            "cannot finalize a partial run; live inventory and quality gates are required"
        )
    if summary.get("matrix") != MATRIX or summary.get("screenshotsExpected") != SCREENSHOTS:
        raise MatrixFailure("cannot finalize; summary matrix contract is not canonical")
    tested_binary = summary.get("testedBinary") or {}
    required_binary_fields = {
        "sha256",
        "gitHead",
        "workspaceStateSha256",
        "workspaceDirty",
    }
    if tested_binary.get("source") != "workspace-build" or not required_binary_fields.issubset(
        tested_binary
    ):
        raise MatrixFailure("cannot finalize; evidence is not bound to a workspace build")
    if tested_binary.get("workspaceDirty") is not False:
        raise MatrixFailure("cannot finalize; release evidence requires a clean workspace")
    current_identity = workspace_identity()
    if any(
        tested_binary.get(key) != current_identity.get(key)
        for key in ("gitHead", "workspaceStateSha256", "workspaceDirty")
    ):
        raise MatrixFailure("cannot finalize; workspace changed after matrix execution")
    workspace_binary = (REPO_ROOT / "target/debug/unpin").resolve()
    if (
        not workspace_binary.is_file()
        or sha256_file(workspace_binary) != tested_binary["sha256"]
    ):
        raise MatrixFailure("cannot finalize; tested workspace binary changed after execution")
    if summary["liveInventory"].get("providerStateUnchanged") is not True:
        raise MatrixFailure("cannot finalize; live provider state check did not pass")
    if any(
        gate.get("status") != "passed" for gate in summary["verification"].values()
    ):
        raise MatrixFailure("cannot finalize; one or more verification gates failed")
    safety = summary.get("safety") or {}
    required_safety = {
        "liveInventoryReadOnly": True,
        "liveProviderStateMutated": False,
        "fixtureMutationOnly": True,
        "isolatedPerScenario": True,
        "envFilesRead": False,
        "rawLiveInventoryPersisted": False,
    }
    if any(safety.get(key) is not expected for key, expected in required_safety.items()):
        raise MatrixFailure("cannot finalize; safety assertions are incomplete")
    required.extend(
        [root / "raw/live-inventory-summary.json", root / "raw/verification.json"]
    )
    missing.extend(str(path.relative_to(root)) for path in required if not path.is_file())
    if missing:
        raise MatrixFailure(f"cannot finalize; missing artifacts: {missing}")

    screenshot_names = SCREENSHOTS
    screenshot_paths = [root / "screenshots" / name for name in screenshot_names]
    missing.extend(
        str(path.relative_to(root)) for path in screenshot_paths if not path.is_file()
    )
    if missing:
        raise MatrixFailure(f"cannot finalize; missing artifacts: {missing}")
    invalid_screenshots = [
        str(path.relative_to(root))
        for path in screenshot_paths
        if path.stat().st_size <= 8 or path.read_bytes()[:8] != b"\x89PNG\r\n\x1a\n"
    ]
    if invalid_screenshots:
        raise MatrixFailure(f"cannot finalize; invalid PNG screenshots: {invalid_screenshots}")

    review_path = root / "screenshot-review.json"
    if not review_path.is_file():
        raise MatrixFailure("cannot finalize; screenshot-review.json is missing")
    screenshot_review = json.loads(review_path.read_text(encoding="utf-8"))
    screenshot_checksums = {
        name: f"sha256:{sha256_file(root / 'screenshots' / name)}"
        for name in screenshot_names
    }
    try:
        reviewed_at = dt.datetime.fromisoformat(
            str(screenshot_review.get("reviewedAt", "")).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise MatrixFailure("cannot finalize; screenshot review time is invalid") from error
    if reviewed_at.tzinfo is None:
        raise MatrixFailure("cannot finalize; screenshot review time must include a timezone")
    reviewed_timestamp = reviewed_at.timestamp()
    review_assertions = screenshot_review.get("assertions") or {}
    required_review_assertions = {
        "matchesExpectedSections",
        "noPrivateNamesVisible",
        "noLocalHomePathsVisible",
        "stateLabelsReadable",
    }
    if (
        screenshot_review.get("status") != "approved"
        or not screenshot_review.get("reviewedBy")
        or not screenshot_review.get("reviewedAt")
        or screenshot_review.get("screenshots") != screenshot_names
        or screenshot_review.get("checksums") != screenshot_checksums
        or not required_review_assertions.issubset(review_assertions)
        or not all(review_assertions[name] is True for name in required_review_assertions)
        or any(path.stat().st_mtime > reviewed_timestamp + 1 for path in screenshot_paths)
    ):
        raise MatrixFailure("cannot finalize; screenshot visual review is not approved")

    publishable_text = [
        root / "report.md",
        root / "dashboard.html",
        root / "announcement.md",
        root / "summary.json",
        review_path,
    ]
    scan_publishable_files(root, publishable_text)
    checksummed = required + [review_path] + screenshot_paths
    cli_cases = summary["results"]["cliCases"]
    tui_cases = summary["results"]["tuiCases"]
    mcp_cases = summary["results"]["mcpCases"]
    expected_slugs = {scenario["slug"] for scenario in MATRIX}
    for label, cases in (
        ("CLI", cli_cases),
        ("TUI", tui_cases),
        ("MCP", mcp_cases),
    ):
        actual_slugs = {case.get("slug") for case in cases}
        if (
            len(cases) != len(expected_slugs)
            or actual_slugs != expected_slugs
            or any(case.get("status") != "passed" for case in cases)
        ):
            raise MatrixFailure(f"cannot finalize; {label} matrix is incomplete")
    if any(
        case.get("mcpWritesEnabled") is not False
        or case.get("unreviewedApplyBlocked") is not True
        or case.get("humanActionHandoff") is not True
        for case in mcp_cases
    ):
        raise MatrixFailure(
            "cannot finalize; MCP no-write human-action handoff contract is incomplete"
        )
    manifest = {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "runId": root.name,
        "source": {
            "gitCommit": tested_binary["gitHead"],
            "workspaceStateSha256": tested_binary["workspaceStateSha256"],
            "workspaceDirty": tested_binary["workspaceDirty"],
            "binarySha256": f"sha256:{tested_binary['sha256']}",
        },
        "assertions": {
            "report": True,
            "dashboard": True,
            "screenshots": True,
            "cliMatrix": True,
            "tuiMatrix": True,
            "mcpMatrix": True,
            "mcpNoWriteHumanActionHandoff": True,
            "liveInventorySummary": True,
            "qualityGates": True,
            "publishableTextSanitized": True,
            "screenshotsVisuallyApproved": True,
        },
        "counts": {
            "cliCases": len(cli_cases),
            "tuiCases": len(tui_cases),
            "mcpCases": len(mcp_cases),
            "screenshots": len(screenshot_names),
            "checksummedFiles": len(checksummed),
        },
        "publishable": [
            "report.md",
            "dashboard.html",
            "announcement.md",
            "screenshot-review.json",
            *[f"screenshots/{name}" for name in screenshot_names],
        ],
        "sensitiveLocalOnly": ["cases/", "tui-cases/", "mcp-cases/"],
        "checksums": {
            str(path.relative_to(root)): f"sha256:{sha256_file(path)}"
            for path in checksummed
        },
    }
    write_json(root / "evidence-manifest.json", manifest)
    tighten_artifact_permissions(root)
    return manifest
