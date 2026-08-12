#!/usr/bin/env python3
"""Run Unpin's local provider matrix without mutating live provider state."""

from __future__ import annotations

import argparse
import collections
import contextlib
import datetime as dt
import hashlib
import math
import json
import os
import plistlib
import signal
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = (REPO_ROOT / "crates/unpin-core/tests/fixtures").resolve()
EVIDENCE_ROOT = REPO_ROOT / "tmp"
FIXTURE_TEMP_ROOT = Path(tempfile.gettempdir()).resolve()
_PLATFORM = os.name
_GRACEFUL_TERMINATION_SECONDS = 2
CAPABILITY_MATRIX = json.loads(
    (FIXTURE_ROOT / "capability-matrix.json").read_text(encoding="utf-8")
)["providers"]

MATRIX: list[dict[str, Any]] = [
    {
        "slug": "claude-global-skill",
        "provider": "claude",
        "kind": "skill",
        "layer": "global",
        "id": "claude:global:skill:example-claude-global-skill",
        "surface": "provider-owned Agent Skill",
    },
    {
        "slug": "claude-project-skill",
        "provider": "claude",
        "kind": "skill",
        "layer": "project",
        "id": "claude:project:skill:example-claude-skill",
        "surface": "repository Agent Skill",
    },
    {
        "slug": "claude-global-connector-plugin",
        "provider": "claude",
        "kind": "plugin",
        "layer": "global",
        "id": "claude:global:tool:settings:connector-kit@example-marketplace",
        "surface": "enabledPlugins connector with bundled MCP metadata",
    },
    {
        "slug": "claude-project-plugin",
        "provider": "claude",
        "kind": "plugin",
        "layer": "project",
        "id": "claude:project:tool:settings:github",
        "surface": "repository enabledPlugins entry",
    },
    {
        "slug": "claude-global-mcp",
        "provider": "claude",
        "kind": "mcp",
        "layer": "global",
        "id": "claude:global:configured-mcp:global-docs",
        "surface": "user configured MCP",
    },
    {
        "slug": "claude-project-mcp",
        "provider": "claude",
        "kind": "mcp",
        "layer": "project",
        "id": "claude:project:configured-mcp:github",
        "surface": "repository MCP approval map",
    },
    {
        "slug": "codex-global-skill",
        "provider": "codex",
        "kind": "skill",
        "layer": "global",
        "id": "codex:global:skill:example-shared-global-skill",
        "surface": "shared Agent Skill with cross-provider vault state",
    },
    {
        "slug": "codex-project-skill",
        "provider": "codex",
        "kind": "skill",
        "layer": "project",
        "id": "codex:project:skill:example-shared-project-skill",
        "surface": "repository shared Agent Skill with cross-provider vault state",
    },
    {
        "slug": "codex-global-connector-plugin",
        "provider": "codex",
        "kind": "plugin",
        "layer": "global",
        "id": "codex:global:plugin-config:config:connector-kit@example-marketplace",
        "surface": "native plugin state with bundled MCP metadata",
    },
    {
        "slug": "codex-global-mcp",
        "provider": "codex",
        "kind": "mcp",
        "layer": "global",
        "id": "codex:global:configured-mcp:github",
        "surface": "user mcp_servers state",
    },
    {
        "slug": "codex-project-mcp",
        "provider": "codex",
        "kind": "mcp",
        "layer": "project",
        "id": "codex:project:configured-mcp:project-docs",
        "surface": "repository mcp_servers state",
    },
    {
        "slug": "cursor-global-skill",
        "provider": "cursor",
        "kind": "skill",
        "layer": "global",
        "id": "cursor:global:skill:example-cursor-skill",
        "surface": "provider-owned Agent Skill",
        "liveIdExcludes": "@compat/",
    },
    {
        "slug": "cursor-global-shared-skill",
        "provider": "cursor",
        "kind": "skill",
        "layer": "global",
        "id": "cursor:global:skill:@compat/agents/example-shared-global-skill",
        "surface": "shared .agents compatibility skill",
        "liveIdContains": "@compat/agents/",
    },
    {
        "slug": "cursor-project-skill",
        "provider": "cursor",
        "kind": "skill",
        "layer": "project",
        "id": "cursor:project:skill:example-cursor-project-skill",
        "surface": "repository Agent Skill",
    },
    {
        "slug": "cursor-global-connector-plugin",
        "provider": "cursor",
        "kind": "plugin",
        "layer": "global",
        "id": "cursor:global:plugin-manifest:local:example-plugin",
        "surface": "local plugin bundle with MCP metadata",
        "liveIdContains": "plugin-manifest:local:",
    },
    {
        "slug": "cursor-global-mcp",
        "provider": "cursor",
        "kind": "mcp",
        "layer": "global",
        "id": "cursor:global:configured-mcp:modern-global",
        "surface": "modern user mcp.json",
    },
    {
        "slug": "cursor-project-mcp",
        "provider": "cursor",
        "kind": "mcp",
        "layer": "project",
        "id": "cursor:project:configured-mcp:project-docs",
        "surface": "repository mcp.json",
    },
    {
        "slug": "pi-global-skill",
        "provider": "pi",
        "kind": "skill",
        "layer": "global",
        "id": "pi:global:skill:workflows/example-pi-global-skill",
        "surface": "provider-owned recursive Pi Agent Skill",
    },
    {
        "slug": "pi-project-skill",
        "provider": "pi",
        "kind": "skill",
        "layer": "project",
        "id": "pi:project:skill:example-pi-project-skill",
        "surface": "repository Pi Agent Skill",
    },
    {
        "slug": "pi-global-package-extensions",
        "provider": "pi",
        "kind": "plugin",
        "layer": "global",
        "id": "pi:global:plugin-config:package-extensions:npm:example-pi-connector",
        "surface": "native package extension resource filter",
    },
    {
        "slug": "pi-project-package-extensions",
        "provider": "pi",
        "kind": "plugin",
        "layer": "project",
        "id": "pi:project:plugin-config:package-extensions:npm:example-pi-project-connector",
        "surface": "repository package extension resource filter",
    },
    {
        "slug": "opencode-global-skill",
        "provider": "opencode",
        "kind": "skill",
        "layer": "global",
        "id": "opencode:global:skill:example-opencode-global-skill",
        "surface": "provider-owned OpenCode Agent Skill",
    },
    {
        "slug": "opencode-project-skill",
        "provider": "opencode",
        "kind": "skill",
        "layer": "project",
        "id": "opencode:project:skill:example-opencode-project-skill",
        "surface": "repository OpenCode Agent Skill",
    },
    {
        "slug": "opencode-global-npm-plugin",
        "provider": "opencode",
        "kind": "plugin",
        "layer": "global",
        "id": "opencode:global:plugin-config:npm:example-opencode-connector",
        "surface": "global npm plugin config reference",
    },
    {
        "slug": "opencode-project-npm-plugin",
        "provider": "opencode",
        "kind": "plugin",
        "layer": "project",
        "id": "opencode:project:plugin-config:npm:example-opencode-project-connector",
        "surface": "repository npm plugin config reference",
    },
    {
        "slug": "opencode-global-mcp",
        "provider": "opencode",
        "kind": "mcp",
        "layer": "global",
        "id": "opencode:global:configured-mcp:example-global",
        "surface": "global native mcp enabled state",
    },
    {
        "slug": "opencode-project-mcp",
        "provider": "opencode",
        "kind": "mcp",
        "layer": "project",
        "id": "opencode:project:configured-mcp:example-project",
        "surface": "repository native mcp enabled state",
    },
    {
        "slug": "zed-global-skill",
        "provider": "zed",
        "kind": "skill",
        "layer": "global",
        "id": "zed:global:skill:example-shared-global-skill",
        "surface": "global standard Agent Skill",
    },
    {
        "slug": "zed-project-skill",
        "provider": "zed",
        "kind": "skill",
        "layer": "project",
        "id": "zed:project:skill:example-shared-project-skill",
        "surface": "repository standard Agent Skill",
    },
    {
        "slug": "zed-global-mcp",
        "provider": "zed",
        "kind": "mcp",
        "layer": "global",
        "id": "zed:global:configured-mcp:github",
        "surface": "global context_servers JSONC state",
    },
    {
        "slug": "zed-project-mcp",
        "provider": "zed",
        "kind": "mcp",
        "layer": "project",
        "id": "zed:project:configured-mcp:local-docs",
        "surface": "repository context_servers JSONC state",
    },
]

DECLARED_EXCEPTIONS = [
    {
        "provider": "codex",
        "kind": "plugin",
        "layer": "project",
        "status": CAPABILITY_MATRIX["codex"]["pluginProjectScope"],
        "reason": "Current Codex plugin host contract is user-scoped.",
    },
    {
        "provider": "cursor",
        "kind": "plugin",
        "layer": "project",
        "status": CAPABILITY_MATRIX["cursor"]["pluginProjectScope"],
        "reason": "Marketplace project installs are inventoried from Cursor-owned state.",
    },
    {
        "provider": "pi",
        "kind": "mcp",
        "layer": "global",
        "status": CAPABILITY_MATRIX["pi"]["configuredMcps"],
        "reason": "Pi has no native MCP core; connector behavior belongs to package extensions.",
    },
    {
        "provider": "pi",
        "kind": "mcp",
        "layer": "project",
        "status": CAPABILITY_MATRIX["pi"]["configuredMcps"],
        "reason": "Pi has no native MCP core; connector behavior belongs to package extensions.",
    },
    {
        "provider": "zed",
        "kind": "plugin",
        "layer": "global",
        "status": CAPABILITY_MATRIX["zed"]["pluginGlobalScope"],
        "reason": "Zed reusable agent instructions use standard Agent Skills.",
    },
    {
        "provider": "zed",
        "kind": "plugin",
        "layer": "project",
        "status": CAPABILITY_MATRIX["zed"]["pluginProjectScope"],
        "reason": "Zed reusable agent instructions use standard Agent Skills.",
    },
]

SCREENSHOTS = [
    "overview.png",
    "live-library.png",
    "coverage-matrix.png",
    "tui-library.png",
    "claude-states.png",
    "codex-states.png",
    "cursor-states.png",
    "pi-states.png",
    "opencode-states.png",
    "zed-states.png",
    "mcp-states.png",
    "desktop-packages-light.png",
    "desktop-packages-dark.png",
]


class MatrixFailure(RuntimeError):
    pass


class MatrixCommandTimeout(MatrixFailure):
    def __init__(
        self,
        command: list[str],
        timeout_seconds: float,
        stdout: str,
        stderr: str,
        termination_issue: str | None = None,
    ) -> None:
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.stdout = stdout
        self.stderr = stderr
        self.termination_issue = termination_issue
        super().__init__(
            f"command timed out after {timeout_seconds}s: {' '.join(command)}"
        )


def parse_args() -> argparse.Namespace:
    timestamp = dt.datetime.now().astimezone().strftime("%Y-%m-%d-%H%M%S")
    parser = argparse.ArgumentParser(
        description=(
            "Capture installed provider inventory read-only, then run isolated CLI and MCP "
            "toggle/restore cycles against committed fixtures."
        )
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=EVIDENCE_ROOT / f"{timestamp}-provider-matrix",
        help="Private evidence directory under the repository tmp/ directory.",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=REPO_ROOT / "target/debug/unpin",
        help="Unpin binary to test.",
    )
    parser.add_argument("--home-root", type=Path, default=Path.home())
    parser.add_argument("--project-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--cursor-root",
        type=Path,
        default=Path.home() / "Library/Application Support/Cursor/User",
    )
    parser.add_argument(
        "--cargo",
        type=Path,
        default=default_cargo_path(),
        help="Cargo executable used for verification gates.",
    )
    parser.add_argument("--skip-live", action="store_true")
    parser.add_argument("--skip-quality-gates", action="store_true")
    parser.add_argument(
        "--quality-gate-timeout-seconds",
        type=quality_gate_timeout_seconds,
        default=1_200,
        help=(
            "Maximum seconds per quality gate (default: 1200). "
            "Use 0 to wait without a timeout."
        ),
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--capture-screenshots",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Capture dashboard sections through the native WebKit XCTest renderer. "
            "Enabled automatically on macOS; use --no-capture-screenshots for the "
            "documented manual workflow."
        ),
    )
    parser.add_argument(
        "--finalize",
        action="store_true",
        help="Validate screenshots and write evidence-manifest.json for an existing run.",
    )
    return parser.parse_args()


def capture_screenshots_enabled(
    requested: bool | None,
    *,
    platform: str = sys.platform,
) -> bool:
    return platform == "darwin" if requested is None else requested


def quality_gate_timeout_seconds(value: str) -> float | None:
    try:
        seconds = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "quality-gate timeout must be a non-negative number"
        ) from error
    if not math.isfinite(seconds) or seconds < 0:
        raise argparse.ArgumentTypeError(
            "quality-gate timeout must be a finite non-negative number"
        )
    return None if seconds == 0 else seconds


def default_cargo_path() -> Path:
    cargo = shutil.which("cargo")
    if cargo:
        return Path(cargo)
    return Path.home() / ".cargo/bin/cargo"


def validate_artifact_root(path: Path) -> Path:
    if EVIDENCE_ROOT.is_symlink():
        raise MatrixFailure("repository tmp must not be a symlink")
    evidence_root = EVIDENCE_ROOT.resolve()
    resolved = path.expanduser().resolve()
    if not resolved.is_relative_to(evidence_root):
        raise MatrixFailure("artifact root must be under repository tmp")
    if not any(
        marker in resolved.name for marker in ("provider-matrix", "local-matrix")
    ):
        raise MatrixFailure(
            "artifact directory name must contain 'provider-matrix' "
            "or legacy 'local-matrix'"
        )
    return resolved


def fixture_subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["TMPDIR"] = str(FIXTURE_TEMP_ROOT)
    return environment


def validate_fixture_temporary_root(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_relative_to(FIXTURE_TEMP_ROOT):
        raise MatrixFailure("fixture workspace must be under the system temporary root")
    return resolved


@contextlib.contextmanager
def private_fixture_workspace() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(
        prefix="unpin-provider-matrix-",
        dir=FIXTURE_TEMP_ROOT,
    ) as temporary_directory:
        workspace_root = validate_fixture_temporary_root(Path(temporary_directory))
        workspace_root.chmod(0o700)
        yield workspace_root


def prepare_artifact_root(path: Path, overwrite: bool) -> Path:
    root = validate_artifact_root(path)
    if root.exists() and any(root.iterdir()):
        if not overwrite:
            raise MatrixFailure(f"artifact root already exists and is non-empty: {root}")
        shutil.rmtree(root)
    for directory in [
        root,
        root / "raw",
        root / "raw/live-plans",
        root / "raw/verification",
        root / "cases",
        root / "tui-cases",
        root / "mcp-cases",
        root / "screenshots",
    ]:
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
    if root.stat().st_mode & 0o777 != 0o700:
        raise MatrixFailure(f"artifact root permissions are not private: {root}")
    return root


def run_command(
    command: list[str | Path],
    *,
    input_text: str | None = None,
    check: bool = True,
    timeout_seconds: float | None = 600,
) -> subprocess.CompletedProcess[str]:
    rendered = [str(part) for part in command]
    environment = (
        fixture_subprocess_environment() if "--fixture-root" in rendered else None
    )
    process_options: dict[str, Any] = {}
    if _PLATFORM == "posix":
        process_options["start_new_session"] = True
    elif _PLATFORM == "nt":
        process_options["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    with contextlib.ExitStack() as capture_stack:
        stdout_capture = capture_stack.enter_context(
            tempfile.TemporaryFile(mode="w+b")
        )
        stderr_capture = capture_stack.enter_context(
            tempfile.TemporaryFile(mode="w+b")
        )
        process = subprocess.Popen(
            rendered,
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=stdout_capture,
            stderr=stderr_capture,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            **process_options,
        )
        try:
            process.communicate(
                input=input_text,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            _close_process_stdin(process)
            termination_issues = _terminate_and_wait(process)
            stdout = _read_capture(stdout_capture)
            stderr = _read_capture(stderr_capture)
            raise MatrixCommandTimeout(
                rendered,
                timeout_seconds,
                stdout,
                stderr,
                "; ".join(termination_issues) if termination_issues else None,
            ) from error
        except BaseException:
            _close_process_stdin(process)
            _terminate_and_wait(process)
            raise
        finally:
            _close_process_stdin(process)
        stdout = _read_capture(stdout_capture)
        stderr = _read_capture(stderr_capture)
    completed = subprocess.CompletedProcess(
        rendered,
        process.returncode,
        stdout,
        stderr,
    )
    if check and completed.returncode != 0:
        raise MatrixFailure(
            f"command failed ({completed.returncode}): {' '.join(rendered)}\n"
            f"stdout:\n{completed.stdout[-4000:]}\nstderr:\n{completed.stderr[-4000:]}"
        )
    return completed


def _read_capture(capture: Any) -> str:
    capture.flush()
    capture.seek(0)
    decoded = capture.read().decode(errors="replace")
    return decoded.replace("\r\n", "\n").replace("\r", "\n")


def _close_process_stdin(process: subprocess.Popen[str]) -> None:
    if process.stdin is not None:
        with contextlib.suppress(OSError, ValueError):
            process.stdin.close()


def _signal_process_tree(
    process: subprocess.Popen[str],
    *,
    force: bool,
) -> list[str]:
    issues: list[str] = []
    if process.poll() is not None:
        return issues
    tree_signalled = False
    if _PLATFORM == "posix":
        try:
            process_group = os.getpgid(process.pid)
            if process_group != process.pid:
                issues.append("process-group identity changed before termination")
            elif process.poll() is None:
                os.killpg(
                    process_group,
                    signal.SIGKILL if force else signal.SIGTERM,
                )
                tree_signalled = True
        except OSError as error:
            issues.append(f"process-group signal failed: {error.__class__.__name__}")
    elif _PLATFORM == "nt":
        try:
            command = ["taskkill", "/PID", str(process.pid), "/T"]
            if force:
                command.append("/F")
            tree_kill = subprocess.run(
                command,
                capture_output=True,
                check=False,
                timeout=5,
            )
            if tree_kill.returncode == 0:
                tree_signalled = True
            elif process.poll() is None:
                issues.append(
                    f"process-tree signal failed with exit code {tree_kill.returncode}"
                )
        except (OSError, subprocess.SubprocessError) as error:
            issues.append(f"process-tree signal failed: {error.__class__.__name__}")
    if not tree_signalled and process.poll() is None:
        try:
            if force:
                process.kill()
            else:
                process.terminate()
        except OSError as error:
            issues.append(f"direct process signal failed: {error.__class__.__name__}")
    return issues


def _terminate_and_wait(process: subprocess.Popen[str]) -> list[str]:
    if _PLATFORM == "nt":
        try:
            issues = _signal_process_tree(process, force=True)
        except Exception as error:
            issues = [f"forced process-tree cleanup failed: {error.__class__.__name__}"]
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            issues.append(f"forced process wait failed: {error.__class__.__name__}")
        return issues

    process_group: int | None = None
    if _PLATFORM == "posix" and process.poll() is None:
        try:
            candidate = os.getpgid(process.pid)
            if candidate == process.pid:
                process_group = candidate
        except OSError:
            pass
    try:
        issues = _signal_process_tree(process, force=False)
    except Exception as error:
        issues = [f"process-tree cleanup failed: {error.__class__.__name__}"]
    try:
        process.wait(timeout=_GRACEFUL_TERMINATION_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    except (OSError, ValueError) as error:
        issues.append(f"process wait failed: {error.__class__.__name__}")

    if process_group is not None:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            issues.append(f"forced process-group cleanup failed: {error.__class__.__name__}")
    elif process.poll() is None:
        try:
            issues.extend(_signal_process_tree(process, force=True))
        except Exception as error:
            issues.append(f"forced process-tree cleanup failed: {error.__class__.__name__}")

    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            issues.append(f"forced process wait failed: {error.__class__.__name__}")
    return issues


def parse_json_output(output: str) -> Any:
    candidates = [index for index in (output.find("{"), output.find("[")) if index >= 0]
    if not candidates:
        raise MatrixFailure(f"command did not emit JSON: {output[-2000:]}")
    return json.loads(output[min(candidates) :])


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    path.chmod(0o600)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_env_path(path: Path) -> bool:
    return any(part.startswith(".env") for part in path.parts)


def copy_fixture_tree(destination: Path) -> None:
    shutil.copytree(
        FIXTURE_ROOT,
        destination,
        symlinks=True,
        ignore=shutil.ignore_patterns(".env*"),
    )


def digest_path(path: Path) -> str:
    digest = hashlib.sha256()
    if not path.exists() and not path.is_symlink():
        return "missing"
    if path.is_symlink():
        digest.update(f"symlink:{os.readlink(path)}".encode())
        return f"sha256:{digest.hexdigest()}"
    if path.is_file():
        return f"sha256:{sha256_file(path)}"
    for child in sorted(path.rglob("*"), key=lambda item: item.as_posix()):
        relative = child.relative_to(path)
        if is_env_path(relative):
            raise MatrixFailure(f"refusing to hash .env input: {child}")
        digest.update(relative.as_posix().encode())
        if child.is_symlink():
            digest.update(f"symlink:{os.readlink(child)}".encode())
        elif child.is_file():
            digest.update(bytes.fromhex(sha256_file(child)))
        elif child.is_dir():
            digest.update(b"directory")
    return f"sha256:{digest.hexdigest()}"


def sanitize_path(value: str, *, artifact_root: Path, home_root: Path) -> str:
    replacements = [
        (str(artifact_root), "<ARTIFACT>"),
        (str(REPO_ROOT), "<REPO>"),
        (str(home_root), "<HOME>"),
    ]
    rendered = value
    for original, replacement in replacements:
        rendered = rendered.replace(original, replacement)
    return rendered


def command_version(command: str) -> dict[str, Any]:
    executable = shutil.which(command)
    if not executable:
        return {"available": False, "surface": "cli", "version": None}
    process = run_command([executable, "--version"], check=False)
    version = (process.stdout or process.stderr).strip().splitlines()
    return {
        "available": process.returncode == 0,
        "surface": "cli",
        "version": version[0] if version else None,
    }


def app_version(candidates: list[Path]) -> dict[str, Any]:
    for bundle in candidates:
        plist_path = bundle / "Contents/Info.plist"
        if not plist_path.is_file():
            continue
        with plist_path.open("rb") as handle:
            info = plistlib.load(handle)
        return {
            "available": True,
            "surface": "app",
            "version": info.get("CFBundleShortVersionString"),
            "channel": bundle.stem,
        }
    return {"available": False, "surface": "app", "version": None}


def installed_hosts() -> dict[str, Any]:
    return {
        "codex": command_version("codex"),
        "claude": command_version("claude"),
        "pi": command_version("pi"),
        "opencode": command_version("opencode"),
        "cursor": app_version(
            [Path("/Applications/Cursor.app"), Path.home() / "Applications/Cursor.app"]
        ),
        "zed": app_version(
            [
                Path("/Applications/Zed.app"),
                Path("/Applications/Zed Preview.app"),
                Path.home() / "Applications/Zed.app",
                Path.home() / "Applications/Zed Preview.app",
            ]
        ),
    }


def list_command(
    binary: Path,
    *,
    fixture_root: Path | None = None,
    app_state_root: Path,
    home_root: Path | None = None,
    project_root: Path | None = None,
    cursor_root: Path | None = None,
    provider: str | None = None,
    kind: str | None = None,
    layer: str | None = None,
) -> list[str | Path]:
    command: list[str | Path] = [binary, "list"]
    if fixture_root is not None:
        command.extend(
            [
                "--fixture-root",
                fixture_root,
                "--home-root",
                fixture_root,
                "--project-root",
                fixture_root,
            ]
        )
    else:
        command.extend(["--home-root", home_root or Path.home()])
        command.extend(["--project-root", project_root or REPO_ROOT])
        if cursor_root is not None and cursor_root.exists():
            command.extend(["--cursor-root", cursor_root])
    for flag, value in (("--provider", provider), ("--kind", kind), ("--layer", layer)):
        if value is not None:
            command.extend([flag, value])
    command.extend(["--app-state-root", app_state_root, "--json"])
    return command


def read_inventory(
    binary: Path,
    fixture_root: Path,
    app_state_root: Path,
    scenario: dict[str, Any],
) -> dict[str, Any]:
    process = run_command(
        list_command(
            binary,
            fixture_root=fixture_root,
            app_state_root=app_state_root,
            provider=scenario["provider"],
            kind=scenario["kind"],
            layer=scenario["layer"],
        )
    )
    return parse_json_output(process.stdout)


def read_full_inventory(
    binary: Path,
    fixture_root: Path,
    app_state_root: Path,
) -> dict[str, Any]:
    process = run_command(
        list_command(
            binary,
            fixture_root=fixture_root,
            app_state_root=app_state_root,
        )
    )
    return parse_json_output(process.stdout)


def find_item(inventory: dict[str, Any], item_id: str) -> dict[str, Any]:
    matches = [item for item in inventory["items"] if item["id"] == item_id]
    if len(matches) != 1:
        raise MatrixFailure(f"expected one inventory item for {item_id}, got {len(matches)}")
    return matches[0]


def fixture_toggle_command(
    binary: Path,
    fixture_root: Path,
    app_state_root: Path,
    scenario: dict[str, Any],
    *,
    plan_fingerprint: str | None = None,
) -> list[str | Path]:
    command: list[str | Path] = [
        binary,
        "toggle",
        "--fixture-root",
        fixture_root,
        "--home-root",
        fixture_root,
        "--project-root",
        fixture_root,
        "--app-state-root",
        app_state_root,
        "--provider",
        scenario["provider"],
        "--kind",
        scenario["kind"],
        "--layer",
        scenario["layer"],
        "--id",
        scenario["id"],
    ]
    if plan_fingerprint is not None:
        command.extend(
            ["--apply", "--confirm", "--plan-fingerprint", plan_fingerprint]
        )
    command.append("--json")
    return command


def fixture_restore_command(
    binary: Path,
    fixture_root: Path,
    app_state_root: Path,
    backup_id: str,
    *,
    plan_fingerprint: str | None = None,
) -> list[str | Path]:
    command: list[str | Path] = [
        binary,
        "restore",
        backup_id,
        "--fixture-root",
        fixture_root,
        "--home-root",
        fixture_root,
        "--project-root",
        fixture_root,
        "--app-state-root",
        app_state_root,
    ]
    if plan_fingerprint is not None:
        command.extend(
            ["--apply", "--confirm", "--plan-fingerprint", plan_fingerprint]
        )
    command.append("--json")
    return command


def validate_manifest(app_state_root: Path, backup_id: str) -> dict[str, Any]:
    manifest_path = app_state_root / "backups" / backup_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    authenticity = manifest.get("authenticity") or {}
    required_authentication = {"algorithm", "keyId", "payloadDigests", "tag"}
    if manifest.get("version") != 3:
        raise MatrixFailure(f"{backup_id} did not use backup manifest v3")
    if not required_authentication.issubset(authenticity):
        raise MatrixFailure(f"{backup_id} is missing authenticated manifest fields")
    return {
        "version": manifest["version"],
        "algorithm": authenticity["algorithm"],
        "payloadDigests": len(authenticity["payloadDigests"]),
    }


def validate_audit(app_state_root: Path) -> dict[str, int]:
    audit_path = app_state_root / "audit/log.jsonl"
    events = [
        json.loads(line)["event"]
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    counts = collections.Counter(events)
    if counts["apply"] != 2 or counts["restore"] != 2:
        raise MatrixFailure(f"expected 2 apply and 2 restore events, got {dict(counts)}")
    return dict(sorted(counts.items()))
