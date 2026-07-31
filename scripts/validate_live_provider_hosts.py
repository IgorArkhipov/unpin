#!/usr/bin/env python3
"""Validate Pi and OpenCode compatibility without touching real provider state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Use installed Pi and OpenCode binaries in a disposable home/project, "
            "then verify Unpin discovery and no-write plans."
        )
    )
    parser.add_argument("--unpin", type=Path, default=Path("target/debug/unpin"))
    parser.add_argument("--pi", default="pi")
    parser.add_argument("--opencode", default="opencode")
    return parser.parse_args()


def executable(command: str | Path) -> Path:
    candidate = Path(command)
    resolved = (
        candidate.expanduser().resolve(strict=True)
        if candidate.parent != Path(".")
        else Path(shutil.which(str(command)) or "").resolve()
    )
    if not resolved.is_file():
        raise SystemExit(f"required executable is unavailable: {command}")
    return resolved


def isolated_environment(home: Path, executable_paths: list[Path]) -> dict[str, str]:
    search_paths = [str(path.parent) for path in executable_paths]
    inherited_path = os.environ.get("PATH")
    if inherited_path:
        search_paths.append(inherited_path)
    environment = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "PATH": os.pathsep.join(search_paths),
        "PI_OFFLINE": "1",
        "PI_TELEMETRY": "0",
        "NO_COLOR": "1",
    }
    for name in ("LANG", "LC_ALL", "TMPDIR"):
        if value := os.environ.get(name):
            environment[name] = value
    return environment


def unpin_environment(host_environment: dict[str, str]) -> dict[str, str]:
    environment = dict(host_environment)
    # macOS locates the login keychain through HOME. Unpin still receives
    # explicit disposable home, project, state, and Cursor roots on every call.
    for name in ("HOME", "USER", "LOGNAME"):
        if value := os.environ.get(name):
            environment[name] = value
    return environment


def run(
    command: list[str | Path],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    rendered = [str(part) for part in command]
    process = subprocess.run(
        rendered,
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if process.returncode != 0:
        raise SystemExit(
            f"command failed ({process.returncode}): {rendered[0]}\n"
            f"stdout:\n{process.stdout[-2000:]}\n"
            f"stderr:\n{process.stderr[-2000:]}"
        )
    return process


def write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{json.dumps(document, indent=2)}\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_version(
    command: Path,
    *,
    cwd: Path,
    environment: dict[str, str],
) -> str:
    process = run([command, "--version"], cwd=cwd, environment=environment)
    version = f"{process.stdout}\n{process.stderr}".strip().splitlines()
    if not version:
        raise SystemExit(f"{command.name} did not report a version")
    return version[0]


def unpin_list(
    unpin: Path,
    provider: str,
    *,
    home: Path,
    project: Path,
    cursor: Path,
    state: Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    process = run(
        [
            unpin,
            "list",
            "--home-root",
            home,
            "--project-root",
            project,
            "--cursor-root",
            cursor,
            "--app-state-root",
            state,
            "--provider",
            provider,
            "--json",
        ],
        cwd=project,
        environment=environment,
    )
    return json.loads(process.stdout)


def assert_discovery(
    document: dict[str, Any],
    expected: dict[str, bool],
) -> None:
    if document.get("warnings"):
        raise SystemExit("live-host discovery produced warnings")
    actual = {
        item["id"]: item["enabled"]
        for item in document.get("items", [])
        if item.get("mutability") == "read-write"
    }
    if actual != expected:
        raise SystemExit(
            f"live-host discovery mismatch: expected {sorted(expected)}, "
            f"found {sorted(actual)}"
        )


def assert_dry_run(
    unpin: Path,
    *,
    provider: str,
    kind: str,
    layer: str,
    item_id: str,
    home: Path,
    project: Path,
    cursor: Path,
    state: Path,
    environment: dict[str, str],
) -> None:
    process = run(
        [
            unpin,
            "toggle",
            "--home-root",
            home,
            "--project-root",
            project,
            "--cursor-root",
            cursor,
            "--app-state-root",
            state,
            "--provider",
            provider,
            "--kind",
            kind,
            "--layer",
            layer,
            "--id",
            item_id,
            "--json",
        ],
        cwd=project,
        environment=environment,
    )
    plan = json.loads(process.stdout)
    if (
        plan.get("status") != "dry-run"
        or plan.get("writes") != "no writes were performed"
        or plan.get("selection", {}).get("id") != item_id
        or len(plan.get("operations", [])) != 1
        or not FINGERPRINT_PATTERN.fullmatch(str(plan.get("planFingerprint", "")))
    ):
        raise SystemExit(f"invalid no-write plan for {provider}/{layer}/{kind}")


def main() -> int:
    args = parse_args()
    unpin = executable(args.unpin)
    pi = executable(args.pi)
    opencode = executable(args.opencode)

    with tempfile.TemporaryDirectory(prefix="unpin-live-provider-hosts-") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        home = root / "home"
        project = root / "project"
        cursor = root / "cursor"
        state = root / "state"
        package = root / "pi-package"
        for directory in (home, project, cursor, state, package / "extensions"):
            directory.mkdir(parents=True, exist_ok=True)

        write_json(
            package / "package.json",
            {
                "name": "unpin-live-pi-package",
                "version": "1.0.0",
                "type": "module",
                "pi": {"extensions": ["./extensions/index.js"]},
            },
        )
        (package / "extensions/index.js").write_text(
            "export default function unpinLiveValidationExtension() {}\n",
            encoding="utf-8",
        )

        environment = isolated_environment(home, [pi, opencode])
        unpin_env = unpin_environment(environment)
        pi_version = parse_version(pi, cwd=project, environment=environment)
        opencode_version = parse_version(
            opencode,
            cwd=project,
            environment=environment,
        )

        run([pi, "install", package], cwd=project, environment=environment)
        run([pi, "install", package, "-l"], cwd=project, environment=environment)
        run([pi, "list"], cwd=project, environment=environment)

        pi_global_path = home / ".pi/agent/settings.json"
        pi_project_path = project / ".pi/settings.json"
        pi_global_source = json.loads(pi_global_path.read_text(encoding="utf-8"))[
            "packages"
        ][0]
        pi_project_source = json.loads(pi_project_path.read_text(encoding="utf-8"))[
            "packages"
        ][0]

        opencode_global_path = home / ".config/opencode/opencode.json"
        opencode_project_path = project / "opencode.json"
        write_json(
            opencode_global_path,
            {
                "$schema": "https://opencode.ai/config.json",
                "autoupdate": False,
                "share": "disabled",
                "mcp": {
                    "unpin-live-global": {
                        "type": "local",
                        "command": ["/usr/bin/false"],
                        "enabled": True,
                    }
                },
            },
        )
        write_json(
            opencode_project_path,
            {
                "$schema": "https://opencode.ai/config.json",
                "mcp": {
                    "unpin-live-project": {
                        "type": "local",
                        "command": ["/usr/bin/false"],
                        "enabled": False,
                    }
                },
            },
        )
        resolved_config = json.loads(
            run(
                [opencode, "--pure", "debug", "config"],
                cwd=project,
                environment=environment,
            ).stdout
        )
        resolved_mcp = resolved_config.get("mcp", {})
        if (
            resolved_mcp.get("unpin-live-global", {}).get("enabled") is not True
            or resolved_mcp.get("unpin-live-project", {}).get("enabled") is not False
        ):
            raise SystemExit("OpenCode did not resolve global/project MCP state")

        global_config = json.loads(opencode_global_path.read_text(encoding="utf-8"))
        project_config = json.loads(opencode_project_path.read_text(encoding="utf-8"))
        global_config["plugin"] = ["unpin-live-global-plugin"]
        project_config["plugin"] = ["unpin-live-project-plugin"]
        write_json(opencode_global_path, global_config)
        write_json(opencode_project_path, project_config)

        pi_expected = {
            f"pi:global:plugin-config:package-extensions:{pi_global_source}": True,
            f"pi:project:plugin-config:package-extensions:{pi_project_source}": True,
        }
        opencode_expected = {
            "opencode:global:configured-mcp:unpin-live-global": True,
            "opencode:global:plugin-config:npm:unpin-live-global-plugin": True,
            "opencode:project:configured-mcp:unpin-live-project": False,
            "opencode:project:plugin-config:npm:unpin-live-project-plugin": True,
        }
        assert_discovery(
            unpin_list(
                unpin,
                "pi",
                home=home,
                project=project,
                cursor=cursor,
                state=state,
                environment=unpin_env,
            ),
            pi_expected,
        )
        assert_discovery(
            unpin_list(
                unpin,
                "opencode",
                home=home,
                project=project,
                cursor=cursor,
                state=state,
                environment=unpin_env,
            ),
            opencode_expected,
        )

        provider_files = [
            pi_global_path,
            pi_project_path,
            opencode_global_path,
            opencode_project_path,
        ]
        before = {path: sha256_file(path) for path in provider_files}
        for item_id in pi_expected:
            layer = "global" if ":global:" in item_id else "project"
            assert_dry_run(
                unpin,
                provider="pi",
                kind="plugin",
                layer=layer,
                item_id=item_id,
                home=home,
                project=project,
                cursor=cursor,
                state=state,
                environment=unpin_env,
            )
        for item_id in opencode_expected:
            layer = "global" if ":global:" in item_id else "project"
            kind = "mcp" if ":configured-mcp:" in item_id else "plugin"
            assert_dry_run(
                unpin,
                provider="opencode",
                kind=kind,
                layer=layer,
                item_id=item_id,
                home=home,
                project=project,
                cursor=cursor,
                state=state,
                environment=unpin_env,
            )
        after = {path: sha256_file(path) for path in provider_files}
        if after != before:
            raise SystemExit("no-write host validation changed provider configuration")

    print(
        json.dumps(
            {
                "status": "passed",
                "hosts": {
                    "pi": pi_version,
                    "opencode": opencode_version,
                },
                "writableCellsDiscovered": len(pi_expected) + len(opencode_expected),
                "dryRunPlans": len(pi_expected) + len(opencode_expected),
                "providerStateUnchanged": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
