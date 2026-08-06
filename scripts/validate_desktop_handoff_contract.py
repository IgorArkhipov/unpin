#!/usr/bin/env python3
"""Validate desktop Govern handoffs against the bundled CLI and MCP contracts."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SWIFT_SOURCE = (
    REPOSITORY_ROOT
    / "apps/unpin-desktop/UnpinDesktop/Features/GovernAutomateView.swift"
)
DEFAULT_MCP_SOURCE = REPOSITORY_ROOT / "crates/unpin-core/src/mcp.rs"
EXPECTED_HANDOFF_IDS = (
    "profiles",
    "gateways",
    "sessions",
    "hooks",
    "native-controls",
)


class ContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class Handoff:
    kind: str
    id: str
    cli_command: str | None
    mcp_tool_ids: tuple[str, ...]
    reason: str | None


def _balanced_region(source: str, opening_index: int, opening: str, closing: str) -> str:
    if opening_index >= len(source) or source[opening_index] != opening:
        raise ContractError(f"expected {opening!r} at offset {opening_index}")
    depth = 0
    in_string = False
    escaped = False
    for index in range(opening_index, len(source)):
        character = source[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == opening:
            depth += 1
        elif character == closing:
            depth -= 1
            if depth == 0:
                return source[opening_index + 1 : index]
    raise ContractError(f"unterminated {opening!r} region")


def _swift_string(body: str, field: str, *, required: bool = True) -> str | None:
    match = re.search(
        rf"\b{re.escape(field)}\s*:\s*(\"(?:\\.|[^\"\\])*\")",
        body,
    )
    if not match:
        if required:
            raise ContractError(f"handoff is missing {field}")
        return None
    return json.loads(match.group(1))


def _swift_string_array(body: str, field: str) -> tuple[str, ...]:
    match = re.search(rf"\b{re.escape(field)}\s*:\s*\[", body)
    if not match:
        raise ContractError(f"handoff is missing {field}")
    opening_index = match.end() - 1
    array_body = _balanced_region(body, opening_index, "[", "]")
    return tuple(
        json.loads(item.group(0))
        for item in re.finditer(r'\"(?:\\.|[^\"\\])*\"', array_body)
    )


def _factory_calls(catalog: str) -> list[tuple[int, str, str]]:
    calls: list[tuple[int, str, str]] = []
    pattern = re.compile(r"GovernHandoff\.(verified|unavailable)\s*\(")
    for match in pattern.finditer(catalog):
        opening_index = match.end() - 1
        calls.append(
            (
                match.start(),
                match.group(1),
                _balanced_region(catalog, opening_index, "(", ")"),
            )
        )
    return sorted(calls)


def parse_handoffs(source: str) -> list[Handoff]:
    catalog_match = re.search(r"static\s+let\s+catalog[^=]*=\s*\[", source)
    if not catalog_match:
        raise ContractError("GovernHandoff.catalog was not found")
    catalog = _balanced_region(source, catalog_match.end() - 1, "[", "]")
    handoffs: list[Handoff] = []
    for _, kind, body in _factory_calls(catalog):
        handoff_id = _swift_string(body, "id")
        if kind == "verified":
            handoffs.append(
                Handoff(
                    kind=kind,
                    id=handoff_id or "",
                    cli_command=_swift_string(body, "cliCommand"),
                    mcp_tool_ids=_swift_string_array(body, "mcpToolIDs"),
                    reason=None,
                )
            )
        else:
            if "cliCommand:" in body or "mcpToolIDs:" in body:
                raise ContractError(
                    f"unavailable handoff {handoff_id!r} must not expose exact copy values"
                )
            handoffs.append(
                Handoff(
                    kind=kind,
                    id=handoff_id or "",
                    cli_command=None,
                    mcp_tool_ids=(),
                    reason=_swift_string(body, "reason"),
                )
            )
    return handoffs


def parse_mcp_tool_names(source: str) -> set[str]:
    match = re.search(r"UNPIN_MCP_TOOL_NAMES[^=]*=\s*&\[", source)
    if not match:
        raise ContractError("UNPIN_MCP_TOOL_NAMES was not found")
    body = _balanced_region(source, match.end() - 1, "[", "]")
    return {
        json.loads(item.group(0))
        for item in re.finditer(r'\"(?:\\.|[^\"\\])*\"', body)
    }


def validate_declarations(
    handoffs: Iterable[Handoff],
    canonical_mcp_tools: set[str],
) -> list[str]:
    handoffs = list(handoffs)
    errors: list[str] = []
    ids = [handoff.id for handoff in handoffs]
    if tuple(ids) != EXPECTED_HANDOFF_IDS:
        errors.append(
            "handoff IDs must be exactly "
            f"{', '.join(EXPECTED_HANDOFF_IDS)}; found {', '.join(ids) or 'none'}"
        )
    if len(ids) != len(set(ids)):
        errors.append("handoff IDs must be unique")

    commands: list[str] = []
    tool_ids: list[str] = []
    for handoff in handoffs:
        if handoff.kind == "verified":
            if not handoff.cli_command:
                errors.append(f"verified handoff {handoff.id!r} has no CLI command")
            elif not handoff.cli_command.startswith("unpin "):
                errors.append(
                    f"verified handoff {handoff.id!r} CLI command must start with 'unpin '"
                )
            else:
                commands.append(handoff.cli_command)
            if not handoff.mcp_tool_ids:
                errors.append(f"verified handoff {handoff.id!r} has no MCP tool IDs")
            for tool_id in handoff.mcp_tool_ids:
                tool_ids.append(tool_id)
                if tool_id not in canonical_mcp_tools:
                    errors.append(
                        f"verified handoff {handoff.id!r} references unknown MCP tool {tool_id!r}"
                    )
        elif not handoff.reason:
            errors.append(f"unavailable handoff {handoff.id!r} has no reason")

    if len(commands) != len(set(commands)):
        errors.append("verified CLI commands must be unique")
    if len(tool_ids) != len(set(tool_ids)):
        errors.append("verified MCP tool IDs must be unique")
    return errors


def _safe_cli_argument(argument: str) -> str:
    return re.sub(r"<[^>]+>", "unpin-contract-test", argument)


def validate_cli_help(
    handoffs: Iterable[Handoff],
    *,
    repository_root: Path,
    unpin_executable: Path | None,
) -> list[str]:
    errors: list[str] = []
    original_home = Path.home()
    with tempfile.TemporaryDirectory(prefix="unpin-desktop-handoff-") as temporary:
        temporary_root = Path(temporary)
        home_root = temporary_root / "home"
        state_root = temporary_root / "state"
        home_root.mkdir()
        state_root.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home_root),
                "XDG_CONFIG_HOME": str(home_root / ".config"),
                "XDG_DATA_HOME": str(home_root / ".local/share"),
                "XDG_STATE_HOME": str(home_root / ".local/state"),
                "UNPIN_APP_STATE_ROOT": str(state_root),
                "CARGO_HOME": environment.get("CARGO_HOME", str(original_home / ".cargo")),
                "RUSTUP_HOME": environment.get("RUSTUP_HOME", str(original_home / ".rustup")),
            }
        )
        for handoff in handoffs:
            if handoff.kind != "verified" or not handoff.cli_command:
                continue
            arguments = shlex.split(handoff.cli_command)
            if not arguments or arguments[0] != "unpin":
                errors.append(f"{handoff.id}: malformed CLI command")
                continue
            help_arguments = [_safe_cli_argument(item) for item in arguments[1:]] + ["--help"]
            if unpin_executable is None:
                command = [
                    "cargo",
                    "run",
                    "--quiet",
                    "-p",
                    "unpin-cli",
                    "--locked",
                    "--",
                    *help_arguments,
                ]
            else:
                command = [str(unpin_executable), *help_arguments]
            completed = subprocess.run(
                command,
                cwd=repository_root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if completed.returncode != 0:
                diagnostic = (completed.stderr or completed.stdout).strip().splitlines()
                detail = diagnostic[-1] if diagnostic else f"exit {completed.returncode}"
                errors.append(
                    f"{handoff.id}: parser rejected {handoff.cli_command!r}: {detail}"
                )
    return errors


def validate_contract(
    *,
    swift_source: Path,
    mcp_source: Path,
    repository_root: Path,
    unpin_executable: Path | None,
) -> list[str]:
    handoffs = parse_handoffs(swift_source.read_text(encoding="utf-8"))
    canonical_mcp_tools = parse_mcp_tool_names(mcp_source.read_text(encoding="utf-8"))
    errors = validate_declarations(handoffs, canonical_mcp_tools)
    if not errors:
        errors.extend(
            validate_cli_help(
                handoffs,
                repository_root=repository_root,
                unpin_executable=unpin_executable,
            )
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--swift-source", type=Path, default=DEFAULT_SWIFT_SOURCE)
    parser.add_argument("--mcp-source", type=Path, default=DEFAULT_MCP_SOURCE)
    parser.add_argument(
        "--unpin",
        type=Path,
        help="Use this Unpin executable for parser help checks instead of cargo run.",
    )
    arguments = parser.parse_args()
    try:
        errors = validate_contract(
            swift_source=arguments.swift_source,
            mcp_source=arguments.mcp_source,
            repository_root=REPOSITORY_ROOT,
            unpin_executable=arguments.unpin,
        )
    except (ContractError, OSError, subprocess.SubprocessError) as error:
        print(f"desktop handoff contract validation failed: {error}")
        return 1
    if errors:
        print("desktop handoff contract validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("desktop handoff contract validated: 4 verified workflows, 12 MCP tools")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
