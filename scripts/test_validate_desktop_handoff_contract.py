#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("validate_desktop_handoff_contract.py")
SPEC = importlib.util.spec_from_file_location("validate_desktop_handoff_contract", SCRIPT_PATH)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class DesktopHandoffContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.swift_source = VALIDATOR.DEFAULT_SWIFT_SOURCE.read_text(encoding="utf-8")
        cls.mcp_tools = VALIDATOR.parse_mcp_tool_names(
            VALIDATOR.DEFAULT_MCP_SOURCE.read_text(encoding="utf-8")
        )

    def test_current_catalog_matches_declared_contract(self) -> None:
        handoffs = VALIDATOR.parse_handoffs(self.swift_source)
        self.assertEqual(VALIDATOR.validate_declarations(handoffs, self.mcp_tools), [])

    def test_missing_command_or_unknown_tool_fails(self) -> None:
        missing_command = self.swift_source.replace(
            'cliCommand: "unpin profile list"',
            'cliCommand: ""',
            1,
        )
        errors = VALIDATOR.validate_declarations(
            VALIDATOR.parse_handoffs(missing_command),
            self.mcp_tools,
        )
        self.assertTrue(any("no CLI command" in error for error in errors))

        unknown_tool = self.swift_source.replace(
            '"unpin_validate_profile"',
            '"unpin_missing_profile_tool"',
            1,
        )
        errors = VALIDATOR.validate_declarations(
            VALIDATOR.parse_handoffs(unknown_tool),
            self.mcp_tools,
        )
        self.assertTrue(any("unknown MCP tool" in error for error in errors))

    def test_duplicate_and_unavailable_copy_values_fail(self) -> None:
        duplicate = self.swift_source.replace(
            'id: "gateways"',
            'id: "profiles"',
            1,
        )
        errors = VALIDATOR.validate_declarations(
            VALIDATOR.parse_handoffs(duplicate),
            self.mcp_tools,
        )
        self.assertTrue(any("must be unique" in error for error in errors))

        unavailable_copy = self.swift_source.replace(
            'reason: "Use one of the verified CLI or MCP handoffs above.',
            'cliCommand: "unpin profile list",\n            reason: "Use one of the verified CLI or MCP handoffs above.',
            1,
        )
        with self.assertRaises(VALIDATOR.ContractError):
            VALIDATOR.parse_handoffs(unavailable_copy)

    def test_parser_help_check_rejects_removed_flag(self) -> None:
        handoffs = VALIDATOR.parse_handoffs(self.swift_source)
        with tempfile.TemporaryDirectory(prefix="unpin-handoff-parser-") as temporary:
            executable = Path(temporary) / "unpin"
            executable.write_text(
                "#!/bin/sh\n"
                "case \" $* \" in\n"
                "  *\" --removed \"*) exit 2 ;;\n"
                "  *\" --help \"*) exit 0 ;;\n"
                "  *) exit 3 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            self.assertEqual(
                VALIDATOR.validate_cli_help(
                    handoffs,
                    repository_root=VALIDATOR.REPOSITORY_ROOT,
                    unpin_executable=executable,
                ),
                [],
            )

            broken = list(handoffs)
            profile = broken[0]
            broken[0] = VALIDATOR.Handoff(
                kind=profile.kind,
                id=profile.id,
                cli_command=f"{profile.cli_command} --removed",
                mcp_tool_ids=profile.mcp_tool_ids,
                reason=profile.reason,
            )
            errors = VALIDATOR.validate_cli_help(
                broken,
                repository_root=VALIDATOR.REPOSITORY_ROOT,
                unpin_executable=executable,
            )
            self.assertTrue(any("parser rejected" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
