import unittest

from local_provider_matrix_support import FIXTURE_ROOT, REPO_ROOT
from run_local_provider_matrix import (
    is_retained_matrix_scenario_path,
    live_inventory_exclusion_reason,
)


class LiveInventoryFilterTests(unittest.TestCase):
    def test_excludes_only_retained_matrix_scenario_trees(self) -> None:
        matrix_root = REPO_ROOT / "tmp/2026-07-24-134032-local-matrix"
        for directory in ("cases", "tui-cases", "mcp-cases"):
            with self.subTest(directory=directory):
                self.assertTrue(
                    is_retained_matrix_scenario_path(
                        (matrix_root / directory / "scenario/provider/item").resolve()
                    )
                )

        self.assertFalse(
            is_retained_matrix_scenario_path(
                (matrix_root / "screenshots/overview.png").resolve()
            )
        )
        self.assertFalse(
            is_retained_matrix_scenario_path(
                (REPO_ROOT / "tmp/project/.agents/skills/review/SKILL.md").resolve()
            )
        )
        self.assertFalse(
            is_retained_matrix_scenario_path(
                REPO_ROOT.parent
                / "2026-07-24-134032-local-matrix/cases/scenario/provider/item"
            )
        )

    def test_reports_fixture_and_retained_matrix_exclusions_separately(self) -> None:
        fixture_item = {
            "sourcePath": str(FIXTURE_ROOT / "claude/global/skills/review"),
            "statePath": str(FIXTURE_ROOT / "claude/global/skills/review"),
        }
        retained_item = {
            "sourcePath": str(
                REPO_ROOT
                / "tmp/2026-07-24-134032-local-matrix/cases/example/provider/item"
            ),
            "statePath": str(REPO_ROOT / "ordinary-provider-state"),
        }
        ordinary_item = {
            "sourcePath": str(REPO_ROOT / "tmp/project/.agents/skills/review"),
            "statePath": str(REPO_ROOT / "tmp/project/.agents/skills/review"),
        }

        self.assertEqual(
            live_inventory_exclusion_reason(fixture_item),
            "repository-fixture",
        )
        self.assertEqual(
            live_inventory_exclusion_reason(retained_item),
            "retained-matrix-scenario",
        )
        self.assertIsNone(live_inventory_exclusion_reason(ordinary_item))
        self.assertIsNone(live_inventory_exclusion_reason({}))


if __name__ == "__main__":
    unittest.main()
