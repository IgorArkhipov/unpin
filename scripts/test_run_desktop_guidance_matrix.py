#!/usr/bin/env python3
from __future__ import annotations

import binascii
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
import zlib


SCRIPT = Path(__file__).with_name("run_desktop_guidance_matrix.py")


def load_module():
    spec = importlib.util.spec_from_file_location("desktop_guidance_matrix", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    checksum = binascii.crc32(kind)
    checksum = binascii.crc32(payload, checksum) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)


def write_png(path: Path, width: int = 1180, height: int = 760) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    pixels = b"".join(b"\x00" + (b"\x00\x00\x00\xff" * width) for _ in range(height))
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(pixels, level=9))
        + png_chunk(b"IEND", b"")
    )


class DesktopGuidanceMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_authoritative_inventory_has_26_unique_scenarios(self) -> None:
        scenario_ids = [scenario.id for scenario in self.module.SCENARIOS]
        self.assertEqual(len(scenario_ids), 26)
        self.assertEqual(len(set(scenario_ids)), 26)
        self.assertEqual(self.module.validate_scenario_ids(scenario_ids), scenario_ids)
        with self.assertRaises(self.module.MatrixError):
            self.module.validate_scenario_ids(scenario_ids[:-1])
        with self.assertRaises(self.module.MatrixError):
            self.module.validate_scenario_ids(scenario_ids + [scenario_ids[0]])
        with self.assertRaises(self.module.MatrixError):
            self.module.validate_scenario_ids(scenario_ids[:-1] + ["unknown-state"])

    def test_output_root_must_stay_below_repository_tmp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "tmp").mkdir()
            accepted = repo / "tmp" / "2026-08-05-matrix"
            self.assertEqual(
                self.module.validate_output_root(repo, accepted),
                accepted.resolve(),
            )
            with self.assertRaises(self.module.MatrixError):
                self.module.validate_output_root(repo, repo / "matrix")
            with self.assertRaises(self.module.MatrixError):
                self.module.validate_output_root(repo, repo / "tmp")

    def test_xcode_capture_receives_exact_environment_contract(self) -> None:
        calls = []
        captured_environment = None

        def runner(command, **kwargs):
            nonlocal captured_environment
            calls.append((command, kwargs))
            if "build-for-testing" in command:
                derived_data = Path(command[command.index("-derivedDataPath") + 1])
                xctestrun = derived_data / "Build" / "Products" / "fixture.xctestrun"
                xctestrun.parent.mkdir(parents=True)
                with xctestrun.open("wb") as handle:
                    plistlib.dump(
                        {
                            "TestConfigurations": [
                                {
                                    "TestTargets": [
                                        {
                                            "BlueprintName": "UnpinDesktopTests",
                                            "EnvironmentVariables": {},
                                        }
                                    ]
                                }
                            ]
                        },
                        handle,
                    )
            if "test-without-building" in command:
                xctestrun = Path(command[command.index("-xctestrun") + 1])
                with xctestrun.open("rb") as handle:
                    captured_environment = plistlib.load(handle)["TestConfigurations"][0][
                        "TestTargets"
                    ][0]["EnvironmentVariables"]

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = repo / "tmp" / "matrix"
            output.mkdir(parents=True)
            self.module.run_xcode_capture(repo, output, runner=runner)

        self.assertEqual(len(calls), 2)
        command, kwargs = calls[1]
        self.assertIn(
            "-only-testing:UnpinDesktopTests/WorkbenchGuidanceMatrixTests/testCaptureGuidanceMatrix",
            command,
        )
        self.assertEqual(kwargs["cwd"], repo)
        self.assertEqual(kwargs["check"], True)
        self.assertEqual(
            json.loads(captured_environment["UNPIN_GUIDANCE_MATRIX_SCENARIOS"]),
            [scenario.id for scenario in self.module.SCENARIOS],
        )
        self.assertEqual(
            captured_environment["UNPIN_GUIDANCE_MATRIX_DIR"],
            str(output),
        )

    def test_capture_validation_rejects_missing_unknown_and_invalid_pngs(self) -> None:
        scenarios = self.module.SCENARIOS[:1]
        themes = ("light", "dark")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_png(root / "light" / f"{scenarios[0].id}.png")
            with self.assertRaises(self.module.MatrixError):
                self.module.validate_capture(root, scenarios=scenarios, themes=themes)

            write_png(root / "dark" / f"{scenarios[0].id}.png")
            extra = root / "dark" / "unknown.png"
            write_png(extra)
            with self.assertRaises(self.module.MatrixError):
                self.module.validate_capture(root, scenarios=scenarios, themes=themes)
            extra.unlink()

            write_png(root / "dark" / f"{scenarios[0].id}.png", width=10, height=10)
            with self.assertRaises(self.module.MatrixError):
                self.module.validate_capture(root, scenarios=scenarios, themes=themes)

            (root / "dark" / f"{scenarios[0].id}.png").write_bytes(b"")
            with self.assertRaises(self.module.MatrixError):
                self.module.validate_capture(root, scenarios=scenarios, themes=themes)

    def test_manifest_checksums_and_review_round_trip(self) -> None:
        scenarios = self.module.SCENARIOS[:1]
        themes = ("light", "dark")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for theme in themes:
                write_png(root / theme / f"{scenarios[0].id}.png")

            images = self.module.validate_capture(
                root,
                scenarios=scenarios,
                themes=themes,
            )
            manifest = self.module.write_evidence(
                root,
                images,
                scenarios=scenarios,
                themes=themes,
            )
            self.assertEqual(manifest["image_count"], 2)
            self.assertEqual(manifest["screenshot_review"]["status"], "pending")
            self.module.verify_checksums(root)

            reviewed = self.module.record_review(
                root,
                status="passed",
                notes="All fixture states are readable in both themes.",
            )
            self.assertEqual(reviewed["screenshot_review"]["status"], "passed")
            self.assertIn("PASSED", (root / "report.md").read_text())

            target = root / "light" / f"{scenarios[0].id}.png"
            target.write_bytes(target.read_bytes() + b"changed")
            with self.assertRaises(self.module.MatrixError):
                self.module.verify_checksums(root)


if __name__ == "__main__":
    unittest.main()
