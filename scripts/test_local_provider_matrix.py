import argparse
import hashlib
import json
import math
import os
import plistlib
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import local_provider_matrix_support as matrix_support
import local_provider_matrix_cases as matrix_cases
import provider_matrix_screenshots as matrix_screenshots
import run_local_provider_matrix as matrix_runner
from local_provider_matrix_finalize import mcp_no_write_handoff_contract_complete
from local_provider_matrix_support import (
    FIXTURE_ROOT,
    REPO_ROOT,
    MatrixCommandTimeout,
    MatrixFailure,
    quality_gate_timeout_seconds,
    run_command,
)
from run_local_provider_matrix import (
    QUALITY_GATE_TIMEOUT_SECONDS,
    is_repository_tmp_path,
    live_inventory_exclusion_reason,
    live_item_has_cross_provider_shared_source,
    live_plan_state_paths,
    validate_workflow_routing_evidence,
)


class ArtifactRootTests(unittest.TestCase):
    def test_accepts_repository_tmp_and_rejects_system_tmp(self) -> None:
        artifact_root = REPO_ROOT / "tmp/2026-08-05-test-provider-matrix"

        self.assertEqual(
            matrix_support.validate_artifact_root(artifact_root),
            artifact_root.resolve(),
        )
        with self.assertRaisesRegex(MatrixFailure, "repository tmp"):
            matrix_support.validate_artifact_root(
                Path("/tmp/2026-08-05-test-provider-matrix")
            )

    def test_accepts_legacy_local_matrix_directory_name(self) -> None:
        artifact_root = REPO_ROOT / "tmp/2026-08-05-test-local-matrix"

        self.assertEqual(
            matrix_support.validate_artifact_root(artifact_root),
            artifact_root.resolve(),
        )

    def test_rejects_unrelated_repository_tmp_directory_name(self) -> None:
        with self.assertRaisesRegex(MatrixFailure, "directory name"):
            matrix_support.validate_artifact_root(
                REPO_ROOT / "tmp/2026-08-05-test-matrix"
            )

    def test_rejects_symlinked_repository_tmp_before_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            external_root = temporary_root / "external"
            external_root.mkdir()
            sentinel = external_root / "sentinel.txt"
            sentinel.write_text("preserve", encoding="utf-8")
            evidence_root = temporary_root / "tmp"
            evidence_root.symlink_to(external_root, target_is_directory=True)

            with mock.patch.object(
                matrix_support, "EVIDENCE_ROOT", evidence_root
            ):
                with self.assertRaisesRegex(MatrixFailure, "must not be a symlink"):
                    matrix_support.prepare_artifact_root(
                        evidence_root / "test-provider-matrix",
                        overwrite=True,
                    )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_rejects_symlinked_artifact_root_before_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            evidence_root = temporary_root / "tmp"
            evidence_root.mkdir()
            external_root = temporary_root / "external"
            external_root.mkdir()
            sentinel = external_root / "sentinel.txt"
            sentinel.write_text("preserve", encoding="utf-8")
            artifact_root = evidence_root / "test-provider-matrix"
            artifact_root.symlink_to(external_root, target_is_directory=True)

            with mock.patch.object(
                matrix_support, "EVIDENCE_ROOT", evidence_root
            ):
                with self.assertRaisesRegex(MatrixFailure, "repository tmp"):
                    matrix_support.prepare_artifact_root(
                        artifact_root,
                        overwrite=True,
                    )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_default_artifact_root_is_repository_local(self) -> None:
        with mock.patch("sys.argv", ["run_local_provider_matrix.py"]):
            args = matrix_support.parse_args()

        self.assertTrue(
            args.artifact_root.resolve().is_relative_to(
                (REPO_ROOT / "tmp").resolve()
            )
        )

    def test_repository_tmp_artifacts_are_ignored(self) -> None:
        ignored = subprocess.run(
            [
                "git",
                "check-ignore",
                "--quiet",
                "tmp/2026-08-05-test-provider-matrix/summary.json",
            ],
            cwd=REPO_ROOT,
            check=False,
        )

        self.assertEqual(ignored.returncode, 0)


@mock.patch.object(sys, "platform", "darwin")
class ScreenshotCaptureArgumentTests(unittest.TestCase):
    def test_capture_preflight_reads_platform_at_call_time(self) -> None:
        with mock.patch.object(sys, "platform", "darwin"):
            matrix_screenshots.preflight_provider_matrix_screenshot_capture()

        with mock.patch.object(sys, "platform", "linux"):
            with self.assertRaisesRegex(MatrixFailure, "requires macOS"):
                matrix_screenshots.preflight_provider_matrix_screenshot_capture()

    def test_capture_screenshot_flag_is_explicitly_selectable(self) -> None:
        with mock.patch(
            "sys.argv",
            ["run_local_provider_matrix.py", "--capture-screenshots"],
        ):
            enabled = matrix_support.parse_args()
        with mock.patch(
            "sys.argv",
            ["run_local_provider_matrix.py", "--no-capture-screenshots"],
        ):
            disabled = matrix_support.parse_args()
        with mock.patch("sys.argv", ["run_local_provider_matrix.py"]):
            automatic = matrix_support.parse_args()

        self.assertIs(enabled.capture_screenshots, True)
        self.assertIs(disabled.capture_screenshots, False)
        self.assertIsNone(automatic.capture_screenshots)

    def test_capture_screenshots_defaults_to_macos_only(self) -> None:
        self.assertTrue(
            matrix_support.capture_screenshots_enabled(None, platform="darwin")
        )
        self.assertFalse(
            matrix_support.capture_screenshots_enabled(None, platform="linux")
        )
        self.assertTrue(
            matrix_support.capture_screenshots_enabled(True, platform="linux")
        )
        self.assertFalse(
            matrix_support.capture_screenshots_enabled(False, platform="darwin")
        )

    def test_explicit_capture_reuses_an_existing_dashboard(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            (artifact_root / "dashboard.html").write_text(
                "<!doctype html><section id='overview'>ready</section>",
                encoding="utf-8",
            )
            failure_path = artifact_root / "failure.json"
            failure_path.write_text('{"status": "failed"}\n', encoding="utf-8")
            args = argparse.Namespace(
                artifact_root=artifact_root,
                finalize=False,
                capture_screenshots=True,
                overwrite=False,
            )
            captured = [
                artifact_root / "screenshots" / name
                for name in matrix_support.SCREENSHOTS
            ]
            with (
                mock.patch.object(matrix_runner, "parse_args", return_value=args),
                mock.patch.object(
                    matrix_runner,
                    "validate_artifact_root",
                    return_value=artifact_root,
                ),
                mock.patch.object(
                    matrix_runner,
                    "capture_provider_matrix_screenshots",
                    return_value=captured,
                ) as capture,
                mock.patch.object(matrix_runner, "tighten_artifact_permissions"),
                mock.patch.object(matrix_runner, "prepare_artifact_root") as prepare,
                mock.patch("builtins.print"),
            ):
                result = matrix_runner.main()
            review = json.loads(
                (artifact_root / "screenshot-review.json").read_text(encoding="utf-8")
            )

        self.assertEqual(result, 0)
        self.assertFalse(failure_path.exists())
        capture.assert_called_once_with(REPO_ROOT, artifact_root)
        prepare.assert_not_called()
        self.assertEqual(review["status"], "pending")
        self.assertIsNone(review["reviewedBy"])
        self.assertIsNone(review["reviewedAt"])
        self.assertEqual(review["checksums"], {})
        self.assertTrue(all(value is False for value in review["assertions"].values()))

    def test_recapture_invalidates_manifest_before_reset_and_capture(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            (artifact_root / "dashboard.html").write_text(
                "<!doctype html><section id='overview'>ready</section>",
                encoding="utf-8",
            )
            manifest_path = artifact_root / "evidence-manifest.json"
            manifest_path.write_text('{"stale": true}\n', encoding="utf-8")
            review_path = artifact_root / "screenshot-review.json"
            review_path.write_text('{"status": "approved"}\n', encoding="utf-8")
            args = argparse.Namespace(
                artifact_root=artifact_root,
                finalize=False,
                capture_screenshots=True,
                overwrite=False,
            )

            def capture(_: Path, captured_root: Path) -> list[Path]:
                self.assertEqual(captured_root, artifact_root)
                self.assertFalse(manifest_path.exists())
                return []

            with (
                mock.patch.object(matrix_runner, "parse_args", return_value=args),
                mock.patch.object(
                    matrix_runner,
                    "validate_artifact_root",
                    return_value=artifact_root,
                ),
                mock.patch.object(
                    matrix_runner,
                    "capture_provider_matrix_screenshots",
                    side_effect=capture,
                ),
                mock.patch.object(matrix_runner, "tighten_artifact_permissions"),
                mock.patch.object(matrix_runner, "prepare_artifact_root") as prepare,
                mock.patch("builtins.print"),
            ):
                result = matrix_runner.main()

            review = json.loads(review_path.read_text(encoding="utf-8"))
            self.assertEqual(result, 0)
            prepare.assert_not_called()
            self.assertFalse(manifest_path.exists())
            self.assertEqual(review["status"], "pending")

    def test_finalize_rejects_capture_flags(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            args = argparse.Namespace(
                artifact_root=artifact_root,
                finalize=True,
                capture_screenshots=True,
            )
            with (
                mock.patch.object(matrix_runner, "parse_args", return_value=args),
                mock.patch.object(
                    matrix_runner,
                    "validate_artifact_root",
                    return_value=artifact_root,
                ),
                mock.patch.object(matrix_runner, "finalize_artifacts") as finalize,
            ):
                with self.assertRaisesRegex(MatrixFailure, "cannot be combined"):
                    matrix_runner.main()

            finalize.assert_not_called()

    def test_capture_failure_writes_failure_evidence_and_preserves_previous_screenshots(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            (artifact_root / "dashboard.html").write_text(
                "<!doctype html><section id='overview'>ready</section>",
                encoding="utf-8",
            )
            screenshots_root = artifact_root / "screenshots"
            screenshots_root.mkdir()
            previous_screenshot = screenshots_root / matrix_support.SCREENSHOTS[0]
            previous_bytes = b"previous screenshot"
            previous_screenshot.write_bytes(previous_bytes)
            manifest_path = artifact_root / "evidence-manifest.json"
            manifest_path.write_text('{"stale": true}\n', encoding="utf-8")
            args = argparse.Namespace(
                artifact_root=artifact_root,
                finalize=False,
                capture_screenshots=True,
                overwrite=False,
            )

            with (
                mock.patch.object(matrix_runner, "parse_args", return_value=args),
                mock.patch.object(
                    matrix_runner,
                    "validate_artifact_root",
                    return_value=artifact_root,
                ),
                mock.patch.object(
                    matrix_runner,
                    "capture_provider_matrix_screenshots",
                    side_effect=MatrixFailure("capture failed"),
                ) as capture,
                mock.patch.object(matrix_runner, "tighten_artifact_permissions"),
                mock.patch.object(matrix_runner, "prepare_artifact_root") as prepare,
                mock.patch("builtins.print"),
            ):
                with self.assertRaisesRegex(MatrixFailure, "capture failed"):
                    matrix_runner.main()

            failure = json.loads(
                (artifact_root / "failure.json").read_text(encoding="utf-8")
            )
            review = json.loads(
                (artifact_root / "screenshot-review.json").read_text(encoding="utf-8")
            )
            capture.assert_called_once_with(REPO_ROOT, artifact_root)
            prepare.assert_not_called()
            self.assertFalse(manifest_path.exists())
            self.assertEqual(previous_screenshot.read_bytes(), previous_bytes)
            self.assertEqual(failure["status"], "failed")
            self.assertEqual(
                failure["error"], "matrix run failed; see terminal output"
            )
            self.assertEqual(failure["type"], "MatrixFailure")
            self.assertTrue(failure["failedAt"])
            self.assertEqual(review["status"], "pending")

    def test_unsupported_capture_preserves_approved_evidence(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            (artifact_root / "dashboard.html").write_text(
                "<!doctype html><section id='overview'>ready</section>",
                encoding="utf-8",
            )
            manifest_path = artifact_root / "evidence-manifest.json"
            manifest_bytes = b'{"approved": true}\n'
            manifest_path.write_bytes(manifest_bytes)
            review_path = artifact_root / "screenshot-review.json"
            review_bytes = b'{"status": "approved"}\n'
            review_path.write_bytes(review_bytes)
            args = argparse.Namespace(
                artifact_root=artifact_root,
                finalize=False,
                capture_screenshots=True,
                overwrite=False,
            )

            with (
                mock.patch.object(matrix_runner, "parse_args", return_value=args),
                mock.patch.object(
                    matrix_runner,
                    "validate_artifact_root",
                    return_value=artifact_root,
                ),
                mock.patch.object(
                    matrix_runner,
                    "preflight_provider_matrix_screenshot_capture",
                    side_effect=MatrixFailure("requires macOS"),
                ),
                mock.patch.object(
                    matrix_runner,
                    "capture_provider_matrix_screenshots",
                ) as capture,
                mock.patch.object(matrix_runner, "prepare_artifact_root") as prepare,
            ):
                with self.assertRaisesRegex(MatrixFailure, "requires macOS"):
                    matrix_runner.main()

            capture.assert_not_called()
            prepare.assert_not_called()
            self.assertEqual(manifest_path.read_bytes(), manifest_bytes)
            self.assertEqual(review_path.read_bytes(), review_bytes)

    def test_capture_request_without_dashboard_fails_before_full_matrix(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            args = argparse.Namespace(
                artifact_root=artifact_root,
                finalize=False,
                capture_screenshots=True,
                overwrite=False,
            )
            with (
                mock.patch.object(matrix_runner, "parse_args", return_value=args),
                mock.patch.object(
                    matrix_runner,
                    "validate_artifact_root",
                    return_value=artifact_root,
                ),
                mock.patch.object(
                    matrix_runner,
                    "capture_provider_matrix_screenshots",
                ) as capture,
                mock.patch.object(
                    matrix_runner,
                    "prepare_artifact_root",
                    side_effect=MatrixFailure("full matrix unexpectedly started"),
                ) as prepare,
                mock.patch("builtins.print"),
            ):
                with self.assertRaisesRegex(MatrixFailure, "dashboard"):
                    matrix_runner.main()

            failure = json.loads(
                (artifact_root / "failure.json").read_text(encoding="utf-8")
            )

        capture.assert_not_called()
        prepare.assert_not_called()
        self.assertEqual(failure["status"], "failed")
        self.assertEqual(failure["type"], "MatrixFailure")

    def test_capture_request_creates_failure_evidence_when_artifact_root_is_missing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory) / "missing-provider-matrix"
            args = argparse.Namespace(
                artifact_root=artifact_root,
                finalize=False,
                capture_screenshots=True,
                overwrite=False,
            )
            with (
                mock.patch.object(matrix_runner, "parse_args", return_value=args),
                mock.patch.object(
                    matrix_runner,
                    "validate_artifact_root",
                    return_value=artifact_root,
                ),
                mock.patch.object(
                    matrix_runner,
                    "capture_provider_matrix_screenshots",
                ) as capture,
                mock.patch.object(matrix_runner, "prepare_artifact_root") as prepare,
                mock.patch("builtins.print"),
            ):
                with self.assertRaisesRegex(MatrixFailure, "dashboard"):
                    matrix_runner.main()

            failure = json.loads(
                (artifact_root / "failure.json").read_text(encoding="utf-8")
            )

        capture.assert_not_called()
        prepare.assert_not_called()
        self.assertEqual(failure["status"], "failed")
        self.assertEqual(failure["type"], "MatrixFailure")

    def test_capture_rejects_unsafe_existing_review_metadata(self) -> None:
        cases = ("symlink", "hardlink", "directory")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                prefix="unpin-provider-screenshot-test-"
            ) as temporary_directory:
                temporary_root = Path(temporary_directory)
                artifact_root = temporary_root / "artifact-provider-matrix"
                artifact_root.mkdir()
                (artifact_root / "dashboard.html").write_text(
                    "<!doctype html><section id='overview'>ready</section>",
                    encoding="utf-8",
                )
                review_path = artifact_root / "screenshot-review.json"
                manifest_path = artifact_root / "evidence-manifest.json"
                manifest_bytes = b'{"stale": true}\n'
                manifest_path.write_bytes(manifest_bytes)
                external_review = temporary_root / "external-review.json"
                external_review.write_text('{"sentinel": true}\n', encoding="utf-8")
                if case == "symlink":
                    review_path.symlink_to(external_review)
                elif case == "hardlink":
                    os.link(external_review, review_path)
                else:
                    review_path.mkdir()
                args = argparse.Namespace(
                    artifact_root=artifact_root,
                    finalize=False,
                    capture_screenshots=True,
                    overwrite=False,
                )
                with (
                    mock.patch.object(matrix_runner, "parse_args", return_value=args),
                    mock.patch.object(
                        matrix_runner,
                        "validate_artifact_root",
                        return_value=artifact_root,
                    ),
                    mock.patch.object(
                        matrix_runner,
                        "capture_provider_matrix_screenshots",
                    ) as capture,
                    mock.patch.object(matrix_runner, "tighten_artifact_permissions"),
                    mock.patch.object(matrix_runner, "prepare_artifact_root") as prepare,
                    mock.patch("builtins.print"),
                ):
                    with self.assertRaisesRegex(MatrixFailure, "screenshot-review"):
                        matrix_runner.main()

                capture.assert_not_called()
                prepare.assert_not_called()
                self.assertEqual(
                    external_review.read_text(encoding="utf-8"),
                    '{"sentinel": true}\n',
                )
                self.assertEqual(manifest_path.read_bytes(), manifest_bytes)
                if case == "symlink":
                    self.assertTrue(review_path.is_symlink())
                elif case == "hardlink":
                    self.assertEqual(review_path.stat().st_nlink, 2)
                else:
                    self.assertTrue(review_path.is_dir())

    def test_capture_rejects_unsafe_existing_failure_metadata(self) -> None:
        cases = ("symlink", "hardlink", "directory")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                prefix="unpin-provider-screenshot-test-"
            ) as temporary_directory:
                temporary_root = Path(temporary_directory)
                artifact_root = temporary_root / "artifact-provider-matrix"
                artifact_root.mkdir()
                (artifact_root / "dashboard.html").write_text(
                    "<!doctype html><section id='overview'>ready</section>",
                    encoding="utf-8",
                )
                failure_path = artifact_root / "failure.json"
                manifest_path = artifact_root / "evidence-manifest.json"
                manifest_bytes = b'{"stale": true}\n'
                manifest_path.write_bytes(manifest_bytes)
                external_failure = temporary_root / "external-failure.json"
                external_failure.write_text(
                    '{"sentinel": true}\n', encoding="utf-8"
                )
                if case == "symlink":
                    failure_path.symlink_to(external_failure)
                elif case == "hardlink":
                    os.link(external_failure, failure_path)
                else:
                    failure_path.mkdir()
                args = argparse.Namespace(
                    artifact_root=artifact_root,
                    finalize=False,
                    capture_screenshots=True,
                    overwrite=False,
                )
                with (
                    mock.patch.object(matrix_runner, "parse_args", return_value=args),
                    mock.patch.object(
                        matrix_runner,
                        "validate_artifact_root",
                        return_value=artifact_root,
                    ),
                    mock.patch.object(
                        matrix_runner,
                        "capture_provider_matrix_screenshots",
                        return_value=[],
                    ) as capture,
                    mock.patch.object(matrix_runner, "tighten_artifact_permissions"),
                    mock.patch.object(matrix_runner, "prepare_artifact_root") as prepare,
                    mock.patch("builtins.print"),
                ):
                    with self.assertRaisesRegex(MatrixFailure, "failure.json"):
                        matrix_runner.main()

                capture.assert_not_called()
                prepare.assert_not_called()
                self.assertEqual(
                    external_failure.read_text(encoding="utf-8"),
                    '{"sentinel": true}\n',
                )
                self.assertEqual(manifest_path.read_bytes(), manifest_bytes)
                if case == "symlink":
                    self.assertTrue(failure_path.is_symlink())
                elif case == "hardlink":
                    self.assertEqual(failure_path.stat().st_nlink, 2)
                else:
                    self.assertTrue(failure_path.is_dir())


class ProviderMatrixScreenshotCaptureTests(unittest.TestCase):
    @staticmethod
    def _fake_png(width: int = 1_480, height: int = 400) -> bytes:
        return (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13)
            + b"IHDR"
            + struct.pack(">II", width, height)
            + b"\x08\x06\x00\x00\x00"
            + (b"capture" * 200)
        )

    @staticmethod
    def _dashboard_html(*, omitted_section=None) -> str:
        sections = (
            f"<section class='panel' id='{section_id}'>ready</section>"
            for section_id in matrix_screenshots.DASHBOARD_SECTION_IDS
            if section_id != omitted_section
        )
        return "<!doctype html>" + "".join(sections)

    def test_capture_stages_exact_inventory_and_binds_xctest_environment(self) -> None:
        calls: list[list[str]] = []
        observed_environment: dict[str, str] = {}

        def runner(
            command: list[str],
            *,
            cwd: Path,
            env: dict[str, str],
            check: bool,
            timeout: int,
            stdout: int,
            stderr: int,
            text: bool,
        ) -> subprocess.CompletedProcess[str]:
            del cwd, env, check, timeout
            self.assertEqual(stdout, subprocess.PIPE)
            self.assertEqual(stderr, subprocess.STDOUT)
            self.assertTrue(text)
            calls.append(command)
            if "build-for-testing" in command:
                derived_data = Path(command[command.index("-derivedDataPath") + 1])
                products = derived_data / "Build/Products"
                products.mkdir(parents=True)
                with (products / "UnpinDesktop.xctestrun").open("wb") as handle:
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
            else:
                xctestrun_path = Path(command[command.index("-xctestrun") + 1])
                with xctestrun_path.open("rb") as handle:
                    xctestrun = plistlib.load(handle)
                target = xctestrun["TestConfigurations"][0]["TestTargets"][0]
                observed_environment.update(target["EnvironmentVariables"])
                staged_dashboard = Path(
                    observed_environment["UNPIN_PROVIDER_MATRIX_DASHBOARD"]
                )
                self.assertNotEqual(
                    staged_dashboard.resolve(),
                    (artifact_root / "dashboard.html").resolve(),
                )
                self.assertEqual(
                    staged_dashboard.read_text(encoding="utf-8"),
                    self._dashboard_html(),
                )
                output_root = Path(
                    observed_environment[
                        "UNPIN_PROVIDER_MATRIX_SCREENSHOTS_DIR"
                    ]
                )
                self.assertFalse(
                    output_root.resolve().is_relative_to(artifact_root.resolve())
                )
                output_root.mkdir(parents=True, exist_ok=True)
                for section in matrix_screenshots.SCREENSHOT_SECTIONS:
                    (output_root / section.filename).write_bytes(self._fake_png())
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            (artifact_root / "dashboard.html").write_text(
                self._dashboard_html(),
                encoding="utf-8",
            )
            captured = matrix_screenshots.capture_provider_matrix_screenshots(
                REPO_ROOT,
                artifact_root,
                platform="darwin",
                runner=runner,
            )

            self.assertEqual(
                [path.name for path in captured],
                [section.filename for section in matrix_screenshots.SCREENSHOT_SECTIONS],
            )
            self.assertTrue(
                all(
                    path.parent == artifact_root.resolve() / "screenshots"
                    for path in captured
                )
            )

        self.assertEqual(len(calls), 2)
        self.assertIn("build-for-testing", calls[0])
        self.assertIn("test-without-building", calls[1])
        self.assertIn(matrix_screenshots.CAPTURE_TEST, calls[1])
        self.assertEqual(
            json.loads(observed_environment["UNPIN_PROVIDER_MATRIX_SECTIONS"]),
            [section._asdict() for section in matrix_screenshots.SCREENSHOT_SECTIONS],
        )

    def test_xcodebuild_failure_reports_bounded_output_tail(self) -> None:
        command = ["xcodebuild", "build-for-testing"]
        output = "start-of-output-sentinel" + "discarded-prefix-" * 400
        output += "compiler diagnostic"

        def runner(*args, **kwargs):
            del args, kwargs
            raise subprocess.CalledProcessError(65, command, output=output)

        with self.assertRaisesRegex(MatrixFailure, "compiler diagnostic") as raised:
            matrix_screenshots._run_xcodebuild(
                command,
                repo_root=REPO_ROOT,
                environment={},
                runner=runner,
            )

        self.assertNotIn("start-of-output-sentinel", str(raised.exception))

    def test_default_xcodebuild_process_reports_failure_output(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import sys; print('xcode diagnostic'); raise SystemExit(7)",
        ]

        with self.assertRaisesRegex(MatrixFailure, "xcode diagnostic"):
            matrix_screenshots._run_xcodebuild_process(
                command,
                repo_root=REPO_ROOT,
                environment=os.environ.copy(),
            )

    def test_default_xcodebuild_process_times_out_and_terminates(self) -> None:
        command = [sys.executable, "-c", "import time; time.sleep(10)"]

        with (
            mock.patch.object(
                matrix_screenshots,
                "XCODEBUILD_TIMEOUT_SECONDS",
                0.05,
            ),
            self.assertRaisesRegex(MatrixFailure, "timed out"),
        ):
            matrix_screenshots._run_xcodebuild_process(
                command,
                repo_root=REPO_ROOT,
                environment=os.environ.copy(),
            )

    def test_xcodebuild_termination_kills_group_after_parent_exits(self) -> None:
        process = mock.Mock(pid=12_345)
        process.poll.side_effect = [None, 0]

        with mock.patch.object(os, "killpg") as kill_group:
            matrix_screenshots._terminate_xcodebuild(process)

        self.assertEqual(
            kill_group.call_args_list,
            [
                mock.call(12_345, signal.SIGTERM),
                mock.call(12_345, signal.SIGKILL),
            ],
        )
        process.wait.assert_called_once_with(
            timeout=matrix_screenshots.XCODEBUILD_TERMINATION_GRACE_SECONDS
        )

    def test_capture_inventory_rejects_missing_and_unknown_pngs(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            output_root = Path(temporary_directory)
            for filename in matrix_support.SCREENSHOTS[1:]:
                (output_root / filename).write_bytes(self._fake_png())
            (output_root / "unexpected.png").write_bytes(self._fake_png())

            with self.assertRaisesRegex(MatrixFailure, "set mismatch"):
                matrix_screenshots.validate_capture_inventory(output_root)

    def test_capture_inventory_rejects_unexpected_non_png_entry(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            output_root = Path(temporary_directory)
            for filename in matrix_support.SCREENSHOTS:
                (output_root / filename).write_bytes(self._fake_png())
            (output_root / "capture.log").write_text("unexpected\n", encoding="utf-8")

            with self.assertRaisesRegex(MatrixFailure, "set mismatch"):
                matrix_screenshots.validate_capture_inventory(output_root)

    def test_capture_inventory_rejects_invalid_dimensions(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            output_root = Path(temporary_directory)
            for filename in matrix_support.SCREENSHOTS:
                (output_root / filename).write_bytes(self._fake_png())
            (output_root / matrix_support.SCREENSHOTS[0]).write_bytes(
                self._fake_png(width=1_479)
            )

            with self.assertRaisesRegex(MatrixFailure, "invalid dimensions"):
                matrix_screenshots.validate_capture_inventory(output_root)

    def test_capture_inventory_rejects_symlinked_png(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)
            output_root = temporary_root / "screenshots"
            output_root.mkdir()
            external = temporary_root / "external.png"
            external.write_bytes(self._fake_png())
            for filename in matrix_support.SCREENSHOTS:
                (output_root / filename).write_bytes(self._fake_png())
            capture = output_root / matrix_support.SCREENSHOTS[0]
            capture.unlink()
            capture.symlink_to(external)

            with self.assertRaisesRegex(MatrixFailure, "private regular file"):
                matrix_screenshots.validate_capture_inventory(output_root)

    def test_capture_inventory_rejects_hardlinked_png(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)
            output_root = temporary_root / "screenshots"
            output_root.mkdir()
            external = temporary_root / "external.png"
            external.write_bytes(self._fake_png())
            for filename in matrix_support.SCREENSHOTS:
                (output_root / filename).write_bytes(self._fake_png())
            capture = output_root / matrix_support.SCREENSHOTS[0]
            capture.unlink()
            os.link(external, capture)

            with self.assertRaisesRegex(MatrixFailure, "private regular file"):
                matrix_screenshots.validate_capture_inventory(output_root)

    def test_capture_rejects_dashboard_section_inventory_drift(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            missing = matrix_screenshots.DASHBOARD_SECTION_IDS[-1]
            (artifact_root / "dashboard.html").write_text(
                self._dashboard_html(omitted_section=missing),
                encoding="utf-8",
            )
            runner = mock.Mock()

            with self.assertRaisesRegex(MatrixFailure, "dashboard section inventory"):
                matrix_screenshots.capture_provider_matrix_screenshots(
                    REPO_ROOT,
                    artifact_root,
                    platform="darwin",
                    runner=runner,
                )

            runner.assert_not_called()

    def test_capture_rolls_back_complete_set_when_publication_fails(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            (artifact_root / "dashboard.html").write_text(
                self._dashboard_html(),
                encoding="utf-8",
            )
            screenshots_root = artifact_root / "screenshots"
            screenshots_root.mkdir()
            previous = self._fake_png(height=401)
            for filename in matrix_support.SCREENSHOTS:
                (screenshots_root / filename).write_bytes(previous)

            def runner(command, **kwargs):
                if "build-for-testing" in command:
                    derived_data = Path(
                        command[command.index("-derivedDataPath") + 1]
                    )
                    products = derived_data / "Build/Products"
                    products.mkdir(parents=True)
                    with (products / "UnpinDesktop.xctestrun").open("wb") as handle:
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
                else:
                    output_root = Path(
                        kwargs["env"]["UNPIN_PROVIDER_MATRIX_SCREENSHOTS_DIR"]
                    )
                    output_root.mkdir(parents=True, exist_ok=True)
                    for filename in matrix_support.SCREENSHOTS:
                        (output_root / filename).write_bytes(
                            self._fake_png(height=402)
                        )
                return subprocess.CompletedProcess(command, 0)

            original_replace = Path.replace

            def fail_staged_directory_publish(source: Path, target: Path) -> Path:
                if (
                    source.name.startswith(".provider-matrix-screenshots-")
                    and not source.name.startswith(
                        ".provider-matrix-screenshots-previous-"
                    )
                    and Path(target).name == "screenshots"
                ):
                    raise OSError("injected publication failure")
                return original_replace(source, target)

            with (
                mock.patch.object(
                    type(screenshots_root),
                    "replace",
                    fail_staged_directory_publish,
                ),
                self.assertRaisesRegex(MatrixFailure, "publish captured screenshots"),
            ):
                matrix_screenshots.capture_provider_matrix_screenshots(
                    REPO_ROOT,
                    artifact_root,
                    platform="darwin",
                    runner=runner,
                )

            self.assertEqual(
                {
                    path.name: path.read_bytes()
                    for path in screenshots_root.glob("*.png")
                },
                {filename: previous for filename in matrix_support.SCREENSHOTS},
            )

    def test_capture_rejects_non_macos_before_running_xcode(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-provider-screenshot-test-"
        ) as temporary_directory:
            artifact_root = Path(temporary_directory)
            (artifact_root / "dashboard.html").write_text(
                "<!doctype html><section id='overview'>ready</section>",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MatrixFailure, "macOS"):
                matrix_screenshots.capture_provider_matrix_screenshots(
                    REPO_ROOT,
                    artifact_root,
                    platform="linux",
                    runner=mock.Mock(),
                )


class FixtureWorkspaceTests(unittest.TestCase):
    def test_accepts_system_temporary_root_and_rejects_repository_tmp(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="unpin-matrix-test-",
            dir=matrix_support.FIXTURE_TEMP_ROOT,
        ) as temporary_directory:
            matrix_support.validate_fixture_temporary_root(
                Path(temporary_directory).resolve()
            )

        with self.assertRaisesRegex(MatrixFailure, "system temporary root"):
            matrix_support.validate_fixture_temporary_root(
                (REPO_ROOT / "tmp/2026-08-05-test-provider-matrix").resolve()
            )

    def test_private_fixture_workspace_is_confined_and_removed(self) -> None:
        with matrix_support.private_fixture_workspace() as workspace_root:
            self.assertTrue(
                workspace_root.is_relative_to(matrix_support.FIXTURE_TEMP_ROOT)
            )
            self.assertEqual(workspace_root.stat().st_mode & 0o777, 0o700)
            self.assertTrue(workspace_root.is_dir())

        self.assertFalse(workspace_root.exists())

    def test_private_fixture_workspace_is_removed_after_failure(self) -> None:
        workspace_root: Path | None = None

        with self.assertRaisesRegex(MatrixFailure, "scenario failed"):
            with matrix_support.private_fixture_workspace() as temporary_root:
                workspace_root = temporary_root
                raise MatrixFailure("scenario failed")

        self.assertIsNotNone(workspace_root)
        self.assertFalse(workspace_root.exists())


class MatrixCaseWorkspaceTests(unittest.TestCase):
    def test_matrix_case_roots_keep_mutable_state_outside_evidence(self) -> None:
        evidence_root = REPO_ROOT / "tmp/2026-08-05-test-provider-matrix"

        with tempfile.TemporaryDirectory(
            prefix="unpin-matrix-test-",
            dir=matrix_support.FIXTURE_TEMP_ROOT,
        ) as temporary_directory:
            fixture_workspace_root = Path(temporary_directory).resolve()

            for directory in ("cases", "tui-cases", "mcp-cases"):
                with self.subTest(directory=directory):
                    case_root, fixture_root, app_state_root = (
                        matrix_cases.matrix_case_roots(
                            evidence_root,
                            fixture_workspace_root,
                            directory,
                            "test-scenario",
                        )
                    )

                    self.assertEqual(
                        case_root,
                        evidence_root / directory / "test-scenario",
                    )
                    self.assertTrue(
                        fixture_root.is_relative_to(fixture_workspace_root)
                    )
                    self.assertTrue(
                        app_state_root.is_relative_to(fixture_workspace_root)
                    )
                    self.assertFalse(fixture_root.is_relative_to(evidence_root))
                    self.assertFalse(app_state_root.is_relative_to(evidence_root))

    def test_matrix_case_roots_reject_evidence_as_fixture_workspace(self) -> None:
        evidence_root = REPO_ROOT / "tmp/2026-08-05-test-provider-matrix"

        with self.assertRaisesRegex(MatrixFailure, "system temporary root"):
            matrix_cases.matrix_case_roots(
                evidence_root,
                evidence_root,
                "cases",
                "test-scenario",
            )

    def test_run_matrix_cases_passes_separate_evidence_and_fixture_roots(self) -> None:
        evidence_root = REPO_ROOT / "tmp/2026-08-05-test-provider-matrix"
        fixture_workspace_root = matrix_support.FIXTURE_TEMP_ROOT / "matrix-test"
        scenario = {"slug": "test-scenario"}
        observed: list[tuple[Path, Path]] = []

        def worker(
            binary: Path,
            artifact_root: Path,
            workspace_root: Path,
            worker_scenario: dict[str, str],
            canonical_fixture_digest: str,
        ) -> dict[str, str]:
            self.assertEqual(binary, Path("/test/unpin"))
            self.assertEqual(worker_scenario, scenario)
            self.assertEqual(canonical_fixture_digest, "sha256:fixtures")
            observed.append((artifact_root, workspace_root))
            return worker_scenario

        with mock.patch.object(matrix_cases, "MATRIX", [scenario]):
            results = matrix_cases.run_matrix_cases(
                worker,
                Path("/test/unpin"),
                evidence_root,
                fixture_workspace_root,
                "sha256:fixtures",
            )

        self.assertEqual(results, [scenario])
        self.assertEqual(observed, [(evidence_root, fixture_workspace_root)])

    def test_fixture_surface_runner_uses_one_private_workspace_for_all_surfaces(
        self,
    ) -> None:
        evidence_root = REPO_ROOT / "tmp/2026-08-05-test-provider-matrix"
        fixture_workspace_root = matrix_support.FIXTURE_TEMP_ROOT / "matrix-test"
        workspace_context = mock.MagicMock()
        workspace_context.__enter__.return_value = fixture_workspace_root
        workspace_context.__exit__.return_value = False
        expected_results = (
            [{"surface": "cli"}],
            [{"surface": "tui"}],
            [{"surface": "mcp"}],
        )

        with (
            mock.patch.object(
                matrix_runner,
                "private_fixture_workspace",
                return_value=workspace_context,
            ),
            mock.patch.object(
                matrix_runner,
                "run_matrix_cases",
                side_effect=expected_results,
            ) as run_cases,
            mock.patch.object(matrix_runner, "write_json") as write_json,
        ):
            results = matrix_runner.run_fixture_matrix_surfaces(
                Path("/test/unpin"),
                evidence_root,
                "sha256:fixtures",
            )

        self.assertEqual(results, expected_results)
        self.assertEqual(
            [call.args[0] for call in run_cases.call_args_list],
            [
                matrix_runner.run_cli_scenario,
                matrix_runner.run_tui_scenario,
                matrix_runner.run_mcp_scenario,
            ],
        )
        for call in run_cases.call_args_list:
            self.assertEqual(call.args[2], evidence_root)
            self.assertEqual(call.args[3], fixture_workspace_root)
            self.assertEqual(call.args[4], "sha256:fixtures")
        self.assertEqual(
            write_json.call_args_list,
            [
                mock.call(evidence_root / "raw/results.json", expected_results[0]),
                mock.call(
                    evidence_root / "raw/tui-results.json", expected_results[1]
                ),
                mock.call(
                    evidence_root / "raw/mcp-results.json", expected_results[2]
                ),
            ],
        )


class McpFinalizationContractTests(unittest.TestCase):
    def test_accepts_handoffs_and_shared_source_prewrite_blocks(self) -> None:
        standard_case = {
            "mcpWritesEnabled": False,
            "unreviewedApplyBlocked": True,
            "humanActionHandoff": True,
            "sharedSourceFanout": {"asserted": False},
        }
        shared_source_case = {
            "confirmationBlocked": True,
            "sharedSourceFanout": {
                "asserted": True,
                "blockedBeforeWrite": True,
            },
        }

        self.assertTrue(
            mcp_no_write_handoff_contract_complete(
                [standard_case, shared_source_case]
            )
        )

    def test_rejects_shared_source_case_without_prewrite_block(self) -> None:
        self.assertFalse(
            mcp_no_write_handoff_contract_complete(
                [
                    {
                        "confirmationBlocked": True,
                        "sharedSourceFanout": {"asserted": True},
                    }
                ]
            )
        )


class WorkflowRoutingEvidenceTests(unittest.TestCase):
    @staticmethod
    def valid_evidence() -> dict[str, object]:
        descriptor = {
            "name": "review__inspect",
            "title": "Inspect",
            "description": "Inspect review fixture",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object",
                "properties": {"result": {"type": "string"}},
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "openWorldHint": False},
            "execution": {"taskSupport": "optional"},
        }
        descriptors = [descriptor]
        schema_bytes = len(
            json.dumps(descriptors, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        mode = {
            "advertisedToolNames": ["review__inspect"],
            "gatewayToolsListNames": ["review__inspect"],
            "expectedToolDescriptors": descriptors,
            "observedToolDescriptors": json.loads(json.dumps(descriptors)),
            "mcpObservationSource": "GatewayMcpServer RMCP tools/list",
            "skillSearchResults": [{"name": "fixture-skill"}],
            "loadedSkillBodyBytes": 10,
            "hookIds": ["fixture-hook"],
            "schemaBytes": schema_bytes,
            "estimatedTokens": math.ceil(schema_bytes / 4),
            "revision": "a" * 64,
        }
        return {
            "schemaVersion": 1,
            "status": "passed",
            "workflow": {"modeOrder": ["planning", "implementation", "review"]},
            "modes": {
                "planning": json.loads(json.dumps(mode)),
                "implementation": json.loads(json.dumps(mode)),
                "review": json.loads(json.dumps(mode)),
            },
            "metrics": {
                "initialActiveSchemaBytes": 20,
                "unroutedInstalledCatalogSchemaBytes": 40,
                "activeSchemaBytes": 20,
                "fullEnvelopeSchemaBytes": 30,
                "activeEstimatedTokens": 5,
                "fullEnvelopeEstimatedTokens": 7,
                "metricDefinition": "deterministic estimates, not billing tokens",
                "thresholds": {
                    "initialActiveLessThanUnrouted": True,
                    "activeLessThanFullEnvelope": True,
                    "activeEstimatedTokensLessThanFullEnvelope": True,
                    "initialModeExcludesNonBaselineTool": True,
                },
            },
            "transitionTimeline": [
                {"event": "initial-primary-list"},
                {
                    "event": "implementation-staged",
                    "desiredRevision": "b",
                    "pendingRevision": "b",
                    "observedRevision": "a",
                },
                {
                    "event": "tools-list-changed-notification",
                    "desiredRevision": "b",
                    "observedRevision": "a",
                },
                {
                    "event": "same-primary-tools-list",
                    "desiredRevision": "b",
                    "observedRevision": "b",
                    "pendingRevision": None,
                },
                {"event": "review-staged"},
                {"event": "same-primary-review-tools-list"},
            ],
            "fallbacks": {
                "supportedRefresh": "NotificationRequired",
                "notification": "NotificationSent",
                "refreshUnconfirmed": "RefreshUnconfirmed",
                "reloadRequired": "ReloadRequired",
                "nextSessionOnly": "NextSessionOnly",
                "cancel": {
                    "observedRevision": "a",
                    "pendingRevision": None,
                    "recoveryRequired": False,
                },
                "nextSessionCancelObservedRevision": "a",
            },
            "connections": {
                "primary": {"role": "primary", "sessionId": "session-a"},
                "auxiliary": {"role": "auxiliary"},
                "secondSessionPrimary": {"sessionId": "session-b"},
                "auxiliaryDataDenial": "connection-control-only",
                "crossSessionClaimDenial": "connection-claim-invalid",
                "staleDisconnectedPrimaryDenial": "connection-epoch-stale",
                "staleTransitionDenial": "workflow:stale",
            },
            "agentPlugin": {
                "packageTogglePerformed": False,
                "nativeStateUnchanged": True,
                "contributedCapabilityIds": ["plugin-tool"],
                "advertisedToolNames": ["plugin__tool"],
                "skillSearchResults": [{"name": "plugin-skill"}],
                "hookIds": ["plugin-hook"],
            },
            "safety": {
                "fixtureMode": True,
                "strictMaskingCoverage": "verified-masked",
                "nativeCapabilities": "native-unmanaged",
                "nativeProviderStateUnchanged": True,
                "nativeProviderStateSha256Before": "sha256:same",
                "nativeProviderStateSha256After": "sha256:same",
                "bridgeAuthentication": "process-root-generation-sequence-bound",
                "protectedRootEvidence": {"repositoryConfigMayRedirect": False},
            },
            "surfaceCoverage": {
                "canonicalObservedFields": [
                    "workflowId",
                    "activeMode",
                    "desiredExposureRevision",
                    "observedExposureRevision",
                    "liveStatus",
                    "nextAction",
                ],
                "roles": {
                    "gateway": {"role": "authoritative-live-runtime"},
                    "mcp": {
                        "role": "gateway-tools-list-and-read-only-session-planning"
                    },
                    "cli": {
                        "role": "definition-validation-and-human-launch-handoff"
                    },
                    "desktop": {"role": "primary-human-workbench"},
                    "tui": {
                        "role": "projection-and-handoff",
                        "editing": False,
                        "liveParityClaimed": False,
                    },
                },
                "observations": {
                    "gateway": {
                        "workflowId": "delivery",
                        "activeMode": "review",
                        "desiredExposureRevision": "a" * 64,
                        "observedExposureRevision": "a" * 64,
                        "liveStatus": "observed-refresh",
                        "nextAction": "continue-in-active-mode",
                    },
                    "mcp": {
                        "workflowId": "delivery",
                        "activeMode": "review",
                        "desiredExposureRevision": "a" * 64,
                        "observedExposureRevision": "a" * 64,
                        "liveStatus": "observed-refresh",
                        "nextAction": "continue-in-active-mode",
 "observationSource": "GatewayMcpServer RMCP tools/list",
                        "observedToolNames": ["review__inspect"],
                    },
                },
            },
        }

    def test_accepts_complete_workflow_routing_evidence(self) -> None:
        validate_workflow_routing_evidence(self.valid_evidence())

    def test_rejects_failed_context_reduction_threshold(self) -> None:
        evidence = self.valid_evidence()
        evidence["metrics"]["thresholds"]["activeLessThanFullEnvelope"] = False
        with self.assertRaisesRegex(MatrixFailure, "context-reduction"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_notification_promoted_as_observation(self) -> None:
        evidence = self.valid_evidence()
        evidence["transitionTimeline"][2]["observedRevision"] = "b"
        with self.assertRaisesRegex(MatrixFailure, "notification or observation"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_next_session_observed_revision_drift(self) -> None:
        evidence = self.valid_evidence()
        evidence["fallbacks"]["nextSessionCancelObservedRevision"] = "b"
        with self.assertRaisesRegex(MatrixFailure, "next-session-only"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_mismatched_canonical_surface_observation(self) -> None:
        evidence = self.valid_evidence()
        evidence["surfaceCoverage"]["observations"]["mcp"]["activeMode"] = (
            "implementation"
        )
        with self.assertRaisesRegex(MatrixFailure, "canonical surface observation"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_synthetic_mcp_observation_source(self) -> None:
        evidence = self.valid_evidence()
        evidence["surfaceCoverage"]["observations"]["mcp"][
            "observationSource"
        ] = "hard-coded fixture"
        with self.assertRaisesRegex(MatrixFailure, "gateway tools/list"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_tui_live_or_editing_parity_claim(self) -> None:
        evidence = self.valid_evidence()
        evidence["surfaceCoverage"]["roles"]["tui"]["editing"] = True
        with self.assertRaisesRegex(MatrixFailure, "TUI.*projection-and-handoff"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_missing_observed_descriptor(self) -> None:
        evidence = self.valid_evidence()
        evidence["modes"]["planning"]["observedToolDescriptors"] = []
        with self.assertRaisesRegex(MatrixFailure, "descriptors do not match"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_changed_descriptor_description(self) -> None:
        evidence = self.valid_evidence()
        evidence["modes"]["planning"]["observedToolDescriptors"][0][
            "description"
        ] = "Changed"
        with self.assertRaisesRegex(MatrixFailure, "descriptors do not match"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_changed_descriptor_input_schema(self) -> None:
        evidence = self.valid_evidence()
        evidence["modes"]["planning"]["observedToolDescriptors"][0]["inputSchema"][
            "additionalProperties"
        ] = True
        with self.assertRaisesRegex(MatrixFailure, "descriptors do not match"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_changed_descriptor_annotations_and_output_schema(self) -> None:
        for field, value in (
            ("annotations", {"readOnlyHint": False}),
            ("outputSchema", {"type": "string"}),
        ):
            with self.subTest(field=field):
                evidence = self.valid_evidence()
                evidence["modes"]["planning"]["observedToolDescriptors"][0][field] = (
                    value
                )
                with self.assertRaisesRegex(MatrixFailure, "descriptors do not match"):
                    validate_workflow_routing_evidence(evidence)

    def test_rejects_same_names_with_mismatched_descriptor_content(self) -> None:
        evidence = self.valid_evidence()
        evidence["modes"]["planning"]["observedToolDescriptors"][0]["execution"] = {
            "taskSupport": "forbidden"
        }
        self.assertEqual(
            evidence["modes"]["planning"]["gatewayToolsListNames"],
            ["review__inspect"],
        )
        with self.assertRaisesRegex(MatrixFailure, "descriptors do not match"):
            validate_workflow_routing_evidence(evidence)

    def test_rejects_schema_bytes_not_measured_from_observed_descriptors(self) -> None:
        evidence = self.valid_evidence()
        evidence["modes"]["planning"]["schemaBytes"] += 1
        with self.assertRaisesRegex(MatrixFailure, "schema metrics"):
            validate_workflow_routing_evidence(evidence)


class LiveInventoryFilterTests(unittest.TestCase):
    def test_live_shared_source_requires_matching_source_and_state_paths(self) -> None:
        target = {
            "provider": "claude",
            "kind": "skill",
            "sourcePath": "/shared/skill/SKILL.md",
            "statePath": "/shared/skill",
        }
        coupled = {
            **target,
            "provider": "opencode",
        }
        distinct_state = {
            **target,
            "provider": "cursor",
            "statePath": "/cursor/config.json",
        }

        self.assertTrue(
            live_item_has_cross_provider_shared_source(target, [target, coupled])
        )
        self.assertFalse(
            live_item_has_cross_provider_shared_source(target, [target, distinct_state])
        )
        self.assertFalse(
            live_item_has_cross_provider_shared_source(
                {**target, "kind": "mcp"}, [target, coupled]
            )
        )

    def test_shared_source_contract_ignores_distinct_mutable_state_paths(self) -> None:
        target = {
            "provider": "codex",
            "kind": "skill",
            "id": "codex:global:skill:shared",
            "sourcePath": "/fixtures/shared/SKILL.md",
            "statePath": "/fixtures/codex/global/config.toml",
            "enabled": True,
        }
        other_provider_view = {
            **target,
            "provider": "zed",
            "id": "zed:global:skill:shared",
            "statePath": "/fixtures/shared",
        }
        with mock.patch.object(
            matrix_cases,
            "read_full_inventory",
            return_value={"items": [target, other_provider_view]},
        ):
            contract = matrix_cases.shared_source_contract(
                Path("/test/unpin"),
                Path("/test/fixtures"),
                Path("/test/state"),
                target,
            )

        self.assertIsNone(contract)

    def test_shared_source_assertion_checks_counterpart_state(self) -> None:
        contract = {
            "sourcePath": "/fixtures/shared/SKILL.md",
            "statePath": "/fixtures/shared",
            "targetId": "claude:global:skill:shared",
            "counterpartStates": {"opencode:global:skill:shared": True},
        }
        counterpart = {
            "provider": "opencode",
            "id": "opencode:global:skill:shared",
            "sourcePath": contract["sourcePath"],
            "statePath": contract["statePath"],
            "enabled": True,
        }

        with mock.patch.object(
            matrix_cases, "read_full_inventory", return_value={"items": [counterpart]}
        ):
            matrix_cases.assert_shared_source_state(
                Path("/test/unpin"),
                Path("/test/fixtures"),
                Path("/test/state"),
                contract,
                True,
                "shared-source",
            )

        counterpart["enabled"] = False
        with (
            mock.patch.object(
                matrix_cases, "read_full_inventory", return_value={"items": [counterpart]}
            ),
            self.assertRaises(MatrixFailure),
        ):
            matrix_cases.assert_shared_source_state(
                Path("/test/unpin"),
                Path("/test/fixtures"),
                Path("/test/state"),
                contract,
                True,
                "shared-source",
            )

    def test_matrix_inventory_group_identity_is_explicit_and_bounded(self) -> None:
        item = {
            "provider": "codex",
            "layer": "project",
            "kind": "mcp",
            "category": "configured-mcp",
            "id": "codex:project:configured-mcp:docs",
        }
        self.assertEqual(
            matrix_cases.inventory_group_member_selector(item),
            "codex:project:mcp:configured-mcp:codex:project:configured-mcp:docs",
        )
        name = matrix_cases.matrix_inventory_group_name(
            {"slug": "Provider Scenario With Spaces!" * 4}
        )
        self.assertTrue(name.startswith("matrix-provider-scenario-with-spaces-"))
        self.assertLessEqual(len(name), 57)

    def test_matrix_inventory_group_includes_every_shared_skill_view(self) -> None:
        target = {
            "provider": "codex",
            "layer": "global",
            "kind": "skill",
            "category": "agent-skill",
            "id": "codex:global:skill:shared",
            "sourcePath": "/fixtures/shared/SKILL.md",
        }
        sibling = {
            **target,
            "provider": "zed",
            "id": "zed:global:skill:shared",
        }
        unrelated = {
            **target,
            "provider": "claude",
            "id": "claude:global:skill:other",
            "sourcePath": "/fixtures/other/SKILL.md",
        }
        inventory = {"items": [target, sibling, unrelated]}

        self.assertEqual(
            matrix_cases.matrix_inventory_group_members(
                inventory, {"id": target["id"]}
            ),
            [target, sibling],
        )

    def test_default_mcp_session_requires_agent_plugin_tools(self) -> None:
        session = matrix_cases.McpSession(
            Path("/test/unpin"),
            Path("/test/fixtures"),
            Path("/test/state"),
        )
        session.request = mock.Mock(
            side_effect=[
                {
                    "serverInfo": {"name": "unpin"},
                    "protocolVersion": "2025-11-25",
                },
                {
                    "tools": [
                        {"name": "unpin_get_inventory_summary"},
                    {"name": "unpin_list_inventory_groups"},
                    {"name": "unpin_get_inventory_group"},
                    {"name": "unpin_plan_inventory_group"},
                    {"name": "unpin_plan_toggle_item"},
                        {"name": "unpin_apply_toggle_item"},
                        {"name": "unpin_restore_backup"},
                    ]
                },
            ]
        )
        session.notify = mock.Mock()

        with self.assertRaisesRegex(
            MatrixFailure, "omitted required matrix tools"
        ):
            session._initialize()

    def test_desktop_snapshot_request_uses_handshake_binding(self) -> None:
        binding = {
            "parentPid": 101,
            "parentStartMarker": "parent-start",
            "childPid": 202,
            "childStartMarker": "child-start",
            "projectRoot": "/test/project",
            "appStateRoot": "/test/state",
            "processGeneration": "generation",
        }
        session_secret = "11" * 32
        request = matrix_cases.authenticated_desktop_bridge_request(
            {
                "version": 2,
                "id": "snapshot",
                "method": "snapshot",
                "params": {},
            },
            binding,
            session_secret,
            1,
        )

        fingerprint = hashlib.sha256(b"{}").hexdigest()
        material = (
            "unpin.desktop.bridge.request.v1\0"
            f"{session_secret}\0{1}\0snapshot\0snapshot\0snapshot\0{fingerprint}\0"
            f"{hashlib.sha256(b'{}').hexdigest()}"
        )
        self.assertEqual(
            request["auth"],
            {
                **binding,
                "sequence": 1,
                "operationId": "snapshot",
                "fingerprint": fingerprint,
                "authTag": hashlib.sha256(material.encode("utf-8")).hexdigest(),
            },
        )

    def test_desktop_bridge_snapshot_authenticates_after_handshake(self) -> None:
        process = mock.Mock(pid=202)
        process.stdin.closed = False
        process.wait.return_value = 0
        binding = {
            "parentPid": os.getpid(),
            "parentStartMarker": "parent-start",
            "childPid": process.pid,
            "childStartMarker": "child-start",
            "projectRoot": "/test/project",
            "appStateRoot": "/test/state",
            "processGeneration": "generation",
        }
        snapshot = {"agentPlugins": []}
        with (
            mock.patch.object(matrix_cases.subprocess, "Popen", return_value=process),
            mock.patch.object(
                matrix_cases,
                "_exchange_desktop_bridge_frame",
                side_effect=[{"binding": binding}, snapshot],
            ) as exchange,
        ):
            result = matrix_cases.desktop_bridge_snapshot(
                Path("/test/unpin"),
                Path("/test/fixtures"),
                Path("/test/project"),
                Path("/test/state"),
            )

        self.assertEqual(result, snapshot)
        handshake_request = exchange.call_args_list[0].args[1]
        snapshot_request = exchange.call_args_list[1].args[1]
        self.assertEqual(handshake_request["params"]["childPid"], process.pid)
        self.assertEqual(snapshot_request["auth"]["sequence"], 1)
        for field, value in binding.items():
            self.assertEqual(snapshot_request["auth"][field], value)
        self.assertEqual(process.stdin.close.call_count, 1)

    def test_agent_plugin_surface_contracts_normalize_provider_shapes(self) -> None:
        base = {
            "logicalId": "plugin:connector-kit",
            "name": "connector-kit",
            "componentSignature": "mcp+skill",
            "projectionFingerprint": "projection-fingerprint",
            "state": "mixed",
            "access": "actionable",
            "componentKinds": ["mcp", "skill"],
            "instanceCount": 2,
            "blockerCount": 1,
            "diagnosticCount": 2,
        }
        expected = [
            {
                **base,
                "providers": ["claude", "codex"],
            }
        ]

        self.assertEqual(
            matrix_cases.agent_plugin_surface_contracts(
                [
                    {
                        **{
                            key: value
                            for key, value in base.items()
                            if key
                            not in {
                                "componentKinds",
                                "instanceCount",
                                "blockerCount",
                                "diagnosticCount",
                            }
                        },
                        "instances": [
                            {
                                "provider": "codex",
                                "components": [{"kind": "skill"}],
                                "blockers": ["blocked"],
                                "diagnostics": ["diagnostic"],
                            },
                            {
                                "provider": "claude",
                                "components": [{"kind": "mcp"}],
                                "diagnostics": ["diagnostic"],
                            },
                        ],
                    }
                ]
            ),
            expected,
        )
        self.assertEqual(
            matrix_cases.agent_plugin_surface_contracts(
                [{**base, "providers": ["codex", "claude"]}]
            ),
            expected,
        )
        self.assertEqual(
            matrix_cases.agent_plugin_surface_contracts(
                [
                    {
                        **base,
                        "componentKinds": None,
                        "coverage": {
                            "providers": ["codex", "claude"],
                            "instanceCount": 2,
                        },
                        "components": [{"kind": "skill"}, {"kind": "mcp"}],
                    }
                ]
            ),
            expected,
        )
        with self.assertRaisesRegex(MatrixFailure, "incomplete identity contract"):
            matrix_cases.agent_plugin_surface_contracts(
                [{key: value for key, value in base.items() if key != "componentSignature"}]
            )

    def test_agent_plugin_surface_redaction_rejects_internal_capabilities(self) -> None:
        matrix_cases.assert_agent_plugin_payload_redacted(
            {"logicalId": "plugin:connector-kit"}, "test"
        )
        with self.assertRaisesRegex(MatrixFailure, "exactIdentities"):
            matrix_cases.assert_agent_plugin_payload_redacted(
                {"exactIdentities": []}, "test"
            )

    def test_run_command_uses_devnull_without_explicit_input(self) -> None:
        observed: dict[str, object] = {}
        real_popen = subprocess.Popen

        def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[str]:
            observed["stdin"] = kwargs.get("stdin")
            return real_popen(*args, **kwargs)

        with mock.patch.object(
            matrix_support.subprocess,
            "Popen",
            side_effect=recording_popen,
        ):
            completed = run_command(
                [
                    os.sys.executable,
                    "-c",
                    "import sys;print(repr(sys.stdin.read()))",
                ]
            )

        self.assertEqual(completed.stdout, "''\n")
        self.assertEqual(observed["stdin"], subprocess.DEVNULL)

    def test_run_command_delivers_utf8_input_and_completed_process_metadata(self) -> None:
        command = [
            os.sys.executable,
            "-c",
            "import sys;sys.stdout.write(sys.stdin.read())",
        ]
        completed = run_command(command, input_text="héllo\n")
        self.assertEqual(completed.args, command)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "héllo\n")

    def test_run_command_cleans_up_after_unexpected_communication_error(self) -> None:
        process = mock.Mock()
        process.stdin = None
        process.communicate.side_effect = KeyboardInterrupt
        with mock.patch.object(
            matrix_support.subprocess,
            "Popen",
            return_value=process,
        ):
            with mock.patch.object(
                matrix_support,
                "_terminate_and_wait",
                return_value=[],
            ) as cleanup:
                with self.assertRaises(KeyboardInterrupt):
                    run_command([os.sys.executable, "-c", "pass"])

        cleanup.assert_called_once_with(process)

    def test_windows_timeout_cleanup_invokes_taskkill_for_process_tree(self) -> None:
        process = mock.Mock()
        process.pid = 123
        process.poll.return_value = None
        tree_kill = subprocess.CompletedProcess(args=[], returncode=0)
        with mock.patch.object(matrix_support, "_PLATFORM", "nt"):
            with mock.patch.object(
                matrix_support.subprocess,
                "run",
                return_value=tree_kill,
            ) as taskkill:
                issues = matrix_support._signal_process_tree(process, force=True)

        self.assertEqual(issues, [])
        taskkill.assert_called_once_with(
            ["taskkill", "/PID", "123", "/T", "/F"],
            capture_output=True,
            check=False,
            timeout=5,
        )

    def test_windows_timeout_cleanup_records_taskkill_failure(self) -> None:
        process = mock.Mock()
        process.pid = 123
        process.poll.return_value = None
        tree_kill = subprocess.CompletedProcess(args=[], returncode=1)
        with mock.patch.object(matrix_support, "_PLATFORM", "nt"):
            with mock.patch.object(
                matrix_support.subprocess,
                "run",
                return_value=tree_kill,
            ):
                issues = matrix_support._signal_process_tree(process, force=True)

        self.assertEqual(
            issues,
            ["process-tree signal failed with exit code 1"],
        )
        process.kill.assert_called_once_with()

    def test_windows_timeout_cleanup_forces_tree_before_waiting(self) -> None:
        process = mock.Mock()
        process.pid = 123
        process.poll.return_value = None
        tree_kill = subprocess.CompletedProcess(args=[], returncode=0)
        with mock.patch.object(matrix_support, "_PLATFORM", "nt"):
            with mock.patch.object(
                matrix_support.subprocess,
                "run",
                return_value=tree_kill,
            ) as taskkill:
                issues = matrix_support._terminate_and_wait(process)

        self.assertEqual(issues, [])
        taskkill.assert_called_once_with(
            ["taskkill", "/PID", "123", "/T", "/F"],
            capture_output=True,
            check=False,
            timeout=5,
        )
        process.wait.assert_called_once_with(timeout=5)

    def test_cleanup_wait_error_still_escalates_to_forced_termination(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [OSError("wait failed"), None]
        with mock.patch.object(matrix_support, "_PLATFORM", "other"):
            issues = matrix_support._terminate_and_wait(process)

        self.assertEqual(issues, ["process wait failed: OSError"])
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()

    def test_run_command_preserves_text_mode_newline_normalization(self) -> None:
        completed = run_command(
            [
                os.sys.executable,
                "-c",
                "import sys;sys.stdout.buffer.write(b'one\\r\\ntwo\\rthree\\n')",
            ]
        )
        self.assertEqual(completed.stdout, "one\ntwo\nthree\n")

    def test_run_command_timeout_with_buffered_input_keeps_typed_failure(self) -> None:
        with self.assertRaises(MatrixCommandTimeout):
            run_command(
                [
                    os.sys.executable,
                    "-c",
                    "import time;time.sleep(10)",
                ],
                input_text="buffered input\n" * 100_000,
                timeout_seconds=0.1,
            )

    @unittest.skipUnless(os.name == "posix", "process-group regression is POSIX-specific")
    def test_run_command_timeout_terminates_descendants_and_captures_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="unpin-timeout-process-test-") as root:
            child_pid_path = Path(root) / "child.pid"
            parent = (
                "import pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "time.sleep(10)']);"
                f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid));"
                "print('partial output',flush=True);"
                "time.sleep(10)"
            )
            started = time.monotonic()
            with self.assertRaises(MatrixCommandTimeout) as timeout:
                run_command(
                    [os.sys.executable, "-c", parent],
                    timeout_seconds=2,
                )
            self.assertLess(time.monotonic() - started, 5.0)
            self.assertEqual(timeout.exception.stdout, "partial output\n")
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail("timed-out command left its descendant process alive")

    def test_quality_gate_timeout_covers_cold_workspace_builds(self) -> None:
        self.assertIsInstance(QUALITY_GATE_TIMEOUT_SECONDS, (int, float))
        self.assertTrue(math.isfinite(QUALITY_GATE_TIMEOUT_SECONDS))
        self.assertGreaterEqual(QUALITY_GATE_TIMEOUT_SECONDS, 1_200)
        self.assertLessEqual(QUALITY_GATE_TIMEOUT_SECONDS, 3_600)

        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="test result: ok. 1 passed\n",
            stderr="",
        )
        with tempfile.TemporaryDirectory(prefix="unpin-local-matrix-test-") as root:
            with mock.patch.object(
                matrix_runner,
                "run_command",
                return_value=completed,
            ) as run_command:
                matrix_runner.run_quality_gates(
                    Path("/test/cargo"),
                    Path("/test/unpin"),
                    Path(root),
                )

        self.assertEqual(run_command.call_count, 8)
        for call in run_command.call_args_list:
            self.assertFalse(call.kwargs["check"])
            self.assertEqual(
                call.kwargs["timeout_seconds"],
                QUALITY_GATE_TIMEOUT_SECONDS,
            )

    def test_quality_gate_timeout_can_be_disabled_for_explicit_release_runs(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="test result: ok. 1 passed\n",
            stderr="",
        )
        with tempfile.TemporaryDirectory(prefix="unpin-local-matrix-test-") as root:
            with mock.patch.object(
                matrix_runner,
                "run_command",
                return_value=completed,
            ) as run_command:
                matrix_runner.run_quality_gates(
                    Path("/test/cargo"),
                    Path("/test/unpin"),
                    Path(root),
                    timeout_seconds=None,
                )

        for call in run_command.call_args_list:
            self.assertIsNone(call.kwargs["timeout_seconds"])

    def test_quality_gate_timeout_parser_accepts_zero_and_rejects_invalid_values(
        self,
    ) -> None:
        self.assertIsNone(quality_gate_timeout_seconds("0"))
        self.assertEqual(quality_gate_timeout_seconds("1.5"), 1.5)
        for value in ("-1", "nan", "infinity", "not-a-number"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    quality_gate_timeout_seconds(value)

    def test_quality_gate_timeout_writes_partial_failure_evidence(self) -> None:
        timeout = MatrixCommandTimeout(
            ["cargo", "test"],
            QUALITY_GATE_TIMEOUT_SECONDS,
            "partial stdout\n",
            "partial stderr\n",
        )
        with tempfile.TemporaryDirectory(prefix="unpin-local-matrix-test-") as root:
            artifact_root = Path(root)
            with mock.patch.object(
                matrix_runner,
                "run_command",
                side_effect=timeout,
            ):
                with self.assertRaises(MatrixCommandTimeout):
                    matrix_runner.run_quality_gates(
                        Path("/test/cargo"),
                        Path("/test/unpin"),
                        artifact_root,
                    )

            verification = json.loads(
                (artifact_root / "raw/verification.json").read_text(encoding="utf-8")
            )
            self.assertEqual(verification["cargo-fmt"]["status"], "timed-out")
            self.assertIsNone(verification["cargo-fmt"]["exitCode"])
            self.assertEqual(
                (artifact_root / "raw/verification/cargo-fmt.stdout.txt").read_text(
                    encoding="utf-8"
                ),
                timeout.stdout,
            )
            self.assertEqual(
                (artifact_root / "raw/verification/cargo-fmt.stderr.txt").read_text(
                    encoding="utf-8"
                ),
                timeout.stderr,
            )

    def test_failed_quality_gate_writes_partial_verification_manifest(self) -> None:
        failed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="failed stdout\n",
            stderr="failed stderr\n",
        )
        with tempfile.TemporaryDirectory(prefix="unpin-local-matrix-test-") as root:
            artifact_root = Path(root)
            with mock.patch.object(
                matrix_runner,
                "run_command",
                return_value=failed,
            ):
                with self.assertRaises(MatrixFailure):
                    matrix_runner.run_quality_gates(
                        Path("/test/cargo"),
                        Path("/test/unpin"),
                        artifact_root,
                    )

            verification = json.loads(
                (artifact_root / "raw/verification.json").read_text(encoding="utf-8")
            )
            self.assertEqual(verification["cargo-fmt"]["status"], "failed")
            self.assertEqual(verification["cargo-fmt"]["exitCode"], 1)

    def test_live_plan_checks_only_the_selected_items_provider_paths(self) -> None:
        selected = {
            "sourcePath": "/tmp/provider/source",
            "statePath": "/tmp/provider/state",
            "unrelatedPath": "/tmp/provider/unrelated",
        }

        self.assertEqual(
            live_plan_state_paths(selected),
            [Path("/tmp/provider/source"), Path("/tmp/provider/state")],
        )
        self.assertEqual(
            live_plan_state_paths(
                {
                    "sourcePath": "/tmp/provider/shared",
                    "statePath": "/tmp/provider/shared",
                }
            ),
            [Path("/tmp/provider/shared")],
        )

    def test_excludes_the_repository_tmp_tree_only(self) -> None:
        matrix_root = REPO_ROOT / "tmp/2026-07-24-134032-local-matrix"
        for path in (
            REPO_ROOT / "tmp",
            matrix_root / "cases/scenario/provider/item",
            matrix_root / "screenshots/overview.png",
            REPO_ROOT / "tmp/project/.agents/skills/review/SKILL.md",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    is_repository_tmp_path(path.resolve())
                )

        self.assertFalse(
            is_repository_tmp_path(
                (REPO_ROOT / "scratch/.agents/skills/review/SKILL.md").resolve()
            )
        )
        self.assertFalse(
            is_repository_tmp_path(
                REPO_ROOT.parent
                / "2026-07-24-134032-local-matrix/cases/scenario/provider/item"
            )
        )

    def test_reports_fixture_and_repository_tmp_exclusions_separately(self) -> None:
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
            "sourcePath": str(REPO_ROOT / "scratch/project/.agents/skills/review"),
            "statePath": str(REPO_ROOT / "scratch/project/.agents/skills/review"),
        }

        self.assertEqual(
            live_inventory_exclusion_reason(fixture_item),
            "repository-fixture",
        )
        self.assertEqual(
            live_inventory_exclusion_reason(retained_item),
            "repository-tmp",
        )
        self.assertIsNone(live_inventory_exclusion_reason(ordinary_item))
        self.assertIsNone(live_inventory_exclusion_reason({}))


if __name__ == "__main__":
    unittest.main()
