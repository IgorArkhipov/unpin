#!/usr/bin/env python3
"""Capture provider-matrix dashboard sections through native macOS WebKit."""

from __future__ import annotations

import json
import os
from html.parser import HTMLParser
from pathlib import Path
import plistlib
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
from typing import NamedTuple

from local_provider_matrix_support import MatrixFailure, SCREENSHOTS


DASHBOARD_WIDTH = 1_480
XCODEBUILD_TIMEOUT_SECONDS = 900
XCODEBUILD_TERMINATION_GRACE_SECONDS = 5
XCODEBUILD_OUTPUT_TAIL_BYTES = 4_000
CAPTURE_TEST = (
    "-only-testing:UnpinDesktopTests/ProviderMatrixDashboardSnapshotTests/"
    "testCaptureProviderMatrixDashboard"
)


class ScreenshotSection(NamedTuple):
    id: str
    filename: str


class DashboardSectionParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.panel_ids: list[str] = []

    def handle_starttag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        if tag != "section":
            return
        values = dict(attributes)
        if "panel" not in values.get("class", "").split():
            return
        section_id = values.get("id")
        if section_id is not None:
            self.panel_ids.append(section_id)


SCREENSHOT_SECTION_IDS = (
    "overview",
    "live-library",
    "coverage-matrix",
    "tui-library",
    "provider-claude",
    "provider-codex",
    "provider-cursor",
    "provider-pi",
    "provider-opencode",
    "provider-zed",
    "mcp-states",
)
if len(SCREENSHOT_SECTION_IDS) != len(SCREENSHOTS):
    raise RuntimeError("provider screenshot section and filename inventories differ")
SCREENSHOT_SECTIONS = tuple(
    ScreenshotSection(section_id, filename)
    for section_id, filename in zip(SCREENSHOT_SECTION_IDS, SCREENSHOTS)
)


def preflight_provider_matrix_screenshot_capture(
    *,
    platform: str | None = None,
) -> None:
    platform = sys.platform if platform is None else platform
    if platform != "darwin":
        raise MatrixFailure(
            "native provider-matrix screenshot capture requires macOS; "
            "use the documented manual dashboard workflow on this platform"
        )


def _run_xcodebuild(
    command: list[str],
    *,
    repo_root: Path,
    environment: dict[str, str],
    runner,
) -> None:
    if runner is subprocess.run:
        _run_xcodebuild_process(
            command,
            repo_root=repo_root,
            environment=environment,
        )
        return

    try:
        runner(
            command,
            cwd=repo_root,
            env=environment,
            check=True,
            timeout=XCODEBUILD_TIMEOUT_SECONDS,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except subprocess.TimeoutExpired as error:
        raise MatrixFailure(
            "provider screenshot capture timed out after "
            f"{XCODEBUILD_TIMEOUT_SECONDS} seconds: {' '.join(command)}"
        ) from error
    except subprocess.CalledProcessError as error:
        output = str(error.stdout or error.stderr or "")
        raise MatrixFailure(
            f"provider screenshot capture command failed ({error.returncode}): "
            f"{' '.join(command)}\noutput:\n{output[-XCODEBUILD_OUTPUT_TAIL_BYTES:]}"
        ) from error


def _capture_tail(capture) -> str:
    capture.flush()
    size = capture.tell()
    capture.seek(max(0, size - XCODEBUILD_OUTPUT_TAIL_BYTES))
    return capture.read().decode(errors="replace").replace("\r\n", "\n")


def _terminate_xcodebuild(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=XCODEBUILD_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        process.wait()


def _run_xcodebuild_process(
    command: list[str],
    *,
    repo_root: Path,
    environment: dict[str, str],
) -> None:
    with tempfile.TemporaryFile(mode="w+b") as output_capture:
        process = subprocess.Popen(
            command,
            cwd=repo_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output_capture,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=XCODEBUILD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            _terminate_xcodebuild(process)
            output = _capture_tail(output_capture)
            raise MatrixFailure(
                "provider screenshot capture timed out after "
                f"{XCODEBUILD_TIMEOUT_SECONDS} seconds: {' '.join(command)}"
                f"\noutput:\n{output}"
            ) from error
        except BaseException:
            _terminate_xcodebuild(process)
            raise

        if returncode != 0:
            output = _capture_tail(output_capture)
            raise MatrixFailure(
                f"provider screenshot capture command failed ({returncode}): "
                f"{' '.join(command)}\noutput:\n{output}"
            )


def run_xcode_capture(
    repo_root: Path,
    dashboard_path: Path,
    output_root: Path,
    *,
    runner=subprocess.run,
) -> None:
    section_metadata = [section._asdict() for section in SCREENSHOT_SECTIONS]
    capture_environment = {
        "UNPIN_PROVIDER_MATRIX_DASHBOARD": str(dashboard_path),
        "UNPIN_PROVIDER_MATRIX_SCREENSHOTS_DIR": str(output_root),
        "UNPIN_PROVIDER_MATRIX_SECTIONS": json.dumps(section_metadata),
    }
    environment = os.environ.copy()
    environment.update(capture_environment)

    with tempfile.TemporaryDirectory(prefix="unpin-provider-matrix-xcode-") as temporary:
        derived_data = Path(temporary)
        build_command = [
            "xcodebuild",
            "build-for-testing",
            "-project",
            "apps/unpin-desktop/UnpinDesktop.xcodeproj",
            "-scheme",
            "UnpinDesktop",
            "-destination",
            "platform=macOS",
            "-derivedDataPath",
            str(derived_data),
        ]
        _run_xcodebuild(
            build_command,
            repo_root=repo_root,
            environment=environment,
            runner=runner,
        )

        xctestrun_files = sorted((derived_data / "Build/Products").glob("*.xctestrun"))
        if len(xctestrun_files) != 1:
            raise MatrixFailure(
                f"expected one xctestrun file, found {len(xctestrun_files)}"
            )
        xctestrun_path = xctestrun_files[0]
        with xctestrun_path.open("rb") as handle:
            xctestrun = plistlib.load(handle)
        targets = [
            target
            for configuration in xctestrun.get("TestConfigurations", [])
            for target in configuration.get("TestTargets", [])
            if target.get("BlueprintName") == "UnpinDesktopTests"
        ]
        if len(targets) != 1:
            raise MatrixFailure(
                f"expected one UnpinDesktopTests xctestrun target, found {len(targets)}"
            )
        target_environment = targets[0].setdefault("EnvironmentVariables", {})
        target_environment.update(capture_environment)
        with xctestrun_path.open("wb") as handle:
            plistlib.dump(xctestrun, handle)

        test_command = [
            "xcodebuild",
            "test-without-building",
            "-xctestrun",
            str(xctestrun_path),
            "-destination",
            "platform=macOS",
            CAPTURE_TEST,
        ]
        _run_xcodebuild(
            test_command,
            repo_root=repo_root,
            environment=environment,
            runner=runner,
        )


def _png_dimensions(path: Path) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MatrixFailure(f"cannot inspect captured PNG: {path.name}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise MatrixFailure(
            f"captured PNG must be a private regular file: {path.name}"
        )
    if metadata.st_size < 1_024:
        raise MatrixFailure(f"captured PNG is unexpectedly small: {path.name}")
    with path.open("rb") as handle:
        header = handle.read(24)
    if (
        len(header) != 24
        or header[:8] != b"\x89PNG\r\n\x1a\n"
        or header[12:16] != b"IHDR"
    ):
        raise MatrixFailure(f"captured file is not a PNG: {path.name}")
    width, height = struct.unpack(">II", header[16:24])
    if width != DASHBOARD_WIDTH or height < 120 or height > 12_000:
        raise MatrixFailure(
            f"captured PNG has invalid dimensions {width}x{height}: {path.name}"
        )
    return width, height


def validate_capture_inventory(output_root: Path) -> list[Path]:
    expected = {section.filename for section in SCREENSHOT_SECTIONS}
    actual = {path.name for path in output_root.iterdir()}
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        raise MatrixFailure(
            f"provider screenshot set mismatch: missing={missing}, unknown={unknown}"
        )
    captures = [output_root / section.filename for section in SCREENSHOT_SECTIONS]
    for capture in captures:
        _png_dimensions(capture)
    return captures


def validate_dashboard_section_inventory(dashboard_path: Path) -> None:
    parser = DashboardSectionParser()
    try:
        parser.feed(dashboard_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise MatrixFailure(
            f"cannot inspect provider matrix dashboard sections: {dashboard_path}"
        ) from error

    actual = tuple(parser.panel_ids)
    if actual != SCREENSHOT_SECTION_IDS:
        expected = set(SCREENSHOT_SECTION_IDS)
        observed = set(actual)
        raise MatrixFailure(
            "provider matrix dashboard section inventory does not match capture "
            f"inventory: missing={sorted(expected - observed)}, "
            f"unexpected={sorted(observed - expected)}, actual={list(actual)}"
        )


def publish_capture_inventory(staging_root: Path, screenshots_root: Path) -> None:
    for capture in validate_capture_inventory(staging_root):
        capture.chmod(0o600)
    staging_root.chmod(0o700)

    backup_root: Path | None = None
    if screenshots_root.exists():
        backup_root = Path(
            tempfile.mkdtemp(
                prefix=".provider-matrix-screenshots-previous-",
                dir=screenshots_root.parent,
            )
        )
        backup_root.rmdir()
        try:
            screenshots_root.replace(backup_root)
        except OSError as error:
            raise MatrixFailure(
                f"cannot stage previous provider screenshots: {screenshots_root}"
            ) from error

    try:
        staging_root.replace(screenshots_root)
    except OSError as error:
        if backup_root is not None and backup_root.exists():
            try:
                backup_root.replace(screenshots_root)
            except OSError as rollback_error:
                raise MatrixFailure(
                    "failed to publish captured screenshots and restore the previous "
                    f"set; previous screenshots remain at {backup_root}"
                ) from rollback_error
        raise MatrixFailure(
            "failed to publish captured screenshots; previous set was restored"
        ) from error

    if backup_root is not None:
        try:
            shutil.rmtree(backup_root)
        except OSError as error:
            raise MatrixFailure(
                f"captured screenshots published but previous set remains at {backup_root}"
            ) from error


def capture_provider_matrix_screenshots(
    repo_root: Path,
    artifact_root: Path,
    *,
    platform: str | None = None,
    runner=subprocess.run,
) -> list[Path]:
    preflight_provider_matrix_screenshot_capture(platform=platform)

    artifact_root = artifact_root.resolve()
    dashboard_path = artifact_root / "dashboard.html"
    if dashboard_path.is_symlink() or not dashboard_path.is_file():
        raise MatrixFailure(f"provider matrix dashboard is unavailable: {dashboard_path}")
    validate_dashboard_section_inventory(dashboard_path)

    screenshots_root = artifact_root / "screenshots"
    if screenshots_root.is_symlink():
        raise MatrixFailure("provider matrix screenshots directory must not be a symlink")
    if screenshots_root.exists() and not screenshots_root.is_dir():
        raise MatrixFailure("provider matrix screenshots path must be a directory")
    if screenshots_root.is_dir():
        expected = {section.filename for section in SCREENSHOT_SECTIONS}
        unknown = sorted(
            path.name
            for path in screenshots_root.glob("*.png")
            if path.name not in expected
        )
        if unknown:
            raise MatrixFailure(f"unexpected existing provider screenshots: {unknown}")

    staging_root = Path(
        tempfile.mkdtemp(
        prefix=".provider-matrix-screenshots-",
        dir=artifact_root,
        )
    )
    try:
        run_xcode_capture(
            repo_root,
            dashboard_path,
            staging_root,
            runner=runner,
        )
        publish_capture_inventory(staging_root, screenshots_root)
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)

    return [screenshots_root / section.filename for section in SCREENSHOT_SECTIONS]
