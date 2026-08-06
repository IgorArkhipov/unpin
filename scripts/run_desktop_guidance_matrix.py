#!/usr/bin/env python3
from __future__ import annotations

import argparse
import binascii
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
from typing import NamedTuple, Sequence
import zlib


WIDTH = 1180
HEIGHT = 760
THEMES = ("light", "dark")
CAPTURE_TEST = (
    "-only-testing:UnpinDesktopTests/WorkbenchGuidanceMatrixTests/"
    "testCaptureGuidanceMatrix"
)


class Scenario(NamedTuple):
    id: str
    area: str
    primer_state: str
    source_fixture: str


SCENARIOS = (
    Scenario("discover-ready-expanded", "discover", "expanded", "inventory-ready"),
    Scenario("discover-ready-collapsed", "discover", "collapsed", "inventory-ready"),
    Scenario("discover-no-workspace", "discover", "expanded", "no-workspace"),
    Scenario("discover-loading", "discover", "expanded", "workspace-loading"),
    Scenario("discover-blocked", "discover", "expanded", "bridge-blocked"),
    Scenario("discover-empty", "discover", "expanded", "empty-inventory"),
    Scenario("discover-filter-zero", "discover", "expanded", "active-filter-zero"),
    Scenario("govern-no-workspace-expanded", "govern", "expanded", "no-workspace"),
    Scenario("govern-no-workspace-collapsed", "govern", "collapsed", "no-workspace"),
    Scenario(
        "govern-workspace-context-expanded",
        "govern",
        "expanded",
        "workspace-context",
    ),
    Scenario(
        "govern-workspace-context-collapsed",
        "govern",
        "collapsed",
        "workspace-context",
    ),
    Scenario("change-ready-expanded", "change", "expanded", "groups-ready"),
    Scenario("change-ready-collapsed", "change", "collapsed", "groups-ready"),
    Scenario("change-no-workspace", "change", "expanded", "no-workspace"),
    Scenario("change-loading", "change", "expanded", "workspace-loading"),
    Scenario("change-blocked", "change", "expanded", "bridge-blocked"),
    Scenario("change-no-groups", "change", "expanded", "no-groups"),
    Scenario(
        "recover-ready-selected-expanded",
        "recover",
        "expanded",
        "selected-restorable-backup",
    ),
    Scenario(
        "recover-ready-selected-collapsed",
        "recover",
        "collapsed",
        "selected-restorable-backup",
    ),
    Scenario("recover-no-workspace", "recover", "expanded", "no-workspace"),
    Scenario("recover-loading", "recover", "expanded", "recovery-loading"),
    Scenario("recover-unavailable", "recover", "expanded", "evidence-unavailable"),
    Scenario(
        "recover-unavailable-preserved",
        "recover",
        "expanded",
        "preserved-evidence-unavailable",
    ),
    Scenario("recover-empty", "recover", "expanded", "empty-evidence"),
    Scenario("recover-no-selection", "recover", "expanded", "evidence-no-selection"),
    Scenario(
        "recover-operation-selected",
        "recover",
        "expanded",
        "selected-operation",
    ),
)


class MatrixError(RuntimeError):
    pass


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def evidence_repository_root(source_root: Path) -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--git-common-dir"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    )
    common_value = result.stdout.strip()
    if not common_value:
        raise MatrixError("git did not report a common repository directory")
    common_directory = Path(common_value)
    if not common_directory.is_absolute():
        common_directory = source_root / common_directory
    common_directory = common_directory.resolve()
    if common_directory.name != ".git":
        raise MatrixError(f"unexpected git common directory: {common_directory}")
    return common_directory.parent


def validate_scenario_ids(scenario_ids: Sequence[str]) -> list[str]:
    requested = list(scenario_ids)
    expected = [scenario.id for scenario in SCENARIOS]
    duplicates = sorted({item for item in requested if requested.count(item) > 1})
    unknown = sorted(set(requested) - set(expected))
    missing = sorted(set(expected) - set(requested))
    if duplicates or unknown or missing or len(requested) != len(expected):
        raise MatrixError(
            "invalid scenario inventory: "
            f"duplicates={duplicates}, unknown={unknown}, missing={missing}"
        )
    return requested


def validate_output_root(repo_root: Path, candidate: Path) -> Path:
    repo_root = repo_root.resolve()
    tmp_root = (repo_root / "tmp").resolve()
    output_root = candidate.expanduser().resolve()
    try:
        output_root.relative_to(tmp_root)
    except ValueError as error:
        raise MatrixError(
            f"guidance matrix output must stay below repository tmp: {tmp_root}"
        ) from error
    if output_root == tmp_root:
        raise MatrixError("guidance matrix output must be a child directory of repository tmp")
    return output_root


def default_output_root(repo_root: Path) -> Path:
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d-%H%M%S")
    return repo_root / "tmp" / f"{stamp}-desktop-first-run-guidance-matrix"


def run_xcode_capture(
    repo_root: Path,
    output_root: Path,
    *,
    runner=subprocess.run,
) -> None:
    scenario_ids = validate_scenario_ids([scenario.id for scenario in SCENARIOS])
    environment = os.environ.copy()
    environment["UNPIN_GUIDANCE_MATRIX_DIR"] = str(output_root)
    environment["UNPIN_GUIDANCE_MATRIX_SCENARIOS"] = json.dumps(scenario_ids)
    with tempfile.TemporaryDirectory(prefix="unpin-guidance-xcode-") as temporary:
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
        runner(build_command, cwd=repo_root, env=environment, check=True)

        xctestrun_files = sorted((derived_data / "Build" / "Products").glob("*.xctestrun"))
        if len(xctestrun_files) != 1:
            raise MatrixError(
                f"expected one xctestrun file, found {len(xctestrun_files)}"
            )
        xctestrun_path = xctestrun_files[0]
        with xctestrun_path.open("rb") as handle:
            xctestrun = plistlib.load(handle)
        test_configurations = xctestrun.get("TestConfigurations", [])
        targets = [
            target
            for configuration in test_configurations
            for target in configuration.get("TestTargets", [])
            if target.get("BlueprintName") == "UnpinDesktopTests"
        ]
        if len(targets) != 1:
            raise MatrixError(
                f"expected one UnpinDesktopTests xctestrun target, found {len(targets)}"
            )
        target_environment = targets[0].setdefault("EnvironmentVariables", {})
        target_environment["UNPIN_GUIDANCE_MATRIX_DIR"] = str(output_root)
        target_environment["UNPIN_GUIDANCE_MATRIX_SCENARIOS"] = json.dumps(scenario_ids)
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
        runner(test_command, cwd=repo_root, env=environment, check=True)


def _read_png(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if not data:
        raise MatrixError(f"PNG is zero bytes: {path}")
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise MatrixError(f"PNG signature is invalid: {path}")

    offset = 8
    width = height = bit_depth = color_type = interlace = None
    compressed = bytearray()
    saw_iend = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise MatrixError(f"PNG chunk is truncated: {path}")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + length
        checksum_end = payload_end + 4
        if checksum_end > len(data):
            raise MatrixError(f"PNG chunk payload is truncated: {path}")
        payload = data[payload_start:payload_end]
        expected_crc = struct.unpack(">I", data[payload_end:checksum_end])[0]
        actual_crc = binascii.crc32(kind)
        actual_crc = binascii.crc32(payload, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise MatrixError(f"PNG chunk checksum is invalid: {path}")
        if kind == b"IHDR":
            if length != 13:
                raise MatrixError(f"PNG IHDR length is invalid: {path}")
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            saw_iend = True
            if checksum_end != len(data):
                raise MatrixError(f"PNG has trailing bytes after IEND: {path}")
            break
        offset = checksum_end

    if width is None or height is None or not compressed or not saw_iend:
        raise MatrixError(f"PNG is missing required chunks: {path}")
    if interlace != 0:
        raise MatrixError(f"interlaced PNG is not supported by matrix validation: {path}")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type)
    if channels is None:
        raise MatrixError(f"PNG color type is unsupported: {path}")
    row_bytes = math.ceil(width * channels * bit_depth / 8)
    try:
        decoded = zlib.decompress(bytes(compressed))
    except zlib.error as error:
        raise MatrixError(f"PNG image data cannot be decoded: {path}") from error
    if len(decoded) != (row_bytes + 1) * height:
        raise MatrixError(f"PNG decoded image length is invalid: {path}")
    return width, height


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_capture(
    output_root: Path,
    *,
    scenarios: Sequence[Scenario] = SCENARIOS,
    themes: Sequence[str] = THEMES,
) -> list[dict[str, object]]:
    expected_paths = {
        Path(theme) / f"{scenario.id}.png"
        for theme in themes
        for scenario in scenarios
    }
    actual_paths = {
        path.relative_to(output_root)
        for path in output_root.rglob("*.png")
        if path.is_file()
    }
    missing = sorted(str(path) for path in expected_paths - actual_paths)
    unknown = sorted(str(path) for path in actual_paths - expected_paths)
    if missing or unknown:
        raise MatrixError(f"capture set mismatch: missing={missing}, unknown={unknown}")

    by_id = {scenario.id: scenario for scenario in scenarios}
    images: list[dict[str, object]] = []
    for relative_path in sorted(expected_paths, key=str):
        absolute_path = output_root / relative_path
        resolved = absolute_path.resolve()
        try:
            resolved.relative_to(output_root.resolve())
        except ValueError as error:
            raise MatrixError(f"capture escapes output root: {relative_path}") from error
        width, height = _read_png(absolute_path)
        if (width, height) != (WIDTH, HEIGHT):
            raise MatrixError(
                f"capture dimensions must be {WIDTH}x{HEIGHT}: "
                f"{relative_path} is {width}x{height}"
            )
        scenario_id = relative_path.stem
        scenario = by_id[scenario_id]
        images.append(
            {
                "path": relative_path.as_posix(),
                "scenario_id": scenario.id,
                "work_area": scenario.area,
                "primer_state": scenario.primer_state,
                "source_fixture": scenario.source_fixture,
                "theme": relative_path.parts[0],
                "width": width,
                "height": height,
                "bytes": absolute_path.stat().st_size,
                "sha256": _sha256(absolute_path),
            }
        )
    return images


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _report(manifest: dict[str, object]) -> str:
    review = manifest["screenshot_review"]
    assert isinstance(review, dict)
    images = manifest["images"]
    assert isinstance(images, list)
    scenario_rows: dict[str, dict[str, object]] = {}
    for image in images:
        assert isinstance(image, dict)
        scenario_rows.setdefault(str(image["scenario_id"]), image)

    lines = [
        "# Desktop first-run guidance matrix",
        "",
        f"- Generated: `{manifest['generated_at_utc']}`",
        f"- Captures: **{manifest['image_count']}** PNG files",
        f"- Dimensions: **{WIDTH} x {HEIGHT}** pixels",
        f"- Themes: {', '.join(manifest['themes'])}",
        f"- Screenshot review: **{str(review['status']).upper()}**",
        f"- Review notes: {review['notes']}",
        "",
        "## Scenario coverage",
        "",
        "| Scenario | Work area | Primer | Source fixture |",
        "|---|---|---|---|",
    ]
    for scenario_id in manifest["scenario_ids"]:
        image = scenario_rows[str(scenario_id)]
        lines.append(
            f"| `{scenario_id}` | {image['work_area']} | {image['primer_state']} "
            f"| {image['source_fixture']} |"
        )
    lines.extend(
        [
            "",
            "## Verification",
            "",
            "- `manifest.json` records every scenario-theme path, dimensions, fixture, size, and SHA-256.",
            "- `SHA256SUMS` covers every PNG and is verified before screenshot review is recorded.",
            "- Captures use the production `WorkbenchView` at the default 1180 x 760 window size.",
            "- Review compares native Light and Dark rendering with the macOS 26 design-system tokens.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_manifest(output_root: Path, manifest: dict[str, object]) -> None:
    _atomic_write(
        output_root / "manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )
    _atomic_write(output_root / "report.md", _report(manifest))


def write_evidence(
    output_root: Path,
    images: Sequence[dict[str, object]],
    *,
    scenarios: Sequence[Scenario] = SCENARIOS,
    themes: Sequence[str] = THEMES,
) -> dict[str, object]:
    generated_at = datetime.now(timezone.utc).isoformat()
    manifest: dict[str, object] = {
        "schema_version": 1,
        "matrix": "desktop-first-run-guidance",
        "generated_at_utc": generated_at,
        "dimensions": {"width": WIDTH, "height": HEIGHT},
        "scenario_count": len(scenarios),
        "image_count": len(images),
        "scenario_ids": [scenario.id for scenario in scenarios],
        "themes": list(themes),
        "design_reference": "macOS-26.lib.pen",
        "capture_test": CAPTURE_TEST.removeprefix("-only-testing:"),
        "images": list(images),
        "screenshot_review": {
            "status": "pending",
            "reviewed_at_utc": None,
            "notes": "Pending visual inspection of every scenario in Light and Dark.",
        },
    }
    checksum_lines = [f"{image['sha256']}  {image['path']}" for image in images]
    _atomic_write(output_root / "SHA256SUMS", "\n".join(checksum_lines) + "\n")
    _write_manifest(output_root, manifest)
    return manifest


def verify_checksums(output_root: Path) -> None:
    checksum_path = output_root / "SHA256SUMS"
    if not checksum_path.is_file():
        raise MatrixError(f"missing checksum file: {checksum_path}")
    seen: set[str] = set()
    for line_number, line in enumerate(checksum_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            expected, relative_value = line.split("  ", maxsplit=1)
        except ValueError as error:
            raise MatrixError(f"invalid SHA256SUMS line {line_number}") from error
        if relative_value in seen:
            raise MatrixError(f"duplicate checksum path: {relative_value}")
        seen.add(relative_value)
        relative_path = Path(relative_value)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise MatrixError(f"unsafe checksum path: {relative_value}")
        target = output_root / relative_path
        if not target.is_file():
            raise MatrixError(f"checksum target is missing: {relative_value}")
        actual = _sha256(target)
        if actual != expected:
            raise MatrixError(f"checksum mismatch: {relative_value}")

    manifest_path = output_root / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_paths = {str(image["path"]) for image in manifest.get("images", [])}
        if seen != expected_paths:
            raise MatrixError("SHA256SUMS paths do not match manifest image paths")


def record_review(
    output_root: Path,
    *,
    status: str,
    notes: str,
) -> dict[str, object]:
    if status not in {"passed", "failed"}:
        raise MatrixError("review status must be passed or failed")
    if not notes.strip():
        raise MatrixError("review notes must not be empty")
    verify_checksums(output_root)
    manifest_path = output_root / "manifest.json"
    if not manifest_path.is_file():
        raise MatrixError(f"missing manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["screenshot_review"] = {
        "status": status,
        "reviewed_at_utc": datetime.now(timezone.utc).isoformat(),
        "notes": notes.strip(),
    }
    _write_manifest(output_root, manifest)
    return manifest


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture and validate the native desktop first-run guidance matrix."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Repository-local tmp directory. A timestamped directory is used by default.",
    )
    parser.add_argument(
        "--record-review",
        choices=("passed", "failed"),
        help="Record the completed visual review for an existing matrix.",
    )
    parser.add_argument(
        "--review-notes",
        help="Non-empty notes required with --record-review.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    source_root = repository_root()

    try:
        evidence_root = evidence_repository_root(source_root)
        output_candidate = args.output_dir or default_output_root(evidence_root)
        output_root = validate_output_root(evidence_root, output_candidate)
        if args.record_review:
            if args.output_dir is None:
                raise MatrixError("--output-dir is required with --record-review")
            if args.review_notes is None:
                raise MatrixError("--review-notes is required with --record-review")
            record_review(
                output_root,
                status=args.record_review,
                notes=args.review_notes,
            )
            print(f"Recorded screenshot review: {output_root}")
            return 0

        if args.review_notes is not None:
            raise MatrixError("--review-notes requires --record-review")
        if output_root.exists() and any(output_root.iterdir()):
            raise MatrixError(f"output directory is not empty: {output_root}")
        output_root.mkdir(parents=True, exist_ok=True)
        run_xcode_capture(source_root, output_root)
        images = validate_capture(output_root)
        write_evidence(output_root, images)
        verify_checksums(output_root)
        print(f"Desktop guidance matrix complete: {output_root}")
        print(f"Captured {len(images)} PNG files; screenshot review is pending.")
        return 0
    except (MatrixError, OSError, subprocess.CalledProcessError) as error:
        print(f"desktop guidance matrix failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
