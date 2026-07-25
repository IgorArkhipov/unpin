#!/usr/bin/env python3
"""Verify finalized matrix evidence and prepare immutable release assets."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import tarfile
from pathlib import Path


TAG_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
CLEAN_WORKSPACE_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def manifest_file(root: Path, relative: str) -> Path:
    relative_path = Path(relative)
    if (
        not relative
        or relative_path.is_absolute()
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise SystemExit(f"invalid evidence path: {relative!r}")
    candidate = root / relative_path
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise SystemExit(f"evidence file is missing: {relative}") from error
    if resolved != candidate or not resolved.is_relative_to(root) or not regular_file(resolved):
        raise SystemExit(f"evidence file is unsafe: {relative}")
    return resolved


def normalized_tar_info(source: Path, archive_name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(archive_name)
    info.size = source.stat().st_size
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def build_evidence_archive(
    artifact_root: Path,
    publishable: list[str],
    manifest_path: Path,
    output_path: Path,
) -> None:
    archive_root = "provider-matrix-evidence"
    with output_path.open("xb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                for relative in [*publishable, "evidence-manifest.json"]:
                    source = manifest_path if relative == "evidence-manifest.json" else artifact_root / relative
                    info = normalized_tar_info(source, f"{archive_root}/{relative}")
                    with source.open("rb") as content:
                        archive.addfile(info, content)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify one finalized local provider matrix and add its approved "
            "evidence archive, manifest, and SHA256SUMS to a release asset directory."
        )
    )
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--expected-commit",
        required=True,
        help="full Git commit ID resolved from the release tag",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not TAG_PATTERN.fullmatch(args.tag):
        raise SystemExit(f"invalid release tag: {args.tag}")
    if not COMMIT_PATTERN.fullmatch(args.expected_commit):
        raise SystemExit("expected commit must be a full lowercase Git commit ID")

    if args.artifact_root.is_symlink():
        raise SystemExit("finalized evidence root must not be a symlink")
    if args.asset_dir.is_symlink():
        raise SystemExit("release asset directory must not be a symlink")
    artifact_root = args.artifact_root.resolve(strict=True)
    asset_dir = args.asset_dir.resolve(strict=True)
    if not asset_dir.is_dir():
        raise SystemExit(f"release asset directory is unsafe: {asset_dir}")

    manifest_path = artifact_root / "evidence-manifest.json"
    if not regular_file(manifest_path):
        raise SystemExit("finalized evidence manifest is missing or unsafe")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    source_binding = manifest.get("source")
    if (
        not isinstance(source_binding, dict)
        or source_binding.get("gitCommit") != args.expected_commit
        or source_binding.get("workspaceDirty") is not False
        or source_binding.get("workspaceStateSha256") != CLEAN_WORKSPACE_DIGEST
        or not SHA256_PATTERN.fullmatch(str(source_binding.get("binarySha256", "")))
    ):
        raise SystemExit("evidence manifest is not bound to the clean release commit")
    assertions = manifest.get("assertions")
    if (
        not isinstance(assertions, dict)
        or not assertions
        or not all(value is True for value in assertions.values())
    ):
        raise SystemExit("evidence manifest assertions are incomplete")
    publishable = manifest.get("publishable")
    checksums = manifest.get("checksums")
    if not isinstance(publishable, list) or not publishable:
        raise SystemExit("evidence manifest publishable list is missing")
    if not isinstance(checksums, dict) or not checksums:
        raise SystemExit("evidence manifest checksums are missing")

    for relative, expected in checksums.items():
        if (
            not isinstance(relative, str)
            or not isinstance(expected, str)
            or not SHA256_PATTERN.fullmatch(expected)
        ):
            raise SystemExit("evidence manifest checksum entry is invalid")
        source = manifest_file(artifact_root, relative)
        actual = f"sha256:{sha256_file(source)}"
        if actual != expected:
            raise SystemExit(f"evidence checksum mismatch: {relative}")

    if len(publishable) != len(set(publishable)):
        raise SystemExit("evidence manifest publishable list contains duplicates")
    for relative in publishable:
        if not isinstance(relative, str):
            raise SystemExit(f"invalid publishable evidence path: {relative!r}")
        manifest_file(artifact_root, relative)
        if relative not in checksums:
            raise SystemExit(f"publishable evidence file is not checksummed: {relative}")

    prefix = f"unpin-{args.tag}-provider-matrix-evidence"
    archive_path = asset_dir / f"{prefix}.tar.gz"
    release_manifest = asset_dir / f"{prefix}-manifest.json"
    checksum_path = asset_dir / "SHA256SUMS"
    for output in (archive_path, release_manifest, checksum_path):
        if output.exists():
            raise SystemExit(f"refusing to overwrite release asset: {output.name}")

    build_evidence_archive(
        artifact_root,
        publishable,
        manifest_path,
        archive_path,
    )
    with manifest_path.open("rb") as source, release_manifest.open("xb") as destination:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            destination.write(chunk)

    assets = sorted(
        path
        for path in asset_dir.iterdir()
        if regular_file(path) and path.name != checksum_path.name
    )
    if not assets:
        raise SystemExit("release asset directory is empty")
    with checksum_path.open("x", encoding="utf-8") as checksum_output:
        checksum_output.write(
            "".join(f"{sha256_file(path)}  {path.name}\n" for path in assets)
        )

    print(
        json.dumps(
            {
                "status": "prepared",
                "tag": args.tag,
                "matrixRun": manifest.get("runId"),
                "publishableFiles": len(publishable),
                "releaseAssetsChecksummed": len(assets),
                "assetDirectory": str(asset_dir),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
