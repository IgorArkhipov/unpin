#!/usr/bin/env python3
"""Create a deterministic Unpin desktop release archive."""

from __future__ import annotations

import argparse
import gzip
import os
import re
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


SUPPORTED_TARGETS = {"aarch64-apple-darwin", "x86_64-apple-darwin"}
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class ArchiveEntry:
    source: Path | None
    name: PurePosixPath
    kind: str
    mode: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--resource", type=Path, action="append", default=[])
    return parser.parse_args()


def fail(message: str) -> None:
    raise SystemExit(message)


def normalized_file_mode(path: Path) -> int:
    return 0o755 if path.lstat().st_mode & 0o111 else 0o644


def collect_entries(
    app: Path,
    resources: list[Path],
    release_name: str,
) -> list[ArchiveEntry]:
    if app.name != "UnpinDesktop.app" or not app.is_dir() or app.is_symlink():
        fail(f"desktop app bundle is missing or unsafe: {app}")

    release_root = PurePosixPath(release_name)
    entries = [ArchiveEntry(None, release_root, "directory", 0o755)]
    resource_names: set[str] = set()
    for resource in resources:
        if (
            resource.name in resource_names
            or not resource.is_file()
            or resource.is_symlink()
            or PurePosixPath(resource.name).name != resource.name
        ):
            fail(f"desktop release resource is missing or unsafe: {resource}")
        resource_names.add(resource.name)
        entries.append(
            ArchiveEntry(
                resource,
                release_root / resource.name,
                "file",
                0o644,
            )
        )

    app_archive_root = release_root / app.name
    entries.append(ArchiveEntry(None, app_archive_root, "directory", 0o755))
    for source in sorted(app.rglob("*"), key=lambda path: path.as_posix()):
        relative = source.relative_to(app)
        archive_name = app_archive_root.joinpath(*relative.parts)
        if source.is_symlink():
            fail(f"desktop app bundle contains unsafe symlink: {source}")
        source_mode = source.lstat().st_mode
        if stat.S_ISDIR(source_mode):
            entries.append(ArchiveEntry(None, archive_name, "directory", 0o755))
        elif stat.S_ISREG(source_mode):
            entries.append(
                ArchiveEntry(
                    source,
                    archive_name,
                    "file",
                    normalized_file_mode(source),
                )
            )
        else:
            fail(f"desktop app bundle contains unsafe file: {source}")
    return sorted(entries, key=lambda entry: entry.name.as_posix())


def tar_info(entry: ArchiveEntry, epoch: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(entry.name.as_posix())
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    info.mode = entry.mode
    if entry.kind == "directory":
        info.type = tarfile.DIRTYPE
        info.size = 0
    else:
        assert entry.source is not None
        info.type = tarfile.REGTYPE
        info.size = entry.source.lstat().st_size
    return info


def write_archive(
    archive: Path,
    entries: list[ArchiveEntry],
    epoch: int,
) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{archive.name}.",
        dir=archive.parent,
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
        try:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=temporary,
                compresslevel=9,
                mtime=epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.GNU_FORMAT,
                ) as packaged:
                    for entry in entries:
                        info = tar_info(entry, epoch)
                        if entry.kind == "directory":
                            packaged.addfile(info)
                        else:
                            assert entry.source is not None
                            with entry.source.open("rb") as source_file:
                                packaged.addfile(info, source_file)
            os.chmod(temporary_path, 0o644)
            os.replace(temporary_path, archive)
        finally:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    args = parse_args()
    if args.target not in SUPPORTED_TARGETS:
        fail(f"unsupported desktop release target: {args.target}")
    if VERSION_PATTERN.fullmatch(args.version) is None:
        fail(f"invalid desktop release version: {args.version}")
    if args.source_date_epoch < 0:
        fail("source date epoch must be non-negative")

    release_name = f"unpin-desktop-v{args.version}-{args.target}"
    archive = args.output_directory / f"{release_name}.tar.gz"
    entries = collect_entries(args.app, args.resource, release_name)
    write_archive(archive, entries, args.source_date_epoch)
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
