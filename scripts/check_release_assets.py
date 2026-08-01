#!/usr/bin/env python3
"""Validate release draft asset names against Unpin's checksum contract."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


CHECKSUM_LINE_PATTERN = re.compile(r"^([0-9a-f]{64})  (.+)$")
RELEASE_ASSET_NAME_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")
EVIDENCE_ASSET_SUFFIXES = (
    "-provider-matrix-evidence.tar.gz",
    "-provider-matrix-evidence-manifest.json",
)


def asset_names(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for line in lines:
        name = line.removesuffix("\n")
        if (
            not name
            or "\n" in name
            or RELEASE_ASSET_NAME_PATTERN.fullmatch(name) is None
        ):
            raise SystemExit(f"release asset name is invalid: {name!r}")
        if name in names:
            raise SystemExit(f"release asset list contains duplicate: {name}")
        names.add(name)
    return names


def checksum_asset_names(checksum_path: Path) -> set[str]:
    try:
        checksum_text = checksum_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise SystemExit(f"cannot read checksum manifest: {checksum_path}") from error
    if not checksum_text or not checksum_text.endswith("\n"):
        raise SystemExit("release checksum manifest entry is invalid")

    names: set[str] = set()
    for line in checksum_text.splitlines():
        matched = CHECKSUM_LINE_PATTERN.fullmatch(line)
        if matched is None:
            raise SystemExit(f"release checksum manifest entry is invalid: {line!r}")
        _, name = matched.groups()
        if (
            name == checksum_path.name
            or Path(name).name != name
            or "\\" in name
            or RELEASE_ASSET_NAME_PATTERN.fullmatch(name) is None
        ):
            raise SystemExit(f"release checksum asset name is unsafe: {name}")
        if name in names:
            raise SystemExit(f"release checksum manifest contains duplicate: {name}")
        names.add(name)
    return names


def reject_evidence(names: set[str]) -> None:
    evidence = sorted(
        name for name in names if name.endswith(EVIDENCE_ASSET_SUFFIXES)
    )
    if evidence:
        raise SystemExit(
            "refusing to refresh a draft that already contains provider-matrix "
            f"evidence: {', '.join(evidence)}"
        )


def verify_set(names: set[str], checksum_path: Path) -> None:
    expected = checksum_asset_names(checksum_path) | {checksum_path.name}
    if names != expected:
        missing = sorted(expected - names)
        extra = sorted(names - expected)
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if extra:
            details.append(f"extra: {', '.join(extra)}")
        raise SystemExit(
            "draft assets do not match SHA256SUMS; do not publish ("
            + "; ".join(details)
            + ")"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "reject-evidence",
        help="reject a draft asset list containing provider-matrix evidence",
    )
    verify = subparsers.add_parser(
        "verify-set",
        help="require draft assets to equal SHA256SUMS entries plus SHA256SUMS",
    )
    verify.add_argument("--checksums", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    names = asset_names(list(sys.stdin))
    if args.command == "reject-evidence":
        reject_evidence(names)
    else:
        verify_set(names, args.checksums)
        print(f"draft asset set verified: {len(names)} assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
