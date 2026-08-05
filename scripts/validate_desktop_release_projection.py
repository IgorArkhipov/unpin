#!/usr/bin/env python3
"""Validate the portable JSON projection emitted by a desktop bridge smoke."""

from __future__ import annotations

import json
import pathlib
import sys


def validate_projection(response_path: pathlib.Path, expected_version: str) -> None:
    responses = [
        json.loads(line)
        for line in response_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    expected_ids = ["archive-handshake", "archive-snapshot", "archive-shutdown"]
    if len(responses) != len(expected_ids):
        raise SystemExit("desktop archive bridge returned an unexpected response count")
    for response, expected_id in zip(responses, expected_ids):
        if response.get("version") != 2 or response.get("id") != expected_id:
            raise SystemExit("desktop archive bridge response envelope is invalid")
        if "error" in response:
            raise SystemExit(f"desktop archive bridge request failed: {response['error']}")

    handshake = responses[0]["result"]
    if (
        handshake.get("protocolVersion") != 2
        or handshake.get("binaryVersion") != expected_version
        or "snapshot" not in handshake.get("capabilities", [])
    ):
        raise SystemExit("desktop archive handshake result is incompatible")

    snapshot = responses[1]["result"]
    if not isinstance(snapshot.get("capturedAtUnix"), int) or isinstance(
        snapshot["capturedAtUnix"], bool
    ):
        raise SystemExit("desktop archive snapshot timestamp is invalid")
    for field in ("inventory", "warnings", "groups", "groupWarnings"):
        if not isinstance(snapshot.get(field), list):
            raise SystemExit(f"desktop archive snapshot field is invalid: {field}")
    if not snapshot["inventory"]:
        raise SystemExit("desktop archive snapshot inventory is empty")
    for item in snapshot["inventory"]:
        string_fields = (
            "provider",
            "kind",
            "category",
            "layer",
            "id",
            "displayName",
            "mutability",
        )
        if any(not isinstance(item.get(field), str) for field in string_fields):
            raise SystemExit("desktop archive inventory projection is invalid")
        if not isinstance(item.get("enabled"), bool):
            raise SystemExit("desktop archive inventory state is invalid")
    for warning in snapshot["warnings"]:
        if not isinstance(warning.get("provider"), str) or not isinstance(
            warning.get("code"), str
        ):
            raise SystemExit("desktop archive warning projection is invalid")
    for group in snapshot["groups"]:
        required = ("qualifiedName", "scope", "revision", "contextCompatible")
        if any(field not in group for field in required):
            raise SystemExit("desktop archive group projection is invalid")
        if not all(isinstance(group[field], str) for field in required[:3]):
            raise SystemExit("desktop archive group identity is invalid")
        # Redacted incompatible groups may omit an empty members field. The Swift
        # bridge contract deliberately decodes that omission as an empty list.
        if not isinstance(group["contextCompatible"], bool) or not isinstance(
            group.get("members", []), list
        ):
            raise SystemExit("desktop archive group state is invalid")
    for warning in snapshot["groupWarnings"]:
        if not isinstance(warning.get("scope"), str) or not isinstance(
            warning.get("code"), str
        ):
            raise SystemExit("desktop archive group warning projection is invalid")

    if responses[2]["result"].get("shutdown") is not True:
        raise SystemExit("desktop archive bridge did not acknowledge shutdown")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: validate_desktop_release_projection.py RESPONSE_FILE VERSION"
        )
    validate_projection(pathlib.Path(sys.argv[1]), sys.argv[2])


if __name__ == "__main__":
    main()
