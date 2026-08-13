#!/usr/bin/env python3
"""Drive the desktop bridge's bound, authenticated release smoke session."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import selectors
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


MAX_FRAME_BYTES = 1_048_576
TERMINATION_GRACE_SECONDS = 1.0


class SmokeFailure(RuntimeError):
    def __init__(self, message: str, *, reported: bool = False) -> None:
        super().__init__(message)
        self.reported = reported


class SmokeTimeout(SmokeFailure):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stop_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise SmokeFailure("desktop archive bridge did not terminate after SIGKILL") from error


class FrameReader:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        if process.stdout is None:
            raise SmokeFailure("desktop archive bridge stdout is unavailable")
        self.process = process
        self.output = process.stdout
        self.buffer = bytearray()
        os.set_blocking(self.output.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.output, selectors.EVENT_READ)

    def read(self, deadline: float) -> tuple[dict[str, Any], bytes]:
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self.buffer[:newline])
                del self.buffer[: newline + 1]
                if len(frame) > MAX_FRAME_BYTES:
                    raise SmokeFailure("desktop archive bridge response exceeded frame limit")
                try:
                    value = json.loads(frame)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise SmokeFailure("desktop archive bridge returned malformed JSON") from error
                if not isinstance(value, dict):
                    raise SmokeFailure("desktop archive bridge returned a non-object response")
                return value, frame

            if len(self.buffer) > MAX_FRAME_BYTES:
                raise SmokeFailure("desktop archive bridge response exceeded frame limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeTimeout("desktop archive bridge smoke timed out")
            events = self.selector.select(min(remaining, 0.1))
            if not events:
                if self.process.poll() is not None:
                    raise SmokeFailure(
                        f"desktop archive bridge exited before responding ({self.process.returncode})"
                    )
                continue
            chunk = os.read(self.output.fileno(), 65_536)
            if not chunk:
                raise SmokeFailure("desktop archive bridge closed stdout before responding")
            self.buffer.extend(chunk)


def write_request(process: subprocess.Popen[bytes], request: dict[str, Any]) -> None:
    if process.stdin is None:
        raise SmokeFailure("desktop archive bridge stdin is unavailable")
    try:
        process.stdin.write(canonical_json(request) + b"\n")
        process.stdin.flush()
    except BrokenPipeError as error:
        raise SmokeFailure("desktop archive bridge closed stdin") from error


def checked_result(response: dict[str, Any], request_id: str) -> dict[str, Any]:
    if response.get("version") != 2 or response.get("id") != request_id:
        raise SmokeFailure("desktop archive bridge response envelope is invalid")
    if "error" in response:
        raise SmokeFailure(f"desktop archive bridge request failed: {response['error']}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise SmokeFailure("desktop archive bridge response result is invalid")
    return result


def authenticated_request(
    *,
    request_id: str,
    method: str,
    sequence: int,
    params: dict[str, Any],
    binding: dict[str, Any],
    session_secret: str,
) -> dict[str, Any]:
    params_digest = sha256(canonical_json(params))
    material = "\0".join(
        [
            "unpin.desktop.bridge.request.v1",
            session_secret,
            str(sequence),
            request_id,
            method,
            request_id,
            params_digest,
            params_digest,
        ]
    )
    return {
        "version": 2,
        "id": request_id,
        "method": method,
        "params": params,
        "auth": {
            "parentPid": binding["parentPid"],
            "parentStartMarker": binding["parentStartMarker"],
            "childPid": binding["childPid"],
            "childStartMarker": binding["childStartMarker"],
            "projectRoot": binding["projectRoot"],
            "appStateRoot": binding["appStateRoot"],
            "processGeneration": binding["processGeneration"],
            "sequence": sequence,
            "operationId": request_id,
            "fingerprint": params_digest,
            "authTag": sha256(material.encode("utf-8")),
        },
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", required=True, type=float)
    parser.add_argument("--response-file", type=Path)
    parser.add_argument("--stdout-file", type=Path)
    parser.add_argument("--stderr-file", type=Path)
    parser.add_argument("--project-root")
    parser.add_argument("--app-state-root")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if arguments.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")
    if arguments.command[:1] == ["--"]:
        arguments.command = arguments.command[1:]
    if not arguments.command:
        parser.error("bridge command is required after --")
    authenticated_arguments = (
        arguments.response_file,
        arguments.stderr_file,
        arguments.project_root,
        arguments.app_state_root,
    )
    if arguments.stdout_file is None and any(value is None for value in authenticated_arguments):
        parser.error(
            "authenticated smoke requires --response-file, --stderr-file, "
            "--project-root, and --app-state-root"
        )
    if arguments.stdout_file is not None and any(
        value is not None for value in authenticated_arguments
    ):
        parser.error("--stdout-file cannot be combined with authenticated smoke options")
    return arguments


def run_bounded_command(arguments: argparse.Namespace) -> None:
    assert arguments.stdout_file is not None
    arguments.stdout_file.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        arguments.command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=arguments.timeout_seconds)
    except subprocess.TimeoutExpired as error:
        stop_process_group(process)
        raise SmokeTimeout("desktop archive bridge smoke timed out") from error
    if stderr:
        sys.stderr.buffer.write(stderr)
    if process.returncode != 0:
        if not stderr:
            raise SmokeFailure(
                f"desktop archive bridge exited with status {process.returncode}"
            )
        raise SmokeFailure("", reported=True)
    arguments.stdout_file.write_bytes(stdout)


def run_authenticated_smoke(arguments: argparse.Namespace) -> None:
    assert arguments.response_file is not None
    assert arguments.stderr_file is not None
    assert arguments.project_root is not None
    assert arguments.app_state_root is not None
    deadline = time.monotonic() + arguments.timeout_seconds
    arguments.response_file.parent.mkdir(parents=True, exist_ok=True)
    arguments.stderr_file.parent.mkdir(parents=True, exist_ok=True)
    with arguments.stderr_file.open("wb") as stderr_handle, arguments.response_file.open(
        "wb"
    ) as response_handle:
        process = subprocess.Popen(
            arguments.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_handle,
            start_new_session=True,
        )
        reader = FrameReader(process)
        session_secret = secrets.token_hex(32)
        handshake_params = {
            "sessionSecret": session_secret,
            "parentPid": os.getpid(),
            "parentStartMarker": uuid.uuid4().hex,
            "childPid": process.pid,
            "processGeneration": uuid.uuid4().hex,
            "projectRoot": arguments.project_root,
            "appStateRoot": arguments.app_state_root,
        }
        try:
            write_request(
                process,
                {
                    "version": 2,
                    "id": "archive-handshake",
                    "method": "handshake",
                    "params": handshake_params,
                },
            )
            response, frame = reader.read(deadline)
            response_handle.write(frame + b"\n")
            handshake = checked_result(response, "archive-handshake")
            binding = handshake.get("binding")
            if not isinstance(binding, dict):
                raise SmokeFailure("desktop archive bridge handshake binding is missing")
            expected_binding = {
                key: value for key, value in handshake_params.items() if key != "sessionSecret"
            }
            if (
                any(binding.get(key) != value for key, value in expected_binding.items())
                or not isinstance(binding.get("childStartMarker"), str)
                or not binding["childStartMarker"]
            ):
                raise SmokeFailure("desktop archive bridge handshake binding is invalid")

            for sequence, (request_id, method) in enumerate(
                (
                    ("archive-snapshot", "snapshot"),
                    ("archive-shutdown", "shutdown"),
                ),
                start=1,
            ):
                write_request(
                    process,
                    authenticated_request(
                        request_id=request_id,
                        method=method,
                        sequence=sequence,
                        params={},
                        binding=binding,
                        session_secret=session_secret,
                    ),
                )
                response, frame = reader.read(deadline)
                checked_result(response, request_id)
                response_handle.write(frame + b"\n")
            response_handle.flush()
            if process.stdin is not None:
                process.stdin.close()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeTimeout("desktop archive bridge smoke timed out")
            try:
                return_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                raise SmokeTimeout("desktop archive bridge smoke timed out") from error
            if return_code != 0:
                raise SmokeFailure(f"desktop archive bridge exited with status {return_code}")
        except BaseException:
            stop_process_group(process)
            raise


def main() -> None:
    try:
        arguments = parse_arguments()
        if arguments.stdout_file is not None:
            run_bounded_command(arguments)
        else:
            run_authenticated_smoke(arguments)
    except SmokeTimeout as error:
        print(error, file=sys.stderr)
        raise SystemExit(124) from error
    except SmokeFailure as error:
        if not error.reported:
            print(error, file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
