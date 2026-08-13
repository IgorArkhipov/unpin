from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("run_authenticated_desktop_bridge_smoke.py")


class AuthenticatedDesktopBridgeSmokeTests(unittest.TestCase):
    def test_runs_bounded_noninteractive_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout_file = root / "stdout"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--timeout-seconds",
                    "5",
                    "--stdout-file",
                    str(stdout_file),
                    "--",
                    sys.executable,
                    "-c",
                    "print('unpin 1.3.0')",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(stdout_file.read_text(encoding="utf-8"), "unpin 1.3.0\n")

    def test_bounded_command_forwards_stderr_without_duplicate_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stdout_file = Path(temporary) / "stdout"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--timeout-seconds",
                    "5",
                    "--stdout-file",
                    str(stdout_file),
                    "--",
                    sys.executable,
                    "-c",
                    "import sys; print('failure', file=sys.stderr); raise SystemExit(7)",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stderr, "failure\n")

    def test_drives_bound_authenticated_bridge_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project_root = root / "project"
            app_state_root = root / "state"
            project_root.mkdir()
            app_state_root.mkdir()
            bridge = root / "fake-bridge.py"
            response_file = root / "responses.jsonl"
            stderr_file = root / "bridge.stderr"
            bridge.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import hashlib
                    import json
                    import os
                    import sys

                    binding = None
                    expected_sequence = 0
                    session_secret = None

                    def digest(value):
                        encoded = json.dumps(
                            value,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode()
                        return hashlib.sha256(encoded).hexdigest()

                    for line in sys.stdin:
                        request = json.loads(line)
                        request_id = request["id"]
                        if request["method"] == "handshake":
                            params = request["params"]
                            assert set(params) == {
                                "sessionSecret",
                                "parentPid",
                                "parentStartMarker",
                                "childPid",
                                "processGeneration",
                                "projectRoot",
                                "appStateRoot",
                            }
                            assert params["parentPid"] == os.getppid()
                            assert params["childPid"] == os.getpid()
                            session_secret = params["sessionSecret"]
                            binding = {
                                **{key: value for key, value in params.items() if key != "sessionSecret"},
                                "childStartMarker": "fake-child-start-marker",
                            }
                            result = {
                                "protocolVersion": 2,
                                "binaryVersion": "1.3.0",
                                "capabilities": ["snapshot"],
                                "binding": binding,
                            }
                        else:
                            assert binding is not None
                            expected_sequence += 1
                            auth = request["auth"]
                            assert auth["sequence"] == expected_sequence
                            for key in (
                                "parentPid",
                                "parentStartMarker",
                                "childPid",
                                "childStartMarker",
                                "projectRoot",
                                "appStateRoot",
                                "processGeneration",
                            ):
                                assert auth[key] == binding[key]
                            params_digest = digest(request["params"])
                            assert auth["operationId"] == request_id
                            assert auth["fingerprint"] == params_digest
                            material = "\\0".join(
                                [
                                    "unpin.desktop.bridge.request.v1",
                                    session_secret,
                                    str(expected_sequence),
                                    request_id,
                                    request["method"],
                                    request_id,
                                    params_digest,
                                    params_digest,
                                ]
                            )
                            assert auth["authTag"] == hashlib.sha256(material.encode()).hexdigest()
                            if request["method"] == "snapshot":
                                result = {"capturedAtUnix": 1}
                            else:
                                assert request["method"] == "shutdown"
                                result = {"shutdown": True}
                        print(
                            json.dumps(
                                {"version": 2, "id": request_id, "result": result},
                                separators=(",", ":"),
                            ),
                            flush=True,
                        )
                        if request["method"] == "shutdown":
                            break
                    """
                ),
                encoding="utf-8",
            )
            bridge.chmod(0o755)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--timeout-seconds",
                    "5",
                    "--response-file",
                    str(response_file),
                    "--stderr-file",
                    str(stderr_file),
                    "--project-root",
                    str(project_root),
                    "--app-state-root",
                    str(app_state_root),
                    "--",
                    str(bridge),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            responses = [
                json.loads(line)
                for line in response_file.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [response["id"] for response in responses],
                ["archive-handshake", "archive-snapshot", "archive-shutdown"],
            )
            self.assertEqual(stderr_file.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
