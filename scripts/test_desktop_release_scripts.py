from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = REPOSITORY_ROOT / "scripts" / "build_desktop_release.sh"
VERIFY_SCRIPT = REPOSITORY_ROOT / "scripts" / "verify_desktop_release_artifact.sh"
PROJECTION_VALIDATOR = (
    REPOSITORY_ROOT / "scripts" / "validate_desktop_release_projection.py"
)


class DesktopReleaseScriptTests(unittest.TestCase):
    def test_builder_stdout_is_one_existing_archive_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command_bin = root / "bin"
            command_bin.mkdir()
            output_directory = root / "dist"

            self._write_executable(
                command_bin / "xcodebuild",
                """\
                #!/bin/sh
                set -eu
                derived_data=
                while [ "$#" -gt 0 ]; do
                    if [ "$1" = "-derivedDataPath" ]; then
                        derived_data="$2"
                        shift 2
                    else
                        shift
                    fi
                done
                test -n "$derived_data"
                printf '%s\\n' 'synthetic xcodebuild diagnostic'
                app="$derived_data/Build/Products/Release/UnpinDesktop.app"
                mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
                printf '%s' 'desktop executable' > "$app/Contents/MacOS/UnpinDesktop"
                printf '%s' 'bridge executable' > "$app/Contents/MacOS/unpin"
                : > "$app/Contents/Resources/unpin-bridge-manifest.json"
                """,
            )
            self._write_executable(
                command_bin / "lipo",
                """\
                #!/bin/sh
                set -eu
                test "$1" = "-archs"
                printf '%s\\n' arm64
                """,
            )
            self._write_executable(
                command_bin / "codesign",
                """\
                #!/bin/sh
                exit 0
                """,
            )

            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join(
                [str(command_bin), environment.get("PATH", "")]
            )
            completed = subprocess.run(
                [
                    str(BUILD_SCRIPT),
                    "aarch64-apple-darwin",
                    "1.0.0-rc.1",
                    str(output_directory),
                ],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            stdout_lines = completed.stdout.splitlines()
            self.assertEqual(len(stdout_lines), 1, completed.stdout)
            archive = Path(stdout_lines[0])
            self.assertTrue(archive.is_file(), stdout_lines[0])
            self.assertIn("synthetic xcodebuild diagnostic", completed.stderr)

    def test_full_verifier_rejects_boolean_inventory_identity(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("full desktop artifact verification requires macOS")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command_bin = root / "bin"
            command_bin.mkdir()
            version = "1.0.0-rc.1"
            target = "aarch64-apple-darwin"
            release_name = f"unpin-desktop-v{version}-{target}"
            app = root / release_name / "UnpinDesktop.app"
            macos = app / "Contents" / "MacOS"
            resources = app / "Contents" / "Resources"
            macos.mkdir(parents=True)
            resources.mkdir()

            self._write_executable(
                macos / "UnpinDesktop",
                "#!/bin/sh\nexit 0\n",
            )
            self._write_executable(
                macos / "unpin",
                f"""\
                #!/bin/sh
                set -eu
                if [ "${{1:-}}" = "--version" ]; then
                    printf '%s\\n' 'unpin {version}'
                    exit 0
                fi
                while IFS= read -r request; do
                    case "$request" in
                        *archive-handshake*)
                            printf '%s\\n' '{{"version":2,"id":"archive-handshake","result":{{"protocolVersion":2,"binaryVersion":"{version}","capabilities":["snapshot"]}}}}'
                            ;;
                        *archive-snapshot*)
                            printf '%s\\n' '{{"version":2,"id":"archive-snapshot","result":{{"capturedAtUnix":1,"inventory":[{{"provider":true,"kind":"skill","category":"skill","layer":"global","id":"item-id","displayName":"Item","enabled":true,"mutability":"read-write"}}],"warnings":[],"groups":[],"groupWarnings":[]}}}}'
                            ;;
                        *archive-shutdown*)
                            printf '%s\\n' '{{"version":2,"id":"archive-shutdown","result":{{"shutdown":true}}}}'
                            ;;
                    esac
                done
                """,
            )
            (app / "Contents" / "Info.plist").write_text("{}", encoding="utf-8")
            bridge = macos / "unpin"
            (resources / "unpin-bridge-manifest.json").write_text(
                json.dumps(
                    {
                        "bridgeProtocolVersion": 2,
                        "unpinVersion": version,
                        "sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            archive = root / f"{release_name}.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(root / release_name, arcname=release_name)

            self._write_executable(
                command_bin / "lipo",
                "#!/bin/sh\nprintf '%s\\n' arm64\n",
            )
            self._write_executable(command_bin / "codesign", "#!/bin/sh\nexit 0\n")
            self._write_executable(
                command_bin / "plutil",
                f"#!/bin/sh\nprintf '%s\\n' '{version}'\n",
            )
            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join(
                [str(command_bin), environment.get("PATH", "")]
            )

            completed = subprocess.run(
                [str(VERIFY_SCRIPT), str(archive), target, version],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("desktop archive inventory projection is invalid", completed.stderr)

    def test_full_verifier_terminates_hung_bridge(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("full desktop artifact verification requires macOS")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command_bin = root / "bin"
            command_bin.mkdir()
            version = "1.0.0-rc.1"
            target = "aarch64-apple-darwin"
            release_name = f"unpin-desktop-v{version}-{target}"
            app = root / release_name / "UnpinDesktop.app"
            macos = app / "Contents" / "MacOS"
            resources = app / "Contents" / "Resources"
            macos.mkdir(parents=True)
            resources.mkdir()
            pid_file = root / "bridge.pid"

            self._write_executable(
                macos / "UnpinDesktop",
                "#!/bin/sh\nexit 0\n",
            )
            self._write_executable(
                macos / "unpin",
                f"""\
                #!/bin/sh
                set -eu
                if [ "${{1:-}}" = "--version" ]; then
                    printf '%s\\n' 'unpin {version}'
                    exit 0
                fi
                printf '%s\\n' "$$" > "{pid_file}"
                trap '' TERM
                while :; do sleep 1; done
                """,
            )
            (app / "Contents" / "Info.plist").write_text("{}", encoding="utf-8")
            bridge = macos / "unpin"
            (resources / "unpin-bridge-manifest.json").write_text(
                json.dumps(
                    {
                        "bridgeProtocolVersion": 2,
                        "unpinVersion": version,
                        "sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            archive = root / f"{release_name}.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(root / release_name, arcname=release_name)

            self._write_executable(
                command_bin / "lipo",
                "#!/bin/sh\nprintf '%s\\n' arm64\n",
            )
            self._write_executable(command_bin / "codesign", "#!/bin/sh\nexit 0\n")
            self._write_executable(
                command_bin / "plutil",
                f"#!/bin/sh\nprintf '%s\\n' '{version}'\n",
            )
            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join(
                [str(command_bin), environment.get("PATH", "")]
            )
            # Leave enough startup budget for `arch` on a busy macOS runner;
            # the fake bridge still proves the TERM/KILL timeout path.
            environment["UNPIN_DESKTOP_RELEASE_BRIDGE_TIMEOUT_SECONDS"] = "1"

            started = time.monotonic()
            completed = subprocess.run(
                [str(VERIFY_SCRIPT), str(archive), target, version],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            elapsed = time.monotonic() - started

            self.assertEqual(completed.returncode, 124, completed.stderr)
            self.assertLess(elapsed, 8, completed.stderr)
            self.assertIn("desktop archive bridge timed out", completed.stderr)
            bridge_pid = int(pid_file.read_text(encoding="utf-8"))
            for _ in range(20):
                try:
                    os.kill(bridge_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"hung bridge process {bridge_pid} survived verifier timeout")

    def test_projection_validator_rejects_boolean_inventory_identity(self) -> None:
        version = "1.0.0-rc.1"
        with tempfile.TemporaryDirectory() as temporary:
            response_file = Path(temporary) / "bridge-responses.jsonl"
            response_file.write_text(
                "\n".join(
                    json.dumps(response)
                    for response in (
                        {
                            "version": 2,
                            "id": "archive-handshake",
                            "result": {
                                "protocolVersion": 2,
                                "binaryVersion": version,
                                "capabilities": ["snapshot"],
                            },
                        },
                        {
                            "version": 2,
                            "id": "archive-snapshot",
                            "result": {
                                "capturedAtUnix": 1,
                                "inventory": [
                                    {
                                        "provider": True,
                                        "kind": "skill",
                                        "category": "skill",
                                        "layer": "global",
                                        "id": "item-id",
                                        "displayName": "Item",
                                        "enabled": True,
                                        "mutability": "read-write",
                                    }
                                ],
                                "warnings": [],
                                "groups": [],
                                "groupWarnings": [],
                            },
                        },
                        {
                            "version": 2,
                            "id": "archive-shutdown",
                            "result": {"shutdown": True},
                        },
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [sys.executable, str(PROJECTION_VALIDATOR), str(response_file), version],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("desktop archive inventory projection is invalid", completed.stderr)

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
