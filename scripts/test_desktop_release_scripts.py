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
BUNDLE_SCRIPT = (
    REPOSITORY_ROOT / "apps" / "unpin-desktop" / "Scripts" / "bundle-unpin.sh"
)
VERIFY_SCRIPT = REPOSITORY_ROOT / "scripts" / "verify_desktop_release_artifact.sh"
PROJECTION_VALIDATOR = (
    REPOSITORY_ROOT / "scripts" / "validate_desktop_release_projection.py"
)


def _authenticated_fake_bridge(version: str, snapshot_result: dict[str, object]) -> str:
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import json
        import sys

        if sys.argv[1:] == ["--version"]:
            print("unpin {version}")
            raise SystemExit(0)

        binding = None
        for line in sys.stdin:
            request = json.loads(line)
            request_id = request["id"]
            if request["method"] == "handshake":
                params = request["params"]
                binding = {{
                    **{{key: value for key, value in params.items() if key != "sessionSecret"}},
                    "childStartMarker": "fake-child-start-marker",
                }}
                result = {{
                    "protocolVersion": 2,
                    "binaryVersion": {version!r},
                    "capabilities": ["snapshot"],
                    "binding": binding,
                }}
            elif request["method"] == "snapshot":
                assert binding is not None
                assert "auth" in request
                result = {snapshot_result!r}
            else:
                assert request["method"] == "shutdown"
                assert "auth" in request
                result = {{"shutdown": True}}
            print(json.dumps({{"version": 2, "id": request_id, "result": result}}), flush=True)
            if request["method"] == "shutdown":
                break
        """
    )


class DesktopReleaseScriptTests(unittest.TestCase):
    def test_builder_build_only_does_not_invoke_codesign(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command_bin = root / "bin"
            command_bin.mkdir()
            output_directory = root / "dist"
            signing_marker = root / "codesign-invoked"

            self._write_executable(
                command_bin / "xcodebuild",
                """#!/bin/sh
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
app="$derived_data/Build/Products/Release/UnpinDesktop.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
printf '%s' desktop > "$app/Contents/MacOS/UnpinDesktop"
printf '%s' bridge > "$app/Contents/MacOS/unpin"
: > "$app/Contents/Resources/unpin-bridge-manifest.json"
""",
            )
            self._write_executable(
                command_bin / "lipo",
                """#!/bin/sh
printf '%s\\n' arm64
""",
            )
            self._write_executable(
                command_bin / "codesign",
                f"#!/bin/sh\nprintf '%s' invoked > '{signing_marker}'\nexit 99\n",
            )

            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join(
                [str(command_bin), environment.get("PATH", "")]
            )
            completed = subprocess.run(
                [
                    str(BUILD_SCRIPT),
                    "aarch64-apple-darwin",
                    "1.0.0",
                    str(output_directory),
                    "build-only",
                ],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            staged_app = Path(completed.stdout.strip())
            self.assertTrue(staged_app.is_dir(), completed.stdout)
            self.assertFalse(signing_marker.exists())

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
set -eu
if [ "${1:-}" = "--display" ]; then
  artifact=
  for argument in "$@"; do
    artifact="$argument"
  done
  case "$artifact" in
    *.app) identifier=dev.unpin.workbench ;;
    *) identifier=dev.unpin.workbench.bridge ;;
  esac
  printf 'Identifier=%s\n' "$identifier" >&2
  printf 'Signature=adhoc\n' >&2
fi
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
                    "1.0.0",
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

    def test_bundle_script_does_not_execute_cross_compiled_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command_bin = root / "bin"
            command_bin.mkdir()
            source_root = root / "apps" / "unpin-desktop"
            source_root.mkdir(parents=True)
            target_binary = (
                root / "target" / "x86_64-apple-darwin" / "release" / "unpin"
            )
            target_binary.parent.mkdir(parents=True)
            execution_marker = root / "cross-compiled-binary-executed"
            self._write_executable(
                target_binary,
                f"""\
                #!/bin/sh
                # arch: x86_64
                printf '%s' executed > '{execution_marker}'
                exit 99
                """,
            )
            self._write_executable(
                command_bin / "cargo",
                """\
                #!/bin/sh
                set -eu
                case "${1:-}" in
                  build)
                    shift
                    test "$#" -eq 8
                    test "$1" = "--locked"
                    test "$2" = "--manifest-path"
                    test "$3" = "$FAKE_WORKSPACE_ROOT/Cargo.toml"
                    test "$4" = "-p"
                    test "$5" = "unpin-cli"
                    test "$6" = "--target"
                    test "$7" = "x86_64-apple-darwin"
                    test "$8" = "--release"
                    exit 0
                    ;;
                  pkgid)
                    shift
                    test "$#" -eq 4
                    test "$1" = "--manifest-path"
                    test "$2" = "$FAKE_WORKSPACE_ROOT/Cargo.toml"
                    test "$3" = "-p"
                    test "$4" = "unpin-cli"
                    printf '%s\\n' "$FAKE_PACKAGE_ID"
                    ;;
                  *)
                    echo "unexpected cargo command: ${1:-missing}" >&2
                    exit 2
                    ;;
                esac
                """,
            )
            self._write_executable(
                command_bin / "lipo",
                """\
                #!/bin/sh
                set -eu
                test "$#" -eq 2
                test "$1" = "-archs"
                sed -n '2s/^# arch: //p' "$2"
                """,
            )
            self._write_executable(
                command_bin / "ditto",
                """\
                #!/bin/sh
                set -eu
                cp "$1" "$2"
                """,
            )

            build_root = root / "build"
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": os.pathsep.join(
                        [str(command_bin), environment.get("PATH", "")]
                    ),
                    "SRCROOT": str(source_root),
                    "CONFIGURATION": "Release",
                    "UNPIN_RUST_TARGET": "x86_64-apple-darwin",
                    "CONTENTS_FOLDER_PATH": "UnpinDesktop.app/Contents",
                    "FAKE_WORKSPACE_ROOT": str(root),
                }
            )

            def run_bundle(
                build_directory: Path,
                package_id: str = (
                    "path+file:///workspace/crates/unpin-cli#1.0.0"
                ),
                marketing_version: str = "1.0.0",
            ) -> subprocess.CompletedProcess[str]:
                invocation_environment = environment.copy()
                invocation_environment.update(
                    {
                        "FAKE_PACKAGE_ID": package_id,
                        "TARGET_BUILD_DIR": str(build_directory),
                        "MARKETING_VERSION": marketing_version,
                    }
                )
                return subprocess.run(
                    ["/bin/sh", str(BUNDLE_SCRIPT)],
                    cwd=REPOSITORY_ROOT,
                    env=invocation_environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            completed = run_bundle(build_root)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(
                execution_marker.exists(),
                "bundle script executed the cross-compiled target binary",
            )
            manifest = json.loads(
                (
                    build_root
                    / "UnpinDesktop.app"
                    / "Contents"
                    / "Resources"
                    / "unpin-bridge-manifest.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["unpinVersion"], "1.0.0")

            named_package_build = root / "build-named-package"
            named_package_completed = run_bundle(
                named_package_build,
                "path+file:///workspace/crates/unpin-cli#unpin-cli@1.0.0",
            )
            self.assertEqual(
                named_package_completed.returncode,
                0,
                named_package_completed.stderr,
            )
            named_package_manifest = json.loads(
                (
                    named_package_build
                    / "UnpinDesktop.app"
                    / "Contents"
                    / "Resources"
                    / "unpin-bridge-manifest.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(named_package_manifest["unpinVersion"], "1.0.0")

            rejection_cases = (
                (
                    "version-mismatch",
                    "path+file:///workspace/crates/unpin-cli#1.0.0",
                    "9.9.9",
                    "does not match app version",
                ),
                (
                    "missing-version-fragment",
                    "path+file:///workspace/crates/unpin-cli",
                    "1.0.0",
                    "could not determine bundled Unpin version",
                ),
                (
                    "empty-version-fragment",
                    "path+file:///workspace/crates/unpin-cli#",
                    "1.0.0",
                    "returned an empty bundled Unpin version",
                ),
            )
            for build_name, package_id, marketing_version, expected_error in (
                rejection_cases
            ):
                with self.subTest(build_name=build_name):
                    rejected_build = root / f"build-{build_name}"
                    rejected = run_bundle(
                        rejected_build,
                        package_id,
                        marketing_version,
                    )
                    self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                    self.assertIn(expected_error, rejected.stderr)
                    self.assertFalse(
                        (
                            rejected_build
                            / "UnpinDesktop.app"
                            / "Contents"
                            / "Resources"
                            / "unpin-bridge-manifest.json"
                        ).exists()
                    )

            self._write_executable(
                target_binary,
                f"""\
                #!/bin/sh
                # arch: arm64
                printf '%s' executed > '{execution_marker}'
                exit 99
                """,
            )
            wrong_architecture = run_bundle(root / "build-wrong-architecture")
            self.assertNotEqual(
                wrong_architecture.returncode,
                0,
                wrong_architecture.stdout,
            )
            self.assertIn(
                "bundled Unpin binary architecture does not match x86_64",
                wrong_architecture.stderr,
            )
            self.assertFalse(
                execution_marker.exists(),
                "bundle script executed the wrong-architecture target binary",
            )

    def test_full_verifier_rejects_boolean_inventory_identity(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("full desktop artifact verification requires macOS")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command_bin = root / "bin"
            command_bin.mkdir()
            version = "1.0.0"
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
            bridge = macos / "unpin"
            self._write_executable(
                bridge,
                _authenticated_fake_bridge(
                    version,
                    {
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
                ),
            )
            (app / "Contents" / "Info.plist").write_text("{}", encoding="utf-8")
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
            self._write_executable(
                command_bin / "codesign",
                """#!/bin/sh
set -eu
if [ "${1:-}" = "--display" ]; then
    artifact=""
    for argument in "$@"; do artifact="$argument"; done
    case "$artifact" in
        *.app) identifier=dev.unpin.workbench ;;
        *) identifier=dev.unpin.workbench.bridge ;;
    esac
    printf 'Identifier=%s\\n' "$identifier" >&2
    printf 'Signature=signed\\n' >&2
fi
exit 0
""",
            )
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
            version = "1.0.0"
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
            self._write_executable(
                command_bin / "codesign",
                """#!/bin/sh
set -eu
if [ "${1:-}" = "--display" ]; then
    artifact=""
    for argument in "$@"; do artifact="$argument"; done
    case "$artifact" in
        *.app) identifier=dev.unpin.workbench ;;
        *) identifier=dev.unpin.workbench.bridge ;;
    esac
    printf 'Identifier=%s\\n' "$identifier" >&2
    printf 'Signature=signed\\n' >&2
fi
exit 0
""",
            )
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
        version = "1.0.0"
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
