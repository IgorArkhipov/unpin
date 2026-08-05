from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = REPOSITORY_ROOT / "scripts" / "build_desktop_release.sh"


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

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
