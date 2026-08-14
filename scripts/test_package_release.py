from __future__ import annotations

import os
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY_ROOT / "scripts" / "package_release.sh"


class PackageReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "dist"
        self.command_bin = self.root / "bin"
        self.command_bin.mkdir()
        (self.root / "README.md").write_text("read me\n", encoding="utf-8")
        (self.root / "LICENSE").write_text("license\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_archive_contains_cli_and_credential_broker(self) -> None:
        target = "x86_64-unknown-linux-gnu"
        self._write_release_binary(target, "unpin", "cli")
        self._write_release_binary(target, "unpin-credential-broker", "broker")

        completed = self._run(target)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        archive = Path(completed.stdout.strip())
        with tarfile.open(archive, "r:gz") as packaged:
            root = "unpin-v1.0.0-x86_64-unknown-linux-gnu"
            members = {member.name: member for member in packaged.getmembers()}
            self.assertIn(f"{root}/unpin", members)
            self.assertIn(f"{root}/unpin-credential-broker", members)
            self.assertEqual(members[f"{root}/unpin"].mode, 0o755)
            self.assertEqual(
                members[f"{root}/unpin-credential-broker"].mode,
                0o755,
            )

    def test_missing_credential_broker_is_rejected(self) -> None:
        target = "x86_64-unknown-linux-gnu"
        self._write_release_binary(target, "unpin", "cli")

        completed = self._run(target)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unpin-credential-broker", completed.stderr)

    def test_macos_signs_cli_and_broker_with_separate_identifiers(self) -> None:
        target = "aarch64-apple-darwin"
        self._write_release_binary(target, "unpin", "cli")
        self._write_release_binary(target, "unpin-credential-broker", "broker")
        signing_log = self.root / "signing.log"
        scripts = self.root / "scripts"
        scripts.mkdir()
        self._write_executable(
            scripts / "sign_macos_artifact.sh",
            """\
            #!/bin/sh
            set -eu
            printf '%s|%s\n' "$1" "$(basename "$2")" >> "$FAKE_SIGNING_LOG"
            """,
        )
        self._write_executable(
            self.command_bin / "git",
            f"#!/bin/sh\nprintf '%s\\n' '{self.root}'\n",
        )

        completed = self._run(
            target,
            extra_environment={"FAKE_SIGNING_LOG": str(signing_log)},
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            signing_log.read_text(encoding="utf-8").splitlines(),
            [
                "dev.unpin.cli|unpin",
                "dev.unpin.credential-broker|unpin-credential-broker",
            ],
        )

    def _run(
        self,
        target: str,
        *,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join(
            [str(self.command_bin), environment.get("PATH", "")]
        )
        environment.update(extra_environment or {})
        return subprocess.run(
            [str(SCRIPT), target, "1.0.0", str(self.output)],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def _write_release_binary(self, target: str, name: str, content: str) -> None:
        path = self.root / "target" / target / "release" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        self._write_executable(path, f"#!/bin/sh\n# {content}\nexit 0\n")

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
