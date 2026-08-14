from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("package_desktop_release.py")


class PackageDesktopReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.app = self.root / "UnpinDesktop.app"
        self.app_binary = self.app / "Contents" / "MacOS" / "UnpinDesktop"
        self.bridge_binary = self.app / "Contents" / "MacOS" / "unpin"
        self.broker_binary = (
            self.app / "Contents" / "MacOS" / "unpin-credential-broker"
        )
        self.app_binary.parent.mkdir(parents=True)
        self.app_binary.write_bytes(b"desktop executable")
        self.bridge_binary.write_bytes(b"bridge executable")
        self.broker_binary.write_bytes(b"broker executable")
        self.app_binary.chmod(0o755)
        self.bridge_binary.chmod(0o755)
        self.broker_binary.chmod(0o755)
        self.readme = self.root / "README.md"
        self.license = self.root / "LICENSE"
        self.readme.write_text("read me\n", encoding="utf-8")
        self.license.write_text("license\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_packager(
        self,
        output: Path,
        *,
        target: str = "aarch64-apple-darwin",
        version: str = "1.0.0",
        epoch: str = "1700000000",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--app",
                str(self.app),
                "--target",
                target,
                "--version",
                version,
                "--output-directory",
                str(output),
                "--source-date-epoch",
                epoch,
                "--resource",
                str(self.readme),
                "--resource",
                str(self.license),
            ],
            capture_output=True,
            text=True,
        )

    def test_creates_normalized_release_archive(self) -> None:
        output = self.root / "dist"

        completed = self.run_packager(output)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        archive = Path(completed.stdout.strip())
        self.assertEqual(
            archive.name,
            "unpin-desktop-v1.0.0-aarch64-apple-darwin.tar.gz",
        )
        with tarfile.open(archive, "r:gz") as packaged:
            members = packaged.getmembers()
            names = [member.name for member in members]
            self.assertEqual(names, sorted(names))
            self.assertEqual(
                names,
                [
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin",
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin/LICENSE",
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin/README.md",
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin/UnpinDesktop.app",
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin/UnpinDesktop.app/Contents",
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin/UnpinDesktop.app/Contents/MacOS",
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin/UnpinDesktop.app/Contents/MacOS/UnpinDesktop",
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin/UnpinDesktop.app/Contents/MacOS/unpin",
                    "unpin-desktop-v1.0.0-aarch64-apple-darwin/UnpinDesktop.app/Contents/MacOS/unpin-credential-broker",
                ],
            )
            for member in members:
                self.assertEqual(member.mtime, 1_700_000_000)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.uname, "")
                self.assertEqual(member.gname, "")
            mode_by_name = {member.name: member.mode for member in members}
            self.assertEqual(mode_by_name[names[-2]], 0o755)
            self.assertEqual(mode_by_name[names[-1]], 0o755)

    def test_same_content_produces_identical_archive_bytes(self) -> None:
        first_output = self.root / "first"
        second_output = self.root / "second"

        first = self.run_packager(first_output)
        self.assertEqual(first.returncode, 0, first.stderr)
        os.utime(self.app_binary, (1_800_000_000, 1_800_000_000))
        os.utime(self.bridge_binary, (1_900_000_000, 1_900_000_000))
        os.utime(self.broker_binary, (2_000_000_000, 2_000_000_000))
        second = self.run_packager(second_output)
        self.assertEqual(second.returncode, 0, second.stderr)

        first_digest = hashlib.sha256(Path(first.stdout.strip()).read_bytes()).hexdigest()
        second_digest = hashlib.sha256(Path(second.stdout.strip()).read_bytes()).hexdigest()
        self.assertEqual(first_digest, second_digest)

    def test_rejects_unsupported_target(self) -> None:
        completed = self.run_packager(
            self.root / "dist", target="x86_64-unknown-linux-gnu"
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsupported desktop release target", completed.stderr)

    def test_rejects_unsafe_symlink(self) -> None:
        outside = self.root / "outside"
        outside.write_text("outside\n", encoding="utf-8")
        link = self.app / "Contents" / "outside"
        try:
            link.symlink_to(outside)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")

        completed = self.run_packager(self.root / "dist")

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsafe symlink", completed.stderr)


if __name__ == "__main__":
    unittest.main()
