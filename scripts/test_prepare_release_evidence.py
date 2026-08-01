from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("prepare_release_evidence.py")
TAG = "v0.1.0-beta.8"
COMMIT = "a" * 40
CLEAN_WORKSPACE_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

SPEC = importlib.util.spec_from_file_location("prepare_release_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PREPARE_RELEASE_EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE_RELEASE_EVIDENCE)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class PrepareReleaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact_root = self.root / "matrix"
        self.asset_dir = self.root / "assets"
        self.artifact_root.mkdir()
        self.asset_dir.mkdir()

        evidence = b'{"status":"approved"}\n'
        (self.artifact_root / "summary.json").write_bytes(evidence)
        manifest = {
            "runId": "test-release-evidence",
            "source": {
                "gitCommit": COMMIT,
                "workspaceDirty": False,
                "workspaceStateSha256": CLEAN_WORKSPACE_DIGEST,
                "binarySha256": f"sha256:{'b' * 64}",
            },
            "assertions": {"approved": True},
            "publishable": ["summary.json"],
            "checksums": {
                "summary.json": f"sha256:{sha256_bytes(evidence)}",
            },
        }
        (self.artifact_root / "evidence-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )

        self.archive_name = f"unpin-{TAG}-x86_64-unknown-linux-gnu.tar.gz"
        self.sbom_name = f"unpin-{TAG}-x86_64-unknown-linux-gnu.cdx.json"
        self.workflow_assets = {
            self.archive_name: b"archive",
            self.sbom_name: b"sbom",
        }
        for name, content in self.workflow_assets.items():
            (self.asset_dir / name).write_bytes(content)

        self.checksum_path = self.asset_dir / "SHA256SUMS"
        self.write_workflow_checksums()
        prefix = f"unpin-{TAG}-provider-matrix-evidence"
        self.evidence_archive = self.asset_dir / f"{prefix}.tar.gz"
        self.evidence_manifest = self.asset_dir / f"{prefix}-manifest.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(self) -> list[str]:
        return [sys.executable, *self.argv()]

    def argv(self) -> list[str]:
        return [
            str(SCRIPT),
            "--artifact-root",
            str(self.artifact_root),
            "--asset-dir",
            str(self.asset_dir),
            "--tag",
            TAG,
            "--expected-commit",
            COMMIT,
        ]

    def run_script(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(self.command(), capture_output=True, text=True)

    def write_workflow_checksums(
        self, entries: list[tuple[str, str]] | None = None
    ) -> bytes:
        if entries is None:
            entries = [
                (sha256_bytes(content), name)
                for name, content in self.workflow_assets.items()
            ]
        content = "".join(f"{digest}  {name}\n" for digest, name in entries).encode()
        self.checksum_path.write_bytes(content)
        return content

    def assert_no_evidence_outputs(self) -> None:
        self.assertFalse(self.evidence_archive.exists())
        self.assertFalse(self.evidence_archive.is_symlink())
        self.assertFalse(self.evidence_manifest.exists())
        self.assertFalse(self.evidence_manifest.is_symlink())

    def checksum_entries(self) -> list[tuple[str, str]]:
        return [
            tuple(line.split("  ", maxsplit=1))
            for line in self.checksum_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_extends_verified_workflow_checksums_without_hashing_stray_files(
        self,
    ) -> None:
        original_checksums = self.checksum_path.read_bytes()
        stray_path = self.asset_dir / ".DS_Store"
        stray_path.write_bytes(b"stray")
        stale_staging_path = self.asset_dir / ".SHA256SUMS.tmp"
        stale_staging_path.write_bytes(b"stale")

        completed = self.run_script()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(result["releaseAssetsChecksummed"], 4)
        self.assertTrue(self.checksum_path.read_bytes().startswith(original_checksums))
        checksum_entries = {
            name: digest for digest, name in self.checksum_entries()
        }
        expected_assets = {
            self.archive_name,
            self.sbom_name,
            self.evidence_archive.name,
            self.evidence_manifest.name,
        }
        self.assertEqual(set(checksum_entries), expected_assets)
        for name, digest in checksum_entries.items():
            self.assertEqual(digest, sha256_bytes((self.asset_dir / name).read_bytes()))
        self.assertNotIn(stray_path.name, checksum_entries)
        self.assertNotIn(stale_staging_path.name, checksum_entries)
        self.assertEqual(stale_staging_path.read_bytes(), b"stale")

    def test_workflow_checksum_mismatch_fails_before_writes(self) -> None:
        original_checksums = self.checksum_path.read_bytes()
        (self.asset_dir / self.archive_name).write_bytes(b"tampered")

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            f"release checksum mismatch: {self.archive_name}", completed.stderr
        )
        self.assertEqual(self.checksum_path.read_bytes(), original_checksums)
        self.assert_no_evidence_outputs()

    def test_malformed_workflow_checksum_manifest_fails_before_writes(self) -> None:
        malformed = b"not a checksum manifest\n"
        self.checksum_path.write_bytes(malformed)

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum manifest entry is invalid", completed.stderr)
        self.assertEqual(self.checksum_path.read_bytes(), malformed)
        self.assert_no_evidence_outputs()

    def test_invalid_utf8_checksum_manifest_fails_before_writes(self) -> None:
        invalid = b"\xff\n"
        self.checksum_path.write_bytes(invalid)

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum manifest entry is invalid", completed.stderr)
        self.assertEqual(self.checksum_path.read_bytes(), invalid)
        self.assert_no_evidence_outputs()

    def test_checksum_manifest_requires_trailing_newline(self) -> None:
        missing_newline = self.checksum_path.read_bytes().removesuffix(b"\n")
        self.checksum_path.write_bytes(missing_newline)

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum manifest entry is invalid", completed.stderr)
        self.assertEqual(self.checksum_path.read_bytes(), missing_newline)
        self.assert_no_evidence_outputs()

    def test_duplicate_workflow_checksum_entry_fails_before_writes(self) -> None:
        digest = sha256_bytes(self.workflow_assets[self.archive_name])
        duplicate = self.write_workflow_checksums(
            [(digest, self.archive_name), (digest, self.archive_name)]
        )

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum manifest contains duplicates", completed.stderr)
        self.assertEqual(self.checksum_path.read_bytes(), duplicate)
        self.assert_no_evidence_outputs()

    def test_unsafe_workflow_checksum_name_fails_before_writes(self) -> None:
        unsafe = self.write_workflow_checksums(
            [(sha256_bytes(b"outside"), "../outside.tar.gz")]
        )

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum asset name is unsafe", completed.stderr)
        self.assertEqual(self.checksum_path.read_bytes(), unsafe)
        self.assert_no_evidence_outputs()

    def test_self_referential_checksum_name_fails_before_writes(self) -> None:
        unsafe = self.write_workflow_checksums(
            [(sha256_bytes(b"checksums"), "SHA256SUMS")]
        )

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum asset name is unsafe", completed.stderr)
        self.assertEqual(self.checksum_path.read_bytes(), unsafe)
        self.assert_no_evidence_outputs()

    def test_backslash_checksum_name_fails_before_writes(self) -> None:
        unsafe = self.write_workflow_checksums(
            [(sha256_bytes(b"outside"), "nested\\outside.tar.gz")]
        )

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum asset name is unsafe", completed.stderr)
        self.assertEqual(self.checksum_path.read_bytes(), unsafe)
        self.assert_no_evidence_outputs()

    def test_missing_workflow_asset_fails_before_writes(self) -> None:
        missing_name = "unpin-missing.tar.gz"
        original_checksums = self.write_workflow_checksums(
            [(sha256_bytes(b"missing"), missing_name)]
        )

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(f"release asset is missing or unsafe: {missing_name}", completed.stderr)
        self.assertEqual(self.checksum_path.read_bytes(), original_checksums)
        self.assert_no_evidence_outputs()

    def test_symlinked_workflow_asset_fails_before_writes(self) -> None:
        target = self.root / "outside-archive"
        target.write_bytes(self.workflow_assets[self.archive_name])
        asset = self.asset_dir / self.archive_name
        asset.unlink()
        try:
            asset.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            f"release asset is missing or unsafe: {self.archive_name}", completed.stderr
        )
        self.assert_no_evidence_outputs()

    def test_checksum_directory_is_rejected_before_writes(self) -> None:
        self.checksum_path.unlink()
        self.checksum_path.mkdir()

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum manifest is unsafe", completed.stderr)
        self.assertTrue(self.checksum_path.is_dir())
        self.assert_no_evidence_outputs()

    def test_missing_checksum_manifest_is_rejected_before_writes(self) -> None:
        self.checksum_path.unlink()

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum manifest is missing", completed.stderr)
        self.assert_no_evidence_outputs()

    def test_checksum_symlink_is_rejected_before_writes(self) -> None:
        target = self.root / "outside-checksums"
        target.write_bytes(self.checksum_path.read_bytes())
        self.checksum_path.unlink()
        try:
            self.checksum_path.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checksum manifest is unsafe", completed.stderr)
        self.assertTrue(self.checksum_path.is_symlink())
        self.assert_no_evidence_outputs()

    def test_existing_manifest_collision_does_not_create_archive(self) -> None:
        original_manifest = b"existing evidence manifest"
        self.evidence_manifest.write_bytes(original_manifest)
        original_checksums = self.checksum_path.read_bytes()

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            f"refusing to overwrite release asset: {self.evidence_manifest.name}",
            completed.stderr,
        )
        self.assertEqual(self.evidence_manifest.read_bytes(), original_manifest)
        self.assertFalse(self.evidence_archive.exists())
        self.assertEqual(self.checksum_path.read_bytes(), original_checksums)

    def test_existing_archive_collision_does_not_change_other_outputs(self) -> None:
        original_archive = b"existing evidence archive"
        self.evidence_archive.write_bytes(original_archive)
        original_checksums = self.checksum_path.read_bytes()

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            f"refusing to overwrite release asset: {self.evidence_archive.name}",
            completed.stderr,
        )
        self.assertEqual(self.evidence_archive.read_bytes(), original_archive)
        self.assertFalse(self.evidence_manifest.exists())
        self.assertEqual(self.checksum_path.read_bytes(), original_checksums)

    def test_dangling_manifest_symlink_collision_does_not_create_archive(self) -> None:
        try:
            self.evidence_manifest.symlink_to(self.root / "missing-evidence-manifest")
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        original_checksums = self.checksum_path.read_bytes()

        completed = self.run_script()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            f"refusing to overwrite release asset: {self.evidence_manifest.name}",
            completed.stderr,
        )
        self.assertTrue(self.evidence_manifest.is_symlink())
        self.assertFalse(self.evidence_archive.exists())
        self.assertEqual(self.checksum_path.read_bytes(), original_checksums)

    def test_race_time_manifest_collision_rolls_back_committed_archive(self) -> None:
        original_build = PREPARE_RELEASE_EVIDENCE.build_evidence_archive
        colliding_manifest = b"created by another process"

        def build_then_collide(*args: object, **kwargs: object) -> None:
            original_build(*args, **kwargs)
            self.evidence_manifest.write_bytes(colliding_manifest)

        with (
            mock.patch.object(sys, "argv", self.argv()),
            mock.patch.object(
                PREPARE_RELEASE_EVIDENCE,
                "build_evidence_archive",
                side_effect=build_then_collide,
            ),
            self.assertRaisesRegex(
                SystemExit,
                f"refusing to overwrite release asset: {self.evidence_manifest.name}",
            ),
        ):
            PREPARE_RELEASE_EVIDENCE.main()

        self.assertFalse(self.evidence_archive.exists())
        self.assertEqual(self.evidence_manifest.read_bytes(), colliding_manifest)

    def test_checksum_replace_failure_rolls_back_evidence_outputs(self) -> None:
        original_checksums = self.checksum_path.read_bytes()

        with (
            mock.patch.object(sys, "argv", self.argv()),
            mock.patch.object(
                Path,
                "replace",
                side_effect=OSError("simulated checksum replacement failure"),
            ),
            self.assertRaisesRegex(OSError, "simulated checksum replacement failure"),
        ):
            PREPARE_RELEASE_EVIDENCE.main()

        self.assertEqual(self.checksum_path.read_bytes(), original_checksums)
        self.assert_no_evidence_outputs()

    def test_checksum_mutation_rolls_back_evidence_outputs(self) -> None:
        original_build = PREPARE_RELEASE_EVIDENCE.build_evidence_archive
        changed_checksums = b"changed by another process\n"

        def build_then_change_checksums(*args: object, **kwargs: object) -> None:
            original_build(*args, **kwargs)
            self.checksum_path.write_bytes(changed_checksums)

        with (
            mock.patch.object(sys, "argv", self.argv()),
            mock.patch.object(
                PREPARE_RELEASE_EVIDENCE,
                "build_evidence_archive",
                side_effect=build_then_change_checksums,
            ),
            self.assertRaisesRegex(
                SystemExit,
                "release checksum manifest changed during evidence preparation",
            ),
        ):
            PREPARE_RELEASE_EVIDENCE.main()

        self.assertEqual(self.checksum_path.read_bytes(), changed_checksums)
        self.assert_no_evidence_outputs()

    def test_checksum_write_failure_leaves_no_evidence_outputs(self) -> None:
        original_checksums = self.checksum_path.read_bytes()
        original_open = Path.open

        def fail_staged_checksum_write(
            path: Path, mode: str = "r", *args: object, **kwargs: object
        ) -> object:
            if path.name == "SHA256SUMS" and "x" in mode:
                raise OSError("simulated checksum write failure")
            return original_open(path, mode, *args, **kwargs)

        with (
            mock.patch.object(sys, "argv", self.argv()),
            mock.patch.object(Path, "open", new=fail_staged_checksum_write),
            self.assertRaisesRegex(OSError, "simulated checksum write failure"),
        ):
            PREPARE_RELEASE_EVIDENCE.main()

        self.assertEqual(self.checksum_path.read_bytes(), original_checksums)
        self.assert_no_evidence_outputs()


if __name__ == "__main__":
    unittest.main()
