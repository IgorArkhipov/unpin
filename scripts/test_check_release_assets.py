from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_release_assets.py")


class CheckReleaseAssetsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.checksums = self.root / "SHA256SUMS"
        self.assets = ["unpin-v1.0.0-a.tar.gz", "unpin-v1.0.0-a.cdx.json"]
        self.checksums.write_text(
            "".join(
                f"{hashlib.sha256(name.encode()).hexdigest()}  {name}\n"
                for name in self.assets
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_guard(
        self, command: str, names: list[str]
    ) -> subprocess.CompletedProcess[str]:
        argv = [sys.executable, str(SCRIPT), command]
        if command == "verify-set":
            argv.extend(["--checksums", str(self.checksums)])
        return subprocess.run(
            argv,
            input="".join(f"{name}\n" for name in names),
            capture_output=True,
            text=True,
        )

    def test_refresh_allows_draft_without_evidence(self) -> None:
        completed = self.run_guard("reject-evidence", self.assets)

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_refresh_rejects_evidence_archive(self) -> None:
        completed = self.run_guard(
            "reject-evidence",
            [*self.assets, "unpin-v1.0.0-provider-matrix-evidence.tar.gz"],
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("already contains provider-matrix evidence", completed.stderr)

    def test_refresh_rejects_partial_evidence_manifest_upload(self) -> None:
        completed = self.run_guard(
            "reject-evidence",
            [
                *self.assets,
                "unpin-v1.0.0-provider-matrix-evidence-manifest.json",
            ],
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("already contains provider-matrix evidence", completed.stderr)

    def test_exact_asset_set_passes(self) -> None:
        completed = self.run_guard(
            "verify-set", [*self.assets, self.checksums.name]
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("draft asset set verified: 3 assets", completed.stdout)

    def test_missing_checksum_asset_fails(self) -> None:
        completed = self.run_guard(
            "verify-set", [self.assets[0], self.checksums.name]
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(f"missing: {self.assets[1]}", completed.stderr)

    def test_extra_draft_asset_fails(self) -> None:
        completed = self.run_guard(
            "verify-set", [*self.assets, self.checksums.name, "unexpected.zip"]
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("extra: unexpected.zip", completed.stderr)

    def test_malformed_checksum_entry_fails_closed(self) -> None:
        self.checksums.write_text("malformed\n", encoding="utf-8")

        completed = self.run_guard(
            "verify-set", [*self.assets, self.checksums.name]
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("checksum manifest entry is invalid", completed.stderr)


if __name__ == "__main__":
    unittest.main()
