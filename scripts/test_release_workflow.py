from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_linux_job_has_no_signing_environment_or_secrets(self) -> None:
        linux_job = self._job("build")

        self.assertIn("target: x86_64-unknown-linux-gnu", linux_job)
        self.assertNotIn("macos-15", linux_job)
        self.assertNotIn("release-signing", linux_job)
        self.assertNotIn("UNPIN_MACOS_SIGNING_CERTIFICATE", linux_job)
        self.assertNotIn("UNPIN_CODESIGN_CERTIFICATE_SHA1", linux_job)
        self.assertNotIn("import_macos_signing_identity.sh", linux_job)
        self.assertNotIn("sign_macos_artifact.sh", linux_job)
        self.assertIn("verify_linux_release_artifact.sh", linux_job)

    def test_cli_macos_architectures_use_stable_signing_and_pair_cleanup(self) -> None:
        macos_cli_job = self._job("build-macos")

        self.assertIn("environment: release-signing", macos_cli_job)
        self.assertIn("target: aarch64-apple-darwin", macos_cli_job)
        self.assertIn("target: x86_64-apple-darwin", macos_cli_job)
        self.assertIn(
            "UNPIN_CODESIGN_EXPECTED_FINGERPRINT: ${{ vars.UNPIN_CODESIGN_CERTIFICATE_SHA1 }}",
            macos_cli_job,
        )
        self.assertIn(
            "UNPIN_CODESIGN_CERTIFICATE_SHA1: ${{ vars.UNPIN_CODESIGN_CERTIFICATE_SHA1 }}",
            macos_cli_job,
        )
        self.assertIn('UNPIN_REQUIRE_STABLE_CODESIGN: "1"', macos_cli_job)
        self._assert_signing_secret_boundary(macos_cli_job)
        self._assert_import_cleanup_order(macos_cli_job)
        self.assertIn("verify_macos_release_artifact.sh", macos_cli_job)

    def test_desktop_architectures_build_unsigned_then_sign_stably(self) -> None:
        desktop_job = self._job("desktop")

        self.assertIn("environment: release-signing", desktop_job)
        self.assertIn("target: aarch64-apple-darwin", desktop_job)
        self.assertIn("target: x86_64-apple-darwin", desktop_job)
        self.assertIn("Build unsigned desktop workbench", desktop_job)
        self.assertIn("build-only", desktop_job)
        self.assertIn("Sign and package desktop workbench", desktop_job)
        self.assertIn("sign_desktop_release.sh", desktop_job)
        self.assertIn("verify_desktop_release_artifact.sh", desktop_job)
        self.assertIn(
            "UNPIN_CODESIGN_CERTIFICATE_SHA1: ${{ vars.UNPIN_CODESIGN_CERTIFICATE_SHA1 }}",
            desktop_job,
        )
        self._assert_signing_secret_boundary(desktop_job)
        self._assert_import_cleanup_order(desktop_job)

        build_index = desktop_job.index("Build unsigned desktop workbench")
        import_index = desktop_job.index("Import stable macOS signing identity")
        sign_index = desktop_job.index("Sign and package desktop workbench")
        self.assertLess(build_index, import_index)
        self.assertLess(import_index, sign_index)

    def test_all_macos_artifact_layers_check_expected_identifiers_and_fingerprint(self) -> None:
        signature_script = (
            REPOSITORY_ROOT / "scripts" / "verify_macos_artifact_signature.sh"
        ).read_text(encoding="utf-8")
        desktop_script = (
            REPOSITORY_ROOT / "scripts" / "verify_desktop_release_artifact.sh"
        ).read_text(encoding="utf-8")
        cli_script = (
            REPOSITORY_ROOT / "scripts" / "verify_macos_release_artifact.sh"
        ).read_text(encoding="utf-8")
        package_script = (
            REPOSITORY_ROOT / "scripts" / "package_release.sh"
        ).read_text(encoding="utf-8")
        desktop_sign_script = (
            REPOSITORY_ROOT / "scripts" / "sign_desktop_release.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("UNPIN_CODESIGN_EXPECTED_FINGERPRINT", signature_script)
        self.assertIn("--display --extract-certificates=", signature_script)
        self.assertIn("dev.unpin.workbench", desktop_script)
        self.assertIn("dev.unpin.workbench.bridge", desktop_script)
        self.assertIn("dev.unpin.credential-broker", desktop_script)
        self.assertIn("dev.unpin.cli", cli_script)
        self.assertIn("dev.unpin.credential-broker", cli_script)
        self.assertIn("dev.unpin.credential-broker", package_script)
        self.assertIn("dev.unpin.credential-broker", desktop_sign_script)

    def test_release_configuration_does_not_reference_the_retired_identity(self) -> None:
        retired_name = "".join(("Code", "Burn Update Signing"))
        retired_fingerprint = "".join(
            ("E2AB4267F6B79DF40B87", "76A2EE9309F64CFD2389")
        )
        repository_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                WORKFLOW,
                REPOSITORY_ROOT / "docs" / "RELEASING.md",
                REPOSITORY_ROOT / "scripts" / "test_macos_signing_identity_scripts.py",
            )
        )

        self.assertNotIn(retired_name, repository_text)
        self.assertNotIn(retired_fingerprint, repository_text.upper())

    def _job(self, name: str) -> str:
        match = re.search(
            rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
            self.workflow,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"workflow job not found: {name}")
        assert match is not None
        return match.group("body")

    @staticmethod
    def _assert_signing_secret_boundary(job: str) -> None:
        assert "environment: release-signing" in job
        assert "UNPIN_MACOS_SIGNING_CERTIFICATE_P12: ${{ secrets." in job
        assert "UNPIN_MACOS_SIGNING_CERTIFICATE_PASSWORD: ${{ secrets." in job

    @staticmethod
    def _assert_import_cleanup_order(job: str) -> None:
        import_index = job.index("import_macos_signing_identity.sh")
        cleanup_index = job.index("cleanup_macos_signing_identity.sh")
        assert import_index < cleanup_index
        assert job.count("import_macos_signing_identity.sh") == 1
        assert job.count("cleanup_macos_signing_identity.sh") == 1


if __name__ == "__main__":
    unittest.main()
