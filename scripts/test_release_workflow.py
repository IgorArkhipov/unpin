from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import textwrap
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

    def test_published_immutable_release_rerun_is_non_mutating(self) -> None:
        release_job = self._job("draft")

        self.assertIn("--write-out '%{http_code}'", release_job)
        self.assertIn("--retry-all-errors", release_job)
        self.assertIn("case \"${http_status}\" in", release_job)
        tag_check = release_job.index(
            'if [[ "${tag_name}" != "${GITHUB_REF_NAME}" ]]'
        )

        draft_start = release_job.index('if [[ "${is_draft}" == "true" ]]')
        published_start = release_job.index(
            'elif [[ "${is_draft}" == "false" ]]'
        )
        unexpected_state = release_job.index("unexpected release state")
        not_found_branch = release_job.index("404)")
        create_release = release_job.index("gh release create")
        refused_status = release_job.index("returned HTTP %s; refusing mutation")
        self.assertLess(tag_check, draft_start)
        self.assertLess(draft_start, published_start)
        self.assertLess(published_start, unexpected_state)
        self.assertLess(unexpected_state, not_found_branch)
        self.assertLess(not_found_branch, create_release)
        self.assertLess(create_release, refused_status)

        draft_branch = release_job[draft_start:published_start]
        published_branch = release_job[published_start:unexpected_state]
        missing_release_branch = release_job[not_found_branch:refused_status]

        self.assertIn("reported isImmutable=%s", draft_branch)
        self.assertIn("check_release_assets.py reject-evidence", draft_branch)
        self.assertIn("gh release upload", draft_branch)

        self.assertIn("is not immutable; refusing mutation", published_branch)
        self.assertIn("skipping draft refresh", published_branch)
        self.assertNotIn("gh release upload", published_branch)
        self.assertNotIn("gh release create", published_branch)
        self.assertNotIn("gh release edit", published_branch)

        self.assertIn("gh release create", missing_release_branch)
        self.assertIn("--draft", missing_release_branch)
        self.assertEqual(release_job.count("gh release upload"), 1)
        self.assertEqual(release_job.count("gh release create"), 1)

    def test_release_lookup_creates_only_after_confirmed_not_found(self) -> None:
        missing, missing_calls = self._run_release_step(
            404,
            {"message": "Not Found"},
        )
        self.assertEqual(missing.returncode, 0, missing.stderr)
        self.assertTrue(
            any(call.startswith("release create ") for call in missing_calls),
            missing_calls,
        )

        for status in (401, 503):
            with self.subTest(status=status):
                failed, failed_calls = self._run_release_step(
                    status,
                    {"message": "lookup failed"},
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(failed_calls, [])
                self.assertIn(f"HTTP {status}", failed.stderr)

        network, network_calls = self._run_release_step(
            0,
            {},
            curl_exit=7,
        )
        self.assertNotEqual(network.returncode, 0)
        self.assertEqual(network_calls, [])
        self.assertIn("release lookup failed", network.stderr)

    def test_release_lookup_preserves_draft_and_published_boundaries(self) -> None:
        published, published_calls = self._run_release_step(
            200,
            {"draft": False, "immutable": True, "tag_name": "v1.4.2"},
        )
        self.assertEqual(published.returncode, 0, published.stderr)
        self.assertEqual(published_calls, [])
        self.assertIn("skipping draft refresh", published.stdout)

        mutable, mutable_calls = self._run_release_step(
            200,
            {"draft": False, "immutable": False, "tag_name": "v1.4.2"},
        )
        self.assertNotEqual(mutable.returncode, 0)
        self.assertEqual(mutable_calls, [])

        draft, draft_calls = self._run_release_step(
            200,
            {"draft": True, "immutable": False, "tag_name": "v1.4.2"},
        )
        self.assertEqual(draft.returncode, 0, draft.stderr)
        self.assertTrue(
            any(call.startswith("release view ") for call in draft_calls),
            draft_calls,
        )
        self.assertTrue(
            any(call.startswith("release upload ") for call in draft_calls),
            draft_calls,
        )

        evidence, evidence_calls = self._run_release_step(
            200,
            {"draft": True, "immutable": False, "tag_name": "v1.4.2"},
            release_assets="unpin-v1.4.2-provider-matrix-evidence.tar.gz\n",
        )
        self.assertNotEqual(evidence.returncode, 0)
        self.assertTrue(
            any(call.startswith("release view ") for call in evidence_calls),
            evidence_calls,
        )
        self.assertFalse(
            any(call.startswith("release upload ") for call in evidence_calls),
            evidence_calls,
        )

    def _run_release_step(
        self,
        http_status: int,
        release_payload: dict[str, object],
        *,
        curl_exit: int = 0,
        release_assets: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_bin = Path(temp_dir)
            gh_log = fake_bin / "gh.log"
            self._write_executable(
                fake_bin / "curl",
                """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

args = sys.argv[1:]
output_path = Path(args[args.index("--output") + 1])
output_path.write_text(os.environ["FAKE_RELEASE_JSON"], encoding="utf-8")
print(os.environ["FAKE_HTTP_STATUS"], end="")
raise SystemExit(int(os.environ["FAKE_CURL_EXIT"]))
""",
            )
            self._write_executable(
                fake_bin / "gh",
                """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["FAKE_GH_LOG"]).open("a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\\n")
if args[:2] == ["release", "view"]:
    print(os.environ.get("FAKE_RELEASE_ASSETS", ""), end="")
""",
            )

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                    "GH_TOKEN": "test-token",
                    "GITHUB_API_URL": "https://api.github.test",
                    "GITHUB_REF_NAME": "v1.4.2",
                    "GITHUB_REPOSITORY": "IgorArkhipov/unpin",
                    "FAKE_RELEASE_JSON": json.dumps(release_payload),
                    "FAKE_HTTP_STATUS": str(http_status),
                    "FAKE_CURL_EXIT": str(curl_exit),
                    "FAKE_GH_LOG": str(gh_log),
                    "FAKE_RELEASE_ASSETS": release_assets,
                }
            )
            result = subprocess.run(
                ["bash", "-c", self._release_script()],
                cwd=REPOSITORY_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            calls = (
                gh_log.read_text(encoding="utf-8").splitlines()
                if gh_log.exists()
                else []
            )
            return result, calls

    def _release_script(self) -> str:
        draft_job = self._job("draft")
        step = draft_job.split(
            "      - name: Create or refresh draft\n",
            maxsplit=1,
        )[1]
        script = step.split("        run: |\n", maxsplit=1)[1]
        return textwrap.dedent(script)

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

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
