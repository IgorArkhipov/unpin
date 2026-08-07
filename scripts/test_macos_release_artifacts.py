from __future__ import annotations

import os
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CLI_VERIFY_SCRIPT = REPOSITORY_ROOT / "scripts" / "verify_macos_release_artifact.sh"
FINGERPRINT = "E2AB4267F6B79DF40B8776A2EE9309F64CFD2389"


class MacosReleaseArtifactTests(unittest.TestCase):
    def test_packaged_cli_requires_exact_signing_fingerprint(self) -> None:
        completed = self._run_cli({"FAKE_CODESIGN_FINGERPRINT": FINGERPRINT})

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("macOS CLI artifact verified", completed.stdout)

    def test_packaged_cli_rejects_mismatched_signing_fingerprint(self) -> None:
        completed = self._run_cli(
            {"FAKE_CODESIGN_FINGERPRINT": "0000000000000000000000000000000000000000"}
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fingerprint mismatch", completed.stderr)

    def test_packaged_cli_rejects_ad_hoc_signature_in_stable_mode(self) -> None:
        completed = self._run_cli(
            {
                "FAKE_CODESIGN_FINGERPRINT": FINGERPRINT,
                "FAKE_CODESIGN_SIGNATURE": "adhoc",
            }
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("ad-hoc signature", completed.stderr)

    def _run_cli(self, overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command_bin = root / "bin"
            command_bin.mkdir()
            target = "aarch64-apple-darwin"
            version = "1.0.0"
            release_name = f"unpin-v{version}-{target}"
            release_root = root / release_name
            binary = release_root / "unpin"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"synthetic signed cli")
            binary.chmod(0o755)
            archive = root / f"{release_name}.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(release_root, arcname=release_name)

            self._write_executable(
                command_bin / "lipo",
                "#!/bin/sh\nprintf '%s\\n' arm64\n",
            )
            self._write_executable(
                command_bin / "codesign",
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import os
                    import pathlib
                    import sys

                    arguments = sys.argv[1:]
                    expected_artifact_suffix = os.environ[
                        "FAKE_CODESIGN_ARTIFACT_SUFFIX"
                    ]
                    certificate_prefix = next(
                        (
                            argument.partition("=")[2]
                            for argument in arguments
                            if argument.startswith("--extract-certificates=")
                        ),
                        None,
                    )
                    if "--verify" in arguments:
                        if not arguments[-1].endswith(expected_artifact_suffix):
                            sys.exit(2)
                    elif certificate_prefix is not None and "--display" in arguments:
                        if not arguments[-1].endswith(expected_artifact_suffix):
                            sys.exit(2)
                        prefix = pathlib.Path(certificate_prefix)
                        prefix.with_name(f"{prefix.name}0").write_bytes(b"certificate")
                    elif "--extract-certificates" in arguments:
                        sys.exit(2)
                    elif "--display" in arguments:
                        if not arguments[-1].endswith(expected_artifact_suffix):
                            sys.exit(2)
                        print("Identifier=dev.unpin.cli", file=sys.stderr)
                        print(
                            f"Signature={os.environ.get('FAKE_CODESIGN_SIGNATURE', 'signed')}",
                            file=sys.stderr,
                        )
                    else:
                        sys.exit(2)
                    """
                ),
            )
            self._write_executable(
                command_bin / "openssl",
                "#!/bin/sh\nprintf 'sha1 Fingerprint=%s\\n' \"$FAKE_CODESIGN_FINGERPRINT\"\n",
            )

            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join(
                [str(command_bin), environment.get("PATH", "")]
            )
            environment.update(
                {
                    "UNPIN_CODESIGN_IDENTITY": FINGERPRINT,
                    "UNPIN_CODESIGN_EXPECTED_FINGERPRINT": FINGERPRINT,
                    "UNPIN_REQUIRE_STABLE_CODESIGN": "1",
                    "FAKE_CODESIGN_ARTIFACT_SUFFIX": f"{release_name}/unpin",
                    "FAKE_CODESIGN_FINGERPRINT": FINGERPRINT,
                }
            )
            environment.update(overrides)
            return subprocess.run(
                [str(CLI_VERIFY_SCRIPT), str(archive), target, version],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
