from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SIGN_SCRIPT = REPOSITORY_ROOT / "scripts" / "sign_macos_artifact.sh"


class SignMacosArtifactTests(unittest.TestCase):
    def test_stable_identity_uses_explicit_identifier_and_secure_timestamp(self) -> None:
        completed, log = self._run(
            {
                "UNPIN_CODESIGN_IDENTITY": "CodeBurn Update Signing",
                "UNPIN_CODESIGN_TIMESTAMP_MODE": "secure",
                "UNPIN_REQUIRE_STABLE_CODESIGN": "1",
            }
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        commands = self._read_log(log)
        sign = commands[0]
        self.assertIn("--force", sign)
        self.assertEqual(sign[sign.index("--sign") + 1], "CodeBurn Update Signing")
        self.assertEqual(
            sign[sign.index("--identifier") + 1],
            "dev.unpin.workbench.bridge",
        )
        self.assertIn("--timestamp", sign)
        self.assertNotIn("--timestamp=none", sign)
        self.assertEqual(sign[sign.index("--options") + 1], "runtime")

    def test_default_ad_hoc_signing_uses_no_timestamp(self) -> None:
        completed, log = self._run()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        sign = self._read_log(log)[0]
        self.assertEqual(sign[sign.index("--sign") + 1], "-")
        self.assertIn("--timestamp=none", sign)

    def test_stable_required_rejects_ad_hoc_identity(self) -> None:
        completed, log = self._run({"UNPIN_REQUIRE_STABLE_CODESIGN": "1"})

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is ad-hoc (-)", completed.stderr)
        self.assertFalse(log.exists())

    def test_invalid_timestamp_mode_is_rejected(self) -> None:
        completed, log = self._run(
            {"UNPIN_CODESIGN_TIMESTAMP_MODE": "eventually"}
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("expected none or secure", completed.stderr)
        self.assertFalse(log.exists())

    def test_reported_identifier_mismatch_is_rejected(self) -> None:
        completed, _ = self._run(
            {"FAKE_CODESIGN_IDENTIFIER": "dev.unpin.wrong"}
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("signature identifier mismatch", completed.stderr)

    def test_ad_hoc_result_is_rejected_in_stable_mode(self) -> None:
        completed, _ = self._run(
            {
                "UNPIN_CODESIGN_IDENTITY": "CodeBurn Update Signing",
                "UNPIN_REQUIRE_STABLE_CODESIGN": "1",
                "FAKE_CODESIGN_SIGNATURE": "adhoc",
            }
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("produced an ad-hoc signature", completed.stderr)

    def test_expected_certificate_fingerprint_is_verified(self) -> None:
        fingerprint = "E2AB4267F6B79DF40B8776A2EE9309F64CFD2389"
        completed, log = self._run(
            {
                "UNPIN_CODESIGN_IDENTITY": fingerprint,
                "UNPIN_CODESIGN_EXPECTED_FINGERPRINT": fingerprint.lower(),
                "UNPIN_REQUIRE_STABLE_CODESIGN": "1",
                "FAKE_CODESIGN_FINGERPRINT": fingerprint,
            }
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(
            any(
                "--display" in command
                and any(
                    argument.startswith("--extract-certificates=")
                    for argument in command
                )
                for command in self._read_log(log)
            )
        )

    def test_mismatched_certificate_fingerprint_is_rejected(self) -> None:
        fingerprint = "E2AB4267F6B79DF40B8776A2EE9309F64CFD2389"
        completed, _ = self._run(
            {
                "UNPIN_CODESIGN_IDENTITY": fingerprint,
                "UNPIN_CODESIGN_EXPECTED_FINGERPRINT": fingerprint,
                "FAKE_CODESIGN_FINGERPRINT": "0000000000000000000000000000000000000000",
            }
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fingerprint mismatch", completed.stderr)

    def _run(
        self, environment_overrides: dict[str, str] | None = None
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        command_bin = root / "bin"
        command_bin.mkdir()
        artifact = root / "unpin"
        artifact.write_bytes(b"synthetic Mach-O")
        artifact.chmod(0o755)
        log = root / "codesign.jsonl"
        state = root / "codesign-state.json"

        fake_codesign = command_bin / "codesign"
        fake_codesign.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                import pathlib
                import sys

                arguments = sys.argv[1:]
                expected_artifact = os.environ["FAKE_CODESIGN_ARTIFACT"]
                log = pathlib.Path(os.environ["FAKE_CODESIGN_LOG"])
                with log.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(arguments) + "\\n")

                state = pathlib.Path(os.environ["FAKE_CODESIGN_STATE"])
                if "--force" in arguments:
                    if arguments[-1] != expected_artifact:
                        sys.exit(2)
                    identifier = arguments[arguments.index("--identifier") + 1]
                    state.write_text(
                        json.dumps({"identifier": identifier}),
                        encoding="utf-8",
                    )
                elif "--verify" in arguments:
                    if arguments[-1] != expected_artifact:
                        sys.exit(2)
                elif "--display" in arguments and any(
                    argument.startswith("--extract-certificates=")
                    for argument in arguments
                ):
                    if arguments[-1] != expected_artifact:
                        sys.exit(2)
                    prefix = pathlib.Path(
                        next(
                            argument.partition("=")[2]
                            for argument in arguments
                            if argument.startswith("--extract-certificates=")
                        )
                    )
                    prefix.with_name(f"{prefix.name}0").write_bytes(
                        b"synthetic certificate"
                    )
                elif "--extract-certificates" in arguments:
                    sys.exit(2)
                elif "--display" in arguments:
                    if arguments[-1] != expected_artifact:
                        sys.exit(2)
                    identifier = os.environ.get("FAKE_CODESIGN_IDENTIFIER")
                    if identifier is None:
                        identifier = json.loads(
                            state.read_text(encoding="utf-8")
                        )["identifier"]
                    signature = os.environ.get("FAKE_CODESIGN_SIGNATURE", "signed")
                    print(f"Identifier={identifier}", file=sys.stderr)
                    print(f"Signature={signature}", file=sys.stderr)
                else:
                    sys.exit(2)
                """
            ),
            encoding="utf-8",
        )
        fake_codesign.chmod(0o755)
        fake_openssl = command_bin / "openssl"
        fake_openssl.write_text(
            "#!/bin/sh\nprintf 'sha1 Fingerprint=%s\\n' \"${FAKE_CODESIGN_FINGERPRINT:-E2AB4267F6B79DF40B8776A2EE9309F64CFD2389}\"\n",
            encoding="utf-8",
        )
        fake_openssl.chmod(0o755)

        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join(
            [str(command_bin), environment.get("PATH", "")]
        )
        environment["FAKE_CODESIGN_LOG"] = str(log)
        environment["FAKE_CODESIGN_STATE"] = str(state)
        environment["FAKE_CODESIGN_ARTIFACT"] = str(artifact)
        for variable in (
            "UNPIN_CODESIGN_IDENTITY",
            "UNPIN_CODESIGN_TIMESTAMP_MODE",
            "UNPIN_REQUIRE_STABLE_CODESIGN",
            "UNPIN_CODESIGN_EXPECTED_FINGERPRINT",
            "FAKE_CODESIGN_IDENTIFIER",
            "FAKE_CODESIGN_SIGNATURE",
            "FAKE_CODESIGN_FINGERPRINT",
        ):
            environment.pop(variable, None)
        environment.update(environment_overrides or {})

        completed = subprocess.run(
            [
                str(SIGN_SCRIPT),
                "dev.unpin.workbench.bridge",
                str(artifact),
            ],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        return completed, log

    @staticmethod
    def _read_log(log: Path) -> list[list[str]]:
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


if __name__ == "__main__":
    unittest.main()
