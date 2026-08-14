from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
IMPORT_SCRIPT = REPOSITORY_ROOT / "scripts" / "import_macos_signing_identity.sh"
CLEANUP_SCRIPT = REPOSITORY_ROOT / "scripts" / "cleanup_macos_signing_identity.sh"
EXPECTED_IDENTITY = "0123456789ABCDEF0123456789ABCDEF01234567"


class MacosSigningIdentityScriptTests(unittest.TestCase):
    def test_import_and_cleanup_use_ephemeral_runner_paths(self) -> None:
        root, environment, security_log = self._environment()

        imported = self._run_script(IMPORT_SCRIPT, environment)
        self.assertEqual(imported.returncode, 0, imported.stderr)

        exported_environment = self._github_environment(root)
        self.assertEqual(set(exported_environment), {"UNPIN_SIGNING_KEYCHAIN"})
        signing_keychain = Path(exported_environment["UNPIN_SIGNING_KEYCHAIN"])
        self.assertTrue(signing_keychain.is_file())
        signing_p12 = root / "unpin-release-signing.p12"
        search_list_file = root / "unpin-release-signing.keychain-search-list"
        self.assertFalse(signing_p12.exists())
        self.assertTrue(search_list_file.is_file())
        signing_p12.write_text("leftover", encoding="utf-8")

        environment.update(exported_environment)
        cleaned = self._run_script(CLEANUP_SCRIPT, environment)
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse(signing_keychain.exists())
        self.assertFalse(signing_p12.exists())
        self.assertFalse(search_list_file.exists())
        self.assertIn("delete-keychain", security_log.read_text(encoding="utf-8"))
        self.assertEqual(
            (root / "current-keychains").read_text(encoding="utf-8"),
            "/Users/example/Library/Keychains/login.keychain-db\n/Library/Keychains/System.keychain\n",
        )

    def test_import_requires_certificate_secret(self) -> None:
        _, environment, security_log = self._environment()
        environment.pop("UNPIN_MACOS_SIGNING_CERTIFICATE_P12")

        completed = self._run_script(IMPORT_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("UNPIN_MACOS_SIGNING_CERTIFICATE_P12", completed.stderr)
        self.assertFalse(security_log.exists())

    def test_import_accepts_self_signed_identity_without_valid_only_filter(self) -> None:
        _, environment, security_log = self._environment()
        environment["FAKE_CODESIGN_IDENTITY_UNTRUSTED"] = "1"

        completed = self._run_script(IMPORT_SCRIPT, environment)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        identity_calls = [
            line.split()
            for line in security_log.read_text(encoding="utf-8").splitlines()
            if line.startswith("find-identity ")
        ]
        self.assertEqual(len(identity_calls), 1)
        self.assertNotIn("-v", identity_calls[0])

    def test_identity_mismatch_removes_temporary_secrets(self) -> None:
        root, environment, security_log = self._environment()
        environment["FAKE_CODESIGN_IDENTITY"] = "0000000000000000000000000000000000000000"

        completed = self._run_script(IMPORT_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not contain the expected identity", completed.stderr)
        self.assertFalse((root / "unpin-release-signing.keychain-db").exists())
        self.assertFalse((root / "unpin-release-signing.p12").exists())
        self.assertIn("delete-keychain", security_log.read_text(encoding="utf-8"))

    def test_identity_display_name_cannot_spoof_hash_match(self) -> None:
        root, environment, _ = self._environment()
        environment["FAKE_CODESIGN_IDENTITY"] = "0000000000000000000000000000000000000000"
        environment["FAKE_CODESIGN_DISPLAY_NAME"] = EXPECTED_IDENTITY

        completed = self._run_script(IMPORT_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not contain the expected identity", completed.stderr)
        self.assertFalse((root / "unpin-release-signing.keychain-db").exists())
        self.assertFalse((root / "unpin-release-signing.p12").exists())

    def test_multiple_identities_are_rejected(self) -> None:
        root, environment, _ = self._environment()
        environment["FAKE_CODESIGN_MULTIPLE"] = "1"
        environment["FAKE_CODESIGN_IDENTITY_UNTRUSTED"] = "1"

        completed = self._run_script(IMPORT_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("exactly one identity", completed.stderr)
        self.assertFalse((root / "unpin-release-signing.keychain-db").exists())
        self.assertFalse((root / "unpin-release-signing.p12").exists())

    def test_failed_security_import_removes_temporary_paths(self) -> None:
        root, environment, _ = self._environment()
        environment["FAKE_SECURITY_IMPORT_FAIL"] = "1"

        completed = self._run_script(IMPORT_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((root / "unpin-release-signing.keychain-db").exists())
        self.assertFalse((root / "unpin-release-signing.p12").exists())
        self.assertFalse((root / "unpin-release-signing.keychain-search-list").exists())

    def test_failed_partition_list_removes_temporary_paths(self) -> None:
        root, environment, _ = self._environment()
        environment["FAKE_SECURITY_PARTITION_FAIL"] = "1"

        completed = self._run_script(IMPORT_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((root / "unpin-release-signing.keychain-db").exists())
        self.assertFalse((root / "unpin-release-signing.p12").exists())
        self.assertFalse((root / "unpin-release-signing.keychain-search-list").exists())

    def test_cleanup_removes_partial_import_without_exported_environment(self) -> None:
        root, environment, _ = self._environment()
        (root / "unpin-release-signing.keychain-db").write_text("partial", encoding="utf-8")
        (root / "unpin-release-signing.p12").write_text("leftover", encoding="utf-8")
        environment.pop("UNPIN_SIGNING_KEYCHAIN", None)

        completed = self._run_script(CLEANUP_SCRIPT, environment)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse((root / "unpin-release-signing.keychain-db").exists())
        self.assertFalse((root / "unpin-release-signing.p12").exists())

    def test_cleanup_removes_p12_when_keychain_path_is_rejected(self) -> None:
        root, environment, _ = self._environment()
        (root / "unpin-release-signing.p12").write_text("leftover", encoding="utf-8")
        environment["UNPIN_SIGNING_KEYCHAIN"] = "/tmp/unexpected.keychain-db"

        completed = self._run_script(CLEANUP_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("refusing to delete unexpected", completed.stderr)
        self.assertFalse((root / "unpin-release-signing.p12").exists())

    def test_cleanup_removes_p12_when_keychain_deletion_fails(self) -> None:
        root, environment, _ = self._environment()
        (root / "unpin-release-signing.keychain-db").write_text("partial", encoding="utf-8")
        (root / "unpin-release-signing.p12").write_text("leftover", encoding="utf-8")
        environment["UNPIN_SIGNING_KEYCHAIN"] = str(root / "unpin-release-signing.keychain-db")
        environment["FAKE_SECURITY_DELETE_FAIL"] = "1"

        completed = self._run_script(CLEANUP_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("failed to delete temporary signing Keychain", completed.stderr)
        self.assertFalse((root / "unpin-release-signing.p12").exists())
        self.assertTrue((root / "unpin-release-signing.keychain-db").exists())

    def test_decoded_p12_is_private_during_import(self) -> None:
        root, environment, _ = self._environment()
        mode_file = root / "import-mode"
        environment["FAKE_IMPORT_MODE_FILE"] = str(mode_file)

        completed = self._run_script(IMPORT_SCRIPT, environment)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(mode_file.read_text(encoding="utf-8"), "600\n")

    def test_cleanup_rejects_paths_outside_runner_temp(self) -> None:
        _, environment, _ = self._environment()
        environment["UNPIN_SIGNING_KEYCHAIN"] = "/tmp/unexpected.keychain-db"

        completed = self._run_script(CLEANUP_SCRIPT, environment)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("refusing to delete unexpected", completed.stderr)

    def _environment(self) -> tuple[Path, dict[str, str], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        command_bin = root / "bin"
        command_bin.mkdir()
        github_environment = root / "github-env"
        github_environment.touch()
        security_log = root / "security.log"
        current_keychains = root / "current-keychains"

        self._write_executable(
            command_bin / "uname", "#!/bin/sh\nprintf '%s\\n' Darwin\n"
        )
        self._write_executable(
            command_bin / "openssl",
            "#!/bin/sh\nprintf 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\\n\n",
        )
        self._write_executable(
            command_bin / "base64",
            "#!/bin/sh\ntest \"$1\" = -D\ncat\n",
        )
        self._write_executable(
            command_bin / "security",
            textwrap.dedent(
                """\
                #!/bin/sh
                set -eu
                printf '%s\\n' "$*" >> "$FAKE_SECURITY_LOG"
                command="$1"
                shift
                case "$command" in
                  create-keychain)
                    while [ "$#" -gt 1 ]; do shift; done
                    : > "$1"
                    ;;
                  find-identity)
                    valid_only=0
                    for argument in "$@"; do
                      if [ "$argument" = -v ]; then
                        valid_only=1
                      fi
                    done
                    identity_count=1
                    if [ "${FAKE_CODESIGN_MULTIPLE:-0}" = 1 ]; then
                      identity_count=2
                    fi
                    if [ "$valid_only" = 0 ]; then
                      printf '\\nPolicy: Code Signing\\n  Matching identities\\n'
                      printf '  1) %s "%s"\\n' "$FAKE_CODESIGN_IDENTITY" "${FAKE_CODESIGN_DISPLAY_NAME:-Unpin Release Signing}"
                      if [ "$identity_count" = 2 ]; then
                        printf '  2) 1111111111111111111111111111111111111111 "Second Identity"\\n'
                      fi
                      printf '     %s identities found\\n\\n  Valid identities only\\n' "$identity_count"
                    fi
                    if [ "${FAKE_CODESIGN_IDENTITY_UNTRUSTED:-0}" != 1 ]; then
                      printf '  1) %s "%s"\\n' "$FAKE_CODESIGN_IDENTITY" "${FAKE_CODESIGN_DISPLAY_NAME:-Unpin Release Signing}"
                      if [ "$identity_count" = 2 ]; then
                        printf '  2) 1111111111111111111111111111111111111111 "Second Identity"\\n'
                      fi
                      valid_identity_count="$identity_count"
                    else
                      valid_identity_count=0
                    fi
                    printf '     %s valid identities found\\n' "$valid_identity_count"
                    ;;
                  import)
                    if [ "${FAKE_SECURITY_IMPORT_FAIL:-0}" = 1 ]; then
                      exit 41
                    fi
                    if [ -n "${FAKE_IMPORT_MODE_FILE:-}" ]; then
                      python3 -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])' "$1" > "$FAKE_IMPORT_MODE_FILE"
                    fi
                    ;;
                  set-key-partition-list)
                    if [ "${FAKE_SECURITY_PARTITION_FAIL:-0}" = 1 ]; then
                      exit 42
                    fi
                    ;;
                  list-keychains)
                    if [ "$#" -eq 2 ]; then
                      old_ifs="$IFS"
                      IFS='|'
                      for keychain in ${FAKE_INITIAL_KEYCHAINS:-}; do
                        printf '    "%s"\\n' "$keychain"
                      done
                      IFS="$old_ifs"
                    else
                      : > "$FAKE_CURRENT_KEYCHAINS"
                      shift 3
                      for keychain do
                        printf '%s\\n' "$keychain" >> "$FAKE_CURRENT_KEYCHAINS"
                      done
                    fi
                    ;;
                  delete-keychain)
                    if [ "${FAKE_SECURITY_DELETE_FAIL:-0}" = 1 ]; then
                      exit 43
                    fi
                    rm -f -- "$1"
                    ;;
                esac
                """
            ),
        )

        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join(
            [str(command_bin), environment.get("PATH", "")]
        )
        environment.update(
            {
                "RUNNER_TEMP": str(root),
                "GITHUB_ENV": str(github_environment),
                "UNPIN_CODESIGN_IDENTITY": EXPECTED_IDENTITY,
                "UNPIN_MACOS_SIGNING_CERTIFICATE_P12": "encoded-p12",
                "UNPIN_MACOS_SIGNING_CERTIFICATE_PASSWORD": "p12-password",
                "FAKE_CODESIGN_IDENTITY": EXPECTED_IDENTITY,
                "FAKE_SECURITY_LOG": str(security_log),
                "FAKE_INITIAL_KEYCHAINS": "/Users/example/Library/Keychains/login.keychain-db|/Library/Keychains/System.keychain",
                "FAKE_CURRENT_KEYCHAINS": str(current_keychains),
            }
        )
        return root, environment, security_log

    @staticmethod
    def _run_script(
        script: Path, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(script)],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    @staticmethod
    def _github_environment(root: Path) -> dict[str, str]:
        values: dict[str, str] = {}
        for line in (root / "github-env").read_text(encoding="utf-8").splitlines():
            name, value = line.split("=", 1)
            values[name] = value
        return values

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
