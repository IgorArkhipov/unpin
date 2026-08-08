# Releasing Unpin

Unpin releases are built by GitHub Actions and published only after either
local provider-matrix evidence or the focused delivery-only artifact evidence
defined below is verified and attached. The release workflow creates a draft
release; it never publishes directly. Tags with a prerelease suffix create a
draft prerelease; final version tags create a stable draft release.

## Release contract

- Canonical repository: `IgorArkhipov/unpin`
- Version format: semantic version, with an optional prerelease suffix
- Supported release artifacts:
  - CLI: `aarch64-apple-darwin`, `x86_64-apple-darwin`, and
    `x86_64-unknown-linux-gnu`
  - desktop: `unpin-desktop` archives for `aarch64-apple-darwin` and
    `x86_64-apple-darwin`
- Distribution channel: GitHub Releases
- crates.io, Homebrew, Linux ARM64, and Windows are deferred
- Published releases are immutable

Every target is a compressed archive with a CycloneDX JSON SBOM. Every archive
has separate GitHub SLSA build-provenance and SBOM attestations. The draft
workflow generates `SHA256SUMS`; ordinary program releases also attach a
manifest-approved provider-matrix evidence bundle.

macOS archives default to reproducible ad-hoc signing with Hardened Runtime and
no timestamp. A maintainer can instead select a stable certificate for both
desktop and CLI archives. A self-signed certificate preserves the designated
requirement that Keychain uses across later updates signed with that same
certificate and identifiers, but it is not Developer ID signing or notarization
and must never be described as Gatekeeper-trusted. A
stable release may include it only when the maintainer explicitly approves the
unsigned-GA exception, release-facing documentation explains Gatekeeper's
manual first-launch requirement, and the downloaded archive passes checksum,
attestation, signature, bridge-handshake, and installed-artifact verification.
Developer ID signing and notarization remain future distribution hardening
rather than a blocker under the explicit exception.

The release workflow opts into the stable certificate and fails closed if it is
unavailable or does not match the expected fingerprint.

### macOS signing modes

Both macOS release builders use `scripts/sign_macos_artifact.sh`. Without
configuration it applies an ad-hoc Hardened Runtime signature. To prevent an
accidental ad-hoc fallback and use an installed certificate, run the builders
with:

```bash
UNPIN_CODESIGN_IDENTITY="Certificate Name or SHA-1" \
UNPIN_CODESIGN_TIMESTAMP_MODE=none \
UNPIN_REQUIRE_STABLE_CODESIGN=1 \
scripts/build_desktop_release.sh TARGET VERSION OUTPUT_DIRECTORY
```

The release workflow uses `UNPIN_CODESIGN_TIMESTAMP_MODE=none` for its personal
self-signed certificate; do not claim secure timestamping for that certificate
without separate verification. Use `UNPIN_CODESIGN_TIMESTAMP_MODE=secure` only
for a Developer ID certificate after confirming that it can reach Apple's
timestamp service. The builders verify the resulting signature and exact
identifiers: `dev.unpin.workbench` for the app,
`dev.unpin.workbench.bridge` for its bundled credential broker, and
`dev.unpin.cli` for the standalone CLI. The bridge and CLI may each require one
new Keychain authorization after switching from ad-hoc signing. In particular,
the first update from `1.0.1` or earlier can prompt because its designated
requirement changes once; later builds signed by the same certificate and
identifier retain that requirement and their **Always Allow** grants.

The GitHub release workflow runs the macOS signing jobs in the protected
`release-signing` Environment. Its
`UNPIN_MACOS_SIGNING_CERTIFICATE_P12` and
`UNPIN_MACOS_SIGNING_CERTIFICATE_PASSWORD` environment secrets are available
only after the Environment's required approval. The workflow imports the P12
into an ephemeral runner Keychain, verifies the exact configured SHA-1 identity,
and removes the temporary Keychain and P12 after packaging. Never commit, log,
or expose the signing private key; the protected environment is the only
approved storage used by release automation. This personal certificate remains
non-Developer-ID and non-notarized, so it does not establish Gatekeeper trust.

### Self-update compatibility gate

The CLI and desktop app discover only GitHub's latest stable release. Keep the
following contract for every release that should be installable through
`unpin update`:

- publish the exact CLI and desktop archive names derived from version and
  target triple, plus `SHA256SUMS` containing each archive;
- never replace a published archive or checksum asset;
- sign the standalone CLI, desktop app, and bundled bridge with the configured
  release certificate and exact identifiers `dev.unpin.cli`,
  `dev.unpin.workbench`, and `dev.unpin.workbench.bridge`;
- verify the same expected certificate fingerprint in every macOS signing job;
- keep each candidate's designated requirement exactly equal to the preceding
  installed release requirement.

The updater independently verifies the checksum, candidate version, signature,
identifier, and exact designated-requirement equality before replacement. The
desktop JSON success response includes `keychainRequirementPreserved: true`,
and the native app refuses to terminate and relaunch unless that proof is
present. This is the release boundary that lets a Keychain **Always Allow**
grant survive normal updates.

A certificate or identifier rotation is deliberately not self-updatable. The
old installed release rejects it because its designated requirement changes.
Publish explicit manual replacement instructions and explain that one new
Keychain authorization is expected after the verified rotation.

### Certificate expiry and rotation

Inspect the installed certificate before each release and set a reminder well
before its `notAfter` date (30 days is a useful minimum):

```bash
security find-certificate -a -p -c "CodeBurn Update Signing" \
  | openssl x509 -noout -subject -fingerprint -sha1 -dates
```

Use the `notAfter` value as the expiry date and compare the SHA-1 fingerprint
with the release workflow. If the P12 exists only in the protected environment,
inspect it through a temporary, local Keychain and delete that Keychain after
reading the certificate; never copy the P12 or password into the repository or
logs.

Before expiry, or immediately if compromise is suspected, rotate all of the
following as one reviewed change:

1. Create a replacement certificate and password-protected P12, then update
   `UNPIN_MACOS_SIGNING_CERTIFICATE_P12` and
   `UNPIN_MACOS_SIGNING_CERTIFICATE_PASSWORD` in the protected
   `release-signing` Environment. Keep required approval enabled.
2. Update the SHA-1 fingerprint in `.github/workflows/release.yml`
   (`UNPIN_CODESIGN_IDENTITY`),
   `scripts/test_macos_signing_identity_scripts.py` (`EXPECTED_IDENTITY`),
   and the versioned release notes (`docs/releases/vVERSION.md`, plus the
   matching `CHANGELOG.md` entry when applicable).
3. Keep timestamp mode `none` for this personal self-signed certificate; do not
   describe it as secure-timestamped or Gatekeeper-trusted.
4. Run the signing helper and release-tooling tests, then the approved
   delivery-only or provider-matrix gates. Tag only after the merged commit is
   verified, and complete the post-tag artifact fingerprint and exact-identifier
   checks before publication.
5. Tell users that certificate rotation resets the designated requirement even
   when bundle identifiers do not change. The first launch of the rotated
   release therefore requires new Keychain approval; old **Always Allow** grants
   do not carry over.

Do not wait for the expiry date to discover a stale fingerprint or secret: the
workflow must fail closed if the imported identity does not match the expected
fingerprint, and a rotation needs a fresh artifact verification cycle.

## Prepare release commit

1. Update the workspace version, exact `unpin-core` dependency, Cargo lockfile,
   Xcode `MARKETING_VERSION`, `CHANGELOG.md`, and
   `docs/releases/vVERSION.md`.
2. Run the focused checks and repository gates:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
   cargo test --workspace --all-features --locked
   cargo run -p unpin-cli --locked -- --help
   cargo audit --deny warnings
   cargo machete
   xcodebuild test \
     -project apps/unpin-desktop/UnpinDesktop.xcodeproj \
     -scheme UnpinDesktop \
     -destination 'platform=macOS'
   ```

3. With supported Pi and OpenCode executables on `PATH`, run
   `python3 scripts/validate_live_provider_hosts.py`.
4. Commit and push the candidate to `main`.
5. Wait for required CI to pass.
6. Run and finalize the full provider matrix from that exact clean commit.
7. Confirm the manifest is approved and the tested Git SHA matches `main`.

### Delivery-only artifact exception

A maintainer may omit the live-host and full provider-matrix gates only when
the release changes no program logic and is limited to release build,
distribution metadata, or documentation. The PR and versioned release notes
must state that scope and the replacement evidence.

For such a release, run `actionlint`, `cargo metadata --locked --no-deps`, and
the version smoke locally. Require the `Linux release compatibility` CI job to
pass from the exact release commit. That job builds the release binary on
Ubuntu 22.04, verifies that its highest required GNU libc symbol is no newer
than `GLIBC_2.35`, and runs `--version` and `--help` in Debian 12. The tag
workflow repeats that artifact check before attestation and draft creation.

The exception does not waive post-tag macOS identity proof. After the tag,
inspect every CLI and desktop artifact's signature, expected certificate SHA-1
fingerprint, and exact identifiers (`dev.unpin.workbench`,
`dev.unpin.workbench.bridge`, and `dev.unpin.cli`) before publication. Delivery
scope replaces provider-matrix/live-host execution; it does not replace this
artifact-level signing evidence.

Do not run `scripts/prepare_release_evidence.py` for this exception: it is the
provider-matrix path and replaces the draft's generated checksum manifest with
matrix evidence.

## Build draft release

Create and push an annotated release tag. The release does not depend on a
maintainer-managed GPG signing key; GitHub attestations verify artifact identity:

```bash
git tag -a vVERSION -m "Unpin vVERSION"
git push origin vVERSION
```

The tag workflow builds and attests all supported CLI and desktop targets,
generates CycloneDX SBOMs and `SHA256SUMS`, and creates a draft release. It
checks that the tag, Cargo package version, and Xcode marketing version match.
A tag with a prerelease suffix creates a draft prerelease; a final version tag
creates a stable draft release. Do not publish it yet.

## Add evidence and checksums

Download draft assets into a new private temporary directory:

```bash
release_assets="$(mktemp -d)"
gh release download vVERSION \
  --repo IgorArkhipov/unpin \
  --dir "$release_assets"
```

For an ordinary program release, prepare the manifest-approved evidence plus
checksums:

```bash
python3 scripts/prepare_release_evidence.py \
  --artifact-root tmp/YOUR-RUN-local-matrix \
  --asset-dir "$release_assets" \
  --tag vVERSION \
  --expected-commit "$(git rev-parse 'vVERSION^{commit}')"
```

The preparation script treats the workflow-generated `SHA256SUMS` as the trust
root: it validates every listed download before creating files, preserves those
entries exactly, ignores unrelated local files, and adds only the evidence
archive and evidence manifest. Inspect the extended `SHA256SUMS` and evidence
archive. Upload the two new evidence assets without replacement, then replace
only the validated checksum manifest:

```bash
gh release upload vVERSION \
  "$release_assets"/unpin-vVERSION-provider-matrix-evidence.tar.gz \
  "$release_assets"/unpin-vVERSION-provider-matrix-evidence-manifest.json \
  --repo IgorArkhipov/unpin
gh release upload vVERSION \
  "$release_assets"/SHA256SUMS \
  --repo IgorArkhipov/unpin \
  --clobber
```

Do not rerun the tag workflow after uploading provider-matrix evidence. The
workflow intentionally refuses to refresh a draft containing either evidence
asset because its build-only `SHA256SUMS` would drop the evidence entries. If a
rebuild is required, remove both evidence assets from the draft, rerun the tag
workflow, download every draft asset into a new directory, and repeat evidence
preparation and upload. If an evidence upload only partially succeeds, do not
publish; remove the partial evidence asset from the draft and repeat the same
fresh-download procedure.

For a delivery-only artifact exception, skip the ordinary evidence path: the
draft already contains the generated `SHA256SUMS`. Verify its checksums and the
GNU/Linux archive before publication:

```bash
(
  set -euo pipefail
  cd "$release_assets"
  shasum -a 256 -c SHA256SUMS
  gh attestation verify unpin-vVERSION-x86_64-unknown-linux-gnu.tar.gz \
    --repo IgorArkhipov/unpin
  tar -xzf unpin-vVERSION-x86_64-unknown-linux-gnu.tar.gz
  docker run --rm \
    -v "$release_assets"/unpin-vVERSION-x86_64-unknown-linux-gnu/unpin:/opt/unpin:ro \
    debian:12 /opt/unpin --version
  docker run --rm \
    -v "$release_assets"/unpin-vVERSION-x86_64-unknown-linux-gnu/unpin:/opt/unpin:ro \
    debian:12 /opt/unpin --help
)
```

## Publish and verify

Confirm private vulnerability reporting and immutable releases are enabled, then
download the complete draft into another new private directory. Verify every
checksum and require the draft's exact asset-name set to equal the names in
`SHA256SUMS` plus `SHA256SUMS` itself:

```bash
(
  set -euo pipefail
  draft_verification_assets="$(mktemp -d)"
  gh release download vVERSION \
    --repo IgorArkhipov/unpin \
    --dir "$draft_verification_assets"
  (
    cd "$draft_verification_assets"
    shasum -a 256 -c SHA256SUMS
  )
  gh release view vVERSION \
    --repo IgorArkhipov/unpin \
    --json assets \
    --jq '.assets[].name' \
    | python3 scripts/check_release_assets.py verify-set \
        --checksums "$draft_verification_assets"/SHA256SUMS

  printf 'draft verification passed; publishing vVERSION\n'
  gh release edit vVERSION \
    --repo IgorArkhipov/unpin \
    --draft=false
)
```

After publication:

1. Download every asset and run `shasum -a 256 -c SHA256SUMS`.
2. Verify each archive:

   ```bash
   gh attestation verify unpin-vVERSION-TARGET.tar.gz \
     --repo IgorArkhipov/unpin
   ```

3. Extract each archive and run `unpin --version` and `unpin --help`.
4. For each desktop archive, run:

   ```bash
   scripts/verify_desktop_release_artifact.sh \
     unpin-desktop-vVERSION-TARGET.tar.gz \
     TARGET \
     VERSION
   ```

   Confirm the app and bundled bridge architectures match the target, the
   bridge digest and version match the manifest, the Hardened Runtime signature
   verifies with the expected certificate fingerprint and exact identifiers,
   and the isolated stdio handshake passes.
5. Confirm the release notes link to the Gatekeeper, manual update, and
   uninstall guidance in `docs/DESKTOP.md`.
6. Confirm the GitHub release is immutable.
7. Confirm onboarding, security, changelog, and release links resolve.

Release evidence must never include raw live inventory, case directories,
backup payloads, audit logs, credentials, or private local paths.
