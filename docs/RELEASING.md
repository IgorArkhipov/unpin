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
  - `aarch64-apple-darwin`
  - `x86_64-apple-darwin`
  - `x86_64-unknown-linux-gnu`
- Distribution channel: GitHub Releases
- crates.io, Homebrew, Linux ARM64, and Windows are deferred
- Published releases are immutable

Every target is a compressed archive with a CycloneDX JSON SBOM. Every archive
has separate GitHub SLSA build-provenance and SBOM attestations. The draft
workflow generates `SHA256SUMS`; ordinary program releases also attach a
manifest-approved provider-matrix evidence bundle.

## Prepare release commit

1. Update the workspace version, `CHANGELOG.md`, and `docs/releases/vVERSION.md`.
2. Run the focused checks and repository gates:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
   cargo test --workspace --all-features --locked
   cargo run -p unpin-cli --locked -- --help
   cargo audit --deny warnings
   cargo machete
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

The tag workflow builds and attests all supported targets, generates CycloneDX
SBOMs and `SHA256SUMS`, and creates a draft release. A tag with a prerelease
suffix creates a draft prerelease; a final version tag creates a stable draft
release. Do not publish it yet.

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
4. Confirm the GitHub release is immutable.
5. Confirm onboarding, security, changelog, and release links resolve.

Release evidence must never include raw live inventory, case directories,
backup payloads, audit logs, credentials, or private local paths.
