# Releasing Unpin

Unpin prereleases are built by GitHub Actions and published only after local
provider-matrix evidence is verified and attached. The release workflow creates
a draft; it never publishes directly.

## Release contract

- Canonical repository: `IgorArkhipov/unpin`
- Version format: semantic version with a prerelease suffix
- Supported beta artifacts:
  - `aarch64-apple-darwin`
  - `x86_64-apple-darwin`
  - `x86_64-unknown-linux-gnu`
- Distribution channel: GitHub Releases
- crates.io, Homebrew, Linux ARM64, and Windows are deferred
- Published releases are immutable

Every target has a compressed archive and CycloneDX JSON SBOM. Every archive
has separate GitHub SLSA build-provenance and SBOM attestations. The final
release also contains `SHA256SUMS` and a manifest-approved provider-matrix
evidence bundle.

## Prepare the release commit

1. Update the workspace version, `CHANGELOG.md`, and
   `docs/releases/vVERSION.md`.
2. Run focused checks, then all repository gates:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
   cargo test --workspace --all-features --locked
   cargo run -p unpin-cli --locked -- --help
   cargo audit --no-yanked
   cargo machete
   ```

3. With supported Pi and OpenCode executables on `PATH`, run
   `python3 scripts/validate_live_provider_hosts.py`.
4. Commit and push the candidate to `main`.
5. Wait for required CI to pass.
6. Run and finalize the full provider matrix from that exact clean commit.
7. Confirm the manifest is approved and the tested Git SHA matches `main`.

## Build the draft release

Create and push an annotated release tag. The release does not depend on a
maintainer-managed GPG signing key; artifact identity and provenance are
verified through GitHub attestations:

```bash
git tag -a vVERSION -m "Unpin vVERSION"
git push origin vVERSION
```

The tag workflow builds and attests all supported targets, generates CycloneDX
SBOMs, and creates a draft prerelease. Do not publish it yet.

## Add evidence and checksums

Download the draft assets into a new private temporary directory:

```bash
release_assets="$(mktemp -d)"
gh release download vVERSION \
  --repo IgorArkhipov/unpin \
  --dir "$release_assets"
```

Verify and prepare the manifest-approved evidence plus checksums:

```bash
python3 scripts/prepare_release_evidence.py \
  --artifact-root tmp/YOUR-RUN-local-matrix \
  --asset-dir "$release_assets" \
  --tag vVERSION \
  --expected-commit "$(git rev-parse 'vVERSION^{commit}')"
```

Inspect `SHA256SUMS` and the evidence archive, then upload only the newly
prepared files:

```bash
gh release upload vVERSION \
  "$release_assets"/unpin-vVERSION-provider-matrix-evidence.tar.gz \
  "$release_assets"/unpin-vVERSION-provider-matrix-evidence-manifest.json \
  "$release_assets"/SHA256SUMS \
  --repo IgorArkhipov/unpin
```

## Publish and verify

Confirm that private vulnerability reporting and immutable releases are enabled,
then publish the complete draft:

```bash
gh release edit vVERSION \
  --repo IgorArkhipov/unpin \
  --draft=false \
  --prerelease
```

After publication:

1. Download every asset and run `shasum -a 256 -c SHA256SUMS`.
2. Verify each archive:

   ```bash
   gh attestation verify unpin-vVERSION-TARGET.tar.gz \
     --repo IgorArkhipov/unpin
   ```

3. Extract each archive and run `unpin --version` and `unpin --help`.
4. Confirm the GitHub release is marked immutable.
5. Confirm the onboarding, security, changelog, and release links resolve.

Release evidence must never include raw live inventory, case directories,
backup payloads, audit logs, credentials, or private local paths.
