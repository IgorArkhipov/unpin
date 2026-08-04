# Unpin desktop workbench

Unpin `1.0.0-rc.1` is the first macOS desktop release candidate. It ships as
separate native archives for Apple Silicon and Intel Macs. The app supervises
the bundled `unpin` executable over stdio; SwiftUI does not write provider
configuration or receive Unpin's secret keys.

## Choose and verify an archive

Use `aarch64-apple-darwin` on Apple Silicon and `x86_64-apple-darwin` on an
Intel Mac. Download the matching desktop archive, `SHA256SUMS`, and release
assets from GitHub Releases. Verify the complete checksum set from the download
directory, then verify the selected archive's GitHub build provenance:

```bash
shasum -a 256 -c SHA256SUMS
gh attestation verify \
  unpin-desktop-v1.0.0-rc.1-TARGET.tar.gz \
  --repo IgorArkhipov/unpin
```

Do not continue if either verification fails.

## Install and open

Extract the archive and move `UnpinDesktop.app` to `/Applications` or
`~/Applications`:

```bash
tar -xzf unpin-desktop-v1.0.0-rc.1-TARGET.tar.gz
open unpin-desktop-v1.0.0-rc.1-TARGET
```

The release candidate is ad-hoc signed with Hardened Runtime. It is not
Developer ID signed or Apple-notarized, so ad-hoc signing does not establish
Gatekeeper trust. On first launch, macOS can report that Apple cannot verify
the developer.

After the checksum and attestation pass, use Finder to Control-click
`UnpinDesktop.app`, choose **Open**, and confirm **Open**. Alternatively, after
one blocked launch, use **System Settings > Privacy & Security > Open Anyway**.
Do not disable Gatekeeper and do not remove quarantine metadata with `xattr`.
If macOS reports that the app is damaged or that its signature is invalid,
stop and download the archive again.

At launch, select the repository workspace to manage. The app passes exactly
that folder to its bundled bridge and does not infer a repository from the app
bundle.

## Update

Updates are manual in `1.0.0-rc.1`:

1. Download the new architecture-matched desktop archive and its release
   checksum file.
2. Verify the checksum and GitHub attestation.
3. Quit Unpin Desktop.
4. Replace the existing `UnpinDesktop.app` in `/Applications` or
   `~/Applications` with the newly extracted bundle.
5. Open the replacement and confirm its version in the release details.

Do not copy a new `unpin` binary into the app bundle. The app verifies its
bundled bridge against the signed release manifest and requires an exact
version match.

## Uninstall

Quit Unpin Desktop and move `UnpinDesktop.app` to Trash. That removes the app
and its bundled bridge.

An ordinary desktop uninstall intentionally leaves the standalone CLI and the
shared Unpin state under `~/.config/unpin` untouched. That directory can hold
group definitions, authenticated backup evidence, audit records, and recovery
state used by CLI, TUI, or MCP workflows. Removing it is a separate destructive
full reset, not part of uninstalling the app.

## Release-candidate limitations

- No Developer ID signature or Apple notarization.
- No automatic update mechanism; replacement is manual.
- No Windows, Linux, or universal macOS desktop bundle.
- Profiles, gateways, sessions, and hooks remain on CLI, TUI, and MCP surfaces.
- GA `1.0.0` remains blocked on signed, notarized distribution and installed-
  artifact verification.
