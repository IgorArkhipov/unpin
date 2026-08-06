# Unpin desktop workbench

Unpin `1.0.0` is the first stable macOS desktop release. It ships as
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
  unpin-desktop-v1.0.0-TARGET.tar.gz \
  --repo IgorArkhipov/unpin
```

Do not continue if either verification fails.

## Install and open

Extract the archive and move `UnpinDesktop.app` to `/Applications` or
`~/Applications`:

```bash
tar -xzf unpin-desktop-v1.0.0-TARGET.tar.gz
open unpin-desktop-v1.0.0-TARGET
```

The release is ad-hoc signed with Hardened Runtime. It is not
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

## Use the workbench guidance

Each work area starts with a collapsible primer that explains its task and the
result to expect. Primer disclosure is stored independently for Discover and
Organize, Govern and Automate, Change Safely, and Recover and Audit. The app
also explains no-workspace, loading, blocked, prerequisite, empty-evidence, and
selection states next to one safe action when one is available.

Guidance does not run CLI commands, call MCP tools, apply changes, or approve a
restore. Govern handoffs are selectable and copyable; Change Safely and Recover
and Audit continue to use the existing plan, approval, backup, recovery, and
restore boundaries. Choose Light or Dark from the title bar appearance control.

## Regenerate the guidance matrix

Maintainers can capture the 26 authoritative workbench scenarios in both Light
and Dark at the default 1180 by 760 window size:

```bash
python3 scripts/test_run_desktop_guidance_matrix.py
python3 scripts/run_desktop_guidance_matrix.py
```

The capture command creates a timestamped directory below repository `tmp/`
with 52 native PNG files, `manifest.json`, `report.md`, and `SHA256SUMS`. The
ordinary Xcode test action skips file capture when the matrix environment is
absent, while still exercising the compact 1040 by 720 render assertions.

After reviewing every scenario in both themes against the macOS design system,
record the result through the same script so the report and manifest retain the
review evidence:

```bash
python3 scripts/run_desktop_guidance_matrix.py \
  --output-dir tmp/YYYY-MM-DD-HHMMSS-desktop-first-run-guidance-matrix \
  --record-review passed \
  --review-notes "All scenarios are readable and visually consistent in Light and Dark."
```

## Update

Updates are manual in `1.0.0`:

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

## Distribution limitations

- No Developer ID signature or Apple notarization.
- No automatic update mechanism; replacement is manual.
- No Windows, Linux, or universal macOS desktop bundle.
- Profiles, gateways, sessions, and hooks remain on CLI, TUI, and MCP surfaces.
- The stable `1.0.0` release uses a maintainer-approved unsigned-GA exception.
  Gatekeeper trust is not claimed; checksum and attestation verification plus
  the documented first-launch override remain required.
