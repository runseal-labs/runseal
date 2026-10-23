# Releasing RunSeal

This document is the release contract for the RunSeal CLI and its downloadable
artifacts. It defines version and tag rules, the per-platform asset names, the
checksum format, stable/prerelease classification, and publication safety.

## Version source of truth

- `Cargo.toml` `[package].version` is the single source of truth for the
  release version.
- `Cargo.lock` must report the same version for the `runseal` package.
- The CLI reads the compiled version from `CARGO_PKG_VERSION`:
  `runseal --version` and `runseal version --json` cannot report a different
  version from `Cargo.toml`.
- `CHANGELOG.md` must contain exactly one `## <version> (YYYY-MM-DD)` section.
- `scripts/check-release.py` enforces these checks, the tag rule, the artifact
  matrix below, and the release workflow rules.

## Tag rules

- A release tag is exactly `v<version>`, for example `v0.2.1` or
  `v0.3.0-rc.1`.
- Versions use standard SemVer `X.Y.Z[-prerelease]`. Leading zeroes, shorthand
  versions such as `v1.2`, and SemVer build metadata (`+...`) are rejected.
- The tag must point at the commit whose `Cargo.toml` reports that version.
  The release workflow checks out the tag and validates the match before it
  builds anything.
- Tags are immutable. Do not move, delete, or re-create a published tag. A
  correction is a new patch version.

## Artifact contract

Each release publishes exactly these platform archives:

| Platform | Asset | Archive contents |
| --- | --- | --- |
| Windows x86_64 | `runseal-v<version>-windows-x86_64.zip` | `runseal.exe`, `runseal-windows-sandbox-setup.exe`, `runseal-command-runner.exe` |
| Windows arm64 | `runseal-v<version>-windows-arm64.zip` | the same three Windows executables |
| Linux x86_64 | `runseal-v<version>-linux-x86_64.tar.gz` | `runseal` |
| Linux aarch64 | `runseal-v<version>-linux-aarch64.tar.gz` | `runseal` |
| macOS x86_64 | `runseal-v<version>-macos-x86_64.tar.gz` | `runseal` |
| macOS arm64 | `runseal-v<version>-macos-arm64.tar.gz` | `runseal` |

The download URL is:

```text
https://github.com/runseal-labs/runseal/releases/download/v<version>/<asset>
```

Archives are flat: the expected executables are at the archive root, with no
wrapper directory. Unix archives contain one regular file. Windows archives
contain three regular files; all three helpers must stay beside `runseal.exe`.
Consumers should reject unexpected entries, symlinks, and missing helpers.

## Checksum contract

Every archive has a matching `<asset>.sha256` file containing exactly one line:

```text
<64 lowercase hexadecimal characters><two spaces><asset filename><LF>
```

Example for a hypothetical `1.2.3` release:

```text
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  runseal-v1.2.3-linux-x86_64.tar.gz
```

- Use two spaces between the digest and the file name.
- Do not include a path, an asterisk, a leading `./`, or extra lines.
- The trailing line feed is required by this contract.
- The Windows and Unix packaging steps must emit this identical format.

The aggregate `SHA256SUMS` asset lists the archives in `sha256sum` format and
does not list the per-asset `.sha256` files. The SBOM is published as
`runseal-v<version>-sbom.cdx.json` and is covered by the release attestations
rather than by `SHA256SUMS`.

Consumers must verify the archive digest against the sidecar before extraction.

## Release classes

- **Stable:** `vX.Y.Z`. The workflow creates the release with `--latest` and
  does not mark it prerelease.
- **Prerelease:** `vX.Y.Z-<prerelease>`. The workflow creates the release with
  `--prerelease` and must never mark it latest or let it become the `latest`
  release.
- **Draft:** a draft is not a public download target and must not be pinned by
  an installer. A draft becomes usable only after an explicit publication step.
  Do not treat a draft asset URL as a dependency.

The `latest` release must always be a stable, published release.

## Publication safety

The release workflow enforces these rules:

- Builds only a checked-out release tag and validates the tag against
  `Cargo.toml` before packaging.
- Runs `scripts/check-release.py --cli` in every package job so the built
  binary's plain version, structured version, and `runseal.protocol/v2` value
  are verified on the target platform before packaging.
- Creates a release with `--verify-tag`.
- Refuses to modify an existing release that is already published. Assets on a
  published release are immutable.
- Refuses to update an existing draft that already has assets. An empty draft
  may receive the build output, but it is never published implicitly.
- Never uses `--clobber`; there is no asset-replacement switch.
- Verifies every archive checksum before uploading.
- Uses a per-tag concurrency group so two runs cannot publish the same tag at
  the same time.

Never `--clobber` assets on a published release. To change the bytes, publish a
new version.

## Client pinning contract

Downloading clients must:

- Pin an exact version. Do not resolve `latest` or a mutable branch.
- Build the download URL from the pinned tag and the exact asset name above.
- Fetch `<asset>.sha256`, ensure the file name in the checksum matches the
  requested asset, compute the archive SHA-256, and compare lowercase hex.
- Extract only the expected flat files; reject directories, symlinks,
  traversal names, and missing helpers.
- Run `runseal --version` and require the exact pinned version.
- Run `runseal version --json` and require
  `"protocol_version": "runseal.protocol/v2"`.
- Treat HTTP 404, a draft-only release, or a checksum mismatch as an install
  failure, not as an invitation to fall back to `latest`.

Windows clients must install `runseal.exe`,
`runseal-windows-sandbox-setup.exe`, and `runseal-command-runner.exe` in the
same directory.

## Compatibility baseline

The RFC-0022 native control and terminal-identity contract required by current
native clients was added after the `v0.2.0` tag:

- The `v0.2.0` tag points at `8c18b10034be51c15d9fd02efded8d8594a3be9a`, which
  predates commits `3a1a74b` (configurable control descriptors) and `ee871b0`
  (terminal identity and native byte pipes). Its assets are not a compatible
  dependency for clients that require that contract.
- The `v0.1.x` line implements `runseal.protocol/v1` and is not compatible with
  v2 clients.
- `0.2.1` is the version prepared with the RFC-0022 contract. Clients that need
  it must pin `0.2.1` or later.

A version existing in this repository does not prove that a tag or downloadable
asset exists. Publication status must be verified from the release page or the
GitHub API before a client depends on it.

## Local verification

From the repository root:

```sh
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test --test release_contract
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/check-release.py --tag v0.2.1 --cli target/debug/runseal
git diff --check
```

`scripts/check-release.py` accepts `--root`, `--tag`, `--cli`, and
`--github-output`. It needs Python 3.11 or newer. `--cli` is optional and
verifies a built binary's plain and structured version output, including
`runseal.protocol/v2`. `scripts/test_check_release.py` covers the version/tag,
prerelease classification, lock/changelog mismatch, workflow guard, and CLI
checks without requiring a built binary.

## Release checklist

1. Update `Cargo.toml` and the `runseal` entry in `Cargo.lock` to the new
   version.
2. Add the matching `CHANGELOG.md` section.
3. Run the local verification commands above.
4. Commit the version change.
5. Create and push the immutable annotated tag `v<version>` after review.
6. Let the release workflow validate, build, package, checksum, attest, and
   publish the release. For a prerelease tag it must create a prerelease, not
   `latest`.
7. Verify the six archives, six `.sha256` sidecars, `SHA256SUMS`, and the SBOM
   on the published release.
8. Download one archive, verify its sidecar, run the binary, and confirm
   `runseal --version` and `runseal version --json` match the pinned release.

## Publication status snapshot

As of 2026-10-23:

- `v0.1.11` is the current `latest` release; it is protocol v1 and is not a
  compatible baseline.
- `v0.2.0` exists as a draft with assets; its tagged commit predates the
  RFC-0022 contract, so those assets are not a compatible baseline.
- The repository prepares `0.2.1`, but this change does not create a `v0.2.1`
  tag, draft, or downloadable assets. Until an external publication step
  completes, a client pinned to `0.2.1` will fail download acceptance with
  HTTP 404.
