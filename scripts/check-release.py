#!/usr/bin/env python3
"""Validate RunSeal release version and artifact-contract consistency.

This script is dependency-free (Python 3.11+) and is used by
`.github/workflows/release.yml` before any release artifact is built. It can
also be run locally before creating a tag.

It checks:

- `Cargo.toml` package version is release SemVer (`X.Y.Z[-prerelease]`).
- `Cargo.lock` reports the same version for the `runseal` package.
- `CHANGELOG.md` has exactly one heading for that version.
- The release tag, when supplied, is exactly `v<version>`.
- `.github/workflows/release.yml` keeps the six stable platform suffixes and
  the immutable-release / prerelease classification rules.
- A built `runseal` binary, when supplied, reports the same version and
  `runseal.protocol/v2`.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

PLATFORM_SUFFIXES = (
    "windows-x86_64.zip",
    "windows-arm64.zip",
    "linux-x86_64.tar.gz",
    "linux-aarch64.tar.gz",
    "macos-x86_64.tar.gz",
    "macos-arm64.tar.gz",
)

SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?$"
)

WORKFLOW_TOKENS = (
    "runseal-${RELEASE_TAG}-",
    "runseal-$($env:RELEASE_TAG)-",
    "--verify-tag",
    "isDraft",
    "--prerelease",
    "--latest",
    "check-release.py",
    "--cli",
)

FORBIDDEN_WORKFLOW_TOKENS = ("--clobber", "replace_draft_assets")


class ContractError(Exception):
    """Raised when the repository does not satisfy the release contract."""


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise ContractError(f"cannot read {path}: {error}") from error


def load_toml(path: Path) -> dict:
    try:
        return tomllib.loads(read_text(path))
    except tomllib.TOMLDecodeError as error:
        raise ContractError(f"invalid TOML in {path}: {error}") from error


def check_version(version: str, tag: str | None) -> bool:
    if not isinstance(version, str):
        raise ContractError("Cargo package version is missing")
    if "+" in version:
        raise ContractError(
            "release versions must not use SemVer build metadata; use a prerelease suffix instead"
        )
    if not SEMVER_RE.fullmatch(version):
        raise ContractError(
            f"Cargo package version '{version}' is not release SemVer (X.Y.Z[-prerelease])"
        )

    prerelease = "-" in version
    if tag is not None:
        expected = f"v{version}"
        if tag != expected:
            raise ContractError(
                f"release tag '{tag}' does not match Cargo package version; expected '{expected}'"
            )
    return prerelease


def check_lock(lock: dict, version: str) -> None:
    packages = [
        package for package in lock.get("package", []) if package.get("name") == "runseal"
    ]
    if len(packages) != 1:
        raise ContractError(
            f"Cargo.lock must contain exactly one runseal package; found {len(packages)}"
        )
    locked = packages[0].get("version")
    if locked != version:
        raise ContractError(
            f"Cargo.lock runseal version is '{locked}', expected '{version}'"
        )


def check_changelog(changelog: str, version: str) -> None:
    heading = re.compile(rf"^## {re.escape(version)}(?: \(|$)", re.MULTILINE)
    matches = heading.findall(changelog)
    if not matches:
        raise ContractError(f"CHANGELOG.md has no '## {version} (...)' section")
    if len(matches) != 1:
        raise ContractError(f"CHANGELOG.md has {len(matches)} sections for {version}")


def check_workflow(workflow: str) -> None:
    suffixes = re.findall(r"^[ \t]*suffix:[ \t]*(\S+)[ \t]*$", workflow, re.MULTILINE)
    if len(suffixes) != len(PLATFORM_SUFFIXES) or set(suffixes) != set(PLATFORM_SUFFIXES):
        raise ContractError(
            "release workflow platform suffixes differ from the documented six-platform contract: "
            f"found {sorted(set(suffixes))}"
        )
    missing = [token for token in WORKFLOW_TOKENS if token not in workflow]
    if missing:
        raise ContractError(
            "release workflow is missing immutable-release or prerelease rules: "
            + ", ".join(missing)
        )
    forbidden = [token for token in FORBIDDEN_WORKFLOW_TOKENS if token in workflow]
    if forbidden:
        raise ContractError(
            "release workflow must not overwrite existing assets: "
            + ", ".join(forbidden)
        )
    if "runseal-v" in workflow:
        raise ContractError(
            "release workflow must derive asset names from RELEASE_TAG, not hard-code a version"
        )


def check_cli(cli: Path, version: str) -> None:
    try:
        plain = subprocess.run(
            [str(cli), "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ContractError(f"cannot run {cli} --version: {error}") from error
    if plain.returncode != 0:
        raise ContractError(
            f"{cli} --version failed with exit code {plain.returncode}: {plain.stderr.strip()}"
        )
    actual = plain.stdout.strip()
    if actual != version:
        raise ContractError(
            f"built binary reports '{actual}' from --version, expected '{version}'"
        )

    try:
        structured = subprocess.run(
            [str(cli), "version", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ContractError(f"cannot run {cli} version --json: {error}") from error
    if structured.returncode != 0:
        raise ContractError(
            f"{cli} version --json failed with exit code {structured.returncode}: "
            f"{structured.stderr.strip()}"
        )
    try:
        payload = json.loads(structured.stdout)
    except json.JSONDecodeError as error:
        raise ContractError(f"{cli} version --json did not return JSON: {error}") from error
    if payload.get("runseal_version") != version:
        raise ContractError(
            f"built binary reports runseal_version "
            f"'{payload.get('runseal_version')}', expected '{version}'"
        )
    if payload.get("protocol_version") != "runseal.protocol/v2":
        raise ContractError(
            f"built binary reports protocol_version "
            f"'{payload.get('protocol_version')}', expected 'runseal.protocol/v2'"
        )


def write_github_output(path: Path, version: str, prerelease: bool) -> None:
    try:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"version={version}\n")
            handle.write(f"is_prerelease={'true' if prerelease else 'false'}\n")
    except OSError as error:
        raise ContractError(f"cannot write GitHub output {path}: {error}") from error


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate RunSeal release version and artifact contract consistency."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of this script)",
    )
    parser.add_argument("--tag", help="release tag, for example v0.2.1")
    parser.add_argument("--cli", type=Path, help="optional built runseal binary to verify")
    parser.add_argument(
        "--github-output",
        type=Path,
        help="optional file to append version and is_prerelease GitHub outputs",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        cargo = load_toml(root / "Cargo.toml")
        package = cargo.get("package")
        if not isinstance(package, dict) or "version" not in package:
            raise ContractError("Cargo.toml has no [package].version")
        version = package["version"]
        prerelease = check_version(version, args.tag)

        check_lock(load_toml(root / "Cargo.lock"), version)
        check_changelog(read_text(root / "CHANGELOG.md"), version)
        check_workflow(read_text(root / ".github" / "workflows" / "release.yml"))
        if args.cli is not None:
            check_cli(args.cli.resolve(), version)
        if args.github_output is not None:
            write_github_output(args.github_output, version, prerelease)
    except ContractError as error:
        print(f"release contract error: {error}", file=sys.stderr)
        return 1

    print(
        f"release contract ok: version={version} "
        f"is_prerelease={'true' if prerelease else 'false'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
