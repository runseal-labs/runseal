#!/usr/bin/env python3
"""Unit tests for scripts/check-release.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

SCRIPT_PATH = Path(__file__).resolve().with_name("check-release.py")
SPEC = importlib.util.spec_from_file_location("check_release", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
check_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_release)

WORKFLOW = """
suffix: windows-x86_64.zip
suffix: windows-arm64.zip
suffix: linux-x86_64.tar.gz
suffix: linux-aarch64.tar.gz
suffix: macos-x86_64.tar.gz
suffix: macos-arm64.tar.gz
--verify-tag
isDraft
--prerelease
--latest
python3 scripts/check-release.py --tag "$RELEASE_TAG" --cli target/release/runseal
runseal-${RELEASE_TAG}-
runseal-$($env:RELEASE_TAG)-
"""


def write_repo(
    root: Path,
    *,
    cargo_version: str = "0.2.1",
    lock_version: str | None = None,
    changelog_version: str | None = None,
    workflow: str = WORKFLOW,
) -> None:
    lock_version = cargo_version if lock_version is None else lock_version
    changelog_version = cargo_version if changelog_version is None else changelog_version
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        f'[package]\nname = "runseal"\nversion = "{cargo_version}"\n',
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text(
        f'version = 4\n\n[[package]]\nname = "runseal"\nversion = "{lock_version}"\n',
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(
        f"# RunSeal release notes\n\n## {changelog_version} (2026-10-23)\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "release.yml").write_text(
        workflow, encoding="utf-8"
    )


def run_check(root: Path, *arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = check_release.main(["--root", str(root), *arguments])
    return code, stdout.getvalue(), stderr.getvalue()


class CheckReleaseTests(unittest.TestCase):
    def test_stable_release_passes_and_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_repo(root)
            output = root / "github-output"
            code, stdout, stderr = run_check(
                root,
                "--tag",
                "v0.2.1",
                "--github-output",
                str(output),
            )
            self.assertEqual(code, 0, stderr)
            self.assertIn("version=0.2.1", stdout)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "version=0.2.1\nis_prerelease=false\n",
            )

    def test_prerelease_is_classified_and_never_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_repo(root, cargo_version="0.3.0-rc.1")
            output = root / "github-output"
            code, _, stderr = run_check(
                root,
                "--tag",
                "v0.3.0-rc.1",
                "--github-output",
                str(output),
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "version=0.3.0-rc.1\nis_prerelease=true\n",
            )

    def test_invalid_or_mismatched_tag_is_rejected(self) -> None:
        for tag in ("0.2.1", "v0.2.2", "v0.2", "v0.2.1+build.1"):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_repo(root)
                code, _, stderr = run_check(root, "--tag", tag)
                self.assertEqual(code, 1)
                self.assertIn("does not match Cargo package version", stderr)

    def test_build_metadata_in_cargo_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_repo(root, cargo_version="0.2.1+build.1")
            code, _, stderr = run_check(root, "--tag", "v0.2.1+build.1")
            self.assertEqual(code, 1)
            self.assertIn("build metadata", stderr)

    def test_lock_version_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_repo(root, lock_version="0.2.0")
            code, _, stderr = run_check(root, "--tag", "v0.2.1")
            self.assertEqual(code, 1)
            self.assertIn("Cargo.lock runseal version", stderr)

    def test_changelog_version_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_repo(root, changelog_version="0.2.0")
            code, _, stderr = run_check(root, "--tag", "v0.2.1")
            self.assertEqual(code, 1)
            self.assertIn("CHANGELOG.md has no", stderr)

    def test_workflow_platform_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_repo(
                root,
                workflow=WORKFLOW.replace("suffix: macos-arm64.tar.gz\n", ""),
            )
            code, _, stderr = run_check(root, "--tag", "v0.2.1")
            self.assertEqual(code, 1)
            self.assertIn("six-platform contract", stderr)

    def test_workflow_clobber_and_replacement_switch_are_rejected(self) -> None:
        for extra in ("\n# --clobber\n", "\nreplace_draft_assets: true\n"):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_repo(root, workflow=WORKFLOW + extra)
                code, _, stderr = run_check(root, "--tag", "v0.2.1")
                self.assertEqual(code, 1)
                self.assertIn("must not overwrite existing assets", stderr)

    def test_cli_version_and_json_protocol_are_checked(self) -> None:
        completed = [
            CompletedProcess([], 0, "0.2.1\n", ""),
            CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "runseal_version": "0.2.1",
                        "protocol_version": "runseal.protocol/v2",
                    }
                ),
                "",
            ),
        ]
        with mock.patch.object(check_release.subprocess, "run", side_effect=completed) as run:
            check_release.check_cli(Path("runseal"), "0.2.1")
        self.assertEqual(run.call_count, 2)

    def test_cli_version_mismatch_is_rejected(self) -> None:
        completed = [CompletedProcess([], 0, "0.2.0\n", "")]
        with (
            mock.patch.object(
                check_release.subprocess, "run", side_effect=completed
            ),
            self.assertRaisesRegex(check_release.ContractError, "expected '0.2.1'"),
        ):
            check_release.check_cli(Path("runseal"), "0.2.1")

    def test_cli_protocol_mismatch_is_rejected(self) -> None:
        completed = [
            CompletedProcess([], 0, "0.2.1\n", ""),
            CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "runseal_version": "0.2.1",
                        "protocol_version": "runseal.protocol/v1",
                    }
                ),
                "",
            ),
        ]
        with (
            mock.patch.object(
                check_release.subprocess, "run", side_effect=completed
            ),
            self.assertRaisesRegex(check_release.ContractError, "protocol_version"),
        ):
            check_release.check_cli(Path("runseal"), "0.2.1")


if __name__ == "__main__":
    unittest.main()
