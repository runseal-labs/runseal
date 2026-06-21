#!/usr/bin/env python3
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PROBES = {
    "Linux": [
        "landlock",
        "landlock_abi_version",
        "user_namespaces",
        "user_namespace_quota",
        "mount_namespaces",
        "pid_namespaces",
        "network_namespaces",
        "seccomp",
        "bubblewrap",
        "unprivileged_user_namespaces",
    ],
    "Darwin": [
        "sandbox_exec",
        "sandbox_exec_executable",
        "macos_version",
        "temporary_profile",
        "canonical_paths",
        "symlink_path_model",
    ],
}


def runseal_bin() -> Path:
    if os.environ.get("RUNSEAL_BIN"):
        return Path(os.environ["RUNSEAL_BIN"])
    exe = "runseal.exe" if platform.system() == "Windows" else "runseal"
    return Path(__file__).resolve().parents[1] / "target" / "debug" / exe


def run_json(args: list[str], expect_success: bool) -> tuple[int, dict]:
    result = subprocess.run(
        [str(runseal_bin()), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if expect_success and result.returncode != 0:
        raise SystemExit(f"runseal failed: {' '.join(args)}\n{result.stderr}")
    if not expect_success and result.returncode == 0:
        raise SystemExit(f"runseal unexpectedly succeeded: {' '.join(args)}")
    if result.stderr:
        raise SystemExit(f"runseal wrote stderr for JSON command: {result.stderr}")
    return result.returncode, json.loads(result.stdout)


def assert_probes(payload: dict, system: str) -> None:
    probes = payload.get("capability_probes")
    if not isinstance(probes, list):
        raise SystemExit("missing capability_probes")
    mechanisms = [probe.get("mechanism") for probe in probes]
    if mechanisms != PROBES[system]:
        raise SystemExit(f"unexpected probe mechanisms: {mechanisms}")
    for probe in probes:
        if probe.get("status") != "unsupported" or probe.get("diagnostic_only") is not True:
            raise SystemExit(f"probe is not diagnostic-only unsupported: {probe}")
        if not isinstance(probe.get("available"), bool):
            raise SystemExit(f"probe availability must be boolean: {probe}")


def probe_available(payload: dict, mechanism: str) -> bool:
    for probe in payload.get("capability_probes", []):
        if probe.get("mechanism") == mechanism:
            return bool(probe.get("available"))
    return False


def assert_linux_read_only(payload: dict) -> None:
    if payload.get("backend_status") != "experimental":
        raise SystemExit(f"unexpected Linux backend status: {payload}")
    if payload.get("sandbox_levels", {}).get("read-only") != "experimental":
        raise SystemExit(f"Linux read-only must be experimental: {payload}")
    if payload.get("network_modes", {}).get("disabled") != "experimental":
        raise SystemExit(f"Linux network.disabled must be experimental: {payload}")
    if payload.get("sandbox_levels", {}).get("workspace-write") != "experimental":
        raise SystemExit(f"Linux workspace-write must be experimental: {payload}")

    target = "read-only-write.txt"
    command = shutil.which("python3") or shutil.which("python") or sys.executable
    with tempfile.TemporaryDirectory(prefix="runseal-linux-read-only-") as cwd:
        write_target = Path(cwd) / target
        _, result = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "read-only",
                "--cwd",
                cwd,
                "--",
                command,
                "-c",
                f"from pathlib import Path; Path({str(write_target)!r}).write_text('blocked')",
            ],
            expect_success=probe_available(payload, "bubblewrap"),
        )
        if probe_available(payload, "bubblewrap"):
            if result.get("platform_plan", {}).get("enforcement") != "linux-experimental":
                raise SystemExit(f"unexpected Linux read-only plan: {result}")
            if result.get("exit_code") == 0 or write_target.exists():
                raise SystemExit(f"Linux read-only did not block workspace write: {result}")
            assert_linux_workspace_write(command)
            assert_linux_proxy_fail_closed(command)
        elif result.get("error", {}).get("data", {}).get("code") != "BACKEND_UNAVAILABLE":
            raise SystemExit(f"expected Linux backend unavailable without bubblewrap: {result}")


def assert_linux_workspace_write(command: str) -> None:
    with tempfile.TemporaryDirectory(prefix="runseal-linux-workspace-write-") as cwd:
        workspace = Path(cwd)
        inside = workspace / "inside.txt"
        outside = workspace.parent / "runseal-outside-write.txt"
        protected = workspace / ".git" / "blocked.txt"
        protected.parent.mkdir()
        _, result = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "workspace-write",
                "--network",
                "disabled",
                "--cwd",
                cwd,
                "--",
                command,
                "-c",
                f"from pathlib import Path; Path({str(inside)!r}).write_text('inside')",
            ],
            expect_success=True,
        )
        if result.get("platform_plan", {}).get("enforcement") != "linux-experimental":
            raise SystemExit(f"unexpected Linux workspace-write plan: {result}")
        if result.get("exit_code") != 0 or inside.read_text() != "inside":
            raise SystemExit(f"Linux workspace-write did not allow workspace write: {result}")
        for target in [outside, protected]:
            _, result = run_json(
                [
                    "exec",
                    "--json",
                    "--policy",
                    "workspace-write",
                    "--network",
                    "disabled",
                    "--cwd",
                    cwd,
                    "--",
                    command,
                    "-c",
                    f"from pathlib import Path; Path({str(target)!r}).write_text('blocked')",
                ],
                expect_success=True,
            )
            if result.get("exit_code") == 0 or target.exists():
                raise SystemExit(f"Linux workspace-write did not block write to {target}: {result}")
        assert_portable_workspace_contained_fail_closed("Linux", command)


def assert_linux_proxy_fail_closed(command: str) -> None:
    with tempfile.TemporaryDirectory(prefix="runseal-linux-proxy-") as cwd:
        _, payload = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "workspace-write",
                "--network",
                "proxy",
                "--cwd",
                cwd,
                "--",
                command,
                "-c",
                "print('must not run')",
            ],
            expect_success=False,
        )
    data = payload["error"]["data"]
    if data.get("code") != "BACKEND_CAPABILITY_MISSING" or data.get("support") != "unsupported":
        raise SystemExit(f"unexpected Linux proxy fail-closed error: {data}")
    backend = data.get("backend", {})
    if (
        backend.get("name"),
        backend.get("status"),
        backend.get("platform"),
    ) != ("runseal-linux-community", "experimental", "linux"):
        raise SystemExit(f"unexpected Linux backend details: {backend}")
    missing = data.get("missing_features", [])
    for feature in ["network_proxy", "managed_proxy"]:
        if feature not in missing:
            raise SystemExit(f"Linux proxy fail-closed missing feature {feature}: {data}")
    plan = data.get("platform_plan", {})
    if plan.get("cwd") != "workspace" or plan.get("runtime_root") != "runtime_root":
        raise SystemExit(f"Linux proxy fail-closed preview is not public-safe: {plan}")


def assert_macos_read_only(payload: dict) -> None:
    if payload.get("backend_status") != "experimental":
        raise SystemExit(f"unexpected macOS backend status: {payload}")
    if payload.get("sandbox_levels", {}).get("read-only") != "experimental":
        raise SystemExit(f"macOS read-only must be experimental: {payload}")
    if payload.get("sandbox_levels", {}).get("workspace-write") != "experimental":
        raise SystemExit(f"macOS workspace-write must be experimental: {payload}")
    if payload.get("network_modes", {}).get("disabled") != "experimental":
        raise SystemExit(f"macOS network.disabled must be experimental: {payload}")

    command = shutil.which("python3") or shutil.which("python") or sys.executable
    with tempfile.TemporaryDirectory(prefix="runseal-macos-read-only-") as cwd:
        write_target = Path(cwd) / "read-only-write.txt"
        _, result = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "read-only",
                "--cwd",
                cwd,
                "--",
                command,
                "-c",
                f"from pathlib import Path; Path({str(write_target)!r}).write_text('blocked')",
            ],
            expect_success=True,
        )
        if result.get("platform_plan", {}).get("enforcement") != "macos-experimental":
            raise SystemExit(f"unexpected macOS read-only plan: {result}")
        if result.get("exit_code") == 0 or write_target.exists():
            raise SystemExit(f"macOS read-only did not block workspace write: {result}")
        assert_macos_workspace_write(command)
        assert_portable_workspace_contained_fail_closed("Darwin", command)
        assert_fail_closed("Darwin")


def assert_macos_workspace_write(command: str) -> None:
    with tempfile.TemporaryDirectory(prefix="runseal-macos-workspace-write-") as cwd:
        workspace = Path(cwd)
        inside = workspace / "inside.txt"
        outside = workspace.parent / "runseal-macos-outside-write.txt"
        protected = workspace / ".git" / "blocked.txt"
        protected.parent.mkdir()
        _, result = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "workspace-write",
                "--network",
                "disabled",
                "--cwd",
                cwd,
                "--",
                command,
                "-c",
                f"from pathlib import Path; Path({str(inside)!r}).write_text('inside')",
            ],
            expect_success=True,
        )
        if result.get("platform_plan", {}).get("enforcement") != "macos-experimental":
            raise SystemExit(f"unexpected macOS workspace-write plan: {result}")
        if result.get("exit_code") != 0 or inside.read_text() != "inside":
            raise SystemExit(f"macOS workspace-write did not allow workspace write: {result}")
        for target in [outside, protected]:
            _, result = run_json(
                [
                    "exec",
                    "--json",
                    "--policy",
                    "workspace-write",
                    "--network",
                    "disabled",
                    "--cwd",
                    cwd,
                    "--",
                    command,
                    "-c",
                    f"from pathlib import Path; Path({str(target)!r}).write_text('blocked')",
                ],
                expect_success=True,
            )
            if result.get("exit_code") == 0 or target.exists():
                raise SystemExit(f"macOS workspace-write did not block write to {target}: {result}")


def assert_portable_workspace_contained_fail_closed(system: str, command: str) -> None:
    with tempfile.TemporaryDirectory(prefix="runseal-portable-contained-") as cwd:
        _, payload = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "workspace-contained",
                "--network",
                "disabled",
                "--cwd",
                cwd,
                "--",
                command,
                "-c",
                "print('must not run')",
            ],
            expect_success=False,
        )
    data = payload["error"]["data"]
    expected_backend = {
        "Darwin": ("runseal-macos-experimental", "experimental", "macos"),
        "Linux": ("runseal-linux-community", "experimental", "linux"),
    }[system]
    if data.get("code") != "BACKEND_CAPABILITY_MISSING" or data.get("support") != "unsupported":
        raise SystemExit(f"unexpected workspace-contained fail-closed error: {data}")
    backend = data.get("backend", {})
    if (backend.get("name"), backend.get("status"), backend.get("platform")) != expected_backend:
        raise SystemExit(f"unexpected workspace-contained backend details: {backend}")
    plan = data.get("platform_plan", {})
    if plan.get("cwd") != "workspace" or plan.get("runtime_root") != "runtime_root":
        raise SystemExit(f"workspace-contained preview is not public-safe: {plan}")


def assert_fail_closed(system: str) -> None:
    command = shutil.which("python3") or shutil.which("python") or sys.executable
    with tempfile.TemporaryDirectory(prefix="runseal-portable-probe-") as cwd:
        _, payload = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "workspace-write" if system == "Darwin" else "read-only",
                "--cwd",
                cwd,
                "--",
                command,
                "-c",
                "print('must not run')",
            ],
            expect_success=False,
        )
    data = payload["error"]["data"]
    expected_backend = {
        "Darwin": ("runseal-macos-experimental", "experimental", "macos"),
    }[system]
    if data.get("code") != "BACKEND_CAPABILITY_MISSING" or data.get("support") != "unsupported":
        raise SystemExit(f"unexpected fail-closed error: {data}")
    backend = data.get("backend", {})
    if (backend.get("name"), backend.get("status"), backend.get("platform")) != expected_backend:
        raise SystemExit(f"unexpected backend details: {backend}")
    plan = data.get("platform_plan", {})
    if plan.get("cwd") != "workspace" or plan.get("runtime_root") != "runtime_root":
        raise SystemExit(f"portable fail-closed preview is not public-safe: {plan}")


def main() -> None:
    system = platform.system()
    if system not in PROBES:
        print(f"portable probe smoke skipped on {system}")
        return
    if not runseal_bin().exists():
        raise SystemExit(f"RunSeal binary not found: {runseal_bin()}")
    _, capabilities = run_json(["capabilities"], expect_success=True)
    assert_probes(capabilities, system)
    if system == "Linux":
        assert_linux_read_only(capabilities)
    else:
        assert_macos_read_only(capabilities)
    print("portable probe smoke ok")


if __name__ == "__main__":
    main()
