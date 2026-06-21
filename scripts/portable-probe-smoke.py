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


def assert_fail_closed(system: str) -> None:
    command = shutil.which("python3") or shutil.which("python") or sys.executable
    with tempfile.TemporaryDirectory(prefix="runseal-portable-probe-") as cwd:
        _, payload = run_json(
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
                "print('must not run')",
            ],
            expect_success=False,
        )
    data = payload["error"]["data"]
    expected_backend = {
        "Linux": ("runseal-linux-community", "future-community", "linux"),
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
    assert_fail_closed(system)
    print("portable probe smoke ok")


if __name__ == "__main__":
    main()
