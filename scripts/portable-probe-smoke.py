#!/usr/bin/env python3
import json
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
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
        if probe.get("status") not in {"experimental", "unavailable", "unsupported"}:
            raise SystemExit(f"unexpected diagnostic probe status: {probe}")
        if probe.get("diagnostic_only") is not True:
            raise SystemExit(f"probe is not diagnostic-only: {probe}")
        if not isinstance(probe.get("available"), bool):
            raise SystemExit(f"probe availability must be boolean: {probe}")
        if (
            system == "Linux"
            and probe.get("mechanism") == "landlock_abi_version"
            and probe.get("available") is True
        ):
            abi_version = probe.get("details", {}).get("abi_version")
            if not isinstance(abi_version, int) or abi_version <= 0:
                raise SystemExit(f"Landlock ABI probe must report a positive ABI version: {probe}")


def probe_available(payload: dict, mechanism: str) -> bool:
    for probe in payload.get("capability_probes", []):
        if probe.get("mechanism") == mechanism:
            return bool(probe.get("available"))
    return False


def assert_network_disabled_blocks_direct_egress(system: str, command: str) -> None:
    policy = "workspace-write"
    with tempfile.TemporaryDirectory(prefix="runseal-network-disabled-") as cwd:
        _, result = run_json(
            [
                "exec",
                "--json",
                "--policy",
                policy,
                "--network",
                "disabled",
                "--cwd",
                cwd,
                "--",
                command,
                "-c",
                "import socket; socket.create_connection(('1.1.1.1', 53), timeout=0.5); print('direct-network-ok')",
            ],
            expect_success=True,
        )
    expected_enforcement = {
        "Darwin": "macos-experimental",
        "Linux": "linux-experimental",
    }[system]
    if result.get("platform_plan", {}).get("enforcement") != expected_enforcement:
        raise SystemExit(f"unexpected network.disabled plan: {result}")
    if result.get("exit_code") == 0 or "direct-network-ok" in result.get("stdout", ""):
        raise SystemExit(f"{system} network.disabled allowed direct egress: {result}")


def assert_linux_read_only(payload: dict) -> None:
    if payload.get("backend_status") != "experimental":
        raise SystemExit(f"unexpected Linux backend status: {payload}")
    if payload.get("sandbox_levels", {}).get("read-only") != "supported":
        raise SystemExit(f"Linux read-only must be supported: {payload}")
    if payload.get("network_modes", {}).get("disabled") != "supported":
        raise SystemExit(f"Linux network.disabled must be supported: {payload}")
    if payload.get("sandbox_levels", {}).get("workspace-write") != "supported":
        raise SystemExit(f"Linux workspace-write must be supported: {payload}")
    if payload.get("sandbox_levels", {}).get("workspace-contained") != "supported":
        raise SystemExit(f"Linux workspace-contained must be supported: {payload}")
    if payload.get("network_modes", {}).get("proxy") != "supported":
        raise SystemExit(f"Linux network.proxy must be supported: {payload}")
    for feature in ["network_proxy", "managed_proxy"]:
        if payload.get("features", {}).get(feature) is not True:
            raise SystemExit(f"Linux {feature} must be available: {payload}")
        if payload.get("feature_statuses", {}).get(feature) != "experimental":
            raise SystemExit(f"Linux {feature} must remain experimental: {payload}")

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
            assert_network_disabled_blocks_direct_egress("Linux", command)
            for policy in ["read-only", "workspace-write", "workspace-contained"]:
                assert_portable_proxy("Linux", "linux-experimental", policy, command)
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
        assert_portable_workspace_contained("Linux")


def assert_macos_read_only(payload: dict) -> None:
    if payload.get("backend_status") != "experimental":
        raise SystemExit(f"unexpected macOS backend status: {payload}")
    if payload.get("sandbox_levels", {}).get("read-only") != "supported":
        raise SystemExit(f"macOS read-only must be supported: {payload}")
    if payload.get("sandbox_levels", {}).get("workspace-write") != "supported":
        raise SystemExit(f"macOS workspace-write must be supported: {payload}")
    if payload.get("sandbox_levels", {}).get("workspace-contained") != "supported":
        raise SystemExit(f"macOS workspace-contained must be supported: {payload}")
    if payload.get("network_modes", {}).get("disabled") != "supported":
        raise SystemExit(f"macOS network.disabled must be supported: {payload}")
    if payload.get("network_modes", {}).get("proxy") != "supported":
        raise SystemExit(f"macOS network.proxy must be supported: {payload}")
    for feature in ["network_proxy", "managed_proxy"]:
        if payload.get("features", {}).get(feature) is not True:
            raise SystemExit(f"macOS {feature} must be available: {payload}")
        if payload.get("feature_statuses", {}).get(feature) != "experimental":
            raise SystemExit(f"macOS {feature} must remain experimental: {payload}")

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
        assert_network_disabled_blocks_direct_egress("Darwin", command)
        assert_portable_workspace_contained("Darwin")
        for policy in ["read-only", "workspace-write", "workspace-contained"]:
            assert_portable_proxy("macOS", "macos-experimental", policy, command)


def assert_portable_proxy(system: str, enforcement: str, policy: str, command: str) -> None:
    contained_command = "/usr/bin/python3"
    proxy_command = contained_command if Path(contained_command).exists() else command
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    port = listener.getsockname()[1]
    server_result: list[object] = []

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                request = connection.recv(4096)
                if not request.startswith(b"GET /proxy-ok HTTP/1.1"):
                    raise RuntimeError(f"unexpected proxy request: {request!r}")
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nproxy-ok"
                )
            server_result.append(True)
        except Exception as exc:
            server_result.append(exc)
        finally:
            listener.close()

    server = threading.Thread(target=serve)
    server.start()
    code = "\n".join(
        [
            "import os, socket, urllib.parse",
            "proxy = urllib.parse.urlparse(os.environ['HTTP_PROXY'])",
            "auth = os.environ['RUNSEAL_NETWORK_PROXY_AUTHORIZATION']",
            f"request = b'GET http://127.0.0.1:{port}/proxy-ok HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\nProxy-Authorization: ' + auth.encode('ascii') + b'\\r\\nConnection: close\\r\\n\\r\\n'",
            "with socket.create_connection((proxy.hostname, proxy.port), timeout=2) as stream:",
            "    stream.sendall(request)",
            "    response = b''",
            "    while True:",
            "        chunk = stream.recv(4096)",
            "        if not chunk:",
            "            break",
            "        response += chunk",
            "assert b'proxy-ok' in response, response",
            "print('managed-proxy-ok')",
        ]
    )
    with tempfile.TemporaryDirectory(prefix="runseal-portable-proxy-") as cwd:
        _, result = run_json(
            [
                "exec",
                "--json",
                "--policy",
                policy,
                "--network",
                "proxy",
                "--cwd",
                cwd,
                "--",
                proxy_command,
                "-c",
                code,
            ],
            expect_success=True,
        )
        _, direct = run_json(
            [
                "exec",
                "--json",
                "--policy",
                policy,
                "--network",
                "proxy",
                "--cwd",
                cwd,
                "--",
                proxy_command,
                "-c",
                "import socket; socket.create_connection(('1.1.1.1', 53), timeout=0.5); print('direct-network-ok')",
            ],
            expect_success=True,
        )
    server.join(timeout=12)
    if server.is_alive() or server_result != [True]:
        raise SystemExit(
            f"{system} {policy} managed proxy did not reach upstream: "
            f"{server_result}; result={result}"
        )
    plan = result.get("platform_plan", {})
    if (
        result.get("exit_code") != 0
        or "managed-proxy-ok" not in result.get("stdout", "")
        or plan.get("enforcement") != enforcement
        or plan.get("network", {}).get("managed_proxy") != "required"
    ):
        raise SystemExit(f"{system} {policy} managed proxy execution failed: {result}")
    if direct.get("exit_code") == 0 or "direct-network-ok" in direct.get("stdout", ""):
        raise SystemExit(f"{system} {policy} proxy mode allowed direct egress: {direct}")


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


def assert_portable_workspace_contained(system: str) -> None:
    expected_enforcement = {
        "Darwin": "macos-experimental",
        "Linux": "linux-experimental",
    }[system]
    with tempfile.TemporaryDirectory(prefix="runseal-portable-contained-") as root:
        root_path = Path(root)
        workspace = root_path / "workspace"
        workspace.mkdir()
        outside = root_path / "outside-secret.txt"
        outside.write_text("outside-secret")
        outside_write = root_path / "outside-write.txt"
        inside = workspace / "inside.txt"

        script = (
            f"test ! -r {shlex.quote(str(outside))} && "
            f"! printf escaped > {shlex.quote(str(outside_write))} && "
            f"printf inside > {shlex.quote(str(inside))}"
        )
        _, result = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "workspace-contained",
                "--network",
                "disabled",
                "--cwd",
                str(workspace),
                "--",
                "/bin/sh",
                "-c",
                script,
            ],
            expect_success=True,
        )
        if result.get("platform_plan", {}).get("enforcement") != expected_enforcement:
            raise SystemExit(f"unexpected workspace-contained plan: {result}")
        if result.get("exit_code") != 0 or inside.read_text() != "inside":
            raise SystemExit(f"{system} workspace-contained boundary failed: {result}")
        if outside_write.exists():
            raise SystemExit(f"{system} workspace-contained allowed external write: {result}")

        escape = workspace / "escape"
        escape.symlink_to(root_path, target_is_directory=True)
        _, result = run_json(
            [
                "exec",
                "--json",
                "--policy",
                "workspace-contained",
                "--network",
                "disabled",
                "--cwd",
                str(workspace),
                "--",
                "/bin/sh",
                "-c",
                "cat escape/outside-secret.txt",
            ],
            expect_success=True,
        )
        if result.get("exit_code") == 0 or "outside-secret" in result.get("stdout", ""):
            raise SystemExit(f"{system} workspace-contained allowed symlink escape: {result}")


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
