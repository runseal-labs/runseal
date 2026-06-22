#!/usr/bin/env python3
"""
RunSeal stdio JSON-RPC third-party integration example.

This script intentionally uses only the Python standard library.

It demonstrates:
- launching `runseal service --stdio`
- calling getVersion/getCapabilities/getServiceStatus/getSetupStatus
- failing closed when the requested sandbox capability or setup is unavailable
- executing a path-qualified command
- handling interleaved JSON-RPC event notifications before the final response
- replaying execution events with subscribeEvents
- retrieving audit events with getAuditEvents
- releasing service session state with disposeSession
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any


JsonObject = dict[str, Any]


class RunSealError(RuntimeError):
    pass


class RunSealClient:
    def __init__(self, runseal_bin: str) -> None:
        self._next_id = 1
        self._proc = subprocess.Popen(
            [runseal_bin, "service", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

        if self._proc.stdin is None or self._proc.stdout is None:
            raise RunSealError("failed to open RunSeal stdio pipes")

    def close(self) -> None:
        if self._proc.stdin is not None and not self._proc.stdin.closed:
            self._proc.stdin.close()

        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired as exc:
            self._proc.kill()
            raise RunSealError("RunSeal service did not exit after stdin closed") from exc

        if self._proc.returncode != 0:
            stderr = self._read_stderr()
            raise RunSealError(
                f"RunSeal service exited with code {self._proc.returncode}: {stderr}"
            )

    def call(
        self,
        method: str,
        params: JsonObject | None = None,
    ) -> tuple[list[JsonObject], JsonObject]:
        if self._proc.poll() is not None:
            raise RunSealError(
                f"RunSeal service already exited with code {self._proc.returncode}: "
                f"{self._read_stderr()}"
            )

        request_id = self._next_id
        self._next_id += 1

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        assert self._proc.stdin is not None
        assert self._proc.stdout is not None

        self._proc.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self._proc.stdin.flush()

        notifications: list[JsonObject] = []

        while True:
            line = self._proc.stdout.readline()
            if line == "":
                raise RunSealError(
                    "RunSeal service closed stdout before returning a response: "
                    f"{self._read_stderr()}"
                )

            message = json.loads(line)

            if message.get("method") == "event":
                params_value = message.get("params")
                if isinstance(params_value, dict):
                    notifications.append(params_value)
                continue

            if message.get("id") != request_id:
                raise RunSealError(f"unexpected JSON-RPC message: {message}")

            if "error" in message:
                raise RunSealError(json.dumps(message["error"], indent=2, sort_keys=True))

            result = message.get("result")
            if not isinstance(result, dict):
                raise RunSealError(f"JSON-RPC result must be an object: {message}")

            return notifications, result

    def _read_stderr(self) -> str:
        if self._proc.stderr is None:
            return ""
        try:
            return self._proc.stderr.read().strip()
        except OSError:
            return ""


def require_status(
    actual: Any,
    *,
    field: str,
    requested: str,
    allow_experimental: bool,
) -> None:
    accepted = {"supported"}
    if allow_experimental:
        accepted.add("experimental")

    if actual not in accepted:
        allowed = "supported or experimental" if allow_experimental else "supported"
        raise RunSealError(
            f"{field}.{requested} must be {allowed}; got {actual!r}. "
            "Refusing to run instead of silently downgrading."
        )


def gate_execution(
    *,
    capabilities: JsonObject,
    setup_status: JsonObject,
    policy: str,
    network_mode: str,
    allow_experimental: bool,
) -> None:
    sandbox_levels = capabilities.get("sandbox_levels", {})

    if not isinstance(sandbox_levels, dict):
        raise RunSealError("getCapabilities result is missing sandbox_levels")

    require_status(
        sandbox_levels.get(policy),
        field="sandbox_levels",
        requested=policy,
        allow_experimental=allow_experimental,
    )

    # Setup readiness is relevant for sandboxed execution. Do not require setup
    # or network capability for explicit local unsandboxed execution.
    if policy != "danger-full-access":
        network_modes = capabilities.get("network_modes", {})
        if not isinstance(network_modes, dict):
            raise RunSealError("getCapabilities result is missing network_modes")

        require_status(
            network_modes.get(network_mode),
            field="network_modes",
            requested=network_mode,
            allow_experimental=allow_experimental,
        )

        if setup_status.get("requires_setup"):
            next_action = setup_status.get("next_action")
            next_command = setup_status.get("next_command")
            raise RunSealError(
                "RunSeal sandbox setup is not ready. "
                f"next_action={next_action!r} next_command={next_command!r}"
            )


def print_json(label: str, value: Any) -> None:
    print(f"\n== {label} ==")
    print(json.dumps(value, indent=2, sort_keys=True))


def example_command() -> list[str]:
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        return [
            str(Path(system_root) / "System32" / "cmd.exe"),
            "/c",
            "echo runseal third-party integration ok",
        ]
    return ["/bin/sh", "-c", "printf '%s\\n' 'runseal third-party integration ok'"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="RunSeal stdio JSON-RPC third-party integration example"
    )
    parser.add_argument(
        "--runseal",
        default=os.environ.get("RUNSEAL_BIN", "runseal"),
        help="Path to the runseal binary. Defaults to RUNSEAL_BIN or 'runseal'.",
    )
    parser.add_argument(
        "--cwd",
        default=os.getcwd(),
        help="Workspace cwd for the execution request.",
    )
    parser.add_argument(
        "--policy",
        default="workspace-write",
        help="Sandbox policy to request. Defaults to workspace-write.",
    )
    parser.add_argument(
        "--network",
        default="disabled",
        help="Network mode to request. Defaults to disabled.",
    )
    parser.add_argument(
        "--allow-experimental",
        action="store_true",
        help="Allow capabilities reported as experimental. Defaults to fail-closed.",
    )
    args = parser.parse_args()

    cwd = str(Path(args.cwd).resolve())

    client = RunSealClient(args.runseal)
    try:
        _, version = client.call("getVersion")
        print_json("version", version)

        _, capabilities = client.call("getCapabilities")
        print_json("capabilities", capabilities)

        _, service_status = client.call("getServiceStatus")
        print_json("service_status", service_status)

        _, setup_status = client.call("getSetupStatus", {"cwd": cwd})
        print_json("setup_status", setup_status)

        gate_execution(
            capabilities=capabilities,
            setup_status=setup_status,
            policy=args.policy,
            network_mode=args.network,
            allow_experimental=args.allow_experimental,
        )

        execute_events, execution = client.call(
            "execute",
            {
                # RunSeal requires command[0] to be path-qualified.
                "command": example_command(),
                "cwd": cwd,
                "policy": args.policy,
                "network": {"mode": args.network},
                "metadata": {
                    "example": "stdio-json-rpc",
                    "client": "third-party",
                },
            },
        )

        print_json("execute_result", execution)
        print_json(
            "execute_event_types",
            [event.get("type") for event in execute_events],
        )

        execution_id = execution.get("execution_id")
        session_id = execution.get("session_id")

        if not isinstance(execution_id, str):
            raise RunSealError("execute result did not include execution_id")
        if not isinstance(session_id, str):
            raise RunSealError("execute result did not include session_id")

        replay_events, replay = client.call(
            "subscribeEvents",
            {
                "execution_id": execution_id,
                "types": ["execution.*"],
            },
        )

        print_json("subscribe_events_result", replay)
        print_json(
            "replayed_event_types",
            [event.get("type") for event in replay_events],
        )

        _, audit = client.call(
            "getAuditEvents",
            {
                "execution_id": execution_id,
                "types": ["execution.finished"],
            },
        )

        print_json("audit_events", audit)

        _, disposed = client.call(
            "disposeSession",
            {
                "session_id": session_id,
            },
        )

        print_json("dispose_session", disposed)

        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
