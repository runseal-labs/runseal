#!/usr/bin/env python3
"""Probe launchd per-job coalitions on macOS without sudo.

Run from an interactive macOS GUI session:

    python3 scripts/macos-coalition-probe.py --run

The probe creates a temporary per-user launchd job with
`launchctl bootstrap gui/<uid> <temp-plist>`, never writes an agent into
~/Library/LaunchAgents, uses a random label that must not already exist, and
boots the label out afterward. It never invokes sudo.

Questions:

1. Does a per-user launchd job receive its own resource/jetsam coalitions?
2. Can unprivileged `proc_pidinfo(PROC_PIDCOALITIONINFO)` read them?
3. Do `setsid`, double-fork, and reparenting preserve coalition membership?
4. Can `coalition_info_resource_usage` show active/started/exited counters
   without privilege?
5. Does killing the job's main process versus booting out the job differ for a
   detached grandchild?
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import plistlib
import signal
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

PROC_ALL_PIDS = 1
PROC_PIDCOALITIONINFO = 20
PROC_PIDUNIQIDENTIFIERINFO = 17
PROC_PIDT_BSDINFOWITHUNIQID = 18
LAUNCHD_PID = 1


class CoalitionInfo(ctypes.Structure):
    _fields_ = [
        ("coalition_id", ctypes.c_uint64 * 2),
        ("reserved", ctypes.c_uint64 * 3),
    ]


class UniqIdentifierInfo(ctypes.Structure):
    _fields_ = [
        ("uuid", ctypes.c_ubyte * 16),
        ("uniqueid", ctypes.c_uint64),
        ("puniqueid", ctypes.c_uint64),
        ("idversion", ctypes.c_int32),
        ("orig_ppidversion", ctypes.c_int32),
        ("reserve2", ctypes.c_uint64),
        ("reserve3", ctypes.c_uint64),
    ]


class AuditToken(ctypes.Structure):
    _fields_ = [("val", ctypes.c_uint32 * 8)]


class ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
        ("xstatus", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("ruid", ctypes.c_uint32),
        ("rgid", ctypes.c_uint32),
        ("svuid", ctypes.c_uint32),
        ("svgid", ctypes.c_uint32),
        ("rfu", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("name", ctypes.c_char * 32),
        ("nfiles", ctypes.c_uint32),
        ("pgid", ctypes.c_uint32),
        ("pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("nice", ctypes.c_int32),
        ("start_tvsec", ctypes.c_uint64),
        ("start_tvusec", ctypes.c_uint64),
    ]


class ProcBsdInfoWithUniqId(ctypes.Structure):
    _fields_ = [
        ("pbsd", ProcBsdInfo),
        ("uniqid", UniqIdentifierInfo),
    ]


def libc() -> ctypes.CDLL:
    path = ctypes.util.find_library("System") or "/usr/lib/libSystem.B.dylib"
    handle = ctypes.CDLL(path, use_errno=True)
    handle.proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    handle.proc_pidinfo.restype = ctypes.c_int
    handle.proc_listpids.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    handle.proc_listpids.restype = ctypes.c_int
    usage = getattr(handle, "coalition_info_resource_usage", None)
    if usage is not None:
        usage.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
        usage.restype = ctypes.c_int
    signal_audit = getattr(handle, "proc_signal_with_audittoken", None)
    if signal_audit is not None:
        signal_audit.argtypes = [ctypes.POINTER(AuditToken), ctypes.c_int]
        signal_audit.restype = ctypes.c_int
    terminate_audit = getattr(handle, "proc_terminate_with_audittoken", None)
    if terminate_audit is not None:
        terminate_audit.argtypes = [
            ctypes.POINTER(AuditToken),
            ctypes.POINTER(ctypes.c_int),
        ]
        terminate_audit.restype = ctypes.c_int
    spawnattr_init = getattr(handle, "posix_spawnattr_init", None)
    if spawnattr_init is not None:
        spawnattr_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        spawnattr_init.restype = ctypes.c_int
    spawnattr_destroy = getattr(handle, "posix_spawnattr_destroy", None)
    if spawnattr_destroy is not None:
        spawnattr_destroy.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        spawnattr_destroy.restype = ctypes.c_int
    set_coalition = getattr(handle, "posix_spawnattr_setcoalition_np", None)
    if set_coalition is not None:
        set_coalition.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint64,
            ctypes.c_int,
            ctypes.c_int,
        ]
        set_coalition.restype = ctypes.c_int
    spawn = getattr(handle, "posix_spawn", None)
    if spawn is not None:
        spawn.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p),
        ]
        spawn.restype = ctypes.c_int
    return handle


LIBC = libc()


def process_uniqid(pid: int) -> dict | None:
    info = UniqIdentifierInfo()
    size = ctypes.sizeof(info)
    result = LIBC.proc_pidinfo(
        pid,
        PROC_PIDUNIQIDENTIFIERINFO,
        0,
        ctypes.byref(info),
        size,
    )
    if result != size:
        return None
    return {
        "uniqueid": int(info.uniqueid),
        "puniqueid": int(info.puniqueid),
        "idversion": int(info.idversion),
        "orig_ppidversion": int(info.orig_ppidversion),
    }


def paired_identity(pid: int) -> dict | None:
    info = ProcBsdInfoWithUniqId()
    size = ctypes.sizeof(info)
    result = LIBC.proc_pidinfo(
        pid,
        PROC_PIDT_BSDINFOWITHUNIQID,
        0,
        ctypes.byref(info),
        size,
    )
    if result != size or int(info.pbsd.pid) != pid:
        return None
    return {
        "pid": int(info.pbsd.pid),
        "ppid": int(info.pbsd.ppid),
        "pgid": int(info.pbsd.pgid),
        "uniqueid": int(info.uniqid.uniqueid),
        "puniqueid": int(info.uniqid.puniqueid),
        "idversion": int(info.uniqid.idversion),
        "orig_ppidversion": int(info.uniqid.orig_ppidversion),
    }


def audit_token(pid: int, idversion: int) -> AuditToken:
    token = AuditToken()
    # audit_token_t: val[5] is pid, val[7] is pidversion.
    token.val[5] = pid
    token.val[7] = idversion & 0xFFFFFFFF
    return token


def audit_signal(token: AuditToken, sig: int) -> int:
    return int(LIBC.proc_signal_with_audittoken(ctypes.byref(token), sig))


def audit_terminate(token: AuditToken) -> tuple[int, int]:
    signal_value = ctypes.c_int(signal.SIGKILL)
    result = int(
        LIBC.proc_terminate_with_audittoken(
            ctypes.byref(token),
            ctypes.byref(signal_value),
        )
    )
    return result, int(signal_value.value)


def audit_token_probe() -> dict:
    pid = os.fork()
    if pid == 0:
        time.sleep(15)
        os._exit(0)
    result: dict = {"pid": pid}
    token: AuditToken | None = None
    reaped = False
    try:
        uniq = process_uniqid(pid)
        paired = paired_identity(pid)
        result["uniqid"] = uniq
        result["paired_identity"] = paired
        if uniq is None and paired is None:
            result["error"] = "process identity unavailable"
            return result
        idversion = (
            paired["idversion"] if paired is not None else uniq["idversion"]
        )
        token = audit_token(pid, idversion)
        result["token"] = {
            "val5_pid": int(token.val[5]),
            "val7_idversion": int(token.val[7]),
        }
        result["stop_return"] = audit_signal(token, signal.SIGSTOP)
        time.sleep(0.1)
        stopped, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
        result["stop_wait"] = {
            "pid": stopped,
            "wifsignaled": os.WIFSIGNALED(status) if stopped else None,
            "wifstopped": os.WIFSTOPPED(status) if stopped else None,
            "stopsig": os.WSTOPSIG(status) if stopped and os.WIFSTOPPED(status) else None,
        }
        result["continue_return"] = audit_signal(token, signal.SIGCONT)
        time.sleep(0.05)
        forged = audit_token(pid, idversion + 1)
        result["forged_kill_return"] = audit_signal(forged, signal.SIGKILL)
        result["alive_after_forged"] = alive(pid)
        terminate_return, delivered_signal = audit_terminate(token)
        result["terminate_return"] = terminate_return
        result["terminate_signal"] = delivered_signal
        reaped_pid, wait_status = os.waitpid(pid, 0)
        reaped = reaped_pid == pid
        result["reaped"] = reaped
        result["exit_signal"] = (
            os.WTERMSIG(wait_status) if os.WIFSIGNALED(wait_status) else None
        )
    except Exception as error:  # probe output only
        result["error"] = repr(error)
    finally:
        if not reaped:
            if token is not None:
                audit_signal(token, signal.SIGKILL)
            else:
                # The child was forked here and has not been reaped; this is the
                # direct-child fallback, not a cohort identity lookup.
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        result["reaped"] = reaped
    return result


def coalition_ids(pid: int) -> dict | None:
    info = CoalitionInfo()
    size = ctypes.sizeof(info)
    result = LIBC.proc_pidinfo(
        pid,
        PROC_PIDCOALITIONINFO,
        0,
        ctypes.byref(info),
        size,
    )
    if result != size:
        return None
    return {
        "resource": int(info.coalition_id[0]),
        "jetsam": int(info.coalition_id[1]),
    }


def coalition_spawn_probe(targets: dict[str, dict | None]) -> dict:
    """Attempt to place a child into another execution's coalition.

    A setter acceptance alone is not evidence: the spawn call must be checked,
    and a successful child's coalition must be read back.
    """
    result: dict = {}
    set_coalition = getattr(LIBC, "posix_spawnattr_setcoalition_np", None)
    spawn = getattr(LIBC, "posix_spawn", None)
    if set_coalition is None or spawn is None:
        return {"available": False, "reason": "posix_spawn coalition symbol missing"}
    for name, coalition in targets.items():
        if coalition is None:
            result[name] = {"skipped": "coalition unavailable"}
            continue
        # Resource coalitions use type 0; jetsam coalitions use type 1.
        target_type = 1 if name.endswith("_jetsam") else 0
        target_id = (
            coalition["jetsam"] if target_type == 1 else coalition["resource"]
        )
        result[name] = {}
        for role in (1, 0):
            attr = ctypes.c_void_p()
            init_result = LIBC.posix_spawnattr_init(ctypes.byref(attr))
            if init_result != 0:
                result[name][f"role_{role}"] = {"attr_init": init_result}
                continue
            try:
                setter = int(
                    set_coalition(
                        ctypes.byref(attr),
                        ctypes.c_uint64(target_id),
                        ctypes.c_int(target_type),
                        ctypes.c_int(role),
                    )
                )
                entry = {"setter_return": setter, "spawn_return": None}
                if setter == 0:
                    pid = ctypes.c_int(-1)
                    argv = (
                        ctypes.c_char_p * 3
                    )(b"/usr/bin/sleep", b"2", None)
                    envp = (ctypes.c_char_p * 1)(None)
                    spawn_result = int(
                        spawn(
                            ctypes.byref(pid),
                            b"/usr/bin/sleep",
                            None,
                            ctypes.byref(attr),
                            argv,
                            envp,
                        )
                    )
                    entry["spawn_return"] = spawn_result
                    entry["spawn_pid"] = int(pid.value)
                    if spawn_result == 0 and pid.value > 0:
                        entry["child_coalition"] = coalition_ids(pid.value)
                        try:
                            os.waitpid(pid.value, 0)
                        except ChildProcessError:
                            pass
                result[name][f"role_{role}"] = entry
            finally:
                LIBC.posix_spawnattr_destroy(ctypes.byref(attr))
    return result


def coalition_usage(cid: int) -> dict:
    usage = getattr(LIBC, "coalition_info_resource_usage", None)
    if usage is None:
        return {"available": False, "reason": "symbol missing"}
    buffer = ctypes.create_string_buffer(4096)
    ctypes.set_errno(0)
    result = usage(cid, ctypes.byref(buffer), ctypes.sizeof(buffer))
    if result != 0:
        return {
            "available": True,
            "error": result,
            "errno": ctypes.get_errno(),
        }
    started, exited = struct.unpack_from("<QQ", buffer.raw)
    return {
        "available": True,
        "tasks_started": started,
        "tasks_exited": exited,
        "active": started - exited,
    }


def all_pids() -> list[int]:
    needed = LIBC.proc_listpids(PROC_ALL_PIDS, 0, None, 0)
    if needed <= 0:
        return []
    for _ in range(4):
        buffer = (ctypes.c_uint32 * (needed // 4 + 32))()
        result = LIBC.proc_listpids(
            PROC_ALL_PIDS,
            0,
            ctypes.byref(buffer),
            ctypes.sizeof(buffer),
        )
        if result <= 0:
            return []
        if result < ctypes.sizeof(buffer):
            count = result // 4
            return [int(buffer[index]) for index in range(count) if buffer[index] > 0]
        needed = ctypes.sizeof(buffer) * 2
    return []


def coalition_members(resource_id: int) -> list[int]:
    members = []
    for pid in all_pids():
        try:
            ids = coalition_ids(pid)
            if ids is not None and ids["resource"] == resource_id:
                members.append(pid)
        except OSError:
            continue
    return members


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    os.replace(temporary, path)


def job_main(work: Path) -> None:
    root_pid = os.getpid()
    root = {
        "pid": root_pid,
        "ppid": os.getppid(),
        "sid": os.getsid(0),
        "coalition": coalition_ids(root_pid),
    }
    child = os.fork()
    if child == 0:
        os.setsid()
        child_pid = os.getpid()
        grandchild = os.fork()
        if grandchild == 0:
            write_json(
                work / "grandchild.json",
                {
                    "pid": os.getpid(),
                    "ppid": os.getppid(),
                    "sid": os.getsid(0),
                    "coalition": coalition_ids(os.getpid()),
                },
            )
            time.sleep(20)
            os._exit(0)
        write_json(
            work / "child.json",
            {
                "pid": child_pid,
                "ppid": os.getppid(),
                "sid": os.getsid(0),
                "grandchild": grandchild,
                "coalition": coalition_ids(child_pid),
            },
        )
        os._exit(0)

    deadline = time.time() + 10
    while time.time() < deadline:
        if (work / "grandchild.json").exists() and (work / "child.json").exists():
            break
        time.sleep(0.02)
    child_info = {}
    grandchild_info = {}
    try:
        child_info = json.loads((work / "child.json").read_text(encoding="utf-8"))
    except OSError:
        pass
    try:
        grandchild_info = json.loads(
            (work / "grandchild.json").read_text(encoding="utf-8")
        )
    except OSError:
        pass
    write_json(
        work / "job.json",
        {
            "root": root,
            "child": child_info,
            "grandchild": grandchild_info,
        },
    )
    time.sleep(20)


def launchctl(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["launchctl", *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except OSError as error:
        return subprocess.CompletedProcess(
            ["launchctl", *args], 127, "", str(error)
        )


def text(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stdout + result.stderr).strip()


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_gone(pids: list[int], timeout: float) -> list[int]:
    deadline = time.time() + timeout
    remaining = set(pids)
    while remaining and time.time() < deadline:
        remaining = {pid for pid in remaining if alive(pid)}
        if remaining:
            time.sleep(0.05)
    return sorted(remaining)


def cleanup(
    label: str,
    root_coalition: dict | None,
    pids: list[int],
    tokens: dict[int, AuditToken],
    bootstrapped: bool,
) -> None:
    if bootstrapped:
        launchctl("bootout", f"gui/{os.getuid()}/{label}")
    if root_coalition is None:
        time.sleep(1)
        return
    for pid in pids:
        token = tokens.get(pid)
        if token is None:
            continue
        try:
            if coalition_ids(pid) == root_coalition:
                audit_signal(token, signal.SIGKILL)
        except OSError:
            pass
    wait_gone(pids, 5)


def run() -> int:
    work = Path(tempfile.mkdtemp(prefix="runseal-coalition-probe-"))
    label = f"com.runseal.coalitionprobe.{os.getpid()}.{uuid.uuid4().hex}"
    domain = f"gui/{os.getuid()}"
    plist_path = work / f"{label}.plist"
    report_path = work / "job.json"
    state: dict = {
        "root_coalition": None,
        "pids": [],
        "tokens": {},
        "bootstrapped": False,
    }
    try:
        print(
            "audit token probe:",
            json.dumps(audit_token_probe(), sort_keys=True),
        )
        existing = launchctl("print", f"{domain}/{label}")
        if existing.returncode == 0:
            print("probe aborted: random label already exists")
            return 1
        with plist_path.open("wb") as handle:
            plistlib.dump(
                {
                    "Label": label,
                    "ProgramArguments": [
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "--job",
                        str(work),
                    ],
                    "RunAtLoad": True,
                    "KeepAlive": False,
                    "WorkingDirectory": str(work),
                },
                handle,
            )
        bootstrap = launchctl("bootstrap", domain, str(plist_path))
        print("launchctl bootstrap:", text(bootstrap))
        if bootstrap.returncode != 0:
            print("probe aborted: per-user launchd bootstrap unavailable")
            return 1
        state["bootstrapped"] = True

        deadline = time.time() + 20
        while not report_path.exists() and time.time() < deadline:
            time.sleep(0.05)
        if not report_path.exists():
            print("probe aborted: job did not publish report")
            return 1

        report = json.loads(report_path.read_text(encoding="utf-8"))
        root = report["root"]
        root_pid = root["pid"]
        root_coalition = root["coalition"]
        pids = [
            root_pid,
            report.get("child", {}).get("pid"),
            report.get("grandchild", {}).get("pid"),
        ]
        pids = [pid for pid in pids if isinstance(pid, int)]
        state["root_coalition"] = root_coalition
        state["pids"] = pids
        tokens: dict[int, AuditToken] = {}
        paired: dict[int, dict | None] = {}
        for pid in pids:
            identity = paired_identity(pid)
            if identity is None:
                uniq = process_uniqid(pid)
                if uniq is None:
                    paired[pid] = None
                    continue
                identity = {"idversion": uniq["idversion"], **uniq}
            paired[pid] = identity
            tokens[pid] = audit_token(pid, identity["idversion"])
        state["tokens"] = tokens
        print(json.dumps(report, indent=2, sort_keys=True))
        print("launchctl print:", text(launchctl("print", f"{domain}/{label}")))
        print("launchctl procinfo:", text(launchctl("procinfo", str(root_pid))))
        print("runner coalition:", json.dumps(coalition_ids(os.getpid())))
        print(
            "coalition spawn probe:",
            json.dumps(
                coalition_spawn_probe(
                    {
                        "runner": coalition_ids(os.getpid()),
                        "job": root_coalition,
                    }
                ),
                sort_keys=True,
            ),
        )

        if root_coalition is not None:
            resource_id = root_coalition["resource"]
            print("job resource coalition:", resource_id)
            print("job usage:", json.dumps(coalition_usage(resource_id)))
            members = coalition_members(resource_id)
            print("job members:", members)
            print(
                "member identities:",
                json.dumps({pid: coalition_ids(pid) for pid in pids}),
            )
            print(
                "member paired identities:",
                json.dumps(paired, sort_keys=True),
            )
            print(
                "independent from runner:",
                coalition_ids(os.getpid()) != root_coalition,
            )

        grandchild_pid = report.get("grandchild", {}).get("pid")
        root_token = tokens.get(root_pid)
        if root_token is not None:
            # Use the saved audit token, not a fresh PID lookup followed by kill.
            audit_signal(root_token, signal.SIGKILL)
        time.sleep(1)
        survivors = [pid for pid in pids if alive(pid)]
        print(
            "after main SIGKILL:",
            json.dumps(
                {
                    "grandchild_alive": bool(
                        isinstance(grandchild_pid, int) and alive(grandchild_pid)
                    ),
                    "pids_alive": survivors,
                },
                sort_keys=True,
            ),
        )
        if root_coalition is not None:
            print(
                "usage after main SIGKILL:",
                json.dumps(coalition_usage(root_coalition["resource"])),
            )

        print("launchctl bootout:", text(launchctl("bootout", f"{domain}/{label}")))
        wait_gone(pids, 5)
        if root_coalition is not None:
            print(
                "usage after bootout:",
                json.dumps(coalition_usage(root_coalition["resource"])),
            )
            print(
                "members after bootout:",
                coalition_members(root_coalition["resource"]),
            )
        print("probe complete; workdir:", work)
        return 0
    except Exception as error:  # probe output only
        print("probe exception:", repr(error))
        return 1
    finally:
        cleanup(
            label,
            state["root_coalition"],
            state["pids"],
            state["tokens"],
            state["bootstrapped"],
        )
        print(
            "cleanup remaining fixture:",
            [pid for pid in state["pids"] if alive(pid)],
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--job", type=Path)
    args = parser.parse_args()
    if args.job is not None:
        job_main(args.job)
        return 0
    if args.run:
        return run()
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
