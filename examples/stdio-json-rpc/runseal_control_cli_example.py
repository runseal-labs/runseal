"""Windows CLI control example using public OS APIs and fixed inherited fd 3."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runseal", required=True)
    parser.add_argument("--policy", choices=["danger-full-access", "workspace-write"], default="workspace-write")
    args = parser.parse_args()
    executable = str(Path(args.runseal).resolve(strict=True))
    winsock = ctypes.WinDLL("ws2_32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    socket_type = ctypes.c_size_t
    invalid_socket = socket_type(-1).value
    winsock.WSASocketW.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    winsock.WSASocketW.restype = socket_type
    for name in ("bind", "connect"):
        getattr(winsock, name).argtypes = [socket_type, ctypes.c_void_p, ctypes.c_int]
    winsock.listen.argtypes = [socket_type, ctypes.c_int]
    winsock.accept.argtypes = [socket_type, ctypes.c_void_p, ctypes.c_void_p]
    winsock.accept.restype = socket_type
    winsock.closesocket.argtypes = [socket_type]
    winsock.shutdown.argtypes = [socket_type, ctypes.c_int]
    winsock.ioctlsocket.argtypes = [socket_type, ctypes.c_long, ctypes.POINTER(wintypes.ULONG)]
    winsock.send.argtypes = [socket_type, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    winsock.recv.argtypes = [socket_type, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    kernel.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]

    class Address(ctypes.Structure):
        _fields_ = [("family", ctypes.c_ushort), ("path", ctypes.c_char * 108)]

    def checked(result):
        if result == -1:
            raise OSError(winsock.WSAGetLastError(), "local control operation failed")
        return result

    data = ctypes.create_string_buffer(512)
    if winsock.WSAStartup(0x0202, data) != 0:
        raise RuntimeError("Winsock unavailable")
    listener = parent = child = invalid_socket
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="rsctrl") as namespace, tempfile.TemporaryDirectory(prefix="rsexec") as workspace:
            name = os.fsencode(str(Path(namespace) / "s"))
            if len(name) >= 108:
                raise RuntimeError("local socket namespace too long")
            address = Address(1, name)  # Native Windows AF_UNIX, not a TCP port.
            listener = winsock.WSASocketW(1, 1, 0, None, 0, 0x81)
            child = winsock.WSASocketW(1, 1, 0, None, 0, 0x80)
            if listener == invalid_socket or child == invalid_socket:
                raise RuntimeError("local control socket unavailable")
            checked(winsock.bind(listener, ctypes.byref(address), ctypes.sizeof(address)))
            checked(winsock.listen(listener, 1))
            checked(winsock.connect(child, ctypes.byref(address), ctypes.sizeof(address)))
            parent = winsock.accept(listener, None, None)
            if parent == invalid_socket:
                raise RuntimeError("local control accept failed")
            winsock.closesocket(listener)
            listener = invalid_socket
            os.unlink(name)
            if not kernel.SetHandleInformation(parent, 1, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            mode = wintypes.ULONG(1)
            checked(winsock.ioctlsocket(parent, ctypes.c_long(0x8004667E), ctypes.byref(mode)))

            code = (
                "import os,sys\n"
                "for _ in range(3):\n"
                " data=b''\n"
                " while len(data)<65536:\n"
                "  chunk=os.read(3,65536-len(data)); assert chunk; data+=chunk\n"
                " os.write(3,data)\n"
                "assert os.read(3,1)==b''\n"
                "os.write(1,b'STDOUT\\n'); os.write(2,b'STDERR\\n'); os.write(3,b'EOF-OK')\n"
                "sys.exit(7)\n"
            )
            command = [executable, "exec", "--control-fd", "3", "--policy", args.policy,
                       "--cwd", workspace, "--", sys.executable, "-u", "-c", code]
            class Startup(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR),
                            ("desktop", wintypes.LPWSTR), ("title", wintypes.LPWSTR),
                            ("x", wintypes.DWORD), ("y", wintypes.DWORD),
                            ("xsize", wintypes.DWORD), ("ysize", wintypes.DWORD),
                            ("xchars", wintypes.DWORD), ("ychars", wintypes.DWORD),
                            ("fill", wintypes.DWORD), ("flags", wintypes.DWORD),
                            ("show", wintypes.WORD), ("reserved_size", wintypes.WORD),
                            ("reserved_data", ctypes.c_void_p),
                            ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE),
                            ("stderr", wintypes.HANDLE)]

            class StartupEx(ctypes.Structure):
                _fields_ = [("startup", Startup), ("attributes", ctypes.c_void_p)]

            class Process(ctypes.Structure):
                _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                            ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]

            kernel.GetStdHandle.argtypes = [wintypes.DWORD]
            kernel.GetStdHandle.restype = wintypes.HANDLE
            kernel.GetHandleInformation.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
            kernel.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
            kernel.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
            kernel.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(Process)]
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            stdio = [kernel.GetStdHandle(index & 0xFFFFFFFF) for index in (-10, -11, -12)]
            handles = (wintypes.HANDLE * 4)(*stdio, child)
            descriptor_bytes = (4).to_bytes(4, "little") + bytes([0, 0, 0, 9])
            for handle in [socket_type(-1).value] * 3 + [child]:
                descriptor_bytes += int(handle).to_bytes(ctypes.sizeof(wintypes.HANDLE), "little")
            descriptor_table = ctypes.create_string_buffer(descriptor_bytes)
            size = ctypes.c_size_t()
            kernel.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
            attributes = ctypes.create_string_buffer(size.value)
            if not kernel.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            previous_flags = []
            try:
                if not kernel.UpdateProcThreadAttribute(attributes, 0, 0x20002, handles, ctypes.sizeof(handles), None, None):
                    raise ctypes.WinError(ctypes.get_last_error())
                for handle in handles:
                    flags = wintypes.DWORD()
                    if not kernel.GetHandleInformation(handle, ctypes.byref(flags)):
                        raise ctypes.WinError(ctypes.get_last_error())
                    previous_flags.append((handle, flags.value))
                    if not kernel.SetHandleInformation(handle, 1, 1):
                        raise ctypes.WinError(ctypes.get_last_error())
                startup = StartupEx()
                startup.startup.cb = ctypes.sizeof(startup)
                startup.startup.flags = 0x100
                startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = stdio
                startup.startup.reserved_size = len(descriptor_bytes)
                startup.startup.reserved_data = ctypes.addressof(descriptor_table)
                startup.attributes = ctypes.addressof(attributes)
                info = Process()
                command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
                if not kernel.CreateProcessW(executable, command_line, None, None, True, 0x80000, None, None, ctypes.byref(startup), ctypes.byref(info)):
                    raise ctypes.WinError(ctypes.get_last_error())
                process = info.process
                kernel.CloseHandle(info.thread)
            finally:
                for handle, flags in previous_flags:
                    if not kernel.SetHandleInformation(handle, 1, flags & 1):
                        raise ctypes.WinError(ctypes.get_last_error())
                kernel.DeleteProcThreadAttributeList(attributes)
            deadline = time.monotonic() + 20

            def transfer(payload):
                offset = 0
                result = bytearray()
                while offset < len(payload) or len(result) < len(payload):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("control round watchdog")
                    if offset < len(payload):
                        chunk = payload[offset:]
                        count = winsock.send(parent, chunk, len(chunk), 0)
                        if count == -1:
                            if winsock.WSAGetLastError() != 10035:
                                checked(count)
                        else:
                            offset += count
                    buffer = ctypes.create_string_buffer(min(65536, len(payload) - len(result)))
                    if len(buffer):
                        count = winsock.recv(parent, buffer, len(buffer), 0)
                        if count == -1:
                            if winsock.WSAGetLastError() != 10035:
                                checked(count)
                        elif count == 0:
                            raise EOFError("control ended during a round")
                        else:
                            result.extend(buffer.raw[:count])
                    time.sleep(0.005)
                if bytes(result) != payload:
                    raise RuntimeError("control bytes changed")

            payload = bytes(range(256)) * 256
            for index in range(3):
                transfer(payload)
                print(f"control round {index + 1}: {len(payload)} bytes, sha256={hashlib.sha256(payload).hexdigest()}", flush=True)
            checked(winsock.shutdown(parent, 1))
            final = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("control EOF watchdog")
                buffer = ctypes.create_string_buffer(8192)
                count = winsock.recv(parent, buffer, len(buffer), 0)
                if count == -1:
                    if winsock.WSAGetLastError() != 10035:
                        checked(count)
                    time.sleep(0.005)
                elif count == 0:
                    break
                else:
                    final.extend(buffer.raw[:count])
            if final != b"EOF-OK":
                raise RuntimeError("final reverse bytes changed")
            if kernel.WaitForSingleObject(process, 20000) != 0:
                raise TimeoutError("CLI exit watchdog")
            status = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(process, ctypes.byref(status)):
                raise ctypes.WinError(ctypes.get_last_error())
            kernel.CloseHandle(process)
            process = None
            exit_code = status.value
            if exit_code != 7:
                raise RuntimeError(f"unexpected CLI exit {exit_code}")
            print("control half-close, final reply, and native exit 7 verified", flush=True)
    finally:
        if process is not None:
            kernel.TerminateProcess(process, 1)
            kernel.WaitForSingleObject(process, 10000)
            kernel.CloseHandle(process)
        for handle in (listener, parent, child):
            if handle != invalid_socket:
                winsock.closesocket(handle)
        winsock.WSACleanup()


if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit("This example requires the Windows reference backend.")
    main()
