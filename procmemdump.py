#!/usr/bin/env python3
"""
procmemdump.py - full process memory capture for incident response.

Platforms: Linux (/proc), macOS (Mach APIs), Windows (Win32 via ctypes).
Dependencies: Python 3.8+ standard library only. No subprocess, no shell.

Output, written to a NEW directory procdump_<pid>_<UTC timestamp>/ :
  memory.bin     every readable memory region, concatenated back to back
  manifest.json  host and process metadata, SHA-256 hashes, and a map of
                 virtual address -> offset in memory.bin for each segment

Run only on systems you are authorized to investigate, elevated
(root / Administrator). A memory dump can contain passwords, tokens and keys:
store it on encrypted or access-restricted storage and handle it as sensitive.

Limitations:
  * The process is not suspended, so memory can change while it is read.
  * Windows: use 64-bit Python to dump 64-bit processes.
  * macOS: task_for_pid is refused for Apple-signed and hardened processes
    (SIP / hardened runtime) even as root.
"""
from __future__ import annotations

import argparse
import ctypes
import getpass
import hashlib
import json
import mmap
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, List, Tuple

VERSION = "1.0.0"
CHUNK = 1 << 20  # read granularity: 1 MiB
MAX_PID = 2**32 - 1
READ_ERRORS = (OSError, OverflowError, ValueError)


@dataclass
class Region:
    base: int
    size: int
    perms: str
    kind: str = ""
    path: str = ""


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------
class LinuxBackend:
    SKIP = {"[vvar]", "[vvar_vclock]", "[vsyscall]"}

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)

    def close(self) -> None:
        os.close(self.fd)

    def exe_path(self) -> str:
        try:
            return os.readlink(f"/proc/{self.pid}/exe")
        except OSError:
            return ""

    def regions(self) -> List[Region]:
        out: List[Region] = []
        with open(f"/proc/{self.pid}/maps", "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()  # snapshot before reading memory
        for line in lines:
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            start_s, end_s = parts[0].split("-")
            start, end = int(start_s, 16), int(end_s, 16)
            perms = parts[1]
            path = parts[5].strip() if len(parts) > 5 else ""
            if "r" not in perms or path in self.SKIP or end > 0x7FFFFFFFFFFFFFFF:
                continue
            out.append(Region(start, end - start, perms, path=path))
        return out

    def read(self, addr: int, size: int) -> bytes:
        return os.pread(self.fd, size, addr)


# --------------------------------------------------------------------------
# macOS
# --------------------------------------------------------------------------
class MacBackend:
    VM_REGION_BASIC_INFO_64 = 9

    def __init__(self, pid: int) -> None:
        self.pid = pid
        L = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        u32, u64, i32 = ctypes.c_uint, ctypes.c_uint64, ctypes.c_int
        L.task_for_pid.argtypes = [u32, i32, ctypes.POINTER(u32)]
        L.task_for_pid.restype = i32
        L.mach_vm_region.argtypes = [u32, ctypes.POINTER(u64), ctypes.POINTER(u64), i32,
                                     ctypes.c_void_p, ctypes.POINTER(u32), ctypes.POINTER(u32)]
        L.mach_vm_region.restype = i32
        L.mach_vm_read_overwrite.argtypes = [u32, u64, u64, u64, ctypes.POINTER(u64)]
        L.mach_vm_read_overwrite.restype = i32
        L.mach_port_deallocate.argtypes = [u32, u32]
        L.mach_port_deallocate.restype = i32
        L.proc_pidpath.argtypes = [i32, ctypes.c_void_p, ctypes.c_uint32]
        L.proc_pidpath.restype = i32
        L.proc_regionfilename.argtypes = [i32, u64, ctypes.c_void_p, ctypes.c_uint32]
        L.proc_regionfilename.restype = i32
        self.L = L
        self.self_task = u32.in_dll(L, "mach_task_self_").value
        task = u32(0)
        kr = L.task_for_pid(self.self_task, pid, ctypes.byref(task))
        if kr != 0:
            raise PermissionError(
                f"task_for_pid failed (kern_return {kr}). Run as root; SIP and the "
                "hardened runtime block protected processes."
            )
        self.task = task.value
        self._buf = ctypes.create_string_buffer(CHUNK)

    def close(self) -> None:
        self.L.mach_port_deallocate(self.self_task, self.task)

    def exe_path(self) -> str:
        buf = ctypes.create_string_buffer(4096)
        n = self.L.proc_pidpath(self.pid, buf, len(buf))
        return buf.value.decode("utf-8", "replace") if n > 0 else ""

    def _region_path(self, addr: int) -> str:
        buf = ctypes.create_string_buffer(1024)
        n = self.L.proc_regionfilename(self.pid, addr, buf, len(buf))
        return buf.value.decode("utf-8", "replace") if n > 0 else ""

    def regions(self) -> List[Region]:
        out: List[Region] = []
        addr = ctypes.c_uint64(0)
        while True:
            size = ctypes.c_uint64(0)
            info = (ctypes.c_int * 9)()
            count = ctypes.c_uint(9)
            obj = ctypes.c_uint(0)
            kr = self.L.mach_vm_region(self.task, ctypes.byref(addr), ctypes.byref(size),
                                       self.VM_REGION_BASIC_INFO_64, info,
                                       ctypes.byref(count), ctypes.byref(obj))
            if kr != 0 or size.value == 0:
                break
            prot = info[0]
            if prot & 1:  # VM_PROT_READ
                perms = "r" + ("w" if prot & 2 else "-") + ("x" if prot & 4 else "-")
                out.append(Region(addr.value, size.value, perms, path=self._region_path(addr.value)))
            nxt = addr.value + size.value
            if nxt <= addr.value:
                break
            addr.value = nxt
        return out

    def read(self, addr: int, size: int) -> bytes:
        out = ctypes.c_uint64(0)
        kr = self.L.mach_vm_read_overwrite(self.task, addr, size,
                                           ctypes.addressof(self._buf), ctypes.byref(out))
        if kr != 0:
            raise OSError(f"mach_vm_read_overwrite kern_return {kr} at {addr:#x}")
        return ctypes.string_at(self._buf, out.value)


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------
_WIN = None


def _load_win():
    global _WIN
    if _WIN is not None:
        return _WIN
    import types
    from ctypes import wintypes as wt

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)

    class MBI(ctypes.Structure):  # MEMORY_BASIC_INFORMATION
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wt.DWORD),
            ("PartitionId", wt.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wt.DWORD),
            ("Protect", wt.DWORD),
            ("Type", wt.DWORD),
        ]

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.OpenProcess.restype = wt.HANDLE
    k32.CloseHandle.argtypes = [wt.HANDLE]
    k32.CloseHandle.restype = wt.BOOL
    k32.GetCurrentProcess.restype = wt.HANDLE
    k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory.restype = wt.BOOL
    k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    k32.QueryFullProcessImageNameW.restype = wt.BOOL
    psapi.GetMappedFileNameW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
    psapi.GetMappedFileNameW.restype = wt.DWORD
    adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    adv.OpenProcessToken.restype = wt.BOOL
    adv.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(LUID)]
    adv.LookupPrivilegeValueW.restype = wt.BOOL
    adv.AdjustTokenPrivileges.argtypes = [wt.HANDLE, wt.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                          wt.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    adv.AdjustTokenPrivileges.restype = wt.BOOL

    _WIN = types.SimpleNamespace(k32=k32, psapi=psapi, adv=adv, wt=wt, MBI=MBI,
                                 LUID=LUID, TOKEN_PRIVILEGES=TOKEN_PRIVILEGES)
    return _WIN


def _enable_debug_privilege(w) -> bool:
    """Enable SeDebugPrivilege on our own token (only called if OpenProcess is denied)."""
    token = w.wt.HANDLE()
    if not w.adv.OpenProcessToken(w.k32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(token)):
        return False
    try:
        luid = w.LUID()
        if not w.adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        tp = w.TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = 0x2  # SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        ok = w.adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        return bool(ok) and ctypes.get_last_error() == 0  # 1300 = not all assigned
    finally:
        w.k32.CloseHandle(token)


_WIN_PERMS = {0x02: "r--", 0x04: "rw-", 0x08: "rw-", 0x10: "--x", 0x20: "r-x", 0x40: "rwx", 0x80: "rwx"}
_WIN_TYPES = {0x1000000: "IMAGE", 0x40000: "MAPPED", 0x20000: "PRIVATE"}


class WindowsBackend:
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100

    def __init__(self, pid: int) -> None:
        self.w = _load_win()
        access = 0x0400 | 0x0010  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        h = self.w.k32.OpenProcess(access, False, pid)
        if not h and ctypes.get_last_error() == 5:  # ACCESS_DENIED: try SeDebugPrivilege
            if _enable_debug_privilege(self.w):
                h = self.w.k32.OpenProcess(access, False, pid)
        if not h:
            raise ctypes.WinError(ctypes.get_last_error())
        self.h = h
        self._buf = ctypes.create_string_buffer(CHUNK)

    def close(self) -> None:
        self.w.k32.CloseHandle(self.h)

    def exe_path(self) -> str:
        buf = ctypes.create_unicode_buffer(32768)
        size = self.w.wt.DWORD(len(buf))
        if self.w.k32.QueryFullProcessImageNameW(self.h, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""

    def _mapped_name(self, base: int) -> str:
        buf = ctypes.create_unicode_buffer(1024)
        n = self.w.psapi.GetMappedFileNameW(self.h, base, buf, 1024)
        return buf.value if n else ""

    def regions(self) -> List[Region]:
        out: List[Region] = []
        mbi = self.w.MBI()
        addr = 0
        while self.w.k32.VirtualQueryEx(self.h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            prot = mbi.Protect
            if (mbi.State == self.MEM_COMMIT and prot != 0
                    and not prot & (self.PAGE_NOACCESS | self.PAGE_GUARD)):
                kind = _WIN_TYPES.get(mbi.Type, "")
                path = self._mapped_name(base) if kind in ("IMAGE", "MAPPED") else ""
                out.append(Region(base, size, _WIN_PERMS.get(prot & 0xFF, "???"), kind, path))
            nxt = base + size
            if size == 0 or nxt <= addr:
                break
            addr = nxt
        return out

    def read(self, addr: int, size: int) -> bytes:
        n = ctypes.c_size_t(0)
        if not self.w.k32.ReadProcessMemory(self.h, addr, self._buf, size, ctypes.byref(n)):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(self._buf, n.value)


# --------------------------------------------------------------------------
# Common engine
# --------------------------------------------------------------------------
def iter_readable(backend, region: Region) -> Iterator[Tuple[int, bytes]]:
    """Yield (address, data) for the readable parts of a region.

    Reads in large chunks; if a chunk fails, retries page by page and skips
    unreadable pages, so one bad page does not lose the rest of the region.
    Every code path advances `addr`, so this always terminates.
    """
    page = mmap.PAGESIZE
    addr, end = region.base, region.base + region.size
    while addr < end:
        n = min(CHUNK, end - addr)
        try:
            data = backend.read(addr, n)
        except READ_ERRORS:
            data = b""
        if data:
            yield addr, data
            addr += len(data)
            continue
        stop = addr + n
        while addr < stop:
            m = min(page, stop - addr)
            try:
                d = backend.read(addr, m)
            except READ_ERRORS:
                d = b""
            if d:
                yield addr, d
            addr += m


def _create_file(path: str) -> int:
    """Create a new file (never overwrite, never follow symlinks), owner-only on POSIX."""
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    return os.open(path, flags, 0o600)


def _make_out_dir(base: str, pid: int) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # Only trusted values (pid, timestamp) go into the path, never target process data.
    path = os.path.join(os.path.abspath(base), f"procdump_{pid}_{stamp}")
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    os.mkdir(path, 0o700)  # fails if it already exists
    return path


def _is_elevated() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return ""


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dump(backend, pid: int, out_dir: str) -> dict:
    started = _utc()
    exe = backend.exe_path()
    regions = backend.regions()

    needed = sum(r.size for r in regions)
    free = shutil.disk_usage(out_dir).free
    if needed >= free:
        raise OSError(f"not enough free space: up to {needed} bytes needed, {free} available")

    overall = hashlib.sha256()
    offset = 0
    entries = []
    mem_path = os.path.join(out_dir, "memory.bin")
    with os.fdopen(_create_file(mem_path), "wb") as f:
        for r in regions:
            rh = hashlib.sha256()
            segs: List[dict] = []
            read_bytes = 0
            for addr, data in iter_readable(backend, r):
                f.write(data)
                overall.update(data)
                rh.update(data)
                if segs and int(segs[-1]["address"], 16) + segs[-1]["size"] == addr:
                    segs[-1]["size"] += len(data)  # contiguous in address and in file
                else:
                    segs.append({"address": f"0x{addr:x}", "size": len(data), "file_offset": offset})
                offset += len(data)
                read_bytes += len(data)
            entries.append({
                "base": f"0x{r.base:x}", "size": r.size, "perms": r.perms,
                "type": r.kind, "path": r.path,
                "bytes_read": read_bytes, "bytes_unreadable": r.size - read_bytes,
                "sha256": rh.hexdigest(), "segments": segs,
            })
        f.flush()
        os.fsync(f.fileno())

    manifest = {
        "tool": "procmemdump", "version": VERSION,
        "started_utc": started, "finished_utc": _utc(),
        "host": platform.node(), "os": platform.platform(), "arch": platform.machine(),
        "collector_user": _user(), "collector_elevated": _is_elevated(),
        "pid": pid, "exe_path": exe,
        "memory_file": "memory.bin", "memory_sha256": overall.hexdigest(),
        "bytes_written": offset,
        "bytes_unreadable": sum(e["bytes_unreadable"] for e in entries),
        "region_count": len(entries),
        "note": "Process was not suspended; memory may have changed during capture.",
        "regions": entries,
    }
    man_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    man_path = os.path.join(out_dir, "manifest.json")
    with os.fdopen(_create_file(man_path), "wb") as f:
        f.write(man_bytes)
        f.flush()
        os.fsync(f.fileno())
    manifest["_manifest_sha256"] = hashlib.sha256(man_bytes).hexdigest()
    return manifest


def _pid(value: str) -> int:
    try:
        pid = int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError("PID must be an integer")
    if not 0 < pid <= MAX_PID:
        raise argparse.ArgumentTypeError("PID out of range")
    return pid


def _select_backend():
    if sys.platform.startswith("linux"):
        return LinuxBackend
    if sys.platform == "darwin":
        return MacBackend
    if sys.platform == "win32":
        return WindowsBackend
    raise SystemExit(f"unsupported platform: {sys.platform}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Full process memory capture with SHA-256 manifest.")
    ap.add_argument("pid", type=_pid, help="target process ID")
    ap.add_argument("-o", "--output-dir", default=".",
                    help="parent directory for the dump folder (default: current directory)")
    args = ap.parse_args(argv)

    if sys.platform == "win32" and sys.maxsize <= 2**32:
        print("warning: 32-bit Python cannot reliably read 64-bit processes", file=sys.stderr)
    if not _is_elevated():
        print("warning: not running as root/Administrator; access may be denied", file=sys.stderr)

    try:
        backend = _select_backend()(args.pid)
    except (OSError, PermissionError) as e:
        print(f"error: cannot open process {args.pid}: {e}", file=sys.stderr)
        return 1

    try:
        out_dir = _make_out_dir(args.output_dir, args.pid)
        result = dump(backend, args.pid, out_dir)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        backend.close()

    print(f"Dump folder     : {out_dir}")
    print(f"Process         : {result['pid']} {result['exe_path']}")
    print(f"Regions         : {result['region_count']}")
    print(f"Bytes written   : {result['bytes_written']}")
    print(f"Bytes unreadable: {result['bytes_unreadable']}")
    print(f"memory.bin  SHA-256: {result['memory_sha256']}")
    print(f"manifest    SHA-256: {result['_manifest_sha256']}")
    print("This dump may contain credentials and keys. Store it encrypted and access-restricted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
