"""Windows-only capture of the hash-checked GC/1.3 disabled IR dump hook.

Only a private child process is instrumented. The executable on disk is untouched.
The caller must compare instrumented and ordinary output before using the trace.
"""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import hashlib
import msvcrt
import os
import struct
import subprocess
import sys
import tempfile
import time

from tricky_backend_ir import COMPILER_SHA256, capture_snapshot

if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
    raise RuntimeError("IR capture requires 64-bit Windows Python and an x86 compiler")

U32 = C.c_uint32
PTR = C.c_void_p
SIZE = C.c_size_t

class ExceptionRecord(C.Structure):
    _fields_ = [("code", U32), ("flags", U32), ("record", PTR), ("address", PTR),
                ("count", U32), ("information", SIZE * 15)]

class ExceptionInfo(C.Structure):
    _fields_ = [("record", ExceptionRecord), ("firstChance", U32)]

class CreateInfo(C.Structure):
    _fields_ = [("file", PTR), ("process", PTR), ("thread", PTR), ("base", PTR),
                ("debugOffset", U32), ("debugSize", U32), ("localBase", PTR),
                ("start", PTR), ("imageName", PTR), ("unicode", W.WORD)]

class ThreadInfo(C.Structure):
    _fields_ = [("thread", PTR), ("localBase", PTR), ("start", PTR)]

class EventUnion(C.Union):
    _fields_ = [("exception", ExceptionInfo), ("create", CreateInfo),
                ("thread", ThreadInfo), ("exitCode", U32), ("file", PTR)]

class Event(C.Structure):
    _fields_ = [("code", U32), ("pid", U32), ("tid", U32), ("info", EventUnion)]

class Startup(C.Structure):
    _fields_ = [("cb", U32), ("reserved", W.LPWSTR), ("desktop", W.LPWSTR), ("title", W.LPWSTR),
                ("x", U32), ("y", U32), ("xSize", U32), ("ySize", U32), ("xChars", U32),
                ("yChars", U32), ("fill", U32), ("flags", U32), ("show", W.WORD),
                ("reservedCount", W.WORD), ("reservedPtr", PTR), ("stdin", PTR),
                ("stdout", PTR), ("stderr", PTR)]

class ProcessInfo(C.Structure):
    _fields_ = [("process", PTR), ("thread", PTR), ("pid", U32), ("tid", U32)]

class FloatSave(C.Structure):
    _fields_ = [("control", U32), ("status", U32), ("tag", U32), ("errorOffset", U32),
                ("errorSelector", U32), ("dataOffset", U32), ("dataSelector", U32),
                ("registers", C.c_ubyte * 80), ("cr0", U32)]

class Context(C.Structure):
    _fields_ = [("flags", U32), ("debug", U32 * 6), ("floatSave", FloatSave),
                ("gs", U32), ("fs", U32), ("es", U32), ("ds", U32),
                ("edi", U32), ("esi", U32), ("ebx", U32), ("edx", U32),
                ("ecx", U32), ("eax", U32), ("ebp", U32), ("eip", U32),
                ("cs", U32), ("eflags", U32), ("esp", U32), ("ss", U32),
                ("extended", C.c_ubyte * 512)]

assert C.sizeof(Event) == 176
assert C.sizeof(Context) == 716
k32 = C.WinDLL("kernel32", use_last_error=True)

def api(name, args, result=W.BOOL):
    function = getattr(k32, name)
    function.argtypes = args
    function.restype = result
    return function

create = api("CreateProcessW", [W.LPCWSTR, W.LPWSTR, PTR, PTR, W.BOOL, U32, PTR, W.LPCWSTR,
                               C.POINTER(Startup), C.POINTER(ProcessInfo)])
wait = api("WaitForDebugEvent", [C.POINTER(Event), U32])
resume = api("ContinueDebugEvent", [U32, U32, U32])
read = api("ReadProcessMemory", [PTR, PTR, PTR, SIZE, C.POINTER(SIZE)])
write = api("WriteProcessMemory", [PTR, PTR, PTR, SIZE, C.POINTER(SIZE)])
flush = api("FlushInstructionCache", [PTR, PTR, SIZE])
getcontext = api("Wow64GetThreadContext", [PTR, C.POINTER(Context)])
setcontext = api("Wow64SetThreadContext", [PTR, C.POINTER(Context)])
close = api("CloseHandle", [PTR])
terminate = api("TerminateProcess", [PTR, U32])
waitprocess = api("WaitForSingleObject", [PTR, U32], U32)
detach = api("DebugActiveProcessStop", [U32])

def require(ok):
    if not ok:
        raise C.WinError(C.get_last_error())

def capture(command, cwd, wanted, timeout=60):
    executable = (Path(cwd) / command[0]).resolve()
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    if digest != COMPILER_SHA256:
        raise ValueError("unrecognized compiler; internal addresses are build-specific")
    pi = ProcessInfo()
    threads = {}
    handles = set()
    snapshots = []
    names = set()
    exit_code = None
    exit_continued = False
    breakpoint = None
    base = None

    def memory(address, size):
        result = C.create_string_buffer(size)
        count = SIZE()
        require(read(pi.process, address, result, size, C.byref(count)))
        if count.value != size:
            raise ValueError("short process memory read")
        return result.raw

    def word(address):
        return struct.unpack("<I", memory(address, 4))[0]

    def string(address):
        value = bytearray()
        for i in range(512):
            byte = memory(address + i, 1)
            if byte == b"\0":
                return value.decode("ascii", errors="replace")
            value += byte
        raise ValueError("unterminated debug-hook argument")

    with tempfile.TemporaryFile() as log, open(os.devnull, "rb") as stdin:
        log_handle = msvcrt.get_osfhandle(log.fileno())
        stdin_handle = msvcrt.get_osfhandle(stdin.fileno())
        os.set_handle_inheritable(log_handle, True)
        os.set_handle_inheritable(stdin_handle, True)
        startup = Startup(cb=C.sizeof(Startup), flags=0x101, show=0,
                          stdin=stdin_handle, stdout=log_handle, stderr=log_handle)
        require(create(str(executable), C.create_unicode_buffer(subprocess.list2cmdline(command)),
                       None, None, True, 0x08000002, None, str(cwd), C.byref(startup), C.byref(pi)))
        handles.update((pi.process, pi.thread))
        deadline = time.monotonic() + timeout
        pending = None
        startup_breakpoints = set()
        try:
            while exit_code is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"compiler debug capture exceeded {timeout} seconds")
                event = Event()
                if not wait(C.byref(event), 1000):
                    if C.get_last_error() == 121:
                        continue
                    require(False)
                pending = event
                status = 0x10002
                if event.code == 3:
                    data = event.info.create
                    base = data.base
                    breakpoint = base + 0xFF2D0
                    threads[event.tid] = data.thread
                    # WaitForDebugEvent's process/thread handles are closed by
                    # Windows on continued exit events, unlike pi's handles.
                    # https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent
                    if data.file:
                        close(data.file)
                    if memory(breakpoint, 1) != b"\xc3":
                        raise ValueError("backend dump hook is not the expected empty return")
                    count = SIZE()
                    require(write(pi.process, breakpoint, b"\xcc", 1, C.byref(count)))
                    if count.value != 1:
                        raise ValueError("short breakpoint write")
                    require(flush(pi.process, breakpoint, 1))
                elif event.code == 2:
                    threads[event.tid] = event.info.thread.thread
                elif event.code == 4:
                    threads.pop(event.tid, None)
                elif event.code == 6:
                    if event.info.file:
                        close(event.info.file)
                elif event.code == 5:
                    exit_code = event.info.exitCode
                elif event.code == 1:
                    exception = event.info.exception.record
                    if exception.address == breakpoint and exception.code in (0x80000003, 0x4000001F):
                        context = Context(flags=0x10007)
                        require(getcontext(threads[event.tid], C.byref(context)))
                        if context.eip != breakpoint + 1:
                            raise ValueError("unexpected instruction pointer at dump breakpoint")
                        name = string(word(context.esp + 4))
                        stage = string(word(context.esp + 8))
                        names.add(name)
                        if name in wanted:
                            snapshots.append(capture_snapshot(memory, name, stage, word(base + 0x1E67B0)))
                        # Emulate only the disabled dump hook's verified one-byte RET.
                        context.eip = word(context.esp)
                        context.esp += 4
                        require(setcontext(threads[event.tid], C.byref(context)))
                    elif (exception.code in (0x80000003, 0x4000001F)
                          and exception.code not in startup_breakpoints):
                        startup_breakpoints.add(exception.code)
                    else:
                        status = 0x80010001
                require(resume(event.pid, event.tid, status))
                if event.code == 5:
                    exit_continued = True
                pending = None
        finally:
            terminated = True
            detached = False
            if not exit_continued:
                terminated = bool(terminate(pi.process, 1))
                # Termination still produces debug events; drain them so the
                # child can exit even when capture failed while it was stopped.
                cleanup_deadline = time.monotonic() + 10
                while not exit_continued and time.monotonic() < cleanup_deadline:
                    if pending is None:
                        event = Event()
                        if not wait(C.byref(event), 100):
                            continue
                        pending = event
                        if event.code == 6 and event.info.file:
                            close(event.info.file)
                        elif event.code == 3 and event.info.create.file:
                            close(event.info.create.file)
                    if resume(pending.pid, pending.tid, 0x10002):
                        exit_continued = pending.code == 5
                        pending = None
                    else:
                        # An uncontinued event is still pending. Waiting for a
                        # different one cannot make progress until it is resumed.
                        time.sleep(0.01)
                if not exit_continued:
                    detached = bool(detach(pi.pid))
            waited = waitprocess(pi.process, 1000)
            for handle in handles:
                close(handle)
            if waited != 0 or not (exit_continued or detached):
                raise RuntimeError(f"incomplete compiler teardown: terminate={terminated}, "
                                   f"exit_continued={exit_continued}, detached={detached}, wait={waited:#x}")
        log.seek(0)
        output = log.read().decode("utf-8", errors="replace")
    if exit_code != 0:
        raise RuntimeError(f"compiler failed ({exit_code}):\n{output}")
    if not snapshots:
        raise RuntimeError("no requested dump points; names=" + repr(sorted(names)))
    return snapshots, output
