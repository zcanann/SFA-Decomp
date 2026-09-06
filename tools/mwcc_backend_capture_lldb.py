"""Capture the GC/1.3 dump hook through macOS LLDB and Wibo.

This is a provider for tricky_backend_trace.py. Only a private compiler process
is instrumented; the caller must require ordinary/traced object equivalence.
The disabled RET and graph PUSH EBX are emulated as 32-bit instructions because
LLDB sees Wibo's host as x86-64, including when it runs under Rosetta.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tricky_backend_ir import COMPILER_SHA256, capture_snapshot
from tricky_backend_graph import capture_graph_snapshot, register_kind


BASE = 0x400000
DUMP = BASE + 0xFF2D0
GRAPH = {BASE + 0x107070: "BEFORE GPR SIMPLIFICATION",
         BASE + 0x106E20: "BEFORE GPR REWRITE"}
_state = None


def emulate_hook(pc, sp, ebx, word, write_word):
    """Return the exact next ESP/EIP, writing only PUSH EBX's stack slot."""
    if not 4 <= sp <= 0xFFFFFFFB:
        raise ValueError("hook stack pointer is outside the 32-bit guest")
    if pc == DUMP:
        destination = word(sp)
        if not BASE <= destination < BASE + 0x20B000:
            raise ValueError("dump-hook return is outside the compiler image")
        return sp + 4, destination
    if pc in GRAPH:
        write_word(sp - 4, ebx & 0xFFFFFFFF)
        return sp - 4, pc + 1
    raise ValueError("unrecognized compiler hook")


def page_reader(read):
    """Cache memory only for one stopped-process callback."""
    pages = {}

    def memory(address, size):
        if address < 0 or size < 0 or address + size > 0x100000000:
            raise ValueError("memory range is outside the 32-bit guest")
        result = bytearray()
        while size:
            page = address & ~4095
            offset = address - page
            count = min(size, 4096 - offset)
            if page not in pages:
                data = read(page, 4096)
                if len(data) != 4096:
                    raise ValueError("short process page read")
                pages[page] = data
            result += pages[page][offset:offset + count]
            address += count
            size -= count
        return bytes(result)

    return memory


class CaptureState:
    def __init__(self, debugger, job):
        import lldb

        self.api = lldb
        self.job = job
        self.target = debugger.GetSelectedTarget()
        self.process = self.target.GetProcess()
        self.wanted = set(job["functions"])
        self.snapshots = []
        self.current_name = None
        self.failure = None
        Path(job["pid"]).write_text(str(self.process.GetProcessID()))
        memory = page_reader(self.read)
        hooks = {DUMP: b"\xc3"}
        if job["graph"]:
            hooks.update({address: b"\x53" for address in GRAPH})
        for address, expected in hooks.items():
            if memory(address, 1) != expected:
                raise ValueError(f"unexpected compiler hook byte at {address:#x}")
            breakpoint = self.target.BreakpointCreateByAddress(address)
            breakpoint.SetScriptCallbackFunction("mwcc_backend_capture_lldb._on_breakpoint")

    def read(self, address, size):
        error = self.api.SBError()
        data = self.process.ReadMemory(address, size, error)
        if error.Fail() or len(data) != size:
            raise ValueError(f"process memory read at {address:#x}: {error}")
        return data

    def write_word(self, address, value):
        error = self.api.SBError()
        count = self.process.WriteMemory(address, struct.pack("<I", value), error)
        if error.Fail() or count != 4:
            raise ValueError("short emulated stack write")

    def string(self, address):
        error = self.api.SBError()
        value = self.process.ReadCStringFromMemory(address, 512, error)
        if error.Fail() or len(value) >= 511:
            raise ValueError("invalid dump-hook string")
        return value

    def stopped(self, frame):
        memory = page_reader(self.read)
        word = lambda address: int.from_bytes(memory(address, 4), "little")
        pc = frame.GetPC()
        sp = frame.FindRegister("rsp").GetValueAsUnsigned()
        if pc == DUMP:
            self.current_name = self.string(word(sp + 4))
            stage = self.string(word(sp + 8))
            if self.current_name in self.wanted:
                snapshot = capture_snapshot(memory, self.current_name, stage, word(BASE + 0x1E67B0))
                snapshot["immediate_commoning"] = {
                    "first_register": int.from_bytes(memory(BASE + 0x1E7260, 2), "little", signed=True),
                    "last_register": int.from_bytes(memory(BASE + 0x1E66B8, 4), "little", signed=True),
                }
                self.snapshots.append(snapshot)
        elif (self.current_name in self.wanted
              and memory(BASE + 0x1E7317, 1) == bytes([self.job.get("register_class", 4)])):
            snapshot = capture_graph_snapshot(memory, BASE, self.current_name,
                                              pc == BASE + 0x106E20, self.job.get("register_class", 4))
            self.snapshots.append(snapshot)
        sp, pc = emulate_hook(pc, sp, frame.FindRegister("rbx").GetValueAsUnsigned(), word, self.write_word)
        if not frame.FindRegister("rsp").SetValueFromCString(str(sp)) or not frame.SetPC(pc):
            raise ValueError("cannot emulate 32-bit compiler hook")


def _install(debugger, job_path):
    global _state
    _state = CaptureState(debugger, json.loads(Path(job_path).read_text()))


def _on_breakpoint(frame, location, internal_dict):
    try:
        _state.stopped(frame)
        return False
    except Exception as error:
        _state.failure = f"{type(error).__name__}: {error}"
        print(_state.failure, flush=True)
        return True


def _finish(debugger):
    process = debugger.GetSelectedTarget().GetProcess()
    if (_state is None or _state.failure or process.GetState() != _state.api.eStateExited
            or process.GetExitStatus() != 0):
        process.Kill()
        raise RuntimeError("compiler capture did not exit normally")
    found = {snapshot["name"] for snapshot in _state.snapshots if snapshot["stage"] == "FINAL CODE"}
    if found != _state.wanted:
        raise ValueError(f"missing final snapshots: {_state.wanted - found}")
    Path(_state.job["result"]).write_text(json.dumps(_state.snapshots))


def _stop_timed_out_capture(process, pid_file, command):
    """Kill only the recorded guest with this capture's unique output path."""
    try:
        pid = int(pid_file.read_text())
        if pid <= 1:
            raise ValueError("invalid guest PID")
        args = subprocess.run(["ps", "-p", str(pid), "-o", "args="],
                              capture_output=True, text=True, timeout=2).stdout
        output = command[command.index("-o") + 1]
        if str(output) in args and "wibo" in args:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def capture(command, cwd, wanted, graph=False, timeout=60, register_class=4):
    register_kind(register_class)
    if sys.platform != "darwin":
        raise RuntimeError("LLDB capture requires macOS and Wibo")
    cwd = Path(cwd).resolve()
    executable = (cwd / command[0]).resolve()
    if hashlib.sha256(executable.read_bytes()).hexdigest() != COMPILER_SHA256:
        raise ValueError("compiler does not match the GC/1.3 capture profile")
    debugger = shutil.which("lldb")
    if not debugger:
        raise RuntimeError("lldb is not installed")
    with tempfile.TemporaryDirectory(prefix="mwcc-lldb-") as scratch:
        scratch = Path(scratch)
        result, pid, job_path = scratch / "snapshots.json", scratch / "pid", scratch / "job.json"
        job_path.write_text(json.dumps({"functions": sorted(wanted), "graph": graph, "register_class": register_class,
                                        "result": str(result), "pid": str(pid)}))
        # Install guest breakpoints only after Wibo has mapped the PE image.
        commands = ["settings set target.disable-aslr false", "breakpoint set --func-regex loadPEFromSource",
                    "run", "breakpoint disable 1", "thread step-out",
                    "command script import " + json.dumps(str(Path(__file__).resolve())),
                    f"script mwcc_backend_capture_lldb._install(lldb.debugger, {str(job_path)!r})",
                    "continue", "script mwcc_backend_capture_lldb._finish(lldb.debugger)"]
        args = [debugger, "--batch", "--one-line-on-crash", "process kill"]
        for item in commands:
            args.extend(["-o", item])
        args.extend(["--", str(cwd / "build/tools/wibo"), *command])
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen(args, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _stop_timed_out_capture(process, pid, command)
                raise TimeoutError(f"LLDB compiler capture exceeded {timeout} seconds") from None
            log.seek(0)
            output = log.read()
        if process.returncode or not result.exists():
            raise RuntimeError("LLDB compiler capture failed:\n" + output[-6000:])
        return json.loads(result.read_text()), output
