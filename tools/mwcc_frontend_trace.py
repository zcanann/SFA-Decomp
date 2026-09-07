"""Observe GC/1.3's otherwise-disabled frontend IR listings using macOS LLDB.

Only diagnostic gates in a private compiler process are changed. An ordinary
compile must produce an identical object. Compiler files and build flags are
not modified. The frontend listing describes reconstructed source, not retail.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from tricky_backend_ir import COMPILER_SHA256


ROOT = Path(__file__).resolve().parents[1]
OPEN = 0x454030
DUMP = 0x454320
DUMP_RETURN = 0x454368
_state = None


class State:
    def __init__(self, debugger, wanted, pid_file):
        import lldb

        self.api = lldb
        self.target = debugger.GetSelectedTarget()
        self.process = self.target.GetProcess()
        Path(pid_file).write_text(str(self.process.GetProcessID()))
        self.wanted = set(wanted)
        self.stages = []
        self.failure = None
        if self.read(DUMP_RETURN, 1) != b"\xc3":
            raise ValueError("unexpected frontend listing return")
        for address, expected in [(OPEN, b"\x57"), (DUMP, b"\x80\x7c\x24\x08\x00\x74\x41")]:
            if self.read(address, len(expected)) != expected:
                raise ValueError(f"unexpected frontend hook bytes at {address:#x}")
            bp = self.target.BreakpointCreateByAddress(address)
            bp.SetScriptCallbackFunction("mwcc_frontend_trace.on_breakpoint")

    def read(self, address, size):
        error = self.api.SBError()
        data = self.process.ReadMemory(address, size, error)
        if error.Fail() or len(data) != size:
            raise ValueError(f"short frontend read at {address:#x}: {error}")
        return data

    def word(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def write(self, address, data):
        error = self.api.SBError()
        count = self.process.WriteMemory(address, data, error)
        if error.Fail() or count != len(data):
            raise ValueError(f"short frontend diagnostic write at {address:#x}")

    def string(self, address):
        error = self.api.SBError()
        value = self.process.ReadCStringFromMemory(address, 512, error)
        if error.Fail() or len(value) >= 511:
            raise ValueError("invalid frontend listing string")
        return value

    def stopped(self, frame):
        sp = frame.FindRegister("rsp").GetValueAsUnsigned()
        if not 4 <= sp <= 0xFFFFFFFB:
            raise ValueError("frontend stack is outside the 32-bit guest")
        if frame.GetPC() == OPEN:
            # The caller hard-codes this listing-only gate to zero. Enable it
            # before the compiler opens <source>.log, then emulate PUSH EDI.
            self.write(0x5E7401, b"\x01")
            edi = frame.FindRegister("rdi").GetValueAsUnsigned() & 0xFFFFFFFF
            self.write(sp - 4, struct.pack("<I", edi))
            if not frame.FindRegister("rsp").SetValueFromCString(str(sp - 4)) or not frame.SetPC(OPEN + 1):
                raise ValueError("cannot emulate the frontend listing prologue")
        elif frame.GetPC() == DUMP:
            function = self.word(0x5E6610)
            name = self.string(self.word(function + 0xA) + 0xA) if function else "Init-code"
            if name in self.wanted:
                self.stages.append((name, self.string(self.word(sp + 4))))
                # Skip only the disabled second-argument gate. The compiler's
                # own listing routine reads and formats its frontend records.
                destination = DUMP + 7
            else:
                destination = DUMP_RETURN
            if not frame.SetPC(destination):
                raise ValueError("cannot enter the frontend listing body")
        else:
            raise ValueError("unrecognized frontend hook")


def install(debugger, wanted, pid_file):
    global _state
    _state = State(debugger, wanted, pid_file)


def on_breakpoint(frame, location, internal_dict):
    try:
        _state.stopped(frame)
        return False
    except Exception as error:
        _state.failure = str(error)
        print("Frontend capture failed:", error, flush=True)
        return True


def finish(debugger, result):
    process = debugger.GetSelectedTarget().GetProcess()
    if (_state is None or _state.failure or process.GetState() != _state.api.eStateExited
            or process.GetExitStatus() != 0):
        process.Kill()
        raise RuntimeError("frontend capture did not finish normally")
    found = {name for name, stage in _state.stages if stage == "After IRO_Optimizer"}
    if found != _state.wanted:
        raise ValueError(f"missing frontend final stages: {_state.wanted - found}")
    Path(result).write_text(json.dumps(_state.stages, indent=2))


def main():
    import flag_probe
    from compiler_command import split_command_line
    from tricky_source_order_probe import compile_command
    from mwcc_backend_capture_lldb import _stop_timed_out_capture

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--function", required=True, action="append")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=60, help="LLDB deadline in seconds (maximum 60)")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("capture requires macOS LLDB and Wibo")
    if not 0 < args.timeout <= 60:
        parser.error("timeout must be between zero and 60 seconds")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    base = split_command_line(flag_probe.base_cmd(args.unit))
    original = args.source or ROOT / base[base.index("-c") + 1]
    source = output / original.name
    if source == original.resolve():
        parser.error("output must be separate from the input source")
    stages = output / "stages.json"
    pid = output / "guest.pid"
    manifest = output / "manifest.json"
    for artifact in [stages, pid, manifest]:
        artifact.unlink(missing_ok=True)
    shutil.copyfile(original, source)
    source.with_suffix(".log").unlink(missing_ok=True)
    normal, traced = output / "normal", output / "traced"
    normal.mkdir(exist_ok=True)
    traced.mkdir(exist_ok=True)
    for directory in [normal, traced]:
        (directory / source.with_suffix(".o").name).unlink(missing_ok=True)
    command = compile_command(base, source, normal)
    subprocess.run(command, cwd=ROOT, capture_output=True, check=True, timeout=30)
    command = compile_command(base, source, traced)
    compiler_index = next(i for i, arg in enumerate(command) if Path(arg).name == "mwcceppc.exe")
    compiler = ROOT / command[compiler_index]
    if hashlib.sha256(compiler.read_bytes()).hexdigest() != COMPILER_SHA256:
        raise ValueError("compiler is not the hash-checked GC/1.3 profile")
    commands = [
        "settings set target.disable-aslr false",
        "breakpoint set --func-regex loadPEFromSource", "run", "breakpoint disable 1", "thread step-out",
        "command script import " + json.dumps(str(Path(__file__).resolve())),
        f"script mwcc_frontend_trace.install(lldb.debugger, {args.function!r}, {str(pid)!r})",
        "continue", f"script mwcc_frontend_trace.finish(lldb.debugger, {str(stages)!r})",
    ]
    debugger = shutil.which("lldb")
    if not debugger:
        raise RuntimeError("LLDB is not installed")
    launch = [debugger, "--batch", "--one-line-on-crash", "process kill"]
    for item in commands:
        launch.extend(["-o", item])
    launch.extend(["--", str(ROOT / "build/tools/wibo"), *command[compiler_index:]])
    with (output / "lldb.log").open("w") as log:
        process = subprocess.Popen(launch, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            _stop_timed_out_capture(process, pid, command)
            raise TimeoutError(f"frontend capture exceeded {args.timeout} seconds; inspect lldb.log") from None
    if process.returncode:
        raise RuntimeError("LLDB frontend capture failed; inspect lldb.log")
    if not stages.exists():
        raise ValueError("frontend trace was not completed; inspect lldb.log")
    before = (normal / source.with_suffix(".o").name).read_bytes()
    after = (traced / source.with_suffix(".o").name).read_bytes()
    if before != after:
        raise ValueError("frontend instrumentation changed the output object")
    listing = source.with_suffix(".log")
    if not listing.is_file() or not listing.stat().st_size:
        raise ValueError("compiler did not produce a frontend listing")
    object_hash = hashlib.sha256(after).hexdigest()
    manifest.write_text(json.dumps({
        "schema": 1, "unit": args.unit, "functions": sorted(set(args.function)),
        "compiler_sha256": COMPILER_SHA256, "object_sha256": object_hash,
        "source": str(original), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "command": command, "stages": str(stages), "listing": str(listing),
        "listing_sha256": hashlib.sha256(listing.read_bytes()).hexdigest(),
    }, indent=2) + "\n")
    print("Instrumented/ordinary raw object SHA256:", object_hash)
    print("Captured frontend stages:", len(json.loads(stages.read_text())))
    print("Frontend listing:", source.with_suffix(".log"))


if __name__ == "__main__":
    main()
