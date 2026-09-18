"""Observe GC/1.3 data-pool assignment through macOS LLDB.

Hooks emulate only the replaced x86 instructions. The runner compares the
complete traced object with an ordinary compile before accepting the trace.
"""

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STATE = None
HOOKS = {0x4B315D: b"\x89\xf8", 0x4D0171: b"\x8b\x07", 0x4D0180: b"\x31\xc0"}


class State:
    def __init__(self, debugger, output, function):
        import lldb

        self.api = lldb
        self.target = debugger.GetSelectedTarget()
        self.process = self.target.GetProcess()
        self.output = Path(output)
        self.function = function
        self.events = []
        self.failure = None
        (self.output / "guest.pid").write_text(str(self.process.GetProcessID()))
        for address, expected in HOOKS.items():
            if self.read(address, len(expected)) != expected:
                raise ValueError(f"Unexpected hook bytes at {address:#x}")
            bp = self.target.BreakpointCreateByAddress(address)
            bp.SetScriptCallbackFunction("mwcc_data_pool_trace.on_breakpoint")

    def read(self, address, size):
        error = self.api.SBError()
        value = self.process.ReadMemory(address, size, error)
        if error.Fail() or len(value) != size:
            raise ValueError(f"Cannot read {address:#x}: {error}")
        return value

    def word(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def string(self, address):
        if not address:
            return None
        error = self.api.SBError()
        value = self.process.ReadCStringFromMemory(address, 512, error)
        if error.Fail():
            raise ValueError(f"Cannot read string at {address:#x}: {error}")
        return value

    def symbol(self, address):
        if not address:
            return None
        return {"address": address, "name": self.string(self.word(address + 10) + 10),
                "kind": self.read(address + 2, 1)[0],
                "flags": self.word(address + 18)}

    def stopped(self, frame):
        pc = frame.GetPC()
        reg = lambda name: frame.FindRegister(name).GetValueAsUnsigned() & 0xFFFFFFFF
        if pc == 0x4B315D:
            symbol, section = reg("rbp"), reg("rdi")
            pool = self.word(section + 0x14)
            self.events.append({"kind": "assign", "symbol": self.symbol(symbol),
                                "section": self.string(self.word(section + 0x1C)),
                                "section_size_before": self.word(section + 0x28),
                                "pool": self.symbol(self.word(pool)) if pool else None,
                                "anchor": self.symbol(self.word(pool + 4)) if pool else None})
            result = section
        else:
            sp = reg("rsp")
            symbol = self.word(sp + 0x1C)
            function = self.word(0x5E6610)
            function_name = self.symbol(function)["name"] if function else None
            result = self.word(reg("rdi")) if pc == 0x4D0171 else 0
            if function_name == self.function:
                self.events.append({"kind": "lookup", "function": function_name,
                                    "symbol": self.symbol(symbol), "pool": self.symbol(result)})
        if not frame.FindRegister("rax").SetValueFromCString(str(result)):
            raise ValueError("Cannot emulate hook result")
        if pc == 0x4D0180:
            # XOR EAX,EAX clears CF/OF/SF and sets ZF/PF. AF is undefined.
            flags = reg("rflags")
            if not frame.FindRegister("rflags").SetValueFromCString(str((flags & ~0x8C5) | 0x44)):
                raise ValueError("Cannot emulate XOR flags")
        if not frame.SetPC(pc + len(HOOKS[pc])):
            raise ValueError("Cannot advance hook")


def on_breakpoint(frame, bp_loc, internal_dict):
    try:
        STATE.stopped(frame)
        return False
    except Exception as exc:
        STATE.failure = str(exc)
        print("Data-pool capture failed:", exc)
        return True


def install(debugger, output, function="gameTextGet"):
    global STATE
    STATE = State(debugger, output, function)


def finish(debugger):
    if STATE.failure:
        raise ValueError(STATE.failure)
    if STATE.process.GetState() != STATE.api.eStateExited or STATE.process.GetExitStatus() != 0:
        raise ValueError("Compiler did not exit successfully")
    if not any(event["kind"] == "lookup" for event in STATE.events):
        raise ValueError(f"No {STATE.function} pool lookups were captured")
    (STATE.output / "events.json").write_text(json.dumps(STATE.events, indent=2) + "\n")


def main():
    import argparse
    import flag_probe
    from compiler_command import split_command_line
    from tricky_source_order_probe import compile_command
    from mwcc_backend_capture_lldb import _stop_timed_out_capture
    from tricky_backend_ir import COMPILER_SHA256

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", default="main/main/gametext")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--function", default="gameTextGet", help="function whose pool lookups to capture")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin" or not shutil.which("lldb"):
        parser.error("capture requires macOS LLDB and Wibo")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    base = split_command_line(flag_probe.base_cmd(args.unit))
    source = args.source or ROOT / base[base.index("-c") + 1]
    ordinary, traced = output / "ordinary", output / "traced"
    for directory in (ordinary, traced):
        directory.mkdir(exist_ok=True)
        (directory / source.with_suffix(".o").name).unlink(missing_ok=True)
    compiler = next(arg for arg in base if Path(arg).name == "mwcceppc.exe")
    if hashlib.sha256((ROOT / compiler).read_bytes()).hexdigest() != COMPILER_SHA256:
        raise ValueError("Compiler differs from the audited GC/1.3 executable")
    subprocess.run(compile_command(base, source, ordinary), cwd=ROOT, check=True,
                   capture_output=True, timeout=30)
    command = compile_command(base, source, traced)
    compiler_index = command.index(compiler)
    commands = ["settings set target.disable-aslr false",
                "breakpoint set --func-regex loadPEFromSource", "run",
                "breakpoint disable 1", "thread step-out",
                "command script import " + json.dumps(str(Path(__file__).resolve())),
                f"script mwcc_data_pool_trace.install(lldb.debugger, {str(output)!r}, {args.function!r})",
                "continue", "script mwcc_data_pool_trace.finish(lldb.debugger)"]
    launch = [shutil.which("lldb"), "--batch", "--one-line-on-crash", "process kill"]
    for item in commands:
        launch.extend(["-o", item])
    launch.extend(["--", str(ROOT / "build/tools/wibo"), *command[compiler_index:]])
    for name in ("events.json", "guest.pid"):
        (output / name).unlink(missing_ok=True)
    with (output / "lldb.log").open("w") as log:
        process = subprocess.Popen(launch, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            _stop_timed_out_capture(process, output / "guest.pid", command)
            raise TimeoutError("Data-pool capture exceeded 60 seconds") from None
    if process.returncode or not (output / "events.json").is_file():
        raise ValueError("Data-pool capture failed; inspect lldb.log")
    normal_bytes = (ordinary / source.with_suffix(".o").name).read_bytes()
    traced_bytes = (traced / source.with_suffix(".o").name).read_bytes()
    if normal_bytes != traced_bytes:
        raise ValueError("Data-pool instrumentation changed the object")
    manifest = {"compiler_sha256": COMPILER_SHA256,
                "object_sha256": hashlib.sha256(normal_bytes).hexdigest(),
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "command": command}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Ordinary/traced object SHA256:", manifest["object_sha256"])
    print("Data-pool events:", len(json.loads((output / "events.json").read_text())))


if __name__ == "__main__":
    main()
