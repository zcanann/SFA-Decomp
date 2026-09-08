"""Capture the GC/1.3 dump hook through GDB and Wibo on Linux.

This is a provider for tricky_backend_trace.py, the Linux counterpart of
mwcc_backend_capture_lldb.py. Only a private compiler process is instrumented;
the caller must require ordinary/traced object equivalence.

The PE image is found by catching mmap system calls until the dump hook's
byte is readable, so no Wibo symbol or hardware breakpoint is needed and the
image is guaranteed to be mapped before the hook breakpoints are installed.
The disabled RET and the graph PUSH EBX are emulated by hand, as in the LLDB
provider.
"""

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tricky_backend_ir import COMPILER_SHA256, capture_snapshot
from tricky_backend_graph import capture_graph_snapshot, register_kind


BASE = 0x400000
DUMP = BASE + 0xFF2D0
GRAPH = {BASE + 0x107070: "BEFORE GPR SIMPLIFICATION",
         BASE + 0x106E20: "BEFORE GPR REWRITE"}


def pe_entry_point(executable):
    data = Path(executable).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("compiler is not a PE image")
    optional = pe + 24
    entry = struct.unpack_from("<I", data, optional + 16)[0]
    base = struct.unpack_from("<I", data, optional + 28)[0]
    if base != BASE:
        raise ValueError(f"unexpected PE image base {base:#x}")
    return base + entry


# ---------------------------------------------------------------- gdb side --

def _gdb_read(address, size):
    import gdb
    data = gdb.selected_inferior().read_memory(address, size).tobytes()
    if len(data) != size:
        raise ValueError("short process memory read")
    return data


def _page_reader():
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
                pages[page] = _gdb_read(page, 4096)
            result += pages[page][offset:offset + count]
            address += count
            size -= count
        return bytes(result)

    return memory


def _gdb_register(name):
    import gdb
    return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF


def _gdb_string(address):
    value = bytearray()
    for i in range(512):
        byte = _gdb_read(address + i, 1)
        if byte == b"\0":
            return value.decode("ascii", errors="replace")
        value += byte
    raise ValueError("unterminated dump-hook argument")


def _capture_main(job_path):
    """Run inside gdb: start the compiler, arm the hooks once the image is mapped, then collect dumps."""
    import gdb

    job = json.loads(Path(job_path).read_text())
    wanted = set(job["functions"])
    register_class = job.get("register_class", 4)
    register_kind(register_class)
    hooks = {DUMP: b"\xc3"}
    if job["graph"]:
        hooks.update({address: b"\x53" for address in GRAPH})
    # Wibo maps the PE image with mmap; stop at each mmap until the hook
    # address is readable, then arm the hook breakpoints on the live image.
    gdb.execute("catch syscall mmap", to_string=True)
    gdb.execute("run", to_string=True)
    for _ in range(4096):
        inferior = gdb.selected_inferior()
        if not inferior.is_valid() or not inferior.threads():
            raise RuntimeError("compiler exited before the PE image was mapped")
        try:
            if _gdb_read(DUMP, 1) == b"\xc3":
                break
        except gdb.MemoryError:
            pass
        gdb.execute("continue", to_string=True)
    else:
        raise RuntimeError("PE image never became readable")
    gdb.execute("delete", to_string=True)
    for address, expected in hooks.items():
        if _gdb_read(address, 1) != expected:
            raise ValueError(f"unexpected compiler hook byte at {address:#x}")
        gdb.Breakpoint(f"*{address:#x}", internal=True)

    snapshots, names, current_name = [], set(), None
    while True:
        gdb.execute("continue", to_string=True)
        inferior = gdb.selected_inferior()
        if not inferior.is_valid() or not inferior.threads():
            break
        pc, sp = _gdb_register("pc"), _gdb_register("sp")
        memory = _page_reader()
        word = lambda address: struct.unpack("<I", memory(address, 4))[0]
        if pc == DUMP:
            name, stage = _gdb_string(word(sp + 4)), _gdb_string(word(sp + 8))
            names.add(name)
            current_name = name
            if name in wanted:
                snapshot = capture_snapshot(memory, name, stage, word(BASE + 0x1E67B0))
                snapshot["immediate_commoning"] = {
                    "first_register": int.from_bytes(memory(BASE + 0x1E7260, 2), "little", signed=True),
                    "last_register": int.from_bytes(memory(BASE + 0x1E66B8, 4), "little", signed=True),
                }
                snapshots.append(snapshot)
            # Emulate only the disabled dump hook's verified one-byte RET.
            gdb.execute(f"set $pc = {word(sp)}")
            gdb.execute(f"set $sp = {sp + 4}")
        elif pc in GRAPH:
            if current_name in wanted and memory(BASE + 0x1E7317, 1) == bytes([register_class]):
                snapshots.append(capture_graph_snapshot(memory, BASE, current_name,
                                                        pc == BASE + 0x106E20, register_class))
            try:
                ebx = _gdb_register("ebx")
            except gdb.error:
                ebx = _gdb_register("rbx")
            # Execute the verified PUSH EBX's exact stack effect.
            inferior.write_memory(sp - 4, struct.pack("<I", ebx & 0xFFFFFFFF))
            gdb.execute(f"set $sp = {sp - 4}")
            gdb.execute(f"set $pc = {pc + 1}")
        else:
            raise ValueError(f"unexpected stop at {pc:#x}")
    Path(job["result"]).write_text(json.dumps({"snapshots": snapshots, "names": sorted(names)}))


# --------------------------------------------------------------- host side --

def capture(command, cwd, wanted, graph=False, timeout=120, register_class=4):
    register_kind(register_class)
    if not sys.platform.startswith("linux"):
        raise RuntimeError("GDB capture requires Linux and Wibo")
    cwd = Path(cwd).resolve()
    executable = (cwd / command[0]).resolve()
    if hashlib.sha256(executable.read_bytes()).hexdigest() != COMPILER_SHA256:
        raise ValueError("compiler does not match the GC/1.3 capture profile")
    pe_entry_point(executable)
    with tempfile.TemporaryDirectory(prefix="mwcc-gdb-") as scratch:
        scratch = Path(scratch)
        result, job_path = scratch / "snapshots.json", scratch / "job.json"
        job_path.write_text(json.dumps({"functions": sorted(wanted), "graph": graph,
                                        "register_class": register_class, "result": str(result)}))
        commands = ["set pagination off", "set confirm off", "set disable-randomization on",
                    "source " + str(Path(__file__).resolve()),
                    f"python _capture_main({str(job_path)!r})"]
        args = ["gdb", "-batch", "-nx", "-q"]
        for item in commands:
            args.extend(["-ex", item])
        args.extend(["--args", str(cwd / "build/tools/wibo"), *command])
        try:
            process = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError(f"GDB compiler capture exceeded {timeout} seconds") from error
        output = process.stdout + process.stderr
        if process.returncode or not result.exists():
            raise RuntimeError("GDB compiler capture failed:\n" + output[-6000:])
        data = json.loads(result.read_text())
    if not data["snapshots"]:
        raise RuntimeError("no requested dump points; names=" + repr(data["names"]))
    return data["snapshots"], output
