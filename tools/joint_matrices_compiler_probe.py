#!/usr/bin/env python3
"""Probe stock MWCC features relevant to the joint-matrix function shape.

Uses the configured render compile command with isolated inputs/outputs. The
assembly case is a diagnostic positive control, never production game source.
Compiler hashes, commands, diagnostics and disassembly are retained under build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import subprocess

from compiler_command import split_command_line

ROOT = Path(__file__).resolve().parents[1]
GC13_SHA256 = "4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715"

CASES = {
    "nested_c": "int outer(int x) { int inner(int y) { return x + y; } return inner(2); }",
    "local_class": "int outer(int x) { struct Local { static int inner(int y) { return y + 2; } }; return Local::inner(x); }",
    "naked_declspec": "__declspec(naked) int outer(int x) { return x + 2; }",
    "naked_attribute": "__attribute__((naked)) int outer(int x) { return x + 2; }",
    "computed_goto": "int outer(int x) { void* p = &&target; goto *p; target: return x; }",
    "mcrxr_intrinsic": "void outer(void) { __mcrxr(0); }",
    "psq_load_intrinsic": "float outer(const short* p) { return __psq_l(p, 1, 5); }",
    "psq_store_intrinsic": "void outer(float f, short* p) { __psq_st(f, p, 1, 5); }",
    "paired_madd_intrinsic": "float outer(float a, float b, float c) { return __ps_madds0(a, b, c); }",
    "known_intrinsics": "float outer(float a, float b, float c) { return __fmadds(a, b, c); }\n"
                        "int count(unsigned n) { return __cntlzw(n); }",
    "alloca_constant": "extern void consume(void*); void outer(void) { consume(__alloca(252)); }",
    "interrupt": "extern void consume(void*); __declspec(interrupt) void outer(void) { char b[252]; consume(b); }",
    "rtos_stack": "void outer(void* stack) { __rtos_change_stack(stack); __rtos_pop_stack(); }",
    "conversions": "float signed_load(const short* p) { return *p; }\n"
                   "float unsigned_load(const unsigned short* p) { return *p; }\n"
                   "unsigned short quantize(float x) { return (unsigned short)x; }\n"
                   "int decrement(int n) { int s=0; while (--n) { s+=n; } return s; }\n",
    "asm_control": "asm void outer(void) {\n nofralloc\n mflr r0\n stwu r1,-0xfc(r1)\n"
                   " stw r0,0x100(r1)\n bl helper\n b done\n helper:\n mflr r29\n"
                   " stwu r1,-0x34(r1)\n mcrxr cr0\n addme. r11,r11\n"
                   " psq_l f0,0(r3),1,5\n ps_madds0 f1,f2,f3,f4\n"
                   " addi r1,r1,0x34\n mtlr r29\n blr\n done:\n lwz r0,0x100(r1)\n"
                   " mtlr r0\n addi r1,r1,0xfc\n blr\n }\n",
}


def configured_command():
    text = subprocess.check_output(["ninja", "-t", "commands", "build/GSAE01/src/main/render.o"],
                                   cwd=ROOT, text=True, timeout=30)
    command = split_command_line(text.strip().splitlines()[-1])
    if "&&" in command:
        command = command[:command.index("&&")]
    return [arg for arg in command if arg != "-MMD"]


def audit_compiler(compiler):
    """Recheck the hash-pinned PE anchors recovered with Ghidra/objdump.

    This reads the executable; it never patches it. The byte scan only decodes
    the known push-string/call-intern pattern in the intrinsic initializer.
    It is not a general x86 disassembler or a proof of whole-program reachability.
    """
    data = compiler.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != GC13_SHA256:
        return {"compiler_sha256": digest, "mapped": False}
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
    sections = [struct.unpack_from("<IIII", data, pe + 24 + optional_size + 40 * i + 8)
                for i in range(count)]

    def read(va, size):
        rva = va - base
        for _, start, raw_size, offset in sections:
            if start <= rva and rva + size <= start + raw_size:
                return data[offset + rva - start:offset + rva - start + size]
        raise ValueError(f"unmapped compiler address {va:#x}")

    # frame = (frame + 15) & -16, followed by further requested alignment.
    expected = bytes.fromhex("a1 d6 cc 5d 00 83 c0 0f 83 e0 f0 2b 05 d6 cc 5d 00 01 05 d6 cc 5d 00")
    if read(0x4F82C7, len(expected)) != expected:
        raise ValueError("GC/1.3 frame-rounding anchor differs")
    names = []
    code = read(0x4C82F0, 0x4CB9D7 - 0x4C82F0)
    for offset in range(len(code) - 9):
        if code[offset] != 0x68 or code[offset + 5] != 0xE8:
            continue
        target = 0x4C82F0 + offset + 10 + struct.unpack_from("<i", code, offset + 6)[0]
        if target != 0x4415D0:
            continue
        address = struct.unpack_from("<I", code, offset + 1)[0]
        name = read(address, 128).split(b"\0", 1)[0].decode("ascii")
        names.append({"name": name, "string_va": hex(address), "registration_va": hex(0x4C82F0 + offset)})
    if len(names) != 315 or len({row["name"] for row in names}) != 315:
        raise ValueError(f"unexpected intrinsic registration count: {len(names)}")
    return {"compiler_sha256": digest, "mapped": True,
            "frame_rounding_va": "0x4f82c7", "frame_rounding_bytes": expected.hex(),
            "frame_size_va": "0x5dccd6", "intrinsics": names}


def inspect_disassembly(text):
    frames = []
    stack_updates = []
    instructions = []
    symbol = None
    for line in text.splitlines():
        match = re.match(r"[0-9a-f]+ <(.+)>:", line)
        if match:
            symbol = match[1]
        match = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)", line)
        if match:
            mnemonic, operands = match[2], match[3]
            instructions.append(mnemonic)
            if mnemonic in ("stwu", "stwux"):
                stack_updates.append({"function": symbol, "instruction": f"{mnemonic} {operands}"})
            if mnemonic == "stwu" and operands.startswith("r1,"):
                displacement = re.search(r"r1,(-?(?:0x[0-9a-f]+|\d+))\(r1\)", operands)
                if displacement:
                    frames.append({"function": symbol, "bytes": -int(displacement[1], 0)})
    return {"frames": frames, "mcrxr": instructions.count("mcrxr"),
            "update_stores": stack_updates,
            "instruction_counts": {op: instructions.count(op) for op in sorted(set(instructions))},
            "paired": {op: instructions.count(op) for op in sorted(set(instructions))
                       if op.startswith(("ps_", "psq_"))}}


def replace_options(command, extra, language):
    # MWCC accepts both -lang=c and -lang c. Do not depend on precedence of
    # repeated options (or let the inherited C setting invalidate C++ probes).
    remove = {"-lang"}
    remove.update(arg for arg in extra if arg.startswith("-") and arg != "-pragma")
    result = []
    i = 0
    while i < len(command):
        arg = command[i]
        if arg.split("=", 1)[0] in remove:
            i += 1 if "=" in arg or arg.startswith("-O") else 2
        elif any(flag.startswith("-O") for flag in extra) and arg.startswith("-O"):
            i += 1
        else:
            result.append(arg)
            i += 1
    return [*result, "-lang", language, *extra]


def run_case(base, output, version, name, source, extra=(), language="c"):
    directory = output / version.replace("/", "_") / name
    directory.mkdir(parents=True, exist_ok=True)
    src = directory / ("probe.cpp" if language == "c++" else "probe.c")
    src.write_text(source + "\n")
    obj = directory / "probe.o"
    obj.unlink(missing_ok=True)
    command = list(base)
    index = next(i for i, arg in enumerate(command) if Path(arg).name == "mwcceppc.exe")
    compiler = ROOT / "build/compilers" / version / "mwcceppc.exe"
    command[index] = str(compiler)
    command[command.index("-c") + 1] = str(src)
    command[command.index("-o") + 1] = str(obj)
    command = replace_options(command, extra, language)
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    (directory / "compiler.log").write_text(result.stdout + result.stderr)
    row = {"compiler": version, "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
           "case": name, "command": command, "returncode": result.returncode}
    if result.returncode == 0:
        asm = subprocess.check_output([str(ROOT / "build/binutils/powerpc-eabi-objdump"),
                                       "-drz", "-M", "gekko", str(obj)], text=True, timeout=30)
        (directory / "disassembly.txt").write_text(asm)
        row.update(inspect_disassembly(asm))
        row["undefined"] = subprocess.check_output([str(ROOT / "build/binutils/powerpc-eabi-nm"),
                                                    "-u", str(obj)], text=True, timeout=30).splitlines()
        row["symbols"] = subprocess.check_output([str(ROOT / "build/binutils/powerpc-eabi-nm"),
                                                  "-S", str(obj)], text=True, timeout=30).splitlines()
        row["object_sha256"] = hashlib.sha256(obj.read_bytes()).hexdigest()
    (directory / "result.json").write_text(json.dumps(row, indent=2) + "\n")
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/joint-matrices-compiler/probes")
    parser.add_argument("--compiler", action="append", help="Compiler version; defaults to GC/1.3")
    args = parser.parse_args()
    base = configured_command()
    output = args.output.resolve()
    rows = []
    frames = "extern void consume(void*);\n" + "\n".join(
        f"int frame_{n}(void) {{ char buf[{n}]; consume(buf); return buf[{n-1}]; }}" for n in range(1, 301))
    for version in args.compiler or ["GC/1.3"]:
        audit = audit_compiler(ROOT / "build/compilers" / version / "mwcceppc.exe")
        output.mkdir(parents=True, exist_ok=True)
        (output / (version.replace("/", "_") + "-binary-audit.json")).write_text(json.dumps(audit, indent=2) + "\n")
        for name, source in CASES.items():
            language = "c++" if name == "local_class" else "c"
            extra = ("-inline", "off") if name == "local_class" else ()
            row = run_case(base, output, version, name, source, extra, language)
            rows.append(row)
            print(json.dumps({k: row[k] for k in ("compiler", "case", "returncode", "frames", "paired", "undefined") if k in row}))
        for name, flags in {
            "frames_current": (), "frames_o0": ("-O0",), "frames_o4s": ("-O4,s",),
            "frames_ibm": ("-pragma", "ibm_stackframe on"),
            "frames_mac68k": ("-align", "mac68k"), "frames_mac68k4byte": ("-align", "mac68k4byte"),
            "frames_multiple": ("-use_lmw_stmw", "on"),
        }.items():
            row = run_case(base, output, version, name, frames, flags)
            rows.append(row)
            print(json.dumps({"compiler": version, "case": name, "returncode": row["returncode"],
                              "frames": len(row.get("frames", [])),
                              "frame_size_gcd": math.gcd(*(f["bytes"] for f in row.get("frames", []))),
                              "retail_sizes": [f for f in row.get("frames", []) if f["bytes"] in (0xFC, 0x34)]}))
    output.mkdir(parents=True, exist_ok=True)
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
