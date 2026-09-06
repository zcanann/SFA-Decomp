#!/usr/bin/env python3
"""Compare compiled joint matrices with EN retail in PPC emulation.

Requires Python 3.13+ and the optional unicorn package. Unicorn executes the PPC instructions;
the code hook supplies the Gekko paired-single subset used by this function.
This is a synthetic behavior probe, not a hardware floating-point conformance
test. Packed outputs compare exactly; matrices allow small rounding differences.
No retail bytes or generated assembly are stored in this script.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import random
import re
import struct
import subprocess

from orig.dol_tables import DolFile

ROOT = Path(__file__).resolve().parents[1]
INPUT = 0x81400000
OUTPUT = 0x81500000
RETURN = 0x81700000
STACK = 0x817FF000
COUNT = 4


def pack(fmt, *values):
    return struct.pack(">" + fmt, *values)


def u32(data, offset=0):
    return struct.unpack_from(">I", data, offset)[0]


def signed(value, bits):
    return (value & ((1 << bits) - 1)) - ((value & (1 << (bits - 1))) << 1)


def f32(value):
    return struct.unpack(">f", pack("f", value))[0]


def link_source(output):
    obj = ROOT / "build/GSAE01/src/main/render.o"
    nm = ROOT / "build/binutils/powerpc-eabi-nm"
    undefined = subprocess.check_output([str(nm), "-u", str(obj)], text=True, timeout=30)
    names = [line.split()[-1] for line in undefined.splitlines()]
    # Data stubs provide real SDA sections. Runtime leaf helpers execute from
    # the loaded retail DOL; unrelated functions remain unreachable in this probe.
    stub = output / "globals.s"
    stub.write_text('.section .sbss,"aw",@nobits\n.balign 4\n' + "".join(
        f".global {name}\n{name}:\n.skip 8\n" for name in names if re.match(r"g[A-Z]", name)))
    stub_obj = output / "globals.o"
    subprocess.run([str(ROOT / "build/binutils/powerpc-eabi-as"), str(stub), "-o", str(stub_obj)],
                   check=True, timeout=30)
    config = (ROOT / "config/GSAE01/symbols.txt").read_text()
    defs = []
    for name in names:
        if name.startswith("_"):
            match = re.search(r"^" + re.escape(name) + r" = \.text:(0x[0-9A-Fa-f]+);", config, re.M)
            if not match:
                raise RuntimeError(f"Missing runtime helper {name}")
            defs.append(f"--defsym={name}={match[1]}")
    elf = output / "render.elf"
    subprocess.run([str(ROOT / "build/binutils/powerpc-eabi-ld"), "-Ttext=0x81000000",
                    "-e", "modelAnimBuildJointMatrices", "--unresolved-symbols=ignore-all",
                    *defs, str(obj), str(stub_obj), "-o", str(elf)], check=True, timeout=30)
    symbols = {fields[2]: int(fields[0], 16) for line in subprocess.check_output(
        [str(nm), str(elf)], text=True, timeout=30).splitlines() if len(fields := line.split()) == 3}
    data = elf.read_bytes()
    ph = u32(data, 28)
    size, count = struct.unpack_from(">HH", data, 42)
    segments = []
    for index in range(count):
        pos = ph + index * size
        if u32(data, pos) == 1:
            offset, address, length = (u32(data, pos + field) for field in (4, 8, 16))
            segments.append((address, data[offset:offset + length]))
    return u32(data, 24), segments, symbols


class GekkoPairs:
    def __init__(self, emulator, ppc):
        self.emu = emulator
        self.ppc = ppc
        self.second = [0.0] * 32
        self.coverage = set()

    def gpr(self, index):
        return self.emu.reg_read(getattr(self.ppc, f"UC_PPC_REG_{index}"))

    def read(self, index):
        bits = self.emu.reg_read(getattr(self.ppc, f"UC_PPC_REG_FPR{index}"))
        return struct.unpack(">d", pack("Q", bits))[0], self.second[index]

    def write(self, index, values):
        bits = struct.unpack(">Q", pack("d", values[0]))[0]
        self.emu.reg_write(getattr(self.ppc, f"UC_PPC_REG_FPR{index}"), bits)
        self.second[index] = values[1]

    def hook(self, emulator, address, size, user):
        self.coverage.add(address)
        ins = u32(emulator.mem_read(address, 4))
        opcode = ins >> 26
        if opcode not in (4, 56, 60):
            return
        dest, a, b, c = ((ins >> shift) & 31 for shift in (21, 16, 11, 6))
        if opcode in (56, 60):
            address = ((self.gpr(a) if a else 0) + signed(ins, 12)) & 0xFFFFFFFF
            quant = (ins >> 12) & 7
            count = 1 if (ins >> 15) & 1 else 2
            fmt = {0: "f", 3: "H", 5: "h"}[quant]
            width = 4 if quant == 0 else 2
            if opcode == 56:
                values = list(struct.unpack(">" + fmt * count, emulator.mem_read(address, width * count)))
                if count == 1:
                    values.append(1.0)
                self.write(dest, values)
            else:
                values = list(self.read(dest)[:count])
                if quant:
                    low, high = (0, 65535) if quant == 3 else (-32768, 32767)
                    values = [int(min(high, max(low, value))) for value in values]
                emulator.mem_write(address, pack(fmt * count, *values))
        else:
            xo = (ins >> 1) & 1023
            short = xo & 31
            av, bv, cv = self.read(a), self.read(b), self.read(c)
            if xo == 72:  # ps_mr
                values = bv
            elif short in (12, 13):  # ps_muls0, ps_muls1
                values = [f32(value * cv[short - 12]) for value in av]
            elif short in (14, 15):  # ps_madds0, ps_madds1
                values = [f32(math.fma(av[i], cv[short - 14], bv[i])) for i in range(2)]
            else:
                raise RuntimeError(f"Unsupported paired instruction {ins:08x}")
            self.write(dest, values)
        emulator.reg_write(self.ppc.UC_PPC_REG_PC, emulator.reg_read(self.ppc.UC_PPC_REG_PC) + 4)


def animation(seed, constant=False, count=COUNT):
    rng = random.Random(seed)
    commands, bits = [], ["", ""]

    def component(kind, flags):
        width = 0 if constant else rng.choice([0, 1, 3, 7, 11, 14, 15])
        mask = 0xFFC0 if kind == 1 else 0xFFF0
        base = rng.randrange(65536) & mask
        if kind == 1:
            base = rng.choice([0, 512, 1024, 2048])
        commands.append(base | flags | width)
        for channel in range(2):
            if width:
                bits[channel] += f"{rng.randrange(1 << width):0{width}b}"

    for joint in range(count):
        for axis in range(3):
            kind = (joint * 3 + axis + seed) % 4
            # Rotation bit 4 signals the following scale/translation command.
            component(2, 0x10 if kind else 0)
            commands[-1] = (commands[-1] & ~0x10) | (0x10 if kind else 0)
            if kind in (2, 3):
                component(1, 0x10 | (0x20 if kind == 3 else 0))
            if kind in (1, 3):
                component(0, 0)
                if kind == 1:
                    commands[-1] &= ~0x10
    streams = []
    for text in bits:
        text += "0" * ((-len(text)) % 8)
        streams.append(int(text or "0", 2).to_bytes(len(text) // 8, "big") + bytes(8))
    header = bytes([count, 8, len(streams[0]), 0]) + pack("H" * len(commands), *commands)
    return header, streams


def run_case(uc, ppc, dol_segments, image, mode, seed, blend, flags, constant=False, phase=None, count=COUNT):
    entry, segments, symbols = image
    emulator = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emulator.mem_map(0x80000000, 0x1800000)
    for address, data in dol_segments + segments:
        if data:
            emulator.mem_write(address, data)
    emulator.reg_write(ppc.UC_PPC_REG_MSR, 0x2000)
    emulator.reg_write(ppc.UC_PPC_REG_2, symbols.get("_SDA2_BASE_", 0x803E6500))
    emulator.reg_write(ppc.UC_PPC_REG_13, symbols.get("_SDA_BASE_", 0x803E31E0))
    emulator.reg_write(ppc.UC_PPC_REG_LR, RETURN)
    emulator.reg_write(ppc.UC_PPC_REG_1, STACK)
    saved = {getattr(ppc, f"UC_PPC_REG_{i}"): 0xA1000000 + i * 0x10101 for i in range(14, 32)}
    saved.update({getattr(ppc, f"UC_PPC_REG_FPR{i}"): struct.unpack(">Q", pack("d", 1.0 + i / 32.0))[0]
                  for i in range(14, 32)})
    for register, value in saved.items():
        emulator.reg_write(register, value)
    initial = bytearray(count * 64)
    for joint in range(count):
        struct.pack_into(">f", initial, joint * 64, 1.0)
        struct.pack_into(">f", initial, joint * 64 + 16, 1.0)
        for axis in range(6):
            struct.pack_into(">H", initial, joint * 64 + 40 + axis * 2, 1024 + joint * 64)
    emulator.mem_write(OUTPUT - 16, b"\xCD" * 16 + initial + b"\xCD" * 16)
    emulator.mem_write(INPUT, pack("I", OUTPUT))
    root = INPUT + 0x100
    emulator.mem_write(root, pack("12f", 1, 0, 0, 3, 0, 1, 0, -2, 0, 0, 1, 7))
    anim = INPUT + 0x200
    for channel in range(2):
        header, streams = animation(seed + channel, constant, count)
        head, frame = INPUT + 0x1000 + channel * 0x1000, INPUT + 0x1400 + channel * 0x1000
        emulator.mem_write(head, header)
        emulator.mem_write(frame, streams[0] + streams[1])
        emulator.mem_write(anim + 4 + channel * 4, pack("f", phase if phase is not None else (2.375 + channel * 0.25)))
        emulator.mem_write(anim + 0x2C + channel * 4, pack("I", frame))
        emulator.mem_write(anim + 0x34 + channel * 4, pack("I", head))
        emulator.mem_write(anim + 0x4C + channel * 2, pack("h", len(streams[0])))
    emulator.mem_write(anim + 0x58, pack("h", blend))
    bones = INPUT + 0x300
    indices = [2, 0, 3, 1] if seed % 2 == 0 and count == 4 else list(range(count))
    for joint in range(count):
        # Last joint branches back to the root; a marked joint tests skipping.
        parent = 0xFF if joint == 0 else indices[0 if joint == 3 else joint - 1]
        marked = ((seed % 3 == 0 and joint == 2) or (seed % 5 == 0 and joint == 0)
                  or seed % 7 == 0 or (seed % 11 == 0 and joint == count - 1))
        index = indices[joint] | (0x80 if marked else 0)
        emulator.mem_write(bones + joint * 28, bytes([parent, index, (joint + seed) % count, count - 1 - joint]) +
                           pack("6f", joint * .25, joint * -.5, joint * .75, 0, 0, 0))
    adjust = INPUT + 0x400
    emulator.mem_write(adjust, pack("8h", 0, 64 if count > 1 else 0, 12, -20, 0x1000, 0x1000, 0, 0))
    for name, address, value in (("gModelRootRotX", 0x803DC7A4, 0x1200),
                                  ("gModelRootRotY", 0x803DC7A6, -0x3400),
                                  ("gModelRootRotZ", 0x803DC7A8, 0x5600)):
        emulator.mem_write(symbols.get(name, address), pack("h", value))
    for reg, value in enumerate((INPUT, root, anim, bones, count, adjust, flags & 0xFFFFFFFF, mode), 3):
        emulator.reg_write(getattr(ppc, f"UC_PPC_REG_{reg}"), value)
    pairs = GekkoPairs(emulator, ppc)
    emulator.hook_add(uc.UC_HOOK_CODE, pairs.hook)
    try:
        emulator.emu_start(entry, RETURN, count=200000)
    except uc.UcError as error:
        pc = emulator.reg_read(ppc.UC_PPC_REG_PC)
        raise RuntimeError(f"PPC failure at {pc:08x}: {emulator.mem_read(pc, 4).hex()}") from error
    if emulator.reg_read(ppc.UC_PPC_REG_PC) != RETURN:
        raise RuntimeError("Function did not return")
    if emulator.reg_read(ppc.UC_PPC_REG_1) != STACK:
        raise RuntimeError("Stack pointer was not restored")
    if any(emulator.reg_read(register) != value for register, value in saved.items()):
        raise RuntimeError("Nonvolatile register was not restored")
    if bytes(emulator.mem_read(OUTPUT - 16, 16)) != b"\xCD" * 16 or bytes(
            emulator.mem_read(OUTPUT + count * 64, 16)) != b"\xCD" * 16:
        raise RuntimeError("Output guard overwritten")
    return bytes(emulator.mem_read(OUTPUT, count * 64)), pairs.coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/joint-matrices-emulation")
    parser.add_argument("--seeds", type=int, default=12)
    args = parser.parse_args()
    if args.seeds < 1:
        parser.error("--seeds must be positive")
    try:
        import unicorn as uc
    except ImportError:
        parser.error("This optional probe requires the unicorn Python package")
    from unicorn import ppc_const as ppc
    args.output.mkdir(parents=True, exist_ok=True)
    source = link_source(args.output)
    dol = DolFile(ROOT / "orig/GSAE01/sys/main.dol")
    segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    retail = (0x80006C6C, [], {})
    rows, coverage = [], set()
    for seed in range(1, args.seeds + 1):
        for mode in (0, 1, 2, 3, 4, 8, 5, 6, 9, 10, 0x10, 0x20, 0x30, 0x40):
            for blend in ((-32768, -1, 0, 8192, 16384, 32767) if mode == 0 else (8192,)):
                case = dict(mode=mode, seed=seed, blend=blend, flags=-1 if seed % 4 else 0x7F,
                            constant=seed % 2 == 0, phase=[0.0, 2.375, -0.25, 2.9999][seed % 4],
                            count=1 if seed % 7 == 0 else COUNT)
                expected, visited = run_case(uc, ppc, segments, retail, **case)
                actual, _ = run_case(uc, ppc, segments, source, **case)
                coverage |= visited
                failures = []
                max_error = 0.0
                early_cache_return = mode & 0x40 and case["flags"] < 0 and (seed % 7 == 0 or seed % 11 == 0)
                cached = mode & 0xC and not mode & 0x40 or early_cache_return
                for joint in range(case["count"]):
                    for offset in range(0, 64, 4):
                        pos = joint * 64 + offset
                        a, b = actual[pos:pos + 4], expected[pos:pos + 4]
                        floating = ((16 <= offset < 32) if mode & 8 else offset < 16) if cached else offset < 48
                        if floating:
                            av, bv = struct.unpack(">f", a)[0], struct.unpack(">f", b)[0]
                            error = abs(av - bv)
                            max_error = max(max_error, error)
                            good = math.isfinite(av) and math.isfinite(bv) and math.isclose(av, bv, rel_tol=2e-5, abs_tol=2e-5)
                        else:
                            good = a == b
                        if not good:
                            failures.append(dict(joint=joint, offset=offset, source=a.hex(), retail=b.hex()))
                row = dict(**case, max_error=max_error, failures=failures)
                rows.append(row)
                if failures:
                    print(json.dumps(row))
    result = dict(cases=len(rows), failed=sum(bool(r["failures"]) for r in rows),
                  retail_instructions_covered=len(coverage & set(range(0x80006C6C, 0x80007F78, 4))),
                  retail_instructions_total=0x130C // 4,
                  uncovered=[f"{p:08x}" for p in range(0x80006C6C, 0x80007F78, 4) if p not in coverage], results=rows)
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "results"}))
    if result["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
