#!/usr/bin/env python3
"""Compare sky lighting inputs and outputs with verified EN retail in PPC emulation.

Requires optional unicorn and pyelftools. Executes the compiled sky updater and
curve evaluators; intercepts the final skySetLightSlot calls. Gekko save/restore
instructions use the existing paired-single emulator. This probes synthetic
state, not rendering or hardware floating-point conformance.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import random
import re
import struct
import tempfile

from gametext_parser_probe import ROOT, RETURN, STACK, link_source, pack
from joint_matrices_emulation_probe import GekkoPairs
from version_progress import read_dol_range, verified_dol

STATE = 0x81200000
FUNCTION = "skyUpdateLightingFromTimeOfDay"
LIGHTING = "gSkyTimeOfDayLighting"


def execute(segments, symbols, state, lighting):
    import unicorn as uc
    from unicorn import ppc_const as ppc

    emu = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emu.mem_map(0x80000000, 0x1800000)
    for address, data in segments:
        emu.mem_write(address, data)

    def read(address, size):
        return bytes(emu.mem_read(address, size))

    def get(index):
        return emu.reg_read(getattr(ppc, f"UC_PPC_REG_{index}"))

    def put(index, value):
        emu.reg_write(getattr(ppc, f"UC_PPC_REG_{index}"), value & 0xFFFFFFFF)

    emu.mem_write(symbols["gSkyState"], pack("I", STATE if state is not None else 0))
    emu.mem_write(STATE - 16, b"\xa5" * (0x258 + 32))
    if state is not None:
        emu.mem_write(STATE, state)
    emu.mem_write(symbols[LIGHTING], lighting)
    emu.mem_write(symbols["gSkyCurrentTextureColor"], b"\x55" * 4)
    saved = {i: 0xCAFE0000 + i for i in range(14, 32)}
    for i, value in saved.items():
        put(i, value)
    sda1 = symbols.get("_SDA_BASE_", 0x803E31E0)
    sda2 = symbols.get("_SDA2_BASE_", 0x803E6500)
    put(1, STACK)
    put(2, sda2)
    put(13, sda1)
    saved_fprs = {i: 0x4020000000000000 + i for i in range(14, 32)}
    for i, value in saved_fprs.items():
        emu.reg_write(getattr(ppc, f"UC_PPC_REG_FPR{i}"), value)
    emu.reg_write(ppc.UC_PPC_REG_LR, RETURN)
    emu.reg_write(ppc.UC_PPC_REG_MSR, 0x2000)
    emu.reg_write(ppc.UC_PPC_REG_CR, 0x13579024)
    pairs = GekkoPairs(emu, ppc)
    pairs.second = [float(i + 1) for i in range(32)]
    saved_second = pairs.second[14:]
    calls = []

    def capture(machine, address, size, user):
        calls.append((tuple(get(i) for i in range(3, 10)),
                      tuple(emu.reg_read(getattr(ppc, f"UC_PPC_REG_FPR{i}")) for i in range(1, 4))))
        # Exercise preservation across the real renderer's EABI call boundary.
        for i in (0, *range(3, 13)):
            put(i, 0xD00D0000 + i)
        for i in range(14):
            pairs.write(i, (-10.0 - i, -1.0))
        emu.reg_write(ppc.UC_PPC_REG_PC, emu.reg_read(ppc.UC_PPC_REG_LR))

    hooks = [emu.hook_add(uc.UC_HOOK_CODE, pairs.hook)]
    address = symbols["skySetLightSlot"]
    hooks.append(emu.hook_add(uc.UC_HOOK_CODE, capture, begin=address, end=address))
    try:
        emu.emu_start(symbols[FUNCTION], RETURN, count=20000)
    except uc.UcError as error:
        raise RuntimeError(f"PPC failed at {emu.reg_read(ppc.UC_PPC_REG_PC):#x}") from error
    finally:
        for hook in hooks:
            emu.hook_del(hook)
    assert emu.reg_read(ppc.UC_PPC_REG_PC) == RETURN, "instruction budget exceeded"
    assert (get(1), get(2), get(13)) == (STACK, sda2, sda1)
    assert all(get(i) == value for i, value in saved.items())
    assert all(emu.reg_read(getattr(ppc, f"UC_PPC_REG_FPR{i}")) == value for i, value in saved_fprs.items())
    assert pairs.second[14:] == saved_second
    assert emu.reg_read(ppc.UC_PPC_REG_CR) & 0x00FFF000 == 0x13579024 & 0x00FFF000
    assert read(STATE - 16, 16) == b"\xa5" * 16
    assert read(STATE + 0x258, 16) == b"\xa5" * 16
    assert read(symbols[LIGHTING], len(lighting)) == lighting
    assert read(STATE, 0x258) == (state if state is not None else b"\xa5" * 0x258)
    assert [call[0][0] for call in calls] == [0, 1, 2]
    return calls, read(symbols["gSkyCurrentTextureColor"], 4)


def fixtures(random_cases):
    rng = random.Random(0x534B59)
    # Include both sides of every interpolation, clamp, and day/night boundary.
    times = [t + delta for t in (0, 18000, 21600, 43200, 64800, 75600, 86400)
             for delta in (-0.0625, 0, 0.0625)]
    times += [rng.uniform(-10000, 100000) for _ in range(random_cases)]
    for time in times:
        for flags in range(4):
            state = bytearray(0x258)
            struct.pack_into(">f", state, 0x20C, time)
            for slot in range(2):
                base = 0x20 + slot * 0xA4
                for i in range(21):
                    struct.pack_into(">f", state, base + i * 4, rng.uniform(-100, 400))
                state[base + 0x54:base + 0x57] = bytes(rng.randrange(256) for _ in range(3))
                struct.pack_into(">f", state, base + 0x98, rng.choice((0, 1, rng.random())))
                state[base + 0xA1] = 0x80 if flags & (1 << slot) else 0
            directions = [rng.uniform(-1, 1) for _ in range(6)]
            # Independent channel values expose curve selection/stride errors.
            curves = [rng.uniform(0, 255) for _ in range(15)]
            yield bytes(state), pack("21f", *(directions + curves))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", type=Path, default=ROOT / "build/GSAE01/src/dlls/engine/5/5.o")
    parser.add_argument("--random-cases", type=int, default=100)
    args = parser.parse_args()
    text = (ROOT / "config/GSAE01/symbols.txt").read_text()
    retail = {name: (section, int(address, 16)) for name, section, address in
              re.findall(r"^(\w+) = (\.\w+):(0x[0-9A-Fa-f]+);", text, re.M)}
    dol = verified_dol(ROOT / "orig/GSAE01/sys/main.dol", ROOT / "config/GSAE01/config.yml")
    segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    retail_symbols = {name: value[1] for name, value in retail.items()}
    lighting = read_dol_range(dol, retail_symbols[LIGHTING], 0x54)
    curves = ROOT / "build/GSAE01/src/main/curves.o"
    with tempfile.TemporaryDirectory(prefix="sfa-sky-lighting-") as directory:
        source_segments, source_symbols = link_source(args.object, Path(directory), retail,
                                                     entry=FUNCTION, extra_objects=(curves,))
        address = source_symbols[LIGHTING]
        segment = next((base, data) for base, data in source_segments if base <= address < base + len(data))
        assert segment[1][address - segment[0]:address - segment[0] + 0x54] == lighting
        cases = [(None, lighting), *fixtures(args.random_cases)]
        for index, (state, data) in enumerate(cases):
            expected = execute(segments, retail_symbols, state, data)
            actual = execute(segments + source_segments, source_symbols, state, data)
            assert actual == expected, f"lighting differs in case {index}: {actual} != {expected}"
    print(f"{len(cases)} cases: exact light-slot calls, colors, storage and preserved registers")


if __name__ == "__main__":
    main()
