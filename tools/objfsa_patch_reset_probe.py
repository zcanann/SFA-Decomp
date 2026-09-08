#!/usr/bin/env python3
"""Run the walk-group checksum gate and empty-curve reset in EN retail PPC.

Requires optional unicorn and pyelftools. Map flags and curve enumeration are
mocked; checksum arithmetic, memset, all 256 patch stores, and ABI execute.
This probe does not exercise curve geometry or exit-point adjustment.
"""

import argparse
from pathlib import Path
import re
import tempfile

from gametext_parser_probe import ROOT, RETURN, STACK, link_source, pack
from joint_matrices_emulation_probe import GekkoPairs
from orig.dol_tables import DolFile
from version_progress import verified_dol

INTERFACE_POINTER = 0x81600000
INTERFACE = INTERFACE_POINTER + 0x100
GET_CURVES = 0x81701000
FUNCTION = 'Objfsa_UpdateWalkGroupPatches'


def run(segments, symbols, retail, flags, previous):
    import unicorn as uc
    from unicorn import ppc_const as ppc

    emulator = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emulator.mem_map(0x80000000, 0x1800000)
    for address, data in segments:
        emulator.mem_write(address, data)

    def read(address, size):
        return bytes(emulator.mem_read(address, size))

    def get(index):
        return emulator.reg_read(getattr(ppc, f'UC_PPC_REG_{index}'))

    def put(index, value):
        emulator.reg_write(getattr(ppc, f'UC_PPC_REG_{index}'), value)

    base = symbols['gObjfsaPatches']
    storage = bytearray((i * 17 + 11) & 255 for i in range(0x4D00))
    emulator.mem_write(base, bytes(storage))
    emulator.mem_write(symbols['gObjfsaPatchCount'], pack('I', 73))
    emulator.mem_write(symbols['gObjfsaBlockFlagsChecksum'], pack('I', previous))
    emulator.mem_write(symbols['gRomCurveInterface'], pack('I', INTERFACE_POINTER))
    emulator.mem_write(INTERFACE_POINTER, pack('I', INTERFACE))
    emulator.mem_write(INTERFACE + 0x10, pack('I', GET_CURVES))

    guards = [(base - 16, read(base - 16, 16)), (base + len(storage), read(base + len(storage), 16))]

    checksum = 1
    for index, active in enumerate(flags):
        if active:
            checksum = checksum * index & 0xFFFFFFFF
    changed = checksum != previous
    if changed:
        for index in range(256):
            storage[index * 48 + 36:index * 48 + 38] = bytes(2)
        storage[0x4C48:0x4C48 + 181] = bytes(181)

    saved = {i: 0xCAFE0000 + i for i in range(14, 32)}
    for index, value in saved.items():
        put(index, value)
    sda1 = symbols.get('_SDA_BASE_', 0x803E31E0)
    sda2 = symbols.get('_SDA2_BASE_', 0x803E6500)
    put(1, STACK)
    put(2, sda2)
    put(13, sda1)
    emulator.reg_write(ppc.UC_PPC_REG_CR, 0x13579024)
    emulator.reg_write(ppc.UC_PPC_REG_LR, RETURN)
    emulator.reg_write(ppc.UC_PPC_REG_MSR, 0x2000)
    saved_fprs = {i: 0x4020000000000000 + i for i in range(14, 32)}
    for index, value in saved_fprs.items():
        emulator.reg_write(getattr(ppc, f'UC_PPC_REG_FPR{index}'), value)
    pairs = GekkoPairs(emulator, ppc)
    pairs.second = [float(i + 1) for i in range(32)]
    saved_second = pairs.second[14:]
    calls = []

    def mock(emu, address, size, name):
        calls.append(name)
        if name == 'flags':
            emulator.mem_write(get(3), flags)
        else:
            emulator.mem_write(get(3), pack('I', 0))
        for index in (0, *range(3, 13)):
            put(index, 0xD00D0000 + index)
        if name == 'curves':
            put(3, INTERFACE + 0x200)
        for index in range(14):
            emulator.reg_write(getattr(ppc, f'UC_PPC_REG_FPR{index}'), 0x4000000000000000 + index)
            pairs.second[index] = -1.0
        emulator.reg_write(ppc.UC_PPC_REG_PC, emulator.reg_read(ppc.UC_PPC_REG_LR))

    emulator.hook_add(uc.UC_HOOK_CODE, pairs.hook)
    for address, name in ((retail['mapGetLoadedMapFlags'][1], 'flags'), (GET_CURVES, 'curves')):
        emulator.hook_add(uc.UC_HOOK_CODE, mock, user_data=name, begin=address, end=address)
    try:
        emulator.emu_start(symbols[FUNCTION], RETURN, count=20000)
    except uc.UcError as error:
        pc = emulator.reg_read(ppc.UC_PPC_REG_PC)
        raise RuntimeError(f'PPC execution failed at {pc:#x}: {read(pc, 4).hex()}') from error
    assert emulator.reg_read(ppc.UC_PPC_REG_PC) == RETURN, 'instruction budget exceeded'
    assert calls == (['flags', 'curves'] if changed else ['flags'])
    assert read(base, len(storage)) == bytes(storage), 'patch/group storage changed unexpectedly'
    assert read(symbols['gObjfsaPatchCount'], 4) == pack('I', 1 if changed else 73)
    assert read(symbols['gObjfsaBlockFlagsChecksum'], 4) == pack('I', checksum)
    for address, value in guards:
        expected = bytearray(value)
        for name, word in (('gObjfsaPatchCount', 1 if changed else 73),
                           ('gObjfsaBlockFlagsChecksum', checksum)):
            offset = symbols[name] - address
            if 0 <= offset <= len(expected) - 4:
                expected[offset:offset + 4] = pack('I', word)
        assert read(address, len(expected)) == bytes(expected)
    assert (get(1), get(2), get(13)) == (STACK, sda2, sda1)
    assert all(get(i) == value for i, value in saved.items())
    assert all(emulator.reg_read(getattr(ppc, f'UC_PPC_REG_FPR{i}')) == value for i, value in saved_fprs.items())
    assert pairs.second[14:] == saved_second
    assert emulator.reg_read(ppc.UC_PPC_REG_CR) & 0x00FFF000 == 0x13579024 & 0x00FFF000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path,
                        default=ROOT / 'build/GSAE01/src/dlls/engine/20_Hcurves/Hcurves.o')
    args = parser.parse_args()
    config = (ROOT / 'config/GSAE01/symbols.txt').read_text()
    retail = {name: (section, int(address, 16)) for name, section, address in
              re.findall(r'^(\w+) = (\.\w+):(0x[0-9A-Fa-f]+);', config, re.M)}
    path = ROOT / 'orig/GSAE01/sys/main.dol'
    verified_dol(path, ROOT / 'config/GSAE01/config.yml')
    dol = DolFile(path)
    segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    cases = [bytes(120)]
    for index in range(120):
        for value in (1, 255):
            flags = bytearray(120)
            flags[index] = value
            cases.append(bytes(flags))
    for indices in ((2, 3), (1, 6), (0, 2, 3), (2, 3, 7, 11, 17, 23, 31, 47, 59), tuple(range(120))):
        cases.append(bytes(int(i in indices) for i in range(120)))
    comparisons = 0
    with tempfile.TemporaryDirectory(prefix='sfa-patch-reset-') as temporary:
        compiled_segments, compiled_symbols = link_source(args.object, Path(temporary), retail, entry=FUNCTION)
        for flags in cases:
            # 6 deliberately collides for distinct sets {2,3} and {1,6}.
            for previous in (0, 1, 6, 0xFFFFFFFF):
                run(segments, {name: value[1] for name, value in retail.items()}, retail, flags, previous)
                run(segments + compiled_segments, compiled_symbols, retail, flags, previous)
                comparisons += 1
    print(f'PASS: {comparisons} retail/source comparisons; checksum, empty-curve reset, guards and ABI')


if __name__ == '__main__':
    main()
