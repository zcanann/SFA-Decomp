#!/usr/bin/env python3
"""Check EN object-sequence map reset against retail in PPC emulation.

Requires optional unicorn and pyelftools. Executes the entire leaf function,
checking all 85 slots, untouched storage and padding, global reset widths,
nonvolatile registers, and the absence of duplicate slot stores.
"""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import random
import re
import tempfile

from gametext_parser_probe import ROOT, RETURN, STACK, link_source
from version_progress import verified_dol

FUNCTION = 'ObjSeq_onMapSetup'
STORAGE_SIZE = 0x3E8C
# Offsets/strides are established by the retail stores, independently of the C overlay.
FIELDS = ((0x3B9C, 1, 0), (0x3B44, 1, 0), (0x3A98, 2, 0),
          (0x3C4C, 1, 0), (0x3BF4, 1, 0), (0x3A40, 1, 0),
          (0x39E8, 1, 0), (0x3894, 4, 0), (0x3740, 4, 0xBF800000),
          (0x3590, 1, 0), (0x33E4, 4, 0), (0x338C, 1, 0))
GLOBALS = {'gObjSeqPreemptCount': 1, 'gObjSeqCamMode': 4,
           'gObjSeqCameraActive': 1, 'lbl_803DD0DC': 4,
           'gObjSeqCameraSourceObj': 4, 'gObjSeqCameraOverrideActive': 1,
           'gObjSeqBgCmdCount': 1}


def execute(segments, symbols, initial):
    import unicorn as uc
    from unicorn import ppc_const as ppc

    emu = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emu.mem_map(0x80000000, 0x1800000)
    for address, contents in segments:
        emu.mem_write(address, contents)
    base = symbols['gObjSeqRuntimeBuffer']
    emu.mem_write(base - 16, b'\xcd' * 16 + initial + b'\xab' * 16)
    expected = bytearray(initial)
    writes = Counter()
    for slot in range(85):
        for offset, width, value in FIELDS:
            at = offset + slot * width
            expected[at:at + width] = value.to_bytes(width, 'big')
            writes[(base + at, width, value)] += 1
    for name, width in GLOBALS.items():
        emu.mem_write(symbols[name], bytes([0xA5]) * width)
        writes[(symbols[name], width, 0)] += 1

    def put(index, value):
        emu.reg_write(getattr(ppc, f'UC_PPC_REG_{index}'), value)

    def get(index):
        return emu.reg_read(getattr(ppc, f'UC_PPC_REG_{index}'))

    sda1 = symbols.get('_SDA_BASE_', 0x803E31E0)
    sda2 = symbols.get('_SDA2_BASE_', 0x803E6500)
    put(1, STACK)
    put(2, sda2)
    put(13, sda1)
    saved = {i: 0xCAFE0000 + i for i in range(14, 32)}
    for index, value in saved.items():
        put(index, value)
    saved_fprs = {i: 0x4020000000000000 + i for i in range(14, 32)}
    for index, value in saved_fprs.items():
        emu.reg_write(getattr(ppc, f'UC_PPC_REG_FPR{index}'), value)
    emu.reg_write(ppc.UC_PPC_REG_CR, 0x13579024)
    emu.reg_write(ppc.UC_PPC_REG_MSR, 0x2000)
    emu.reg_write(ppc.UC_PPC_REG_LR, RETURN)
    observed = Counter()

    def store(machine, access, address, width, value, context):
        if STACK - 32 <= address < STACK:
            return
        observed[(address, width, value & ((1 << (width * 8)) - 1))] += 1

    emu.hook_add(uc.UC_HOOK_MEM_WRITE, store)
    emu.emu_start(symbols[FUNCTION], RETURN, count=20000)
    assert emu.reg_read(ppc.UC_PPC_REG_PC) == RETURN, 'instruction budget exceeded'
    assert bytes(emu.mem_read(base, STORAGE_SIZE)) == expected, 'incorrect slot storage'
    assert bytes(emu.mem_read(base - 16, 16)) == b'\xcd' * 16, 'leading guard changed'
    assert bytes(emu.mem_read(base + STORAGE_SIZE, 16)) == b'\xab' * 16, 'trailing guard changed'
    for name, width in GLOBALS.items():
        assert bytes(emu.mem_read(symbols[name], width)) == bytes(width), name
    assert observed == writes, f'unexpected stores: {observed - writes}; missing: {writes - observed}'
    assert (get(1), get(2), get(13)) == (STACK, sda2, sda1)
    assert all(get(index) == value for index, value in saved.items())
    assert all(emu.reg_read(getattr(ppc, f'UC_PPC_REG_FPR{index}')) == value
               for index, value in saved_fprs.items())
    assert emu.reg_read(ppc.UC_PPC_REG_CR) & 0x00FFF000 == 0x13579024 & 0x00FFF000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path,
                        default=ROOT / 'build/GSAE01/src/dlls/engine/2/2.o')
    parser.add_argument('--retail-only', action='store_true')
    args = parser.parse_args()
    config = (ROOT / 'config/GSAE01/symbols.txt').read_text()
    retail = {name: (section, int(address, 16)) for name, section, address in
              re.findall(r'^(\w+) = (\.\w+):(0x[0-9A-Fa-f]+);', config, re.M)}
    dol = verified_dol(ROOT / 'orig/GSAE01/sys/main.dol', ROOT / 'config/GSAE01/config.yml')
    segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    patterns = [bytes(STORAGE_SIZE), bytes([255]) * STORAGE_SIZE,
                bytes((i * 17 + 11) & 255 for i in range(STORAGE_SIZE)),
                random.Random(0x534641).randbytes(STORAGE_SIZE)]
    for initial in patterns:
        execute(segments, {name: value[1] for name, value in retail.items()}, initial)
    if not args.retail_only:
        with tempfile.TemporaryDirectory(prefix='sfa-objseq-reset-') as temporary:
            compiled_segments, compiled_symbols = link_source(args.object, Path(temporary), retail, entry=FUNCTION)
            for initial in patterns:
                execute(segments + compiled_segments, compiled_symbols, initial)
    print(f'PASS: {len(patterns)} storage patterns; all 85 slots, 1,027 stores, guards, globals, and ABI'
          + (' (retail only)' if args.retail_only else ' (retail and source)'))


if __name__ == '__main__':
    main()
