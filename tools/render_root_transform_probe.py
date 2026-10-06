#!/usr/bin/env python3
"""Check the root-transform oracle against EN retail PPC execution.

Requires the optional unicorn package. Executes retail floorf and integer runtime
helpers too. This covers synthetic inputs, not arbitrary assets or hardware FP.
The matching source build is verified separately by objdiff and the DOL checksum.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from orig.dol_tables import DolFile
from joint_matrices_emulation_probe import GekkoPairs
from test_render_root_transform import cases

ROOT = Path(__file__).resolve().parents[1]
ANIM, HEADER, FRAMES, OUTPUT = 0x81400000, 0x81400100, 0x81400200, 0x81500000
RETURN, STACK = 0x81700000, 0x817ff000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/root-transform-emulation/results.json')
    parser.add_argument('--limit', type=int, default=1600)
    args = parser.parse_args()
    if not 1 <= args.limit <= 1600:
        parser.error('--limit must be between 1 and 1600')
    try:
        import unicorn as uc
        from unicorn import ppc_const as ppc
    except ImportError:
        parser.error('This optional probe requires the unicorn package')

    config = (ROOT / 'config/GSAE01/symbols.txt').read_text()
    names = ['modelRenderInterpolateRootTransform', 'render_copyPackedU64Head', 'render_copyPackedU64Tail']
    spans = {}
    for name in names:
        match = re.search(r'^' + name + r' = \.text:(0x[\dA-Fa-f]+); // type:function size:(0x[\dA-Fa-f]+)', config, re.M)
        assert match, name
        spans[name] = (int(match[1], 16), int(match[2], 16))
    dol = DolFile(ROOT / 'orig/GSAE01/sys/main.dol')
    expected_hash = re.search(r'^hash: (\w+)', (ROOT / 'config/GSAE01/config.yml').read_text(), re.M)[1]
    assert hashlib.sha1(dol.data).hexdigest() == expected_hash
    emulator = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emulator.mem_map(0x80000000, 0x1800000)
    for section in dol.sections:
        emulator.mem_write(section.address, dol.data[section.offset:section.offset + section.size])

    # Unicorn needs the existing Gekko shim for the compiler's paired FPR saves.
    pairs = GekkoPairs(emulator, ppc)
    coverage = pairs.coverage
    emulator.hook_add(uc.UC_HOOK_CODE, pairs.hook)
    saved = {getattr(ppc, f'UC_PPC_REG_{i}'): 0xa1000000 + i * 0x10101 for i in range(14, 32)}
    saved.update({getattr(ppc, f'UC_PPC_REG_FPR{i}'): struct.unpack('>Q', struct.pack('>d', 1.0 + i / 32))[0]
                  for i in range(14, 32)})
    checked = 0
    for case in list(cases())[:args.limit]:
        # Walk all 64 pairs of source alignments across consecutive cases.
        offset = (case['index'] // 8) % 8
        cursor = FRAMES + 16 + offset
        state = bytearray(0x80)
        struct.pack_into('>f', state, 4, case['phase'])
        struct.pack_into('>I', state, 0x2c, cursor)
        struct.pack_into('>I', state, 0x34, HEADER)
        struct.pack_into('>H', state, 0x4c, case['stride'])
        header = bytes(4) + struct.pack('>' + 'H' * len(case['descriptors']), *case['descriptors'])
        frames = bytearray(b'\xa5' * 144)
        frames[16 + offset:48 + offset] = case['streams'][0]
        frames[16 + offset + case['stride']:48 + offset + case['stride']] = case['streams'][1]
        expected = bytearray(b'\xcd' * 64)
        expected[16:22] = struct.pack('>3H', *case['positions'])
        expected[40:46] = struct.pack('>3H', *case['rotations'])
        emulator.mem_write(ANIM, bytes(state))
        emulator.mem_write(HEADER, header)
        emulator.mem_write(FRAMES, bytes(frames))
        emulator.mem_write(OUTPUT, b'\xcd' * 64)
        for register, value in saved.items():
            emulator.reg_write(register, value)
        for name, value in [('MSR', 0x2000), ('2', 0x803e6500), ('13', 0x803e31e0),
                            ('LR', RETURN), ('1', STACK), ('3', ANIM), ('4', OUTPUT + 16), ('5', OUTPUT + 40)]:
            emulator.reg_write(getattr(ppc, 'UC_PPC_REG_' + name), value)
        try:
            emulator.emu_start(spans[names[0]][0], RETURN, count=100000)
        except uc.UcError as error:
            pc = emulator.reg_read(ppc.UC_PPC_REG_PC)
            raise RuntimeError(f"Case {case['index']} failed at {pc:08x}") from error
        assert emulator.reg_read(ppc.UC_PPC_REG_PC) == RETURN, ('did not return', case['index'])
        assert emulator.reg_read(ppc.UC_PPC_REG_1) == STACK, ('stack', case['index'])
        assert all(emulator.reg_read(reg) == value for reg, value in saved.items()), ('callee saves', case['index'])
        actual = bytes(emulator.mem_read(OUTPUT, 64))
        assert actual == expected, (case['index'], actual.hex(), expected.hex())
        for address, data in [(ANIM, state), (HEADER, header), (FRAMES, frames)]:
            assert bytes(emulator.mem_read(address, len(data))) == data, ('modified input', case['index'])
        checked += 1
    result = {'cases': checked, 'failed': 0, 'retail_sha1': expected_hash, 'functions': {}}
    for name, (start, size) in spans.items():
        instructions = set(range(start, start + size, 4))
        result['functions'][name] = {'instructions': len(instructions), 'covered': len(instructions & coverage),
                                     'uncovered': [f'{address:08x}' for address in sorted(instructions - coverage)]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({**result, 'functions': {
        name: {key: value for key, value in row.items() if key != 'uncovered'}
        for name, row in result['functions'].items()}}, indent=2))


if __name__ == '__main__':
    main()
