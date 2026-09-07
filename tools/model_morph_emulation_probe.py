#!/usr/bin/env python3
"""Check compiled morph code and EN retail against the dense integer oracle.

Requires optional unicorn and pyelftools packages. Loads only the two compiled
functions, resolving their internal REL24 calls, and rejects other relocations.
No retail instructions are stored here. Cache DMA and asset loading are outside
this integer/ABI probe's scope.
"""

import argparse
from io import BytesIO
from pathlib import Path
import re
import struct

from orig.dol_tables import DolFile
from test_model_morph_blend import encode, oracle_cases

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('modelBlendMorphTargetChunk', 'modelReadMorphDelta')
CODE = 0x81000000
BASE, OUTPUT, STREAM_A, STREAM_B, CURSORS = (
    0x81400000, 0x81410000, 0x81420000, 0x81430000, 0x81440000)
RETURN, STACK = 0x81700000, 0x817ff000


def pack(fmt, *values):
    return struct.pack('>' + fmt, *values)


def compiled_functions(path):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    elf = ELFFile(BytesIO(path.read_bytes()))
    assert elf['e_machine'] == 'EM_PPC' and elf['e_type'] == 'ET_REL'
    symbols = elf.get_section_by_name('.symtab')
    selected = {name: symbols.get_symbol_by_name(name)[0] for name in NAMES}
    addresses = {name: CODE + index * 0x10000 for index, name in enumerate(NAMES)}
    segments = []
    for name, symbol in selected.items():
        start, size = symbol['st_value'], symbol['st_size']
        data = bytearray(elf.get_section(symbol['st_shndx']).data()[start:start + size])
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection) or section['sh_info'] != symbol['st_shndx']:
                continue
            table = elf.get_section(section['sh_link'])
            for reloc in section.iter_relocations():
                offset = reloc['r_offset'] - start
                if not 0 <= offset < size:
                    continue
                target = table.get_symbol(reloc['r_info_sym']).name
                assert reloc['r_info_type'] == 10 and target in addresses, (name, reloc, target)
                word = struct.unpack_from('>I', data, offset)[0]
                assert word & 0xfc000003 == 0x48000001, hex(word)
                delta = addresses[target] + reloc['r_addend'] - (addresses[name] + offset)
                assert delta % 4 == 0 and -(1 << 25) <= delta < (1 << 25)
                struct.pack_into('>I', data, offset, (word & 0xfc000003) | (delta & 0x03fffffc))
        segments.append((addresses[name], bytes(data)))
    return addresses, segments


class Machine:
    def __init__(self, segments):
        import unicorn
        from unicorn import ppc_const

        self.ppc = ppc_const
        self.emu = unicorn.Uc(unicorn.UC_ARCH_PPC, unicorn.UC_MODE_32 | unicorn.UC_MODE_BIG_ENDIAN)
        self.emu.mem_map(0x80000000, 0x1800000)
        for address, data in segments:
            self.emu.mem_write(address, data)

    def reg(self, index):
        return getattr(self.ppc, 'UC_PPC_REG_' + str(index))

    def get(self, index):
        return self.emu.reg_read(self.reg(index))

    def set(self, index, value):
        self.emu.reg_write(self.reg(index), value & 0xffffffff)

    def call(self, entry, args, preserved):
        for index in range(32):
            self.set(index, 0xa1000000 + index * 0x10101)
        self.set(1, STACK)
        for index, value in args.items():
            self.set(index, value)
        before = {index: self.get(index) for index in preserved}
        self.emu.reg_write(self.ppc.UC_PPC_REG_LR, RETURN)
        self.emu.reg_write(self.ppc.UC_PPC_REG_CR, 0xa5c39e71)
        self.emu.emu_start(entry, RETURN, count=100000)
        assert self.emu.reg_read(self.ppc.UC_PPC_REG_PC) == RETURN, 'did not return'
        assert self.emu.reg_read(self.ppc.UC_PPC_REG_LR) == RETURN, 'LR corrupted'
        assert self.emu.reg_read(self.ppc.UC_PPC_REG_CR) & 0x00fff000 == 0x00c39000
        for index, value in before.items():
            assert self.get(index) == value, ('preserved register', index)

    def blend(self, entry, values):
        count, first, weight, alen, blen, limit = values[:6]
        base = values[6:6 + count * 3]
        a = values[6 + count * 3:6 + count * 3 + alen]
        b = values[6 + count * 3 + alen:]
        assert len(b) == blen
        self.emu.mem_write(BASE, pack('h' * len(base), *base))
        self.emu.mem_write(OUTPUT - 4, b'\x5a' * (count * 6 + 8))
        self.emu.mem_write(STREAM_A, pack('H' * alen, *a))
        self.emu.mem_write(STREAM_B, pack('H' * blen, *b))
        self.emu.mem_write(CURSORS, pack('II', STREAM_A, STREAM_B))
        offset = 0
        while True:
            chunk = min(count - offset, limit)
            self.call(entry, {3: BASE + offset * 6, 4: OUTPUT + offset * 6, 5: chunk,
                             6: CURSORS, 7: CURSORS + 4, 8: weight, 9: first + offset},
                      (1, 2, 13, *range(14, 32)))
            offset += chunk
            if offset >= count:
                break
        assert self.emu.mem_read(OUTPUT - 4, 4) == b'\x5a' * 4
        assert self.emu.mem_read(OUTPUT + count * 6, 4) == b'\x5a' * 4
        assert self.emu.mem_read(BASE, count * 6) == pack('h' * len(base), *base)
        for address, words in ((STREAM_A, a), (STREAM_B, b)):
            assert self.emu.mem_read(address, len(words) * 2) == pack('H' * len(words), *words)
        acur, bcur = struct.unpack('>II', self.emu.mem_read(CURSORS, 8))
        return [(acur - STREAM_A) // 2, (bcur - STREAM_B) // 2,
                *struct.unpack('>' + 'h' * (count * 3), self.emu.mem_read(OUTPUT, count * 6))]

    def decoder(self, entry):
        for mask in range(8):
            for values in ((-32768, 32767, -1), (0, 1, -32768)):
                components = tuple(values[axis] if mask & (1 << axis) else None for axis in range(3))
                words = encode({123: components}, 124)
                self.emu.mem_write(STREAM_A, pack('H' * len(words), *words))
                self.call(entry, {20: STREAM_A},
                          tuple(i for i in range(32) if i not in (10, 12, 15, 20, 21, 22)))
                assert self.get(20) == STREAM_A + (len(words) - 1) * 2
                for reg, value in zip((10, 12, 15), components):
                    assert self.get(reg) == ((value or 0) & 0xffffffff)
                assert self.emu.mem_read(STREAM_A, len(words) * 2) == pack('H' * len(words), *words)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, default=ROOT / 'build/GSAE01/src/main/model.o')
    args = parser.parse_args()
    addresses, segments = compiled_functions(args.object)
    dol = DolFile(ROOT / 'orig/GSAE01/sys/main.dol')
    config = (ROOT / 'config/GSAE01/symbols.txt').read_text()
    retail = {name: int(re.search(r'^' + name + r' = \.text:(0x[0-9a-fA-F]+);', config, re.M)[1], 16)
              for name in NAMES}
    retail_segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    inputs, expected = oracle_cases()
    for label, symbols, code in (('compiled', addresses, segments), ('retail', retail, retail_segments)):
        machine = Machine(code)
        machine.decoder(symbols[NAMES[1]])
        for index, (line, result) in enumerate(zip(inputs, expected)):
            actual = machine.blend(symbols[NAMES[0]], list(map(int, line.split())))
            assert actual == result, (label, index, actual, result)
        print(f'{label}: 16 decoder cases and {len(inputs)} morph scenarios passed, including ABI checks')


if __name__ == '__main__':
    main()
