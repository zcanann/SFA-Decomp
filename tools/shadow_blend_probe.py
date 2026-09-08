#!/usr/bin/env python3
"""Check tiled texture blending against retail PPC and an independent pixel oracle.

Requires unicorn, pyelftools and the selected retail DOL. Executes the compiled
function and register-save helpers; only DCStoreRange is intercepted. No retail
code is embedded. Invalid dimensions that are not multiples of four, overlapping
headers, and non-finite blend weights are outside this probe's scope.
"""
from io import BytesIO
from pathlib import Path
import argparse
import random
import re
import struct

from model_morph_emulation_probe import Machine, pack
from version_progress import read_dol_range, verified_dol


ROOT = Path(__file__).resolve().parents[1]
CODE, CONSTANTS, SDA2 = 0x81000000, 0x81010000, 0x81018000
TEXTURES = (0x81200020, 0x81300020, 0x81400020)
HEADER_SIZE = 0x60
GUARD = bytes([0xA5]) * 32


def f32(value):
    return struct.unpack('>f', pack('f', value))[0]


def encode(pixels, width, height, format_id):
    """Serialize row-major pixels by enumerating GX 4x4 tiles and their planes."""
    output = bytearray()
    for tile_y in range(0, height, 4):
        for tile_x in range(0, width, 4):
            tile = [pixels[(tile_y + y) * width + tile_x + x] for y in range(4) for x in range(4)]
            if format_id == 4:
                output.extend(b''.join(pack('H', pixel) for pixel in tile))
            else:
                output.extend(bytes(channel for r, g, b, a in tile for channel in (a, r)))
                output.extend(bytes(channel for r, g, b, a in tile for channel in (g, b)))
    return bytes(output)


def reference(a, b, blend, format_id):
    weight_a = int(f32(255.0 * f32(blend))) & 255
    weight_b = 255 - weight_a

    def channels(pixel):
        if format_id == 6:
            return pixel[:3]
        r, g, b = pixel >> 11, (pixel >> 5) & 63, pixel & 31
        return ((r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2))

    output = []
    for first, second in zip(a, b):
        rgb = [((x * weight_a) // 256) + ((y * weight_b) // 256)
               for x, y in zip(channels(first), channels(second))]
        r, g, b = rgb
        output.append(((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
                      if format_id == 4 else (r, g, b, 0))
    return output


def compiled_segments(path, retail_symbols):
    from elftools.elf.elffile import ELFFile

    elf = ELFFile(BytesIO(path.read_bytes()))
    assert elf['e_machine'] == 'EM_PPC' and elf['e_type'] == 'ET_REL' and not elf.little_endian
    table = elf.get_section_by_name('.symtab')
    function, = table.get_symbol_by_name('blendTextures')
    start, size = function['st_value'], function['st_size']
    code = bytearray(elf.get_section(function['st_shndx']).data()[start:start + size])
    constants = elf.get_section_by_name('.sdata2').data()
    assert len(constants) <= 0x10000
    calls = []
    for section in elf.iter_sections():
        if section['sh_type'] != 'SHT_RELA' or section['sh_info'] != function['st_shndx']:
            continue
        symbols = elf.get_section(section['sh_link'])
        for relocation in section.iter_relocations():
            offset = relocation['r_offset'] - start
            if not 0 <= offset < size:
                continue
            symbol = symbols.get_symbol(relocation['r_info_sym'])
            kind = relocation['r_info_type']
            word_offset = offset & ~3
            word, = struct.unpack_from('>I', code, word_offset)
            if kind == 10:
                assert offset % 4 == 0 and word & 0xFC000003 == 0x48000001
                assert symbol.name in ('_savegpr_24', '_restgpr_24', 'DCStoreRange'), symbol.name
                displacement = retail_symbols[symbol.name] + relocation['r_addend'] - (CODE + offset)
                assert displacement % 4 == 0 and -(1 << 25) <= displacement < (1 << 25)
                word = (word & 0xFC000003) | (displacement & 0x03FFFFFC)
                calls.append(symbol.name)
            else:
                assert kind == 109 and word >> 26 == 48, (kind, symbol.name, hex(word))
                assert isinstance(symbol['st_shndx'], int)
                assert elf.get_section(symbol['st_shndx']).name == '.sdata2'
                position = symbol['st_value'] + relocation['r_addend']
                assert 0 <= position <= len(constants) - 4
                displacement = CONSTANTS + position - SDA2
                assert -32768 <= displacement < 32768
                word = (word & 0xFFE00000) | (2 << 16) | (displacement & 0xFFFF)
            struct.pack_into('>I', code, word_offset, word)
    assert sorted(calls) == sorted(('_savegpr_24', '_restgpr_24', 'DCStoreRange'))
    return [(CODE, bytes(code)), (CONSTANTS, constants)]


class BlendMachine(Machine):
    def __init__(self, segments, symbols, entry, sda1, sda2):
        import unicorn

        super().__init__(segments)
        self.entry, self.sda1, self.sda2 = entry, sda1, sda2
        self.flushes = []
        self.emu.reg_write(self.ppc.UC_PPC_REG_MSR, 0x2000)

        def flush(emu, address, size, user_data):
            self.flushes.append((self.get(3), self.get(4)))
            for index in (0, *range(3, 13)):
                self.set(index, 0xD00D0000 + index)
            emu.reg_write(self.ppc.UC_PPC_REG_PC, emu.reg_read(self.ppc.UC_PPC_REG_LR))

        self.emu.hook_add(unicorn.UC_HOOK_CODE, flush,
                          begin=symbols['DCStoreRange'], end=symbols['DCStoreRange'])

    def blend(self, a, b, expected, width, height, format_id, weight, destination, invalid=None, same_source=False):
        payloads = [encode(a, width, height, format_id), encode(b, width, height, format_id)]
        payloads.append(bytes([0xCD]) * len(payloads[0]))
        initial = []
        for index, (address, payload) in enumerate(zip(TEXTURES, payloads)):
            header = bytearray((i * 17 + 3) & 255 for i in range(HEADER_SIZE))
            struct.pack_into('>HH', header, 0xA, width, height)
            header[0x16] = format_id
            struct.pack_into('>I', header, 0x44, len(payload))
            if invalid == 'format' and index == 1:
                header[0x16] = 0
            if invalid == 'unsupported':
                header[0x16] = 0
            if invalid in ('width', 'height', 'src2_width', 'src2_height'):
                target = 1 if invalid.startswith('src2_') else 2
                if index == target:
                    is_width = invalid.endswith('width')
                    struct.pack_into('>H', header, 0xA if is_width else 0xC, 4 + (width if is_width else height))
            initial.append(bytearray(GUARD + header + payload + GUARD))
            self.emu.mem_write(address - len(GUARD), bytes(initial[-1]))
        pointers = [TEXTURES[0], TEXTURES[1], TEXTURES[destination]]
        if same_source:
            pointers[1] = pointers[0]
        if invalid and invalid.startswith('null'):
            pointers[int(invalid[-1])] = 0
        self.flushes.clear()
        self.emu.reg_write(self.ppc.UC_PPC_REG_FPR1, struct.unpack('>Q', pack('d', f32(weight)))[0])
        saved_fprs = {}
        for index in range(14, 32):
            reg = getattr(self.ppc, 'UC_PPC_REG_FPR' + str(index))
            saved_fprs[reg] = struct.unpack('>Q', pack('d', 1.0 + index / 32.0))[0]
            self.emu.reg_write(reg, saved_fprs[reg])
        self.call(self.entry, {2: self.sda2, 13: self.sda1, 3: pointers[0], 4: pointers[1], 5: pointers[2]},
                  (1, 2, 13, *range(14, 32)))
        assert all(self.emu.reg_read(reg) == value for reg, value in saved_fprs.items())
        assert self.flushes == ([] if invalid else [(pointers[2] + HEADER_SIZE, len(payloads[destination]))])
        if not invalid:
            initial[destination][len(GUARD) + HEADER_SIZE:-len(GUARD)] = encode(expected, width, height, format_id)
        for address, contents in zip(TEXTURES, initial):
            actual = bytes(self.emu.mem_read(address - len(GUARD), len(contents)))
            assert actual == contents, ('texture/guard changed', hex(address), width, height, format_id, weight, destination, invalid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='GSAE01', choices=['GSAE01', 'GSAE01_rev1', 'GSAJ01', 'GSAP01', 'GSAP01_rev1'])
    parser.add_argument('--object', type=Path)
    args = parser.parse_args()
    path = args.object or ROOT / 'build' / args.version / 'src/main/newshadows.o'
    config = (ROOT / 'config' / args.version / 'symbols.txt').read_text()
    symbols = {name: int(address, 16) for name, address in re.findall(r'^(\w+) = \.\w+:(0x[0-9A-Fa-f]+);', config, re.M)}
    dol = verified_dol(ROOT / 'orig' / args.version / 'sys/main.dol',
                       ROOT / 'config' / args.version / 'config.yml')
    bases = {}
    for offset, register in ((8, 2), (16, 13)):
        high, low = struct.unpack('>II', read_dol_range(dol, symbols['__init_registers'] + offset, 8))
        assert high >> 16 == 0x3C00 | (register << 5)
        assert low >> 16 == 0x6000 | (register << 5) | register
        bases[register] = ((high & 0xFFFF) << 16) | (low & 0xFFFF)
    retail = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    machines = [BlendMachine(retail, symbols, symbols['blendTextures'], bases[13], bases[2]),
                BlendMachine(retail + compiled_segments(path, symbols), symbols, CODE, bases[13], SDA2)]
    rng = random.Random(0x5658888)
    cases = 0
    for format_id in (4, 6):
        for width, height in ((0, 4), (4, 0), (4, 4), (8, 4), (4, 8), (12, 8), (16, 16)):
            count = width * height
            a = [rng.randrange(65536) if format_id == 4 else tuple(rng.randrange(256) for _ in range(4)) for _ in range(count)]
            b = [rng.randrange(65536) if format_id == 4 else tuple(rng.randrange(256) for _ in range(4)) for _ in range(count)]
            for weight in (-1.0, -0.5, 0.0, 1.0 / 255.0, 0.25, 0.5, 1.0, 1.5):
                for same_source in (False, True):
                    expected = reference(a, a if same_source else b, weight, format_id)
                    for destination in range(3):
                        for machine in machines:
                            machine.blend(a, b, expected, width, height, format_id, weight, destination,
                                          same_source=same_source)
                        cases += 1
        for invalid in ('null0', 'null1', 'null2', 'unsupported', 'format', 'width', 'height', 'src2_width', 'src2_height'):
            for machine in machines:
                machine.blend(a, b, [], width, height, format_id, 0.5, 2, invalid)
            cases += 1
    print(f'{args.version}: PASS {cases} cases; retail, source and oracle agree; in-place output, guards, cache stores and ABI')


if __name__ == '__main__':
    main()
