#!/usr/bin/env python3
"""Check the compiled I8 shadow blur against retail and an untiled box-filter oracle.

Requires optional unicorn and pyelftools packages plus the selected retail DOL.
Cache flushes are recorded, not emulated. No retail code or image bytes are embedded here.
"""
from io import BytesIO
from pathlib import Path
import argparse
import random
import re
import struct

from version_progress import read_dol_range, verified_dol


ROOT = Path(__file__).resolve().parents[1]
SOURCE_CODE = 0x81000000
TEXTURE = 0x81200020
HEADER_SIZE = 0x60
RETURN = 0x81700000
STACK = 0x817FF000


def source_code(path, symbols):
    from elftools.elf.elffile import ELFFile

    elf = ELFFile(BytesIO(path.read_bytes()))
    assert elf['e_machine'] == 'EM_PPC' and not elf.little_endian
    table = elf.get_section_by_name('.symtab')
    function, = table.get_symbol_by_name('boxBlurTexture')
    section = elf.get_section(function['st_shndx'])
    start, size = function['st_value'], function['st_size']
    code = bytearray(section.data()[start:start + size])
    calls = []
    for relocations in elf.iter_sections():
        if relocations['sh_type'] != 'SHT_RELA' or relocations['sh_info'] != function['st_shndx']:
            continue
        reloc_table = elf.get_section(relocations['sh_link'])
        for relocation in relocations.iter_relocations():
            offset = relocation['r_offset'] - start
            if not 0 <= offset < size:
                continue
            symbol = reloc_table.get_symbol(relocation['r_info_sym']).name
            assert relocation['r_info_type'] == 10 and symbol in (
                '_savegpr_24', '_restgpr_24', 'DCFlushRange'), (symbol, relocation['r_info_type'])
            instruction, = struct.unpack_from('>I', code, offset)
            assert instruction >> 26 == 18 and not instruction & 2
            displacement = symbols[symbol] + relocation['r_addend'] - (SOURCE_CODE + offset)
            assert displacement % 4 == 0 and -0x2000000 <= displacement < 0x2000000
            struct.pack_into('>I', code, offset, (instruction & 0xFC000003) | (displacement & 0x3FFFFFC))
            calls.append(symbol)
    assert sorted(calls) == sorted(('_savegpr_24', '_restgpr_24', 'DCFlushRange'))
    return bytes(code)


def tiled(image, size):
    """Serialize a square I8 image as 8-by-4 tiles, in tile-row order."""
    return bytes(image[(tile_y + y) * size + tile_x + x]
                 for tile_y in range(0, size, 4) for tile_x in range(0, size, 8)
                 for y in range(4) for x in range(8))


def reference(image, size, window, fill):
    pattern = struct.pack('>I', fill) if window % 8 == 0 else struct.pack('>H', fill & 0xFFFF)
    padding = pattern * (window // (2 * len(pattern)))

    def line(values):
        padded = list(padding) + list(values) + list(padding)
        return [sum(padded[i:i + window]) // window for i in range(size)]

    rows = [line(image[y * size:(y + 1) * size]) for y in range(size)]
    columns = [line([rows[y][x] for y in range(size)]) for x in range(size)]
    return [columns[x][y] for y in range(size) for x in range(size)]


def execute(segments, entry, symbols, bases, payload, size, window, fill):
    import unicorn as uc
    from unicorn import ppc_const as ppc

    emulator = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emulator.mem_map(0x80000000, 0x1800000)
    for address, contents in segments:
        emulator.mem_write(address, contents)

    def register(index):
        return getattr(ppc, 'UC_PPC_REG_' + str(index))

    def get(index):
        return emulator.reg_read(register(index))

    def put(index, value):
        emulator.reg_write(register(index), value)

    header = bytes((i * 17 + 3) & 255 for i in range(HEADER_SIZE))
    emulator.mem_write(TEXTURE - 32, b'\xA5' * 32 + header + payload + b'\xA5' * 32)
    saved = {index: 0xCAFE0000 + index for index in range(14, 32)}
    for index, value in saved.items():
        put(index, value)
    for index, value in ((1, STACK), (2, bases[2]), (13, bases[13]),
                         (3, TEXTURE), (4, size), (5, window), (6, fill)):
        put(index, value)
    emulator.reg_write(ppc.UC_PPC_REG_CR, 0x13579024)
    emulator.reg_write(ppc.UC_PPC_REG_LR, RETURN)
    flushes = []

    def flush(emu, address, length, user_data):
        flushes.append((get(3), get(4)))
        for index in (0, *range(3, 13)):
            put(index, 0xD00D0000 + index)
        emulator.reg_write(ppc.UC_PPC_REG_PC, emulator.reg_read(ppc.UC_PPC_REG_LR))

    hook = emulator.hook_add(uc.UC_HOOK_CODE, flush, begin=symbols['DCFlushRange'], end=symbols['DCFlushRange'])
    try:
        emulator.emu_start(entry, RETURN, count=2000000)
    finally:
        emulator.hook_del(hook)
    assert emulator.reg_read(ppc.UC_PPC_REG_PC) == RETURN, 'blur exceeded its instruction budget'
    assert get(1) == STACK and get(2) == bases[2] and get(13) == bases[13]
    assert all(get(index) == value for index, value in saved.items()), 'callee-saved GPR changed'
    assert emulator.reg_read(ppc.UC_PPC_REG_CR) & 0x00FFF000 == 0x13579024 & 0x00FFF000
    assert bytes(emulator.mem_read(TEXTURE - 32, 32 + HEADER_SIZE)) == b'\xA5' * 32 + header
    assert bytes(emulator.mem_read(TEXTURE + HEADER_SIZE + len(payload), 32)) == b'\xA5' * 32
    assert flushes == [(TEXTURE + HEADER_SIZE, size * size)]
    return bytes(emulator.mem_read(TEXTURE + HEADER_SIZE, len(payload)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='GSAE01',
                        choices=['GSAE01', 'GSAE01_rev1', 'GSAJ01', 'GSAP01', 'GSAP01_rev1'])
    parser.add_argument('--object', type=Path)
    args = parser.parse_args()
    path = args.object or ROOT / 'build' / args.version / 'src/main/newshadows.o'
    config = (ROOT / 'config' / args.version / 'symbols.txt').read_text()
    symbols = {name: int(address, 16) for name, address in
               re.findall(r'^(\w+) = \.\w+:(0x[0-9A-Fa-f]+);', config, re.M)}
    dol = verified_dol(ROOT / 'orig' / args.version / 'sys/main.dol',
                       ROOT / 'config' / args.version / 'config.yml')
    bases = {}
    for offset, register in ((8, 2), (16, 13)):
        high, low = struct.unpack('>II', read_dol_range(dol, symbols['__init_registers'] + offset, 8))
        assert high >> 16 == 0x3C00 | (register << 5)
        assert low >> 16 == 0x6000 | (register << 5) | register
        bases[register] = ((high & 0xFFFF) << 16) | (low & 0xFFFF)
    retail = [(section.address, dol.data[section.offset:section.offset + section.size])
              for section in dol.sections]
    compiled = retail + [(SOURCE_CODE, source_code(path, symbols))]
    rng = random.Random(0x8006A028)
    cases = 0
    for size in (8, 16, 32, 64, 128):
        images = [bytes(size * size), bytes([255]) * (size * size),
                  bytes(rng.randrange(256) for _ in range(size * size))]
        impulse = bytearray(size * size)
        for position in (0, size - 1, size * (size // 2) + size // 2, size * size - 1):
            impulse[position] = 255
        images.append(bytes(impulse))
        for window in (4, 8, 12, 16, 20, 24):
            for fill in (0, 0xFFFFFFFF, 0x1234ABCD):
                for image in images:
                    payload = tiled(image, size)
                    expected = tiled(reference(image, size, window, fill), size)
                    for segments, entry in ((retail, symbols['boxBlurTexture']), (compiled, SOURCE_CODE)):
                        actual = execute(segments, entry, symbols, bases, payload, size, window, fill)
                        assert actual == expected, (size, window, hex(fill), entry)
                    cases += 1
        print(f'{size}x{size}: retail, compiled source and oracle agree', flush=True)
    print(f'{args.version}: PASS {cases} image cases; both padding widths, tile layout, guards, cache flush and ABI')


if __name__ == '__main__':
    main()
