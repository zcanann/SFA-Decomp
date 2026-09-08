#!/usr/bin/env python3
"""Compare the compiled text-resource parser with EN retail in PPC emulation.

Requires optional unicorn and pyelftools packages. Allocation and cache calls
are mocked; the complete parser, copying loops, relocation, and register-save
helpers execute. No retail source or binary bytes are stored in this tool.
Use --resources to add individual extracted gametext files to the synthetic cases.
"""

from __future__ import annotations

import argparse
from collections import Counter
from io import BytesIO
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from orig.dol_tables import DolFile

ROOT = Path(__file__).resolve().parents[1]
INPUT = 0x81200000
SLOT = 0x81300000
TEXTURES = 0x81400000
COMPACT = 0x81500000
RETURN = 0x81700000
STACK = 0x817FF000
CALLS = ('DCStoreRange', 'DCFlushRange', 'mmSetFreeDelay', 'mm_free', 'mmAlloc', 'textureAlloc')


def pack(fmt, *values):
    return struct.pack('>' + fmt, *values)


def word(data, offset=0):
    return struct.unpack_from('>I', data, offset)[0]


def resource_layout(data):
    """Audit serialized extents independently of the runtime pointer relocation."""
    def require(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError(f'resource span {offset:#x}+{size:#x} exceeds {len(data):#x}')

    require(0, 4)
    glyphs = word(data)
    if glyphs == 0:
        return {'empty': True}
    header = 4 + glyphs * 16
    require(header, 4)
    definitions, string_size = struct.unpack_from('>HH', data, header)
    string_table = header + 4 + definitions * 12
    require(string_table, 4)
    strings = word(data, string_table)
    string_data = string_table + 4 + strings * 4
    require(string_data, string_size + 4)
    for index in range(definitions):
        record = header + 4 + index * 12
        count = struct.unpack_from('>H', data, record + 2)[0]
        if word(data, record + 8) + count > strings:
            raise ValueError('definition extends beyond the string-pointer table')
    for index in range(strings):
        if word(data, string_table + 4 + index * 4) >= string_size:
            raise ValueError('string offset lies outside the string-data block')
    padding_start = string_data + string_size + 4
    padding_size = word(data, padding_start - 4)
    require(padding_start, padding_size)
    texture_start = cursor = padding_start + padding_size
    textures = []
    while True:
        require(cursor, 8)
        format_id, bpp, width, height = struct.unpack_from('>4H', data, cursor)
        cursor += 8
        if width == 0 and height == 0:
            break
        size = width * height * bpp // 8
        require(cursor, size)
        textures.append((format_id, bpp, width, height))
        cursor += size
    if cursor != len(data):
        raise ValueError(f'{len(data) - cursor} bytes follow the texture terminator')
    return {'glyphs': glyphs, 'definitions': definitions, 'strings': strings,
            'header': header, 'string_table': string_table, 'string_data': string_data,
            'padding_size': padding_size, 'padding_values': sorted(set(data[padding_start:texture_start])),
            'texture_start': texture_start, 'textures': textures}


def synthetic_resource(strings=3, textures=2, dimensions=None):
    text = b''.join(b'A' * (i + 1) + b'\0' for i in range(strings))
    text += bytes((-len(text)) % 4)
    offsets, cursor = [], 0
    for i in range(strings):
        offsets.append(cursor)
        cursor += i + 2
    glyph = pack('IHH4b4B', 65, 0, 0, 0, 8, 0, 8, 8, 8, 4, 0)
    definitions = 2 if strings > 1 else 1
    entries = pack('HH4BI', 42, strings, 0, 0, 0, 0, 0)
    if definitions == 2:
        entries += pack('HH4BI', 43, 1, 1, 0, 0, 0, strings - 1)
    data = pack('I', 1) + glyph + pack('HH', definitions, len(text)) + entries
    data += pack('I', strings) + b''.join(pack('I', offset) for offset in offsets) + text
    data += pack('I', 8) + b'\xee' * 8
    for i in range(textures):
        format_id, bpp = (2, 4) if i % 2 == 0 else (1, 16)
        width, height = dimensions[i] if dimensions else (8, 8)
        data += pack('4H', format_id, bpp, width, height)
        data += bytes((n * 13 + i) & 255 for n in range(width * height * bpp // 8))
    return data + bytes(8)


def link_source(obj, directory, retail_symbols):
    from elftools.elf.elffile import ELFFile

    prefix = ROOT / 'build/binutils/powerpc-eabi-'
    nm, assembler, linker = (str(prefix) + name for name in ('nm', 'as', 'ld'))
    undefined = subprocess.check_output([nm, '-u', str(obj)], text=True, timeout=30)
    definitions, data_stubs = [], []
    for line in undefined.splitlines():
        name = line.split()[-1]
        value = retail_symbols.get(name)
        if value and value[0] == '.text':
            definitions.append(f'--defsym={name}={value[1]}')
        else:
            # Only the parser is entered. Unrelated external data needs SDA
            # placement for linking, but is never part of a parser fixture.
            data_stubs.append(f'.global {name}\n{name}:\n.skip 8\n')
    stub = directory / 'globals.s'
    stub.write_text('.section .sbss,"aw",@nobits\n.balign 4\n' + ''.join(data_stubs))
    subprocess.run([assembler, str(stub), '-o', str(directory / 'globals.o')], check=True, timeout=30)
    output = directory / 'gametext.elf'
    subprocess.run([linker, '-Ttext=0x81000000', '-e', 'gameTextFinalizeLoad', *definitions,
                    str(obj), str(directory / 'globals.o'), '-o', str(output)], check=True, timeout=30)
    elf = ELFFile(BytesIO(output.read_bytes()))
    segments = [(segment['p_vaddr'], segment.data()) for segment in elf.iter_segments()
                if segment['p_type'] == 'PT_LOAD']
    symbols = {symbol.name: symbol['st_value'] for symbol in elf.get_section_by_name('.symtab').iter_symbols()}
    return segments, symbols


def execute(segments, symbols, retail_symbols, data, source_id, fail_texture):
    import unicorn as uc
    from unicorn import ppc_const as ppc

    emulator = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    assert len(data) < SLOT - INPUT
    emulator.mem_map(0x80000000, 0x1800000)
    for address, contents in segments:
        emulator.mem_write(address, contents)
    def read(address, size):
        return bytes(emulator.mem_read(address, size))
    def register(index):
        return getattr(ppc, f'UC_PPC_REG_{index}')
    def get(index):
        return emulator.reg_read(register(index))
    def put(index, value):
        emulator.reg_write(register(index), value & 0xffffffff)

    globals_base = symbols['gGameTextCharsets']
    emulator.mem_write(globals_base, bytes(160))
    for slot in range(4):
        emulator.mem_write(globals_base + slot * 40 + 16,
                           pack('3I', *(0x81180000 + i * 256 for i in range(3))))
    for name in ('curGameTextDir', 'curLanguage'):
        emulator.mem_write(symbols[name], pack('I', 99))
    emulator.mem_write(INPUT, data)
    emulator.mem_write(SLOT, bytes(60) + pack('3I4B', INPUT, len(data), 2, 7, 4, 1, source_id))
    nonvolatile = {i: 0xcafe0000 + i for i in range(14, 32)}
    for index, value in nonvolatile.items():
        put(index, value)
    put(1, STACK)
    sda2 = symbols.get('_SDA2_BASE_', 0x803E6500)
    sda1 = symbols.get('_SDA_BASE_', 0x803E31E0)
    put(2, sda2)
    put(13, sda1)
    put(3, SLOT)
    emulator.reg_write(ppc.UC_PPC_REG_CR, 0x13579024)
    emulator.reg_write(ppc.UC_PPC_REG_LR, RETURN)
    calls, allocations = [], []
    texture_count = 0
    compact_size = 0

    def mock(emu, address, size, name):
        nonlocal texture_count, compact_size
        result = 0
        if name in ('DCStoreRange', 'DCFlushRange'):
            args = (get(3), get(4))
        elif name in ('mmSetFreeDelay', 'mm_free'):
            args = (get(3),)
        elif name == 'mmAlloc':
            args = (get(3), get(4), get(5))
            compact_size = args[0]
            assert compact_size < 0x100000
            result = COMPACT
            emulator.mem_write(COMPACT - 16, b'\xcd' * (compact_size + 32))
        elif name == 'textureAlloc':
            args = tuple(get(i) for i in range(3, 11)) + (word(read(get(1) + 8, 4)),)
            width, height, format_id = args[:3]
            assert args[3:] == (0, 0, 0, 0, 1, 1)
            assert format_id in (0, 5)
            image_size = width * height // 2 if format_id == 0 else width * height * 2
            assert image_size + 96 < 0x40000 and texture_count < 3
            if texture_count != fail_texture:
                result = TEXTURES + texture_count * 0x40000
                emulator.mem_write(result - 16, b'\xcd' * (image_size + 128))
                emulator.mem_write(result, bytes(96) + b'\xcd' * image_size)
                emulator.mem_write(result + 0x44, pack('I', image_size))
                allocations.append((result, image_size))
            texture_count += 1
        else:
            raise AssertionError(name)
        calls.append((name, args))
        # Exercise the caller's preservation of live values across external calls.
        for index in (0, *range(4, 13)):
            put(index, 0xd00d0000 + index)
        put(3, result)
        emulator.reg_write(ppc.UC_PPC_REG_PC, emulator.reg_read(ppc.UC_PPC_REG_LR))

    for name in CALLS:
        address = retail_symbols[name][1]
        emulator.hook_add(uc.UC_HOOK_CODE, mock, user_data=name, begin=address, end=address)
    emulator.emu_start(symbols['gameTextFinalizeLoad'], RETURN, count=10000000)
    assert emulator.reg_read(ppc.UC_PPC_REG_PC) == RETURN, 'parser did not return within instruction budget'
    assert get(1) == STACK
    assert get(2) == sda2 and get(13) == sda1
    assert all(get(i) == value for i, value in nonvolatile.items())
    assert emulator.reg_read(ppc.UC_PPC_REG_CR) & 0x00fff000 == 0x13579024 & 0x00fff000
    guarded = [(address, 96 + length) for address, length in allocations]
    if compact_size:
        guarded.append((COMPACT, compact_size))
    for address, length in guarded:
        assert read(address - 16, 16) == b'\xcd' * 16
        assert read(address + length, 16) == b'\xcd' * 16
    return {'calls': calls, 'fonts': read(globals_base, 160), 'slot': read(SLOT, 76),
            'language': read(symbols['curLanguage'], 4), 'directory': read(symbols['curGameTextDir'], 4),
            'compacted': read(COMPACT, compact_size), 'input': read(INPUT, len(data)),
            'textures': [read(address, 96 + length) for address, length in allocations]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, default=ROOT / 'build/GSAE01/src/main/gametext.o')
    parser.add_argument('--resources', type=Path, nargs='*', default=[])
    parser.add_argument('--audit-root', type=Path, help='Audit all resource extents without emulating every file')
    args = parser.parse_args()
    if args.audit_root:
        files = sorted(args.audit_root.rglob('*.bin'))
        if not files:
            parser.error('no resource files found under --audit-root')
        shapes = Counter()
        for path in files:
            layout = resource_layout(path.read_bytes())
            shapes['empty' if layout.get('empty') else f"{len(layout['textures'])} textures"] += 1
        print(f'Audited {len(files)} resource extents: {dict(shapes)}')
    config = (ROOT / 'config/GSAE01/symbols.txt').read_text()
    retail_symbols = {name: (section, int(address, 16)) for name, section, address in
                      re.findall(r'^(\w+) = (\.\w+):(0x[0-9A-Fa-f]+);', config, re.M)}
    dol = DolFile(ROOT / 'orig/GSAE01/sys/main.dol')
    retail_segments = [(section.address, dol.data[section.offset:section.offset + section.size])
                       for section in dol.sections]
    cases = [('empty', bytes(4))]
    for count in (0, 1, 3, 7, 8, 9, 17):
        for textures in (0, 1, 2, 3):
            cases.append((f'{count} strings/{textures} textures', synthetic_resource(count, textures)))
    cases.append(('short images and copy tails', synthetic_resource(3, 3, [(4, 2), (6, 2), (12, 2)])))
    cases += [(str(path), path.read_bytes()) for path in args.resources]
    comparisons = 0
    with tempfile.TemporaryDirectory(prefix='sfa-text-parser-') as temporary:
        source_segments, source_symbols = link_source(args.object, Path(temporary), retail_symbols)
        for name, data in cases:
            resource_layout(data)
            for source_id in range(4):
                for fail_texture in (-1, 0, 1):
                    retail = execute(retail_segments, {name: value[1] for name, value in retail_symbols.items()},
                                     retail_symbols, data, source_id, fail_texture)
                    current = execute(retail_segments + source_segments, source_symbols,
                                      retail_symbols, data, source_id, fail_texture)
                    for field in retail:
                        assert current[field] == retail[field], (name, source_id, fail_texture, field)
                    comparisons += 1
    print(f'{comparisons} compiled/retail parser comparisons passed')


if __name__ == '__main__':
    main()
