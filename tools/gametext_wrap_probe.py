#!/usr/bin/env python3
"""Compare line wrapping with EN retail in PPC emulation.

Requires optional unicorn and pyelftools. Only allocation is mocked; UTF-8
reading, glyph lookup, control parsing, line splitting and Gekko saves execute.
"""
from pathlib import Path
import argparse
import re
import struct
import tempfile

from gametext_parser_probe import ROOT, RETURN, STACK, link_source, pack
from joint_matrices_emulation_probe import GekkoPairs
from version_progress import verified_dol

INPUT, GLYPHS, OUTPUT, HEAP = 0x81200000, 0x81300000, 0x81400000, 0x81500000


def execute(segments, symbols, retail, text, width, scale, want_height, fail=False,
            cursor=(0, 0), charset=0):
    import unicorn as uc
    from unicorn import ppc_const as ppc

    emu = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emu.mem_map(0x80000000, 0x1800000)
    for address, data in segments:
        emu.mem_write(address, data)

    def read(address, size):
        return bytes(emu.mem_read(address, size))

    def write(name, data):
        emu.mem_write(symbols[name], data)

    def get(index):
        return emu.reg_read(getattr(ppc, f'UC_PPC_REG_{index}'))

    def put(index, value):
        emu.reg_write(getattr(ppc, f'UC_PPC_REG_{index}'), value & 0xffffffff)

    def fput(index, value):
        bits = struct.unpack('>Q', pack('d', value))[0]
        emu.reg_write(getattr(ppc, f'UC_PPC_REG_FPR{index}'), bits)

    # Every fixture glyph advances five pixels; font heights are distinct.
    glyphs = b''.join(pack('IHH4b4B', code, 0, 0, -1, 2, 0, 0, 4, 8, font, 0)
                      for font in range(7) for code in (32, 65, 66, 67, 0xe9, 0x3000, 0x303f))
    emu.mem_write(GLYPHS, glyphs)
    write('gGameTextCharsets', pack('III', GLYPHS, 0, len(glyphs) // 16) + bytes(28))
    write('gameTextFonts', pack('I', symbols['gGameTextCharsets']))
    metrics = bytearray(7 * 16)
    for font in range(7):
        struct.pack_into('>HH', metrics, font * 16 + 8, 5, 10 + font)
    write('gGameTextFontMetrics', bytes(metrics))
    write('sLanguageNameTable', bytes(6 * 8))
    write('curLanguage', pack('I', 0))
    write('gameTextCharset', pack('I', charset))
    write('gGameTextCursorX', pack('H', cursor[0]))
    write('gGameTextCursorY', pack('H', cursor[1]))
    write('gGameTextStringStore', pack('I', 0x81600000))
    if text is not None:
        emu.mem_write(INPUT, text + b'\0')
    emu.mem_write(OUTPUT, pack('if', -99, -123.0))
    emu.mem_write(HEAP - 16, b'\xa5' * (0x10000 + 32))
    calls, allocations = [], []
    saved = {i: 0xcafe0000 + i for i in range(14, 32)}
    for i, value in saved.items():
        put(i, value)
    sda1, sda2 = symbols.get('_SDA_BASE_', 0x803e31e0), symbols.get('_SDA2_BASE_', 0x803e6500)
    put(1, STACK)
    put(2, sda2)
    put(13, sda1)
    put(3, INPUT if text is not None else 0)
    put(4, OUTPUT)
    put(5, OUTPUT + 4 if want_height else 0)
    fput(1, width)
    fput(2, scale)
    saved_fprs = {i: 0x4020000000000000 + i for i in range(14, 32)}
    for i, value in saved_fprs.items():
        emu.reg_write(getattr(ppc, f'UC_PPC_REG_FPR{i}'), value)
    emu.reg_write(ppc.UC_PPC_REG_LR, RETURN)
    emu.reg_write(ppc.UC_PPC_REG_MSR, 0x2000)
    emu.reg_write(ppc.UC_PPC_REG_CR, 0x13579024)
    pairs = GekkoPairs(emu, ppc)
    pairs.second = [float(i + 1) for i in range(32)]
    saved_second = pairs.second[14:]

    def allocate(machine, address, size, name):
        assert not allocations, 'unexpected second allocation'
        if name == 'mmAlloc':
            amount = get(3)
            assert (get(4), get(5)) == (0, 0)
        else:
            assert get(3) == 0x81600000
            amount = get(4)
        assert 0 < amount < 0x10000
        calls.append((name, amount))
        allocations.append(amount)
        for index in (0, *range(3, 13)):
            put(index, 0xd00d0000 + index)
        for index in range(14):
            fput(index, -10.0 - index)
            pairs.second[index] = -1.0
        put(3, 0 if fail else HEAP)
        emu.reg_write(ppc.UC_PPC_REG_PC, emu.reg_read(ppc.UC_PPC_REG_LR))

    hooks = [emu.hook_add(uc.UC_HOOK_CODE, pairs.hook)]
    for name in ('mmAlloc', 'mmAllocateFromFBMemoryStore'):
        address = retail[name][1]
        hooks.append(emu.hook_add(uc.UC_HOOK_CODE, allocate, user_data=name, begin=address, end=address))
    try:
        emu.emu_start(symbols['gameTextWrapLines'], RETURN, count=250000)
    except uc.UcError as error:
        raise RuntimeError(f'PPC failed at {emu.reg_read(ppc.UC_PPC_REG_PC):#x}') from error
    finally:
        for hook in hooks:
            emu.hook_del(hook)
    assert emu.reg_read(ppc.UC_PPC_REG_PC) == RETURN, 'instruction budget exceeded'
    assert (get(1), get(2), get(13)) == (STACK, sda2, sda1)
    assert all(get(i) == value for i, value in saved.items())
    assert all(emu.reg_read(getattr(ppc, f'UC_PPC_REG_FPR{i}')) == value for i, value in saved_fprs.items())
    assert pairs.second[14:] == saved_second
    assert emu.reg_read(ppc.UC_PPC_REG_CR) & 0x00fff000 == 0x13579024 & 0x00fff000
    count, height = struct.unpack('>if', read(OUTPUT, 8))
    result, strings = get(3), []
    amount = allocations[0] if allocations and not fail else 0
    assert read(HEAP - 16, 16) == b'\xa5' * 16
    assert read(HEAP + amount, 16) == b'\xa5' * 16
    if result:
        assert result == HEAP and 0 < count <= 30
        for index in range(count):
            pointer = struct.unpack('>I', read(HEAP + index * 4, 4))[0]
            if pointer == 0:
                assert index == count - 1, 'only the final pointer may be unfilled'
                strings.append(None)
                continue
            assert HEAP + count * 4 <= pointer < HEAP + amount
            tail = read(pointer, HEAP + amount - pointer)
            assert b'\0' in tail
            strings.append(tail.split(b'\0', 1)[0])
    return result, count, height, calls, read(HEAP, amount), strings


def control(code, value):
    return chr(code).encode('utf-8') + pack('H', value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, default=ROOT / 'build/GSAE01/src/main/gametext.o')
    args = parser.parse_args()
    config = (ROOT / 'config/GSAE01/symbols.txt').read_text()
    retail = {name: (section, int(address, 16)) for name, section, address in
              re.findall(r'^(\w+) = (\.\w+):(0x[0-9A-Fa-f]+);', config, re.M)}
    dol = verified_dol(ROOT / 'orig/GSAE01/sys/main.dol', ROOT / 'config/GSAE01/config.yml')
    segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    texts = [None, b'', b'ABC', b'A B C', b'A  B', b'ABABAB', 'AéB'.encode(),
             'A\u3000B'.encode(), 'A\u303fB'.encode(), b'A?B',
             b'A ' * 28 + b'A', b'A ' * 29 + b'A', b'A ' * 30 + b'A', b'A ' * 32,
             control(0xf8f4, 128) + b'ABC', control(0xf8f4, 512) + b'ABC',
             control(0xf8f7, 1) + b'ABC', control(0xf8f7, 5) + b'ABC',
             control(0xf8f7, 1) + control(0xf8f4, 512) + b'ABC']
    texts += [control(0xf8f4, value) + b'ABC' for value in (0, 1, 255, 32768, 65535)]
    cases = 0
    with tempfile.TemporaryDirectory(prefix='sfa-text-wrap-') as temporary:
        compiled, symbols = link_source(args.object, Path(temporary), retail)
        for text in texts:
            for width in (5.0, 11.0, 40.0):
                for want_height in (False, True):
                    options = dict(text=text, width=width, scale=1.0, want_height=want_height)
                    expected = execute(segments, {n: v[1] for n, v in retail.items()}, retail, **options)
                    actual = execute(segments + compiled, symbols, retail, **options)
                    assert actual == expected, (options, expected, actual)
                    if text is None or text == b'':
                        assert actual[0] == 0 and actual[1] == (0 if text is None else 1)
                        assert not actual[3]
                    if text == b'ABC':
                        if width == 5:
                            assert actual[0:2] == (0, 0) and not actual[3], (options, actual)
                        else:
                            lines = [b'AB', b'C'] if width == 11 else [b'ABC']
                            assert actual[5] == lines and actual[1] == len(lines)
                            assert actual[3][0][1] == 3 + len(lines) * 5
                    if text == b'A ' * 32 and width == 40:
                        assert actual[1] == 9 and actual[5][-1] is None
                        assert actual[5][-2] == b'A A A A '
                    if text == b'A?B' and width == 11:
                        assert actual[1] == 1 and actual[5] == [b'A?B']
                    if text in (b'A  B', 'A\u3000B'.encode(), 'A\u303fB'.encode()) and width == 11:
                        assert actual[1] == 2 and actual[5] == [b'A', b'B']
                    if text == b'A B C' and width == 11:
                        assert actual[1] == 3 and actual[5] == [b'A', b'B', b'C']
                    if text == b'A ' * 29 + b'A' and width == 11:
                        assert actual[1] == 30 and actual[5] == [b'A'] * 30
                    if text == b'A ' * 30 + b'A' and width == 11:
                        assert actual[0:2] == (0, 0) and not actual[3], (options, actual)
                    if want_height:
                        expected_height = 10.0
                        if text is not None and text.startswith(control(0xf8f7, 1)):
                            expected_height = 22.0 if control(0xf8f4, 512) in text else 11.0
                        elif text is not None and text.startswith(chr(0xf8f4).encode()):
                            argument = struct.unpack('>H', text[3:5])[0]
                            expected_height = max(10.0, 10.0 * argument / 256.0)
                        assert actual[2] == expected_height
                    else:
                        assert actual[2] == -123.0
                    cases += 1
        for options in [dict(fail=True), dict(fail=True, want_height=False),
                        dict(cursor=(11, 0)), dict(cursor=(0, 1)),
                        dict(charset=2), dict(scale=0.5), dict(scale=2.0)]:
            values = dict(text=b'A B C', width=40.0, scale=1.0, want_height=True)
            values.update(options)
            expected = execute(segments, {n: v[1] for n, v in retail.items()}, retail, **values)
            actual = execute(segments + compiled, symbols, retail, **values)
            assert actual == expected, (values, expected, actual)
            if options.get('fail'):
                allocator = 'mmAllocateFromFBMemoryStore' if values['want_height'] else 'mmAlloc'
                assert actual[0:2] == (0, 1) and actual[3] == [(allocator, 10)]
            if options.get('cursor') == (0, 1):
                assert actual[0:2] == (0, 0) and not actual[3], (options, actual)
            if options.get('charset') == 2:
                assert actual[2] == 16.0
            cases += 1
    print(f'PASS: {cases} retail/compiled wrapping cases; output bytes, allocations, metrics, guards and ABI')


if __name__ == '__main__':
    main()
