#!/usr/bin/env python3
"""Execute idle text-runner frames against retail and an independent state oracle.

Requires optional unicorn and pyelftools. Queued commands and resource loading
are disabled; fallback expiry, window maintenance, font timers and ABI execute.
Only blank-string formatting and the reveal-loop sound stop are mocked. The
existing Gekko adapter supplies paired-single register saves and restores.
"""
from pathlib import Path
import argparse
import re
import struct
import tempfile

from gametext_parser_probe import ROOT, RETURN, STACK, link_source, pack
from joint_matrices_emulation_probe import GekkoPairs
from orig.dol_tables import DolFile


def run(segments, symbols, retail, mask, delta, status):
    import unicorn as uc
    from unicorn import ppc_const as ppc

    emulator = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emulator.mem_map(0x80000000, 0x1800000)
    for address, data in segments:
        emulator.mem_write(address, data)

    def read(address, size):
        return bytes(emulator.mem_read(address, size))

    def write(name, data):
        emulator.mem_write(symbols[name], bytes(data))

    def get(index):
        return emulator.reg_read(getattr(ppc, f'UC_PPC_REG_{index}'))

    def put(index, value):
        emulator.reg_write(getattr(ppc, f'UC_PPC_REG_{index}'), value)

    fonts = bytearray(160)
    for i in range(4):
        fonts[i * 40 + 36] = 255
    struct.pack_into('>If', fonts, 28, status, 17.5)
    write('gGameTextCharsets', fonts)
    write('gameTextFonts', pack('I', symbols['gGameTextCharsets']))
    write('curGameTexts', bytes(8 * 76))
    write('lbl_803DC9C8', pack('I', 0))
    write('timeDelta', pack('f', delta))
    write('gGameTextRevealActive', pack('I', 7))
    write('gGameTextCursorX', pack('H', 19))
    write('gGameTextCursorY', pack('H', 23))
    write('gCurTextBox', pack('I', symbols['gTextBoxes']))

    boxes = bytearray((i * 17 + 13) & 255 for i in range(148 * 32))
    write('gTextBoxes', boxes)
    for i in range(148):
        boxes[i * 32 + 24:i * 32 + 28] = bytes(4)
        boxes[i * 32 + 29] &= 254

    elapsed = [0.0, 119.0, 119.5, 120.0, 120.5, 121.0, -1.0, 240.0]
    requests = [float(i + 1) if mask & (1 << i) else float(-i) for i in range(8)]
    write('sGameTextFallbackElapsedFrames', pack('8f', *elapsed))
    write('sGameTextFallbackRequestDelta', pack('8f', *requests))
    buffers = [bytearray((i * 29 + j + 1) & 255 for j in range(64)) for i in range(8)]
    definitions = bytearray(8 * 12)
    strings = []
    expired = []
    for i in range(8):
        strings.append(symbols['sGameTextFallbackBuffers'] + 64 * i)
        struct.pack_into('>I', definitions, 12 * i + 8, symbols['sGameTextFallbackStrings'] + 4 * i)
        emulator.mem_write(strings[-1], bytes(buffers[i]))
        if requests[i] > 0:
            elapsed[i] = struct.unpack('>f', pack('f', elapsed[i] + delta))[0]
            if elapsed[i] > 120.0:
                elapsed[i] = requests[i] = 0.0
                buffers[i][:5] = b'    \0'
                expired.append(i)
    write('sGameTextFallbackDefs', definitions)
    write('sGameTextFallbackStrings', pack('8I', *strings))
    guards = [(symbols[name] + offset, read(symbols[name] + offset, 16))
              for name, length in (('gTextBoxes', len(boxes)), ('sGameTextFallbackBuffers', 512))
              for offset in (-16, length)]

    saved = {i: 0xCAFE0000 + i for i in range(14, 32)}
    for index, value in saved.items():
        put(index, value)
    sda1, sda2 = symbols.get('_SDA_BASE_', 0x803E31E0), symbols.get('_SDA2_BASE_', 0x803E6500)
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
        if name == 'sprintf':
            assert get(3) in strings and read(get(4), 5) == b'    \0'
            calls.append(('blank', strings.index(get(3))))
            emulator.mem_write(get(3), b'    \0')
        else:
            assert name == 'Sfx_StopFromObject' and (get(3), get(4)) == (0, 0x397)
            calls.append(('stop',))
        for index in (0, *range(3, 13)):
            put(index, 0xD00D0000 + index)
        for index in range(14):
            emulator.reg_write(getattr(ppc, f'UC_PPC_REG_FPR{index}'), 0x4000000000000000 + index)
            pairs.second[index] = -1.0
        emulator.reg_write(ppc.UC_PPC_REG_PC, emulator.reg_read(ppc.UC_PPC_REG_LR))

    hooks = [emulator.hook_add(uc.UC_HOOK_CODE, pairs.hook)]
    for name in ('sprintf', 'Sfx_StopFromObject'):
        address = retail[name][1]
        hooks.append(emulator.hook_add(uc.UC_HOOK_CODE, mock, user_data=name, begin=address, end=address))
    try:
        emulator.emu_start(symbols['gameTextRun'], RETURN, count=100000)
    except uc.UcError as error:
        pc = emulator.reg_read(ppc.UC_PPC_REG_PC)
        raise RuntimeError(f'PPC execution failed at {pc:#x}: {read(pc, 4).hex()}') from error
    finally:
        for hook in hooks:
            emulator.hook_del(hook)
    assert emulator.reg_read(ppc.UC_PPC_REG_PC) == RETURN, 'runner exceeded instruction budget'
    assert (get(1), get(2), get(13)) == (STACK, sda2, sda1)
    assert all(get(i) == value for i, value in saved.items())
    assert all(emulator.reg_read(getattr(ppc, f'UC_PPC_REG_FPR{i}')) == value for i, value in saved_fprs.items())
    assert pairs.second[14:] == saved_second
    assert all(read(address, len(value)) == value for address, value in guards)
    assert emulator.reg_read(ppc.UC_PPC_REG_CR) & 0x00FFF000 == 0x13579024 & 0x00FFF000
    assert calls == [('blank', i) for i in reversed(expired)] + [('stop',)]
    expected = {
        'gTextBoxes': bytes(boxes),
        'sGameTextFallbackElapsedFrames': pack('8f', *elapsed),
        'sGameTextFallbackRequestDelta': pack('8f', *requests),
        'sGameTextFallbackDefs': bytes(definitions),
        'sGameTextFallbackStrings': pack('8I', *strings),
        'sGameTextFallbackBuffers': b''.join(buffers),
        'gGameTextRevealActive': bytes(4), 'gGameTextCursorX': bytes(2), 'gGameTextCursorY': bytes(2),
        'gCurTextBox': bytes(4), 'lbl_803DC9C8': bytes(4),
        'curGameTexts': bytes(8 * 76),
        'gGameTextCommandStringCursor': pack('I', symbols['sGameTextCommandStringBuffer']),
    }
    struct.pack_into('>f', fonts, 32, 17.5 + delta if status == 1 else 0.0)
    expected['gGameTextCharsets'] = bytes(fonts)
    for name, value in expected.items():
        assert read(symbols[name], len(value)) == value, (name, mask, delta, status)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, default=ROOT / 'build/GSAE01/src/main/gametext.o')
    args = parser.parse_args()
    config = (ROOT / 'config/GSAE01/symbols.txt').read_text()
    retail = {name: (section, int(address, 16)) for name, section, address in
              re.findall(r'^(\w+) = (\.\w+):(0x[0-9A-Fa-f]+);', config, re.M)}
    dol = DolFile(ROOT / 'orig/GSAE01/sys/main.dol')
    segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    cases = 0
    with tempfile.TemporaryDirectory(prefix='sfa-text-maintenance-') as temporary:
        compiled_segments, compiled_symbols = link_source(args.object, Path(temporary), retail)
        for mask in (0, 255, 1, 128, 85, 170, 15, 240):
            for delta in (0.0, 0.5, 1.0, 2.0):
                for status in (0, 1):
                    run(segments, {name: value[1] for name, value in retail.items()}, retail, mask, delta, status)
                    run(segments + compiled_segments, compiled_symbols, retail, mask, delta, status)
                    cases += 1
    print(f'PASS: {cases} retail/compiled frame cases; fallback expiry, 148 windows, timers, sound and ABI')


if __name__ == '__main__':
    main()
