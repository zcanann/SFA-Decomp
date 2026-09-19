#!/usr/bin/env python3
"""Compare a compiled vertex-stream wrapper with retail and an independent call oracle.

Only the wrapper executes. Cache transfers and the skinning kernel are recorded
and stubbed; this does not validate DMA or paired-single arithmetic. Requires
Unicorn. Inputs are local ELF objects, never executable host compiler binaries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import struct

from obj_equal import Elf
from version_progress import verified_dol, read_dol_range

NAME = 'ObjModel_BlendVertexStream'
CODE, TABLE, MATRIX, JOB, DATA, OFFSETS, OUTPUT, CHUNKS = (
    0x80010000, 0x80100000, 0x80200000, 0x80300000,
    0x80400000, 0x80500000, 0x80600000, 0x80700000)
CACHE = [0x80800000 + i * 0x10000 for i in range(4)]
STOP, STACK = 0x80f00000, 0x80fff000
ARITY = {'setGQR7Packed': 4, 'ObjModel_InitScratchBuffers': 0,
         'copyToCache': 3, 'cacheQueueWait': 1,
         'ObjModel_TransformVerticesWithTranslation': 6, 'memcpyToCache': 3}


def words(values):
    return struct.pack('>' + 'I' * len(values), *(x & 0xffffffff for x in values))


class Wrapper:
    def __init__(self, path):
        import unicorn as uc
        from unicorn import ppc_const as ppc
        self.ppc = ppc
        self.uc = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
        self.uc.mem_map(0x80000000, 0x1000000)
        elf = Elf(str(path))
        symbol = next(s for s in elf.symbols if s['name'] == NAME)
        start, size = symbol['value'], symbol['size']
        code = bytearray(elf.body(elf.by_name['.text'])[start:start + size])
        self.calls = {}
        for off, kind, addend, target in elf.relocs()['.text']:
            if not start <= off < start + size:
                continue
            off -= start
            assert target[0] == 'NAME', target
            name = target[1]
            if kind == 10:
                assert name in ARITY or name.startswith(('_savegpr_', '_restgpr_')), name
                address = CODE + 0x10000 + len(self.calls) * 4
                self.calls[address] = name
                ins = struct.unpack_from('>I', code, off)[0]
                ins = (ins & 0xfc000003) | ((address + addend - CODE - off) & 0x03fffffc)
                struct.pack_into('>I', code, off, ins)
            else:
                assert name == 'gModelCacheBuffersA' and kind in (4, 6), (name, kind)
                value = TABLE + addend
                half = ((value + 0x8000) >> 16) if kind == 6 else value
                struct.pack_into('>H', code, off, half & 0xffff)
        self.uc.mem_write(CODE, bytes(code))
        self.uc.hook_add(uc.UC_HOOK_CODE, self.hook)

    def reg(self, index):
        return getattr(self.ppc, 'UC_PPC_REG_' + str(index))

    def hook(self, emulator, address, size, user):
        name = self.calls.get(address)
        if name is None:
            return
        if name in ARITY:
            self.trace.append((name, tuple(emulator.reg_read(self.reg(i)) for i in range(3, 3 + ARITY[name]))))
            # Exercise the ABI boundary: no volatile GPR survives a call.
            for i in [0, *range(3, 13)]:
                emulator.reg_write(self.reg(i), 0xdead0000 + i)
        emulator.reg_write(self.ppc.UC_PPC_REG_PC, emulator.reg_read(self.ppc.UC_PPC_REG_LR))

    def run(self, quant, chunks, offsets):
        self.trace = []
        u = self.uc
        u.mem_write(TABLE, words(CACHE))
        job = bytearray(16)
        struct.pack_into('>H', job, 2, len(chunks))
        job[6] = quant
        struct.pack_into('>I', job, 12, CHUNKS)
        u.mem_write(JOB, bytes(job))
        for i, (src, weight, ma, mb, wb, count, offset, vb) in enumerate(chunks):
            data = bytearray(0x74)
            struct.pack_into('>iI', data, 0x60, src, weight)
            data[0x6c:0x70] = bytes([ma, mb, 0, wb])
            struct.pack_into('>HBB', data, 0x70, count, offset, vb)
            u.mem_write(CHUNKS + i * 0x74, bytes(data))
        if offsets:
            u.mem_write(OFFSETS, words(offsets))
        for i in range(32):
            u.reg_write(self.reg(i), 0)
        for i, value in enumerate([MATRIX, JOB, DATA, OFFSETS, OUTPUT], 3):
            u.reg_write(self.reg(i), value)
        u.reg_write(self.reg(1), STACK)
        u.reg_write(self.ppc.UC_PPC_REG_LR, STOP)
        u.emu_start(CODE, STOP, count=100000)
        assert u.reg_read(self.ppc.UC_PPC_REG_PC) == STOP, 'wrapper did not return'
        return self.trace


def expected(quant, chunks, offsets):
    calls = [('setGQR7Packed', (quant, 7, quant, 7)), ('ObjModel_InitScratchBuffers', ())]
    def prefetch(index):
        src, weight, ma, mb, wb, count, offset, vb = chunks[index]
        slot = 2 * (index % 2)
        calls.extend([('copyToCache', (CACHE[slot], DATA + src, vb)),
                      ('copyToCache', (CACHE[slot + 1], weight, wb))])
    if not chunks:
        return calls
    prefetch(0)
    for i, (src, weight, ma, mb, wb, count, offset, vb) in enumerate(chunks):
        if i + 1 < len(chunks):
            prefetch(i + 1)
        calls.append(('cacheQueueWait', (2 if i + 1 < len(chunks) else 0,)))
        slot = 2 * (i % 2)
        pointer = CACHE[slot] + offset
        calls.extend([
            ('ObjModel_TransformVerticesWithTranslation',
             (MATRIX + ma * 48, MATRIX + mb * 48, CACHE[slot + 1], pointer, pointer, count)),
            ('memcpyToCache', (OUTPUT + offsets[i], CACHE[slot], vb))])
    calls.append(('cacheQueueWait', (0,)))
    return [(name, tuple(x & 0xffffffff for x in args)) for name, args in calls]



def verify_retail(path):
    """Resolve the extracted object's relocations and require verified DOL bytes."""
    root = Path(__file__).resolve().parents[1]
    config = root / 'config/GSAE01'
    dol = verified_dol(root / 'orig/GSAE01/sys/main.dol', config / 'config.yml')
    symbols = {name: int(address, 16) for name, address in re.findall(
        r'^(\S+) = \.[^:]+:(0x[0-9a-fA-F]+);',
        (config / 'symbols.txt').read_text(), re.M)}
    elf = Elf(str(path))
    symbol = next(s for s in elf.symbols if s['name'] == NAME)
    start, size = symbol['value'], symbol['size']
    address = symbols[NAME]
    code = bytearray(elf.body(elf.by_name['.text'])[start:start + size])
    for off, kind, addend, target in elf.relocs()['.text']:
        if not start <= off < start + size:
            continue
        off -= start
        assert target[0] == 'NAME', target
        value = symbols[target[1]] + addend
        if kind == 10:
            ins = struct.unpack_from('>I', code, off)[0]
            ins = (ins & 0xfc000003) | ((value - address - off) & 0x03fffffc)
            struct.pack_into('>I', code, off, ins)
        else:
            assert kind in (4, 6), kind
            half = ((value + 0x8000) >> 16) if kind == 6 else value
            struct.pack_into('>H', code, off, half & 0xffff)
    assert code == read_dol_range(dol, address, size), 'retail ELF differs from verified DOL'
    return hashlib.sha1(dol.data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--retail', type=Path, default=Path('build/GSAE01/obj/main/model.o'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    retail_sha1 = verify_retail(args.retail)
    wrappers = [Wrapper(args.retail), Wrapper(args.candidate)]
    rng = random.Random(0x29b00)
    total = 0
    for count in [0, 1, 2, 3, 4, 7, 8, 15, 16, 31]:
        for sample in range(64):
            chunks, offsets = [], []
            for i in range(count):
                chunks.append((rng.randint(-0x1000, 0x1000), 0x80900000 + i * 0x1000,
                               rng.randrange(256), rng.randrange(256), rng.randrange(256),
                               rng.randrange(65536), rng.randrange(256), rng.randrange(256)))
                offsets.append(rng.randint(-0x2000, 0x2000))
            oracle = expected(sample * 4, chunks, offsets)
            for wrapper in wrappers:
                got = wrapper.run(sample * 4, chunks, offsets)
                assert got == oracle, (count, sample, got, oracle)
            total += 1
    report = {'retail_dol_sha1': retail_sha1, 'cases': total, 'matched_comparisons': total * 2,
              'scope': 'Wrapper call arguments/order only; DMA, transforms, save/restore helpers stubbed.',
              'sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in [args.retail, args.candidate, Path(__file__)]}}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{total} scenarios passed for both retail and candidate')


if __name__ == '__main__':
    main()
