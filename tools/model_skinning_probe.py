#!/usr/bin/env python3
"""Compare scalar model skinning with retail PPC and a float32 arithmetic oracle.

Requires unicorn and pyelftools. Emulates only the paired-single quantization
and arithmetic used by these kernels, plus GQR reads. This is a finite-input
behavior probe, not a hardware floating-point conformance test. No retail code
is embedded. Run after building the EN model source object.
"""
import argparse
import ctypes
import ctypes.util
import json
import math
from pathlib import Path
import random
import re
import struct
import tempfile

from gametext_parser_probe import link_source
from joint_matrices_emulation_probe import GekkoPairs, signed
from version_progress import verified_dol

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('ObjModel_TransformVerticesWithTranslation', 'ObjModel_TransformVerticesLinear',
         'ObjModel_TransformNormalTriplets')
MATRIX_A, MATRIX_B, WEIGHTS, INPUT, OUTPUT = (0x81400000 + i * 0x10000 for i in range(5))
RETURN, STACK = 0x81700000, 0x817ff000
LIBM = ctypes.CDLL(ctypes.util.find_library('m'))
FMA = LIBM.fmaf
FMA.argtypes = (ctypes.c_float,) * 3
FMA.restype = ctypes.c_float


def pack(fmt, *values):
    return struct.pack('>' + fmt, *values)


def f32(value):
    return struct.unpack('>f', pack('f', value))[0]


class QuantizedPairs(GekkoPairs):
    def __init__(self, emulator, ppc, config):
        super().__init__(emulator, ppc)
        self.gqr = [0, 0, 0x00040004, 0x00050005, 0x00060006, 0x00070007,
                    0x07040704, config]

    def hook(self, emulator, pc, size, user):
        ins = int.from_bytes(emulator.mem_read(pc, 4), 'big')
        opcode = ins >> 26
        dest, a, b, c = ((ins >> shift) & 31 for shift in (21, 16, 11, 6))
        if opcode == 31 and (ins >> 1) & 1023 == 339:
            spr = ((ins >> 16) & 31) | ((ins >> 6) & 0x3e0)
            assert 912 <= spr <= 919, ('unexpected special-register read', spr)
            emulator.reg_write(getattr(self.ppc, f'UC_PPC_REG_{dest}'), self.gqr[spr - 912])
        elif opcode in (56, 57, 60, 61):
            address = ((self.gpr(a) if a else 0) + signed(ins, 12)) & 0xffffffff
            config = self.gqr[(ins >> 12) & 7]
            load = opcode in (56, 57)
            field = config >> (16 if load else 0)
            kind, scale = field & 7, signed(field >> 8, 6)
            count = 1 if (ins >> 15) & 1 else 2
            fmt, width, low, high = {0: ('f', 4, None, None), 4: ('B', 1, 0, 255),
                5: ('H', 2, 0, 65535), 6: ('b', 1, -128, 127),
                7: ('h', 2, -32768, 32767)}[kind]
            if load:
                values = struct.unpack('>' + fmt * count, emulator.mem_read(address, width * count))
                values = [f32(math.ldexp(v, -scale)) if kind else v for v in values]
                self.write(dest, values + ([1.0] if count == 1 else []))
            else:
                values = list(self.read(dest)[:count])
                if kind:
                    values = [int(min(high, max(low, f32(math.ldexp(v, scale))))) for v in values]
                emulator.mem_write(address, pack(fmt * count, *values))
            if opcode & 1:
                assert a
                emulator.reg_write(getattr(self.ppc, f'UC_PPC_REG_{a}'), address)
        elif opcode == 4:
            short = (ins >> 1) & 31
            av, bv, cv = self.read(a), self.read(b), self.read(c)
            if short in (12, 13):
                self.write(dest, [f32(v * cv[short - 12]) for v in av])
            elif short in (14, 15):
                self.write(dest, [FMA(av[i], cv[short - 14], bv[i]) for i in range(2)])
            else:
                raise AssertionError(('unexpected paired arithmetic', hex(ins)))
        else:
            return
        self.coverage.add(pc)
        emulator.reg_write(self.ppc.UC_PPC_REG_PC, pc + 4)


def oracle(mode, matrices, weights, values, load_scale, store_scale):
    result = []
    width = 16 if mode == 0 else 8
    group = 3 if mode == 2 else 1
    for index in range(len(values) // 3):
        xyz = [math.ldexp(v, -load_scale) for v in values[index * 3:index * 3 + 3]]
        wa, wb = (math.ldexp(v, -7) for v in weights[(index // group) * 2:(index // group) * 2 + 2])
        for axis in range(3):
            transformed = []
            for matrix in matrices:
                v = FMA(matrix[axis], xyz[0], matrix[axis + 9]) if mode == 0 else f32(matrix[axis] * xyz[0])
                v = FMA(matrix[axis + 3], xyz[1], v)
                transformed.append(FMA(matrix[axis + 6], xyz[2], v))
            mixed = FMA(transformed[1], wb, f32(transformed[0] * wa))
            result.append(int(min((1 << (width - 1)) - 1, max(-(1 << (width - 1)),
                          f32(math.ldexp(mixed, store_scale))))))
    return pack(('h' if mode == 0 else 'b') * len(result), *result)


def cases():
    rng = random.Random(0x534641)
    for mode in range(3):
        for scale in range(-32, 32):
            for count in (2, 3, 7):
                for store_scale in (scale, max(-32, scale - 2)):
                    group = 3 if mode == 2 else 1
                    limit = 32768 if mode == 0 else 128
                    matrices = [[f32(rng.uniform(-2, 2)) for _ in range(12)] for _ in range(2)]
                    weights = [rng.randrange(256) for _ in range(count * 2)]
                    values = [rng.randrange(-limit, limit) for _ in range(count * group * 3)]
                    yield mode, count, scale, store_scale, matrices, weights, values
    # Cancellation makes translation order visible in integer output.
    matrix = [0.0] * 12
    matrix[0], matrix[3], matrix[9] = 16777216.0, 1.0, -16777216.0
    yield 0, 2, 0, 0, [matrix, [0.0] * 12], [128, 0] * 2, [1, 1, 0] * 2


def execute(segments, symbols, name, case, in_place):
    import unicorn as uc
    from unicorn import ppc_const as ppc

    mode, count, load_scale, store_scale, matrices, weights, values = case
    emulator = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
    emulator.mem_map(0x80000000, 0x1800000)
    for address, data in segments:
        if data:
            emulator.mem_write(address, data)
    emulator.reg_write(ppc.UC_PPC_REG_MSR, 0x2000)
    emulator.reg_write(ppc.UC_PPC_REG_2, symbols.get('_SDA2_BASE_', 0x803E6500))
    emulator.reg_write(ppc.UC_PPC_REG_13, symbols.get('_SDA_BASE_', 0x803E31E0))
    emulator.reg_write(ppc.UC_PPC_REG_1, STACK)
    emulator.reg_write(ppc.UC_PPC_REG_LR, RETURN)
    saved = {i: 0xa1000000 + i * 0x10101 for i in range(14, 32)}
    for i, value in saved.items():
        emulator.reg_write(getattr(ppc, f'UC_PPC_REG_{i}'), value)
    for address, matrix in zip((MATRIX_A, MATRIX_B), matrices):
        emulator.mem_write(address, pack('12f', *matrix))
    emulator.mem_write(WEIGHTS, bytes(weights) + bytes(8))
    data = pack(('h' if mode == 0 else 'b') * len(values), *values)
    destination = INPUT if in_place else OUTPUT
    # Retail pipelines prefetch one vector beyond the last output.
    emulator.mem_write(INPUT - 16, b'\xcd' * 16 + data + b'\xcd' * 16)
    if not in_place:
        emulator.mem_write(OUTPUT - 16, b'\xcd' * (len(data) + 32))
    for i, value in enumerate((MATRIX_A, MATRIX_B, WEIGHTS, INPUT, destination, count), 3):
        emulator.reg_write(getattr(ppc, f'UC_PPC_REG_{i}'), value)
    kind = 7 if mode == 0 else 6
    config = ((load_scale & 63) << 24) | (kind << 16) | ((store_scale & 63) << 8) | kind
    pairs = QuantizedPairs(emulator, ppc, config)
    emulator.hook_add(uc.UC_HOOK_CODE, pairs.hook)
    emulator.emu_start(symbols[name], RETURN, count=100000)
    assert emulator.reg_read(ppc.UC_PPC_REG_PC) == RETURN, 'did not return'
    assert emulator.reg_read(ppc.UC_PPC_REG_1) == STACK, 'stack corrupted'
    for i, value in saved.items():
        assert emulator.reg_read(getattr(ppc, f'UC_PPC_REG_{i}')) == value, ('GPR corrupted', i)
    assert emulator.mem_read(destination - 16, 16) == b'\xcd' * 16
    assert emulator.mem_read(destination + len(data), 16) == b'\xcd' * 16
    return bytes(emulator.mem_read(destination, len(data)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, default=ROOT / 'build/GSAE01/src/main/model.o')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--allow-source-mismatch', action='store_true', help='audit the prior reconstruction')
    args = parser.parse_args()
    text = (ROOT / 'config/GSAE01/symbols.txt').read_text()
    retail_symbols = {n: (s, int(a, 16)) for n, s, a in re.findall(
        r'^(\S+) = (\.[^:]+):(0x[0-9a-fA-F]+);', text, re.M)}
    dol = verified_dol(ROOT / 'orig/GSAE01/sys/main.dol', ROOT / 'config/GSAE01/config.yml')
    retail_segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    results = {}
    with tempfile.TemporaryDirectory() as directory:
        segments, symbols = link_source(args.object, Path(directory), retail_symbols, entry=NAMES[0])
        # Accept the former descriptive name when auditing an older source object.
        if NAMES[2] not in symbols:
            symbols[NAMES[2]] = symbols['ObjModel_TransformQuadVerticesLinear']
        for label, image, names in [('retail', retail_segments, {n: a for n, (_, a) in retail_symbols.items()}),
                                    ('compiled', retail_segments + segments, symbols)]:
            failed = []
            scenarios = list(cases())
            for i, case in enumerate(scenarios):
                mode, count, load, store, matrices, weights, values = case
                expected = oracle(mode, matrices, weights, values, load, store)
                for in_place in (False, True):
                    actual = execute(image, names, NAMES[mode], case, in_place)
                    if actual != expected:
                        failed.append({'case': i, 'mode': mode, 'count': count, 'load': load,
                                       'store': store, 'in_place': in_place,
                                       'expected': expected.hex(), 'actual': actual.hex()})
            results[label] = {'cases': len(scenarios) * 2, 'failures': failed}
            print(label, results[label]['cases'], 'cases,', len(failed), 'mismatches', flush=True)
            if label == 'retail' or not args.allow_source_mismatch:
                assert not failed, failed[:1]
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
