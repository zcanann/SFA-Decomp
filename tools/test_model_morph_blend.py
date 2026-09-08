"""Execute the portable morph decoding/blending reference against a dense integer oracle.

Streams use host-endian words, representing the already-loaded retail data.
This checks scalar C semantics, not the private PPC ABI or cache DMA wrapper.
"""

from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


def encode(records, sentinel):
    words = []
    for index, components in sorted(records.items()):
        flags = sum(0x2000 << axis for axis, value in enumerate(components) if value is not None)
        words.append(index | flags)
        words.extend(value & 0xffff for value in components if value is not None)
    words.append(sentinel)
    return words


def signed_halfword(value):
    value &= 0xffff
    return value if value < 0x8000 else value - 0x10000


def oracle_cases():
    """Return encoded inputs and independent dense results for both probes."""
    cases = []
    rng = random.Random(0x8002430c)
    weights = (-65536, -32768, -1, 0, 1, 32768, 65535, 65536)
    # All eight component-presence masks, including a zero-delta record.
    a = {i: tuple((-32768, 32767, -1)[axis] if i & (1 << axis) else None
                   for axis in range(3)) for i in range(8)}
    b = {i: tuple((32767, -32768, 1)[axis] if (7 - i) & (1 << axis) else None
                   for axis in range(3)) for i in range(8)}
    for weight in weights:
        for streams in ((a, b), (a, {}), ({}, b), ({}, {})):
            cases.append((10, 0, weight, 3, *streams))
    # Sparse A-only, B-only, shared and untouched vertices across the real
    # 0x2a0-vertex chunk boundary; compare whole and split execution.
    for limit in (0x2a0, 1024):
        cases.append((680, 0, -65536, limit,
                      {0: (-32768, None, 32767), 671: (None, 10, None), 672: (1, 2, 3)},
                      {1: (1, None, -1), 671: (2, 3, 4), 673: (None, -32768, None)}))
    cases.append((0, 7, -65536, 1, {}, {}))
    for _ in range(100):
        count, first = rng.randrange(1, 40), rng.randrange(100, 200)
        streams = []
        for _ in range(2):
            records = {}
            for index in range(first, first + count):
                if rng.randrange(3) == 0:
                    records[index] = tuple(rng.randrange(-32768, 32768) if rng.randrange(2) else None
                                           for _ in range(3))
            streams.append(records)
        cases.append((count, first, rng.choice(weights), rng.randrange(1, 12), *streams))
    inputs, expected = [], []
    for count, first, weight, limit, a, b in cases:
        base = [rng.randrange(-32768, 32768) for _ in range(count * 3)]
        aWords, bWords = encode(a, first + count + 1), encode(b, first + count + 1)
        inputs.append(' '.join(map(str, [count, first, weight, len(aWords), len(bWords), limit,
                                        *base, *aWords, *bWords])))
        result = [len(aWords) - 1, len(bWords) - 1]
        for i, original in enumerate(base):
            index, axis = first + i // 3, i % 3
            da = a.get(index, (0, 0, 0))[axis] or 0
            db = b.get(index, (0, 0, 0))[axis] or 0
            # Unlimited-precision arithmetic, then the retail low-word
            # product/sum, logical shift and halfword store.
            fixed = (da * (65536 - weight) + db * weight) & 0xffffffff
            result.append(signed_halfword(original + (fixed >> 16)))
        expected.append(result)
    return inputs, expected


class ModelMorphBlendTests(unittest.TestCase):
    def test_sparse_streams_and_fixed_point_wrap(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required for source-body tests')
        source = (ROOT / 'docs/foreign/model_morph_reference.c').read_text()
        macros = '\n'.join(re.findall(r'^#define MODEL_MORPH_.*$', source, re.M))
        functions = []
        for name in ('modelReadMorphDelta', 'modelBlendMorphTargetChunk'):
            start, end = find_function_body(source, name)
            declaration = source.rfind('\n', 0, source.rfind(name, 0, start)) + 1
            functions.append(source[declaration:end + 1])
        fixture = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u8;
typedef short s16;
typedef unsigned short u16;
typedef unsigned int u32;
''' + macros + '\n' + '\n'.join(functions) + r'''
int main(void) {
    int count, first, weight, aLength, bLength, chunkLimit;
    while (scanf("%d%d%d%d%d%d", &count, &first, &weight, &aLength, &bLength, &chunkLimit) == 6) {
        int i, offset, value;
        s16 *base = malloc((count * 3 + 2) * sizeof(s16));
        s16 *output = malloc((count * 3 + 2) * sizeof(s16));
        u16 *a = malloc(aLength * sizeof(u16)), *b = malloc(bLength * sizeof(u16));
        u16 *aCursor = a, *bCursor = b;
        assert(base && output && a && b && chunkLimit > 0);
        for (i = 0; i < count * 3; i++) {
            assert(scanf("%d", &value) == 1);
            base[i] = value;
        }
        for (i = 0; i < aLength; i++) {
            assert(scanf("%d", &value) == 1);
            a[i] = value;
        }
        for (i = 0; i < bLength; i++) {
            assert(scanf("%d", &value) == 1);
            b[i] = value;
        }
        memset(output, 0x5a, (count * 3 + 2) * sizeof(s16));
        offset = 0;
        do {
            int chunk = count - offset;
            if (chunk > chunkLimit) chunk = chunkLimit;
            modelBlendMorphTargetChunk((u8*)(base + offset * 3), (u8*)(output + offset * 3),
                                       chunk, &aCursor, &bCursor, weight, first + offset);
            offset += chunk;
        } while (offset < count);
        assert(output[count * 3] == 0x5a5a && output[count * 3 + 1] == 0x5a5a);
        printf("%td %td", aCursor - a, bCursor - b);
        for (i = 0; i < count * 3; i++) printf(" %d", output[i]);
        puts("");
        free(base); free(output); free(a); free(b);
    }
    return 0;
}
'''
        inputs, expected = oracle_cases()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'morph.c'
            path.write_text(fixture)
            for optimization in ('-O0', '-O2'):
                executable = Path(directory) / ('morph' + optimization)
                subprocess.run([compiler, '-std=c99', optimization, '-fno-strict-aliasing',
                                '-fsanitize=signed-integer-overflow', '-fno-sanitize-recover=all',
                                str(path), '-o', str(executable)], check=True, capture_output=True, text=True, timeout=30)
                result = subprocess.run([str(executable)], input='\n'.join(inputs) + '\n',
                                        check=True, capture_output=True, text=True, timeout=30)
                actual = [list(map(int, line.split())) for line in result.stdout.splitlines()]
                self.assertEqual(actual, expected, optimization)
                print(f'{optimization}: {len(inputs)} sparse morph scenarios passed')


if __name__ == '__main__':
    unittest.main()
