#!/usr/bin/env python3
"""Execute the production model stream wrappers with native cache pointers.

The call oracle checks both normal modes and the vertex path, including cache
priming, alternating prefetch, waits and output selection. DMA and the assembly
skinning kernels are stubs; this does not validate their arithmetic or hardware.
"""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float ROMtx[4][3];
_Static_assert(sizeof(size_t) == sizeof(void*), "native address width");
"""
SERVICES = r"""
enum { MAX_CHUNKS = 31, MAX_EVENTS = 256 };
enum { QUANTIZE, INIT_CACHE, PREFETCH, WAIT, VERTEX, NORMAL, TRIPLET, OUTPUT };
typedef struct Event {
    int kind;
    uintptr_t args[6];
} Event;
static Event expected[MAX_EVENTS];
static int expectedCount, nextEvent;
static u8 cache[0x4000], data[0x4000], output[0x8000];
static u8 weights[MAX_CHUNKS][32];
static ROMtx matrices[256];
static ModelVtxAnimChunk chunks[MAX_CHUNKS];
static s32 offsets[MAX_CHUNKS];
static u8* outputs[MAX_CHUNKS];
static u8* gModelCacheBuffersA[4];
static u8* gModelCacheBuffersB[6];
static int cacheCalls;

static void expect(int kind, uintptr_t a, uintptr_t b, uintptr_t c,
                   uintptr_t d, uintptr_t e, uintptr_t f) {
    assert(expectedCount < MAX_EVENTS);
    expected[expectedCount++] = (Event){kind, {a, b, c, d, e, f}};
}
static void observe(int kind, uintptr_t a, uintptr_t b, uintptr_t c,
                    uintptr_t d, uintptr_t e, uintptr_t f) {
    assert(nextEvent < expectedCount);
    Event* event = &expected[nextEvent++];
    assert(event->kind == kind);
    assert(event->args[0] == a && event->args[1] == b && event->args[2] == c);
    assert(event->args[3] == d && event->args[4] == e && event->args[5] == f);
}
static void setGQR7Packed(int loadScale, int loadType, int storeScale, int storeType) {
    observe(QUANTIZE, loadScale, loadType, storeScale, storeType, 0, 0);
}
static u8* getCache(void) {
    if (cacheCalls++ == 0) observe(INIT_CACHE, 0, 0, 0, 0, 0, 0);
    assert(cacheCalls <= 2);
    return cache;
}
static void copyToCache(void* dst, void* src, u32 count) {
    observe(PREFETCH, (uintptr_t)dst, (uintptr_t)src, count, 0, 0, 0);
}
static void cacheQueueWait(int remaining) {
    observe(WAIT, remaining, 0, 0, 0, 0, 0);
}
static void memcpyToCache(void* dst, void* src, u32 count) {
    observe(OUTPUT, (uintptr_t)dst, (uintptr_t)src, count, 0, 0, 0);
}
static void transform(int kind, u8* a, u8* b, u8* weight, u8* src, u8* dst, int count) {
    observe(kind, (uintptr_t)a, (uintptr_t)b, (uintptr_t)weight,
            (uintptr_t)src, (uintptr_t)dst, count);
    assert(src == dst);
    assert((uintptr_t)src > UINT32_MAX);
    /* Touch the native address, including the nonzero offset within its slot. */
    *dst = (u8)count;
}
static void ObjModel_TransformVerticesWithTranslation(u8* a, u8* b, u8* w, u8* s, u8* d, int n) {
    transform(VERTEX, a, b, w, s, d, n);
}
static void ObjModel_TransformVerticesLinear(u8* a, u8* b, u8* w, u8* s, u8* d, int n) {
    transform(NORMAL, a, b, w, s, d, n);
}
static void ObjModel_TransformNormalTriplets(u8* a, u8* b, u8* w, u8* s, u8* d, int n) {
    transform(TRIPLET, a, b, w, s, d, n);
}
"""
CASES = r"""
static void prefetch(int index) {
    ModelVtxAnimChunk* chunk = &chunks[index];
    u8* slot = cache + (index % 2) * 0x2000;
    expect(PREFETCH, (uintptr_t)slot, (uintptr_t)(data + 0x2000 + chunk->srcDataOffset),
           chunk->vtxBlocks, 0, 0, 0);
    expect(PREFETCH, (uintptr_t)(slot + 0x1000), (uintptr_t)chunk->weightStream,
           chunk->weightBlocks, 0, 0, 0);
}
static void run(int count, int sample, int mode, int flags) {
    ModelVtxAnimJob job = {0};
    job.chunkCount = count;
    job.quantShift = sample * 4;
    job.chunks = count ? chunks : NULL;
    for (int i = 0; i < count; i++) {
        ModelVtxAnimChunk* chunk = &chunks[i];
        chunk->srcDataOffset = ((sample * 131 + i * 271) % 0x2001) - 0x1000;
        chunk->weightStream = weights[i];
        chunk->mtxIdxA = sample * 37 + i * 19;
        chunk->mtxIdxB = sample * 73 + i * 7;
        chunk->weightBlocks = sample * 23 + i * 13;
        chunk->vtxBlocks = sample * 7 + i * 11;
        chunk->vtxCount = sample * 65535 / 63 + i * 293;
        chunk->dstByteOffset = sample * 17 + i * 61;
        offsets[i] = ((sample * 313 + i * 967) % 0x4001) - 0x2000;
        outputs[i] = output + 0x4000 - offsets[i];
    }
    expectedCount = nextEvent = cacheCalls = 0;
    expect(QUANTIZE, job.quantShift, mode == VERTEX ? 7 : 6,
           job.quantShift, mode == VERTEX ? 7 : 6, 0, 0);
    expect(INIT_CACHE, 0, 0, 0, 0, 0, 0);
    if (count) prefetch(0);
    for (int i = 0; i < count; i++) {
        ModelVtxAnimChunk* chunk = &chunks[i];
        u8* slot = cache + (i % 2) * 0x2000;
        if (i + 1 < count) prefetch(i + 1);
        expect(WAIT, i + 1 < count ? 2 : 0, 0, 0, 0, 0, 0);
        expect(mode, (uintptr_t)&matrices[chunk->mtxIdxA], (uintptr_t)&matrices[chunk->mtxIdxB],
               (uintptr_t)(slot + 0x1000), (uintptr_t)(slot + chunk->dstByteOffset),
               (uintptr_t)(slot + chunk->dstByteOffset), chunk->vtxCount);
        expect(OUTPUT, (uintptr_t)(mode == VERTEX ? output + 0x4000 + offsets[i] : outputs[i]),
               (uintptr_t)slot, chunk->vtxBlocks, 0, 0, 0);
    }
    if (count) expect(WAIT, 0, 0, 0, 0, 0, 0);
    if (mode == VERTEX) {
        ObjModel_BlendVertexStream((u8*)matrices, &job, data + 0x2000,
                                   count ? offsets : NULL, output + 0x4000);
    } else {
        ObjModel_BlendNormalStream((u8*)matrices, &job, data + 0x2000,
                                   count ? outputs : NULL, flags);
    }
    assert(nextEvent == expectedCount && cacheCalls == 2);
}
int main(void) {
    const int counts[] = {0, 1, 2, 3, 4, 7, 8, 15, 16, 31};
    const int normalFlags[] = {0, 1, 0x100, 0x101, -256, -1};
    assert(sizeof(void*) == 8 && (uintptr_t)cache > UINT32_MAX);
    assert((uintptr_t)gModelCacheBuffersA > UINT32_MAX);
    for (unsigned i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        for (int sample = 0; sample < 64; sample++) {
            run(counts[i], sample, VERTEX, 0);
            for (unsigned j = 0; j < sizeof(normalFlags) / sizeof(normalFlags[0]); j++) {
                int flags = normalFlags[j];
                run(counts[i], sample, (u8)flags ? TRIPLET : NORMAL, flags);
            }
        }
    }
    return 0;
}
"""


def harness():
    header = (ROOT / "include/main/model.h").read_text()
    parts = [PRELUDE]
    for name in ("ModelVtxAnimJob", "ModelVtxAnimChunk"):
        parts.append(re.search(rf"typedef struct {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    parts.append(SERVICES)
    source = (ROOT / "src/main/model.c").read_text()
    for name in ("ObjModel_InitScratchBuffers", "modelConsumeNormalChunk", "ObjModel_BlendNormalStream",
                 "modelPrefetchNextVertexChunk", "modelConsumeVertexChunk", "ObjModel_BlendVertexStream"):
        start, end = find_function_body(source, name)
        declaration = source.rfind("\n", 0, source.rfind(name, 0, start)) + 1
        parts.append(source[declaration:end + 1])
    return "\n".join(parts + [CASES])


class ModelCacheStreamTests(unittest.TestCase):
    def test_native_stream_pointers_and_call_order(self):
        with tempfile.TemporaryDirectory(prefix="model-cache-streams-") as directory:
            source = Path(directory) / "streams.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "streams"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
