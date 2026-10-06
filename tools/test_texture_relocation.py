#!/usr/bin/env python3
"""Run texture relocation, registry lookup and GX initialization with native records.

Heap, resource-defrag, diagnostic and GX services are spies. The actual texture
layout, registry, relocation loop and GX initializer come from production.
This does not decode on-disc headers or implement texture loading/rendering.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float f32;
typedef u8 GXBool;
typedef int GXTexFmt;
typedef struct { u8 opaque[32]; } GXTexObj;
#define TRUE 1
#define FALSE 0
"""
SERVICES = r"""
enum { BLOCK_COUNT = 10, BLOCK_BYTES = 0x4000 };
static union { Texture alignment; u8 bytes[BLOCK_BYTES]; } memory[BLOCK_COUNT];
static u8* addresses[BLOCK_COUNT];
static struct { int live, region, heapBytes, stage; } blocks[BLOCK_COUNT];
static struct { void* image; void* user; int width, height, format, mipmaps; } gx[BLOCK_COUNT];
static LoadedTextureEntry registry[LOADED_TEXTURE_CAPACITY], expected[LOADED_TEXTURE_CAPACITY];
static LoadedTextureEntry* gLoadedTextures = registry;
static int gLoadedTextureCount;
static int plan[16], planCount, allocations, allocationHeaps[16];
static int copies, flushes, gxInitializations, frees, freeLog[16], copyTo[16];
static int forceHeap, freeDelay, delayChanges, forceCalls, textureState, stateCalls;
static int defragCalls, heapPrints, finishedPasses, cases;
static int activeSlot, allocationBytes;
static Texture* original;
static u8 originalBytes[BLOCK_BYTES];
static Texture chainNode;
static u32 tmem[4];
static Texture* textureAt(int block) { return (Texture*)addresses[block]; }
static int blockId(const void* pointer) {
    for (int i = 0; i < BLOCK_COUNT; i++) if (pointer == addresses[i]) return i;
    abort();
}
static int objectId(GXTexObj* object) { return blockId((u8*)object - offsetof(Texture, gxTexObj)); }
static void mmSetTextureAllocationState(int state) {
    assert(state == (stateCalls == 0 ? 2 : 0)); textureState = state; stateCalls++;
}
static int mmSetForceHeaps1and2Only(int value) {
    assert(value == (forceCalls++ == 0 ? 1 : -1)); int old = forceHeap; forceHeap = value; return old;
}
static int mmSetFreeDelay(int value) {
    assert(value == (delayChanges++ % 2 == 0 ? 0 : 7)); int old = freeDelay; freeDelay = value; return old;
}
static int mmGetRegionForPtr(u8* pointer) {
    int id = blockId(pointer); assert(blocks[id].live); return blocks[id].region;
}
static int getHeapItemSize(void* pointer) {
    int id = blockId(pointer); assert(blocks[id].live); return blocks[id].heapBytes;
}
static void* mmAlloc(int bytes, int tag, const char* allocationName) {
    assert(bytes == allocationBytes && (u32)tag == 0xa0a0a0a0u && allocationName == 0 && freeDelay == 7);
    assert(textureState == (defragCalls ? 0 : 2) && allocations < 16);
    allocationHeaps[allocations] = forceHeap;
    int id = allocations < planCount ? plan[allocations] : -1;
    allocations++;
    if (id < 0) return NULL;
    assert(!blocks[id].live);
    memset(addresses[id], 0xa7, BLOCK_BYTES);
    blocks[id].live = 1; blocks[id].stage = 1;
    return addresses[id];
}
static void mm_free(void* pointer) {
    int id = blockId(pointer); assert(blocks[id].live && freeDelay == 0 && frees < 16);
    if (blocks[id].stage != 1) {
        /* The old texture remains published until after GX initialization and free-delay restoration. */
        assert(registry[activeSlot].texture == pointer && copies && blocks[copyTo[copies - 1]].stage == 5);
    }
    blocks[id].live = 0; freeLog[frees++] = id;
}
static void relocationCopy(void* destination, const void* source, size_t size) {
    int a = blockId(source), b = blockId(destination);
    assert(blocks[a].live && blocks[b].live && blocks[b].stage == 1 && size == (size_t)allocationBytes);
    assert(registry[activeSlot].texture == source && freeDelay == 7);
    memcpy(destination, source, size); blocks[b].stage = 2; copyTo[copies++] = b;
}
static void DCStoreRange(void* pointer, u32 size) {
    int id = blockId(pointer); assert(blocks[id].stage == 2 && size == (u32)allocationBytes);
    assert(registry[activeSlot].texture != pointer); blocks[id].stage = 3; flushes++;
}
static void GXInitTexObj(GXTexObj* object, void* image, u16 width, u16 height, GXTexFmt format,
                         int wrapS, int wrapT, GXBool mipmaps) {
    int id = objectId(object); Texture* texture = textureAt(id);
    assert(blocks[id].stage == 3 && texture->tmemAddr == NULL && texture->preloaded == 0);
    assert(image == (u8*)texture + sizeof(Texture) && width == texture->width && height == texture->height);
    assert(format == texture->format && wrapS == texture->wrapS && wrapT == texture->wrapT);
    assert(mipmaps == (texture->maxLod > texture->minLod));
    gx[id].image = image; gx[id].width = width; gx[id].height = height; gx[id].format = format;
    gx[id].mipmaps = mipmaps; memset(object, 0xbc, sizeof(*object));
    blocks[id].stage = 4; gxInitializations++;
}
static void GXInitTexObjLOD(GXTexObj* object, int minFilter, int magFilter, f32 minLod, f32 maxLod,
                            f32 bias, int clamp, int edge, int anisotropy) {
    int id = objectId(object); Texture* texture = textureAt(id);
    assert(blocks[id].stage == 4 && minFilter == texture->minFilter && magFilter == texture->magFilter);
    assert(minLod == (gx[id].mipmaps ? texture->minLod : 0));
    assert(maxLod == (gx[id].mipmaps ? texture->maxLod : 0));
    assert(bias == (gx[id].mipmaps ? -2.0f : 0.0f) && !clamp && !edge && !anisotropy);
}
static void GXInitTexObjUserData(GXTexObj* object, void* user) {
    int id = objectId(object); assert(blocks[id].stage == 4 && user == textureAt(id));
    gx[id].user = user; blocks[id].stage = 5;
}
static GXTexFmt GXGetTexObjFmt(GXTexObj* object) { return gx[objectId(object)].format; }
static u16 GXGetTexObjWidth(GXTexObj* object) { return gx[objectId(object)].width; }
static u16 GXGetTexObjHeight(GXTexObj* object) { return gx[objectId(object)].height; }
static u32 GXGetTexBufferSize(u16 width, u16 height, GXTexFmt format, int mipmaps, int maxLod) {
    assert(width == 8 && height == 4 && format == 6 && mipmaps == 0 && maxLod == 0);
    return 64; /* Service result, not a GX format-size implementation. */
}
static void OSReport(const char* format, ...) {
    if (format == sTexRestructFinishedFormat) {
        va_list args; va_start(args, format); finishedPasses = va_arg(args, int); va_end(args);
    }
}
static int printHeapStats(int mode) { assert(mode == 1); heapPrints++; return 0; }
static void defragMemory(int mode) {
    assert(mode == 2 && forceHeap == -1 && heapPrints == 2 && defragCalls++ == 0);
    /* The real resource pass resets this state before returning to texture compaction. */
    mmSetTextureAllocationState(0);
}
static void reset(int slot, int count, int oldBlock, int region, int bytes) {
    memset(registry, 0xab, sizeof(registry)); memset(blocks, 0, sizeof(blocks)); memset(gx, 0, sizeof(gx));
    for (int i = 0; i < LOADED_TEXTURE_CAPACITY; i++) {
        registry[i].assetId = i + 1000; registry[i].texture = NULL; registry[i].usesHandle = 0;
    }
    activeSlot = slot; gLoadedTextureCount = count; allocationBytes = bytes;
    for (int i = 0; i < BLOCK_COUNT; i++) {
        blocks[i].heapBytes = bytes; addresses[i] = memory[i].bytes;
    }
    original = textureAt(oldBlock); blocks[oldBlock].live = 1; blocks[oldBlock].region = region;
    for (int i = 0; i < BLOCK_BYTES; i++) addresses[oldBlock][i] = (u8)(i * 13 + 7);
    original->nextAnimationFrame = NULL; original->cached = 0;
    original->width = 8; original->height = 4; original->format = 6;
    original->wrapS = 1; original->wrapT = 2; original->minFilter = 3; original->magFilter = 4;
    original->minLod = 0; original->maxLod = 2;
    original->tmemAddr = tmem; original->preloaded = 1;
    registry[slot].texture = original; registry[slot].usesHandle = 1; registry[slot].allocationSize = bytes;
    allocations = planCount = copies = flushes = gxInitializations = frees = 0;
    forceCalls = delayChanges = stateCalls = defragCalls = heapPrints = 0; finishedPasses = -1;
    forceHeap = 37; freeDelay = 7; textureState = 39;
    assert((uintptr_t)original > UINT32_MAX && (uintptr_t)registry > UINT32_MAX);
}
static void snapshot(void) {
    memcpy(expected, registry, sizeof(expected)); memcpy(originalBytes, original, BLOCK_BYTES);
}
static void check(int wantedAllocations, int wantedCopies, int wantedFrees, int passes) {
    assert(allocations == wantedAllocations && copies == wantedCopies && frees == wantedFrees);
    assert(copies == flushes && copies == gxInitializations && delayChanges == 2 * frees && freeDelay == 7);
    assert(forceCalls == 2 && forceHeap == -1 && stateCalls == 3 && textureState == 0 && defragCalls == 1);
    assert(heapPrints == 2 + passes && finishedPasses == passes);
    assert(memcmp(registry, expected, sizeof(registry)) == 0);
    assert(memcmp(original, originalBytes, BLOCK_BYTES) == 0);
    for (int i = 0; i < copies; i++) {
        int id = copyTo[i]; Texture expectedTexture;
        memcpy(&expectedTexture, originalBytes, sizeof(expectedTexture));
        memset(&expectedTexture.gxTexObj, 0xbc, sizeof(expectedTexture.gxTexObj));
        expectedTexture.tmemAddr = NULL; expectedTexture.preloaded = 0; expectedTexture.dataSize = 64;
        assert(memcmp(textureAt(id), &expectedTexture, sizeof(expectedTexture)) == 0);
        assert(memcmp(addresses[id] + sizeof(Texture), originalBytes + sizeof(Texture), allocationBytes - sizeof(Texture)) == 0);
        assert(gx[id].user == textureAt(id) && gx[id].image == addresses[id] + sizeof(Texture));
        for (int j = allocationBytes; j < allocationBytes + 32; j++) assert(addresses[id][j] == 0xa7);
    }
    cases++;
}
#define memcpy relocationCopy
"""
CASES = r"""
#undef memcpy
static void eligibility(void) {
    for (int mode = 0; mode < 2; mode++) for (int region = -1; region <= 3; region++)
        for (int present = 0; present < 2; present++) for (int handle = 0; handle < 2; handle++)
            for (int cached = 0; cached < 2; cached++) for (int chain = 0; chain < 2; chain++)
                for (int valid = 0; valid < 2; valid++) {
                    reset(2, 5, 0, region, 0x3000);
                    registry[2].texture = present ? original : NULL; registry[2].usesHandle = handle ? 255 : 0;
                    registry[2].allocationSize = valid ? 0x3000 : UINT32_MAX;
                    original->cached = cached; original->nextAnimationFrame = chain ? &chainNode : NULL;
                    snapshot(); texRestructRefs(mode);
                    int eligible = present && handle && !cached && !chain && valid;
                    int attempts = eligible ? (region == 0 ? 2 : !mode && (region == 1 || region == 2)) : 0;
                    check(attempts, 0, 0, 1);
                }
}
static void eviction(void) {
    for (int mode = 0; mode < 2; mode++) for (int region = 1; region <= 2; region++) {
        reset(1, 3, 4, 0, 256); blocks[1].region = region; plan[planCount++] = 1;
        snapshot(); expected[1].texture = textureAt(1);
        texRestructRefs(mode); check(1, 1, 1, 1);
        assert(freeLog[0] == 4 && allocationHeaps[0] == 1 && blocks[1].live && !blocks[4].live);
    }
}
static void compaction(void) {
    for (int mode = 0; mode < 2; mode++) for (int destination = 1; destination <= 7; destination += 6)
        for (int region = 0; region <= 2; region++) for (int mipmaps = 0; mipmaps < 3; mipmaps++) {
            reset(1, 3, 4, 0, 256); blocks[destination].region = region;
            original->minLod = mipmaps == 2 ? 2 : 0; original->maxLod = mipmaps == 1 ? 2 : 0;
            plan[planCount++] = -1; plan[planCount++] = destination;
            int accepted = region == 0 && destination > 4;
            snapshot(); if (accepted) expected[1].texture = textureAt(destination);
            texRestructRefs(mode); check(accepted ? 3 : 2, accepted, 1, accepted ? 2 : 1);
            assert(freeLog[0] == (accepted ? 4 : destination));
            assert(allocationHeaps[0] == 1 && allocationHeaps[1] == -1);
        }
}
static void promotion(void) {
    for (int mode = 0; mode < 2; mode++) for (int from = 1; from <= 2; from++)
        for (int bytes = 0x2fff; bytes <= 0x3001; bytes++) for (int to = 0; to <= 2; to++)
            for (int destination = -1; destination <= 7; destination += 4) {
                reset(1, 3, 4, from, bytes);
                if (destination >= 0) blocks[destination].region = to;
                plan[planCount++] = destination;
                int attempt = !mode && bytes >= 0x3000;
                int accepted = attempt && destination >= 0 && to == 0;
                snapshot(); if (accepted) expected[1].texture = textureAt(destination);
                texRestructRefs(mode); check(attempt + accepted, accepted, attempt && destination >= 0, accepted ? 2 : 1);
                if (attempt) assert(allocationHeaps[0] == -1);
                if (attempt && destination >= 0) assert(freeLog[0] == (accepted ? 4 : destination));
            }
}
static void passLimit(void) {
    reset(1, 3, 0, 0, 256); plan[planCount++] = -1;
    for (int i = 1; i <= 5; i++) plan[planCount++] = i;
    snapshot(); expected[1].texture = textureAt(4);
    texRestructRefs(0); check(5, 4, 4, 4);
    for (int i = 0; i < 4; i++) assert(freeLog[i] == i && copyTo[i] == i + 1);
    assert(blocks[4].live && !blocks[5].live);
}
static void registrySlots(void) {
    for (int slot = 0; slot < LOADED_TEXTURE_CAPACITY; slot++) {
        reset(slot, LOADED_TEXTURE_CAPACITY, 0, 0, 256); snapshot();
        assert(getLoadedTexture(slot + 1000) == original && getLoadedTexture(-100) == NULL);
        texRestructRefs(0); check(2, 0, 0, 1);
        assert(getLoadedTexture(slot + 1000) == original);
    }
    reset(0, 0, 0, 0, 256); snapshot();
    assert(getLoadedTexture(1000) == NULL);
    texRestructRefs(0); check(0, 0, 0, 1);
}
static void crossBoundary(void) {
    size_t span = (size_t)UINT64_C(0x200000000);
    u8* mapping = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(mapping != MAP_FAILED);
    uintptr_t boundary = ((uintptr_t)mapping + UINT64_C(0xffffffff)) & ~UINT64_C(0xffffffff);
    if (boundary - (uintptr_t)mapping < 0x100000) boundary += UINT64_C(0x100000000);
    u8* low = (u8*)(boundary - 0x100000), *high = (u8*)(boundary + 0x100000);
    assert(low >= mapping && high + BLOCK_BYTES <= mapping + span);
    assert(mprotect(low, BLOCK_BYTES, PROT_READ | PROT_WRITE) == 0);
    assert(mprotect(high, BLOCK_BYTES, PROT_READ | PROT_WRITE) == 0);
    assert((uintptr_t)low < (uintptr_t)high && (u32)(uintptr_t)low > (u32)(uintptr_t)high);
    for (int up = 0; up < 2; up++) {
        reset(1, 3, 0, 0, 256);
        addresses[0] = up ? low : high; addresses[1] = up ? high : low;
        memcpy(addresses[0], original, BLOCK_BYTES);
        original = textureAt(0); registry[1].texture = original;
        plan[planCount++] = -1; plan[planCount++] = 1;
        snapshot(); if (up) expected[1].texture = textureAt(1);
        texRestructRefs(0); check(up ? 3 : 2, up, 1, up ? 2 : 1);
        assert(freeLog[0] == (up ? 0 : 1));
    }
    assert(munmap(mapping, span) == 0);
}
int main(void) {
    eligibility(); eviction(); compaction(); promotion(); passLimit(); registrySlots(); crossBoundary();
    printf("%d complete texture relocation and registry cases checked\n", cases);
    return 0;
}
"""


def harness():
    source = (ROOT / 'src/main/texture.c').read_text()
    header = (ROOT / 'include/main/texture.h').read_text()
    parts = [PRELUDE, re.search(r'typedef struct Texture \{.*?\} Texture;', header, re.S)[0],
             re.search(r'typedef struct LoadedTextureEntry \{.*?\} LoadedTextureEntry;', source, re.S)[0],
             re.search(r'^#define LOADED_TEXTURE_CAPACITY[^\n]*', source, re.M)[0]]
    parts.extend(re.findall(r'^char sTexRestruct\w+\[\]\s*=\s*"[^";]*";', source, re.M))
    parts.append(SERVICES)
    for name in ('textureGetGXTexObj', 'textureGetImageData'):
        parts.append(function(header, name))
    for name in ('textureHasMipmaps', 'textureInitGXTexObj', 'texRestructRefs', 'getLoadedTexture'):
        parts.append(function(source, name))
    return '\n'.join(parts + [CASES])


class TextureRelocationTests(unittest.TestCase):
    def test_native_relocation_and_gx_rebuild(self):
        with tempfile.TemporaryDirectory(prefix='texture-relocation-') as directory:
            source = Path(directory) / 'textures.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / 'textures'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(executable)],
                                   check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
