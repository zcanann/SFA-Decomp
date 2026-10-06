#!/usr/bin/env python3
"""Exercise the production object-definition loader and cache-release block.

The real ObjDef declaration and C bodies run with pointers above 4 GiB. The I/O
spy supplies a decoded host header, not raw big-endian disk bytes: retail layout,
endianness and code generation are checked separately by the matching builds.
Other GameObject teardown work is outside this harness.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float f32;
typedef struct ObjTextureSlotDef ObjTextureSlotDef;
typedef struct ObjHitReactMoveEntry ObjHitReactMoveEntry;
typedef struct ObjAttachPoint ObjAttachPoint;
typedef struct ObjDefHitVolume ObjDefHitVolume;
typedef struct ObjJointBinding ObjJointBinding;
"""
FIXTURE = r"""
enum { MLDF_FILEID_OBJECTS_BIN = 24, RESOURCE_SIZE = 2048, CAPACITY = 8 };
typedef struct GameObject { struct { s16 defId; } anim; } GameObject;
static int offsets[CAPACITY + 1], gObjFileCount = CAPACITY;
static int* gObjFileOffsetTable = offsets;
static ObjDef* cache[CAPACITY];
static ObjDef** gObjFileBufferTable = cache;
static u8 refs[CAPACITY];
static u8* gObjFileRefCount = refs;
static const char sObjFreeObjdefError[] = "release without reference";
static ObjDef diskHeader;
static void *resource, *modLines, *intersections;
static int currentId, allocationFails, collisionMask, lineCount;
static int allocCalls, ioCalls, lineCalls, buildCalls, freeCalls, warnings;

static void* mmAlloc(int size, int tag, int flags) {
    assert(size == RESOURCE_SIZE && tag == 0xe && flags == 0);
    allocCalls++;
    if (allocationFails) return NULL;
    resource = calloc(1, size);
    assert(resource && (uintptr_t)resource > UINT32_MAX);
    return resource;
}
static void fileLoadToBufferOffset(int file, u8* buf, int base, int size) {
    assert(file == MLDF_FILEID_OBJECTS_BIN && buf == resource);
    assert(base == offsets[currentId] && size == RESOURCE_SIZE);
    memcpy(buf, &diskHeader, sizeof(diskHeader));
    ioCalls++;
}
static void* loadModLines(int index, s16* count) {
    assert(index == diskHeader.modLineIndex && index >= 0);
    assert(((ObjDef*)resource)->modLines == NULL);
    assert(((ObjDef*)resource)->intersectionLines == NULL);
    lineCalls++;
    *count = lineCount;
    if (collisionMask & 1) {
        modLines = malloc(32);
        assert(modLines);
    }
    return modLines;
}
static void intersectModLineBuild(ObjDef* definition) {
    assert(definition == resource && definition->modLines == modLines);
    assert(definition->modLineCount == (u8)lineCount);
    buildCalls++;
    if (collisionMask & 2) {
        intersections = malloc(128);
        assert(intersections);
        definition->intersectionLines = intersections;
        definition->intersectionPoints = (f32*)((u8*)intersections + 32);
        definition->intersectionSegmentRanges =
            (struct TrackModelLineRange*)((u8*)intersections + 64);
    }
}
static void mm_free(void* pointer) {
    /* Derived views and resource-relative tables must never be freed here. */
    assert(pointer != NULL);
    if (modLines) {
        assert(pointer == modLines);
        modLines = NULL;
    } else if (intersections) {
        assert(pointer == intersections);
        intersections = NULL;
    } else {
        assert(pointer == resource);
        resource = NULL;
    }
    freeCalls++;
    free(pointer);
}
static void debugPrintf(const char* format, ...) {
    assert(format == sObjFreeObjdefError);
    warnings++;
}
"""
CASES = r"""
static void reset(int id) {
    assert(!resource && !modLines && !intersections);
    memset(cache, 0, sizeof(cache));
    memset(refs, 0, sizeof(refs));
    memset(&diskHeader, 0, sizeof(diskHeader));
    currentId = id;
    diskHeader.modLineIndex = -1;
    diskHeader.modLineCount = 99;
    /* These disk words are ignored and cleared before collision loading. */
    diskHeader.modLines = (struct MapHitLine*)(uintptr_t)0x1234;
    diskHeader.intersectionLines = (struct IntersectLine*)(uintptr_t)0x5678;
    allocCalls = ioCalls = lineCalls = buildCalls = freeCalls = warnings = 0;
    allocationFails = collisionMask = 0;
}
static void check(int mask, int index, int collision) {
    reset(mask % CAPACITY);
    GameObject object = {{currentId}};
    const int values[] = {0, 1, 255, 256};
    collisionMask = collision;
    lineCount = values[(mask + collision) % 4];
    diskHeader.modLineIndex = index;
    /* Four required fixups still relocate zero to the resource base. */
    diskHeader.modelFileIdsOffset = (mask & 1) ? 512 : 0;
    diskHeader.textureSlotDefsOffset = (mask & 2) ? 544 : 0;
    diskHeader.jointBindingsOffset = (mask & 4) ? 576 : 0;
    diskHeader.attachPointsOffset = (mask & 8) ? 608 : 0;
    diskHeader.extraSetupDataOffset = (mask & 16) ? 640 : 0;
    diskHeader.sequenceMapOffset = (mask & 32) ? 672 : 0;
    diskHeader.eventMoveTableOffset = (mask & 64) ? 704 : 0;
    diskHeader.hitReactMoveTableOffset = (mask & 128) ? 736 : 0;
    diskHeader.weaponDaTableOffset = (mask & 256) ? 768 : 0;
    diskHeader.hitVolumesOffset = (mask & 512) ? 800 : 0;
    ObjDef* definition = loadObjectFile(currentId);
    assert(definition == resource && cache[currentId] == definition);
    assert(allocCalls == 1 && ioCalls == 1 && refs[currentId] == 1);
    void* actual[] = {
        definition->modelFileIds, definition->textureSlotDefs,
        definition->jointBindings, definition->attachPoints,
        definition->extraSetupData, definition->sequenceMap,
        definition->eventMoveTable, definition->hitReactMoveTable,
        definition->weaponDaTable, definition->hitVolumes
    };
    for (int field = 0; field < 10; field++) {
        void* expected = NULL;
        if (mask & (1 << field)) expected = (u8*)resource + 512 + field * 32;
        else if (field < 4) expected = resource;
        assert(actual[field] == expected);
    }
    assert(lineCalls == (index >= 0) && buildCalls == lineCalls);
    assert(definition->modLines == modLines);
    assert(definition->intersectionLines == intersections);
    assert(definition->modLineCount == (index >= 0 ? (u8)lineCount : 99));
    /* Every nonzero byte refcount takes the cache-hit path, even 255 -> 0. */
    for (int count = 1; count <= 255; count++) {
        assert(refs[currentId] == count);
        assert(loadObjectFile(currentId) == definition);
    }
    assert(refs[currentId] == 0 && allocCalls == 1 && ioCalls == 1);
    refs[currentId] = 2;
    releaseDefinition((u8*)&object);
    assert(refs[currentId] == 1 && freeCalls == 0);
    releaseDefinition((u8*)&object);
    assert(refs[currentId] == 0 && !resource && !modLines && !intersections);
    assert(freeCalls == 1 + (index >= 0 ? !!(collision & 1) + !!(collision & 2) : 0));
    releaseDefinition((u8*)&object);
    assert(warnings == 1);
    for (int i = 0; i < CAPACITY; i++) assert(refs[i] == 0);
}
int main(void) {
    for (int i = 0; i <= CAPACITY; i++) offsets[i] = 100 + i * RESOURCE_SIZE;
    const int indices[] = {-128, -1, 0, 127};
    int cases = 0;
    for (int mask = 0; mask < 1024; mask++)
        for (int i = 0; i < 4; i++) for (int collision = 0; collision < 4; collision++) {
            check(mask, indices[i], collision);
            cases++;
        }
    reset(0);
    GameObject object = {{0}};
    diskHeader.modelFileIdsOffset = diskHeader.textureSlotDefsOffset =
        diskHeader.jointBindingsOffset = diskHeader.attachPointsOffset =
        diskHeader.extraSetupDataOffset = diskHeader.sequenceMapOffset =
        diskHeader.eventMoveTableOffset = diskHeader.hitReactMoveTableOffset =
        diskHeader.weaponDaTableOffset = diskHeader.hitVolumesOffset = RESOURCE_SIZE;
    ObjDef* definition = loadObjectFile(0);
    void* end = (u8*)resource + RESOURCE_SIZE;
    assert(definition->modelFileIds == end && definition->textureSlotDefs == end);
    assert(definition->jointBindings == end && definition->attachPoints == end);
    assert(definition->extraSetupData == end && definition->sequenceMap == end);
    assert(definition->eventMoveTable == end && definition->hitReactMoveTable == end);
    assert(definition->weaponDaTable == end && definition->hitVolumes == end);
    releaseDefinition((u8*)&object);
    /* A stale cache slot with zero references must reload the definition. */
    definition = loadObjectFile(0);
    assert(definition == resource && refs[0] == 1);
    assert(allocCalls == 2 && ioCalls == 2);
    releaseDefinition((u8*)&object);
    assert(freeCalls == 2);
    reset(0);
    assert(loadObjectFile(CAPACITY) == NULL && loadObjectFile(CAPACITY + 10) == NULL);
    assert(allocCalls == 0 && ioCalls == 0);
    allocationFails = 1;
    assert(loadObjectFile(0) == NULL && refs[0] == 0 && cache[0] == NULL);
    assert(allocCalls == 1 && ioCalls == 0);
    printf("%d load/cache/release cases; end offsets, reload and failure paths checked\n", cases);
    return 0;
}
"""


def harness():
    header = (ROOT / "include/main/objanim_internal.h").read_text()
    definition = re.search(r"typedef struct ObjDef\s*\{.*?\} ObjDef;", header, re.S)[0]
    source = (ROOT / "src/main/object.c").read_text()
    start, end = find_function_body(source, "loadObjectFile")
    loader = "ObjDef* loadObjectFile(int id) " + source[start:end + 1]
    start, end = find_function_body(source, "objFreeObjdef")
    teardown = source[start:end + 1]
    start = teardown.index("    {\n        s16 type;")
    end = teardown.index("    if (((GameObject*)obj)->seqIndex", start)
    release = "static void releaseDefinition(u8* obj) {\n    void* entry;\n"
    release += teardown[start:end] + "}\n"
    return "\n".join((PRELUDE, definition, FIXTURE, loader, release, CASES))


class ObjectDefinitionLifecycleTests(unittest.TestCase):
    def test_offsets_cache_and_owned_allocations(self):
        with tempfile.TemporaryDirectory(prefix="object-definition-lifecycle-") as directory:
            source = Path(directory) / "lifecycle.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "lifecycle"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
