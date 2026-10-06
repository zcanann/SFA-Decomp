#!/usr/bin/env python3
"""Execute production model sizing, instance layout and initialization handoff.

The real record declarations and C bodies run with native pointers above 4 GiB.
Cache flush, animation reset and relocation are spies; this does not deserialize
retail assets or execute their animation streams. Joint and vertex-chunk counts
keep native pointer-bearing tail records 8-byte aligned while retaining the
retail allocator's 4-byte alignment operations. Target layout/codegen is checked
by the full matching builds.
"""

from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body
from test_model_animation_lifecycle import PRELUDE

ROOT = Path(__file__).resolve().parents[1]

FIXTURE = r"""
#include <stdlib.h>
static ModelFileHeader* activeFile;
static ObjModel* activeModel;
static void* flushPointers[3];
static u32 flushSizes[3];
static int flushCount, resetCount, relocateCount, storeCount;
static void DCFlushRange(void* pointer, u32 size) {
    assert(flushCount < 3 && (uintptr_t)pointer > UINT32_MAX);
    flushPointers[flushCount] = pointer;
    flushSizes[flushCount++] = size;
}
static void modelAnimResetState(ObjModel* model, ObjAnimState* state) {
    assert(model == activeModel && model->file == activeFile);
    assert(state == (resetCount == 0 ? model->animStateA : model->animStateB));
    assert(activeFile->unk08 == 0x12345678 && relocateCount == 0 && storeCount == 0);
    resetCount++;
}
static void ObjModel_RelocateAnimData(ModelFileHeader* file, ObjModel* model) {
    assert(file == activeFile && model == activeModel && resetCount != 0);
    assert(file->unk08 == 0x12345678 && storeCount == 0);
    relocateCount++;
}
static void DCStoreRange(void* pointer, u32 size) {
    assert(pointer == activeFile && size == (u32)activeFile->dataSize);
    assert(activeFile->unk08 == 0 && relocateCount == 1);
    storeCount++;
}
"""
CASES = r"""
static size_t align(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}
static void expect(const void* actual, const u8* arena, size_t* cursor, size_t bytes, size_t alignment) {
    *cursor = align(*cursor, alignment);
    assert(actual == arena + *cursor);
    *cursor += bytes;
}
static void check(int mask, int variant) {
    const int counts[] = {0, 1, 17, 65};
    const int joints[] = {0, 8, 16, 24};
    const int chunks[] = {0, 2, 4, 6};
    u8 vertices[65 * 6], normals[65 * 9], marker;
    ModelFileHeader file = {0};
    ModelInstanceSizes sizes, forced;
    file.animationCount = mask & 2048 ? 1 : 0;
    file.jointCount = joints[variant];
    file.extraJointCount = variant;
    file.vertexCount = counts[variant];
    file.normalCount = counts[3 - variant];
    file.vertexAnimJob.chunkCount = chunks[variant];
    file.normalAnimJob.chunkCount = variant;
    file.renderOpCount = variant + 1;
    file.hitVolumeCount = mask & 128 ? variant + 1 : 0;
    file.animationCacheSize = 137 + variant;
    file.flags = (mask & 1 ? MODEL_FLAG_CACHED_ANIMATIONS : 0) |
        (mask & 32 ? MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS : 0);
    file.flags24 = mask & 64 ? MODEL_FLAGS24_NBT_NORMALS : 0;
    file.morphTargetCount = mask & 4 ? 2 : 0;
    file.vertexAnimEntries = mask & 8 ? (ModelVtxAnimChunk*)&marker : NULL;
    file.normalAnimEntries = mask & 16 ? (ModelVtxAnimChunk*)&marker : NULL;
    file.jointData = mask & 256 ? &marker : NULL;
    file.unk18 = mask & 256 ? &marker : NULL;
    file.unk1C = mask & 512 ? NULL : &marker;
    file.vertices = vertices;
    file.normals = normals;
    file.refCount = variant == 0 ? 1 : 2;
    file.unk08 = 0x12345678;
    file.dataSize = 1024;
    for (size_t i = 0; i < sizeof(vertices); i++) vertices[i] = i * 13 + variant;
    for (size_t i = 0; i < sizeof(normals); i++) normals[i] = i * 17 + variant;
    int flags = (mask & 2 ? 0x80 : 0) | (mask & 1024 ? 0x8000 : 0);
    memset(&sizes, 0xcd, sizeof(sizes));
    size_t capacity = modelLoad_calcSizes(&file, flags, &sizes, 0);
    size_t forcedCapacity = modelLoad_calcSizes(&file, flags, &forced, 1);
    assert(forcedCapacity >= capacity && (capacity & 31) == 0);
    size_t matrices = file.animationCount ? file.jointCount + file.extraJointCount : 1;
    assert(sizes.jointMatrixBytes == (int)(matrices * 128));
    assert(sizes.hitSphereBytes == file.hitVolumeCount * 32);
    int dynamic = !!(mask & (4 | 8 | 32));
    size_t vertexBytes = file.vertexCount * 6;
    size_t normalBytes = file.normalCount * (mask & 64 ? 9 : 3);
    assert(sizes.geometryBytes == (int)((dynamic ? vertexBytes * 2 + 96 : 0) +
        (mask & 16 ? normalBytes + 64 : 0)));
    assert(sizes.stateBytes == (int)(sizeof(ObjAnimState) * (mask & 2 ? 2 : 1) + (mask & 4 ? 48 : 0)));
    assert(forced.stateBytes == (int)(sizeof(ObjAnimState) * (mask & 2 ? 2 : 1) + 48));
    size_t cacheSlot = align(file.animationCacheSize, 8);
    assert(sizes.moveCacheBytes == (mask & 1 ? (int)cacheSlot * (mask & 2 ? 8 : 4) : 0));
    if (mask & 1) assert(sizes.moveCacheSlotBytes == (int)cacheSlot);
    for (int i = 0; i < 4; i++) assert(sizes.unused08[i] == 0xcd);
    u8* arena = aligned_alloc(32, capacity + 32);
    assert(arena && (uintptr_t)arena > UINT32_MAX);
    /* The caller zeroes the header. Poison the tail to distinguish writes. */
    memset(arena, 0, sizeof(ObjModel));
    memset(arena + sizeof(ObjModel), 0xcd, capacity - sizeof(ObjModel));
    memset(arena + capacity, 0xab, 32);
    activeFile = &file;
    activeModel = (ObjModel*)arena;
    activeModel->renderAttachment = &marker;
    activeModel->vtxBufDirty = 0xab;
    activeModel->skeletonJointData = (ModelJointWork*)&marker;
    flushCount = resetCount = relocateCount = storeCount = 0;
    ObjModel* model = ObjModel_LoadAnimData(&file, flags, arena);
    assert(model == activeModel && model->file == &file);
    assert(resetCount == (mask & 2 ? 2 : 1) && relocateCount == 1 && storeCount == 1);
    assert(model->renderAttachment == NULL && model->vtxBufDirty == 0);
    size_t cursor = sizeof(ObjModel);
    expect(model->jointMatrices[0], arena, &cursor, matrices * 64, 32);
    expect(model->jointMatrices[1], arena, &cursor, matrices * 64, 1);
    assert(model->curMtxBuf == model->jointMatrices[0]);
    int flush = 0;
    if (dynamic) {
        for (int i = 0; i < 2; i++) {
            expect(model->vtxBuf[i], arena, &cursor, vertexBytes, 32);
            assert(memcmp(model->vtxBuf[i], vertices, vertexBytes) == 0);
            assert(flushPointers[flush] == model->vtxBuf[i] && flushSizes[flush++] == vertexBytes);
        }
        cursor = align(cursor, 32);
    } else assert(model->vtxBuf[0] == vertices && model->vtxBuf[1] == vertices);
    if (mask & 16) {
        expect(model->normalBuf, arena, &cursor, normalBytes, 32);
        assert(memcmp(model->normalBuf, normals, normalBytes) == 0);
        assert(flushPointers[flush] == model->normalBuf && flushSizes[flush++] == normalBytes);
        cursor = align(cursor, 32);
    } else assert(model->normalBuf == normals);
    assert(flush == flushCount);
    expect(model->animStateA, arena, &cursor, sizeof(ObjAnimState), 4);
    if (mask & 2) expect(model->animStateB, arena, &cursor, sizeof(ObjAnimState), 1);
    else assert(model->animStateB == NULL);
    if (mask & 1) {
        cursor = align(cursor, 8);
        for (int state = 0; state < (mask & 2 ? 2 : 1); state++) {
            ObjAnimState* animation = state ? model->animStateB : model->animStateA;
            for (int slot = 0; slot < 4; slot++) expect(animation->cachedMoves[slot], arena, &cursor, cacheSlot, 1);
        }
    }
    if (mask & 4) {
        expect(model->blendChannels, arena, &cursor, 48, 4);
        for (int i = 0; i < 3; i++) {
            ObjModelBlendChannel* channel = &model->blendChannels[i];
            assert(channel->morphTargetA == -1 && channel->morphTargetB == -1);
            assert(channel->weight == 0 && channel->previousWeight == 0 && channel->weightRate == 0);
            assert(channel->flags == 0xcd);
        }
    } else assert(model->blendChannels == NULL);
    if (mask & 128) {
        expect(model->hitVolumeSphereBuffers[0], arena, &cursor, file.hitVolumeCount * 16, 4);
        expect(model->hitVolumeSphereBuffers[1], arena, &cursor, file.hitVolumeCount * 16, 1);
        assert(model->activeHitVolumeSpheres == model->hitVolumeSphereBuffers[0]);
    } else assert(model->activeHitVolumeSpheres == NULL);
    if ((mask & 256) && !(mask & 512) && file.jointCount) {
        ModelJointWork* work = model->skeletonJointData;
        expect(work, arena, &cursor, sizeof(ModelJointWork), 4);
        expect(work->jointPositions, arena, &cursor, file.jointCount * 12, 1);
        expect(work->jointRadii, arena, &cursor, file.jointCount * 4, 1);
        expect(work->radiiSq, arena, &cursor, file.jointCount * 4, 1);
        expect(work->jointLengths, arena, &cursor, file.jointCount * 4, 1);
        expect(work->jointCullDistances, arena, &cursor, file.jointCount * 4, 1);
        expect(work->touchedJoints, arena, &cursor, file.jointCount, 1);
    } else assert(model->skeletonJointData == NULL);
    if (mask & 8) expect(model->vertexAnimOffsets, arena, &cursor, file.vertexAnimJob.chunkCount * 4, 4);
    else assert(model->vertexAnimOffsets == NULL);
    if (mask & 16) expect(model->normalAnimOutputs, arena, &cursor, file.normalAnimJob.chunkCount * sizeof(u8*), 4);
    else assert(model->normalAnimOutputs == NULL);
    expect(model->textureRefs, arena, &cursor, file.renderOpCount * sizeof(ModelRenderOpTextureRefs), 4);
    for (int i = 0; i < file.renderOpCount; i++) assert(model->textureRefs[i].swapSelector == 0);
    if (mask & 1024) {
        expect(model->groundShadowQuad, arena, &cursor, sizeof(GroundShadowQuad), 2);
        assert(model->groundShadowQuad->status == 0);
    } else assert(model->groundShadowQuad == NULL);
    assert(cursor <= capacity);
    for (int i = 0; i < 32; i++) assert(arena[capacity + i] == 0xab);
    free(arena);
}
int main(void) {
    assert(modelLoad_layoutBuffers(NULL, 0, 0, NULL) == NULL);
    for (int mask = 0; mask < 4096; mask++) for (int variant = 0; variant < 4; variant++) check(mask, variant);
    puts("16384 model instance layouts and initialization handoffs checked");
    return 0;
}
"""


def function(source, name):
    start, end = find_function_body(source, name)
    declaration = source.rfind("\n", 0, source.rfind(name, 0, start)) + 1
    return source[declaration:end + 1]


def harness():
    def read(name):
        return (ROOT / name).read_text()
    model = read("include/main/model.h")
    anim = read("include/main/objanim_internal.h")
    source = read("src/main/model.c")
    parts = [PRELUDE, "typedef struct Vec3s { s16 x, y, z; } Vec3s;",
             "typedef struct ObjAnimFrameHeader ObjAnimFrameHeader;"]
    parts.append(re.search(r"typedef size_t TextureReference;", (ROOT / "include/main/texture.h").read_text())[0])
    for header, name in ((model, "MODEL_FLAG_CACHED_ANIMATIONS"), (model, "MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS"),
                         (model, "MODEL_FLAGS24_NBT_NORMALS"), (anim, "OBJANIM_MOVE_CACHE_SLOT_COUNT")):
        parts.append(re.search(rf"^#define {name}\s+[^\n]+", header, re.M)[0])
    for header, kind, name in (
        (model, "union", "ModelTextureEntry"), (model, "struct", "ModelVtxAnimJob"),
        (model, "struct", "ModelFuzzScaleDef"), (model, "struct", "ModelFileHeader"),
        (model, "struct", "ModelRenderOpTextureRefs"), (model, "struct", "ModelJointWork"),
        (model, "struct", "ObjModel"), (model, "struct", "ModelPackedNormal"),
        (model, "struct", "ModelNormalTriplet"), (model, "struct", "ObjModelJointMatrix"),
        (model, "struct", "ObjModelBlendChannel"), (model, "struct", "ObjModelHitSphere"),
        (read("include/main/ground_shadow.h"), "struct", "GroundShadowQuad"),
        (anim, "struct", "ObjAnimState"), (source, "struct", "ModelInstanceSizes"),
    ):
        parts.append(re.search(rf"typedef {kind} {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    parts.append(FIXTURE)
    for name in ("alignUp2", "roundUpTo4", "roundUpTo8", "roundUpTo32"):
        parts.append(function(read("src/main/mm.c"), name))
    for name in ("modelLoad_calcSizes", "modelLoad_layoutBuffers", "ObjModel_LoadAnimData"):
        parts.append(function(source, name))
    return "\n".join(parts + [CASES])


class ModelInstanceLayoutTests(unittest.TestCase):
    def test_native_instance_layout_and_handoff(self):
        with tempfile.TemporaryDirectory(prefix="model-instance-layout-") as directory:
            source = Path(directory) / "layout.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "layout"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1"})


if __name__ == "__main__":
    unittest.main()
