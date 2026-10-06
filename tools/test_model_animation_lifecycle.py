#!/usr/bin/env python3
"""Exercise production model animation setup/release with native pointers.

Asset IO, caches and deallocation are spies. This checks ownership and state
transitions, not asset decoding or the target's integer-address alignment API.
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
#include <string.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float f32;
typedef struct Vec { f32 x, y, z; } Vec;
typedef struct Texture { int id; } Texture;
typedef struct Shader Shader;
typedef struct ModelExtraJointDef ModelExtraJointDef;
typedef struct ModelCollisionTriangle ModelCollisionTriangle;
typedef struct CollisionPolygonGroup CollisionPolygonGroup;
typedef struct ModelVtxAnimChunk ModelVtxAnimChunk;
typedef union ModelMorphTargetRef ModelMorphTargetRef;
typedef struct GroundShadowQuad GroundShadowQuad;
typedef struct ObjAnimState ObjAnimState;
typedef struct ObjAnimMoveData ObjAnimMoveData;
typedef struct ObjAnimCachedMove ObjAnimCachedMove;
"""
SERVICES = r"""
enum { MLDF_FILEID_ANIM_BIN_A = 0x30 };
enum { FLAGS, LOOKUP, QUERY, ALLOCATE, READ, INSERT, PRIVATE, SHADER,
       REMOVE_MODEL, RESOLVE, FREE_TEXTURE, FIND_MOVE, REMOVE_MOVE, FREE_MEMORY };
typedef struct Event { int kind; const void* pointer; int value; } Event;
static Event events[128];
static int eventCount, loadedFlags, cacheHit;
static int modelList, animList;
static void* gModelList = &modelList;
static void* gModelAnimCacheList = &animList;
static u32 offsets[4] = {0, 0, 0x1234, 0};
static u32* gModelAnimDataOffsetTable = offsets;
static union { max_align_t alignment; u8 bytes[256]; } shared, privateMoves[4];
static ModelFileHeader file;
static ObjModel model;
static Texture textures[3];
static const u32 references[3] = {1, 0x81234560u, 0};
static ObjAnimMoveData* releaseMoves[6];
static void event(int kind, const void* pointer, int value) {
    assert(eventCount < 128);
    events[eventCount++] = (Event){kind, pointer, value};
}
static void expect(int* position, int kind, const void* pointer, int value) {
    assert(*position < eventCount);
    Event* actual = &events[(*position)++];
    assert(actual->kind == kind && actual->pointer == pointer && actual->value == value);
}
static int getLoadedFileFlags(int unused) {
    assert(unused == 0);
    event(FLAGS, NULL, loadedFlags);
    return loadedFlags;
}
static int ModelList_getHeader(void* list, int id, ObjAnimMoveData** output) {
    assert(list == gModelAnimCacheList && id == 2);
    event(LOOKUP, list, id);
    if (cacheHit) *output = (ObjAnimMoveData*)shared.bytes;
    return cacheHit;
}
static void loadAndDecompressDataFile(int fileId, void* output, int offset, int size, int* written, int id, int query) {
    assert(fileId == MLDF_FILEID_ANIM_BIN_A && offset == 0x1234 && id == 2);
    assert(size == (query ? 0 : 32));
    assert(output == (query ? NULL : shared.bytes));
    *written = 32;
    event(query ? QUERY : READ, output, size);
}
static void* mmAlloc(int size, int tag, int unused) {
    assert(size == 32 && tag == 10 && unused == 0);
    event(ALLOCATE, shared.bytes, size);
    return shared.bytes;
}
static void modelInitModelList(void* list, int id, ObjAnimMoveData** animation) {
    assert(list == gModelAnimCacheList && id == 2 && (void*)*animation == shared.bytes);
    assert((*animation)->refCount == 1);
    event(INSERT, *animation, id);
}
static void* animLoadFromTable(ModelFileHeader* owner, int id, int index, ObjAnimCachedMove* cache) {
    assert(owner == &file && id == 2 && index == 0 && (uintptr_t)cache > UINT32_MAX);
    event(PRIVATE, cache, id);
    return &cache->moveData;
}
static void ShaderDef_free(void** refs) { event(SHADER, refs, 0); }
static void model_adjustModelList(void* list, int id) {
    event(list == gModelList ? REMOVE_MODEL : REMOVE_MOVE, list, id);
}
static void* textureIdxToPtr(TextureReference reference) {
    event(RESOLVE, NULL, reference);
    for (int i = 0; i < 3; i++) if ((u32)reference == references[i]) return references[i] ? &textures[i] : NULL;
    assert(0 && "unexpected texture reference");
    return NULL;
}
static void textureFree(Texture* texture) { event(FREE_TEXTURE, texture, 0); }
static void model_findIdxInModelList(void* list, ObjAnimMoveData** animation, int* index) {
    assert(list == gModelAnimCacheList);
    for (int i = 0; i < 6; i++) {
        if (releaseMoves[i] == *animation) {
            *index = i + 10;
            event(FIND_MOVE, *animation, *index);
            return;
        }
    }
    assert(0 && "unexpected animation release");
}
static void mm_free(void* pointer) { event(FREE_MEMORY, pointer, 0); }
"""
CASES = r"""
static int allowed(void) {
    return !(loadedFlags & LOADED_FILE_FLAG_PI_LOCKED) || file.modelId == 1 || file.modelId == 3;
}
static void checkAcquire(int modelId, int flags, int mode, int referencesBefore) {
    int position = 0;
    s16 id = 2;
    ObjAnimMoveData* animation = (ObjAnimMoveData*)shared.bytes;
    ObjAnimCachedMove* cache = mode == 2 ? (ObjAnimCachedMove*)privateMoves[0].bytes : NULL;
    memset(&file, 0, sizeof(file));
    file.modelId = modelId;
    file.cachedAnimIds = &id;
    loadedFlags = flags;
    cacheHit = mode == 1;
    animation->refCount = referencesBefore;
    eventCount = 0;
    modelLoadInitialMove(&file, cache);
    expect(&position, FLAGS, NULL, flags);
    if (allowed()) {
        if (cache) expect(&position, PRIVATE, cache, 2);
        else {
            expect(&position, LOOKUP, gModelAnimCacheList, 2);
            if (!cacheHit) {
                expect(&position, QUERY, NULL, 0);
                expect(&position, ALLOCATE, shared.bytes, 32);
                expect(&position, READ, shared.bytes, 32);
                expect(&position, INSERT, animation, 2);
            }
        }
    }
    assert(position == eventCount);
    assert(animation->refCount == (!allowed() || cache ? referencesBefore : cacheHit ? (u8)(referencesBefore + 1) : 1));
}
static void checkReset(int animations, int cached, int modelId, int flags, int control, int frames) {
    ObjAnimState state, expected;
    ObjAnimMoveData* moves[1] = {(ObjAnimMoveData*)shared.bytes};
    s16 id = 2;
    memset(&file, 0, sizeof(file));
    memset(&model, 0, sizeof(model));
    memset(&state, 0xA5, sizeof(state));
    for (int i = 0; i < 4; i++) state.cachedMoves[i] = (ObjAnimCachedMove*)privateMoves[i].bytes;
    file.animationCount = animations;
    file.flags = cached ? MODEL_FLAG_CACHED_ANIMATIONS : 0;
    file.cachedAnimIds = &id;
    file.moveData = moves;
    file.modelId = modelId;
    model.file = &file;
    loadedFlags = flags;
    ObjAnimMoveData* move = cached ? &state.moveCache[0]->moveData : moves[0];
    move->frameControl = (s8)control;
    ObjAnimFrameHeader* frame = (ObjAnimFrameHeader*)move->frameCommands;
    frame->frameCount = frames;
    memcpy(&expected, &state, sizeof(state));
    expected.moveCacheSlot = expected.eventStep = expected.eventCountdown = 0;
    expected.eventState = expected.prevEventState = 0;
    expected.frameStep = expected.framePhase = expected.frameLength = 0;
    expected.frameType = 0;
    if (animations) {
        expected.moveFrameData = expected.prevMoveFrameData = expected.blendFrameData = expected.prevBlendFrameData = frame;
        expected.frameType = expected.prevFrameType = (s8)(control & 0xF0);
        expected.frameLength = expected.prevFrameLength = frames - ((control & 0xF0) == 0);
        expected.prevMoveCacheSlot = expected.blendCacheSlot = expected.prevBlendCacheSlot = 0;
        expected.prevFramePhase = expected.savedFrameStep = 0;
    }
    eventCount = 0;
    modelAnimResetState(&model, &state);
    assert(memcmp(&state, &expected, sizeof(state)) == 0);
    int position = 0;
    if (animations && cached) {
        for (int i = 0; i < 4; i++) {
            expect(&position, FLAGS, NULL, flags);
            if (allowed()) expect(&position, PRIVATE, state.cachedMoves[i], 2);
        }
    }
    assert(position == eventCount);
}
static void checkRelease(int refs, int shaders, int count, int loaded, int attachment, int moveMode) {
    ObjModel expectedModel;
    ModelFileHeader expectedFile;
    ModelTextureEntry entries[3];
    ModelRenderOpTextureRefs shaderRefs[3];
    ObjAnimMoveData resources[6];
    const u8 counts[6] = {1, 2, 0, 128, 129, 0};
    int position = 0;
    memset(&file, 0, sizeof(file));
    memset(&model, 0, sizeof(model));
    model.file = &file;
    model.bufferFlags = 0x8001 | (loaded ? OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED : 0);
    model.textureRefs = shaderRefs;
    model.renderAttachment = attachment ? &textures[0] : NULL;
    file.refCount = refs;
    file.modelId = 23;
    file.renderOpCount = shaders;
    file.textureCount = count;
    file.textureEntries = entries;
    file.animationCount = moveMode == 1 ? 0 : 6;
    file.moveData = moveMode == 0 ? NULL : releaseMoves;
    for (int i = 0; i < 3; i++) entries[i].reference = references[i];
    for (int i = 0; i < 6; i++) {
        resources[i].refCount = counts[i];
        releaseMoves[i] = i == 2 ? NULL : &resources[i];
    }
    memcpy(&expectedModel, &model, sizeof(model));
    memcpy(&expectedFile, &file, sizeof(file));
    expectedModel.bufferFlags &= ~OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED;
    expectedFile.refCount--;
    eventCount = 0;
    ObjModel_Release(&model);
    assert(memcmp(&model, &expectedModel, sizeof(model)) == 0);
    assert(memcmp(&file, &expectedFile, sizeof(file)) == 0);
    if (loaded) for (int i = 0; i < shaders; i++) expect(&position, SHADER, &shaderRefs[i], 0);
    if (attachment) expect(&position, FREE_MEMORY, model.renderAttachment, 0);
    if (refs == 1) {
        expect(&position, REMOVE_MODEL, gModelList, 23);
        for (int i = 0; i < count; i++) {
            expect(&position, RESOLVE, NULL, (s32)references[i]);
            expect(&position, FREE_TEXTURE, references[i] ? &textures[i] : NULL, 0);
        }
        if (moveMode == 2) {
            for (int i = 0; i < 6; i++) {
                if (releaseMoves[i] && (s8)(u8)(counts[i] - 1) <= 0) {
                    expect(&position, FIND_MOVE, releaseMoves[i], i + 10);
                    expect(&position, REMOVE_MOVE, gModelAnimCacheList, i + 10);
                    expect(&position, FREE_MEMORY, releaseMoves[i], 0);
                }
            }
        }
        expect(&position, FREE_MEMORY, &file, 0);
    }
    for (int i = 0; i < 6; i++) assert(resources[i].refCount == (u8)(counts[i] - (refs == 1 && moveMode == 2 && i != 2)));
    assert(position == eventCount);
}
int main(void) {
    const int modelIds[] = {0, 1, 2, 3, 4, 65535};
    const int flags[] = {0, LOADED_FILE_FLAG_PI_LOCKED, 2, LOADED_FILE_FLAG_PI_LOCKED | 2};
    const int refs[] = {0, 1, 255};
    const int controls[] = {0, 1, 15, 16, 127, 128, 240, 255};
    const int frames[] = {0, 1, 2, 255};
    int acquireCases = 0, resetCases = 0, releaseCases = 0;
    assert(sizeof(void*) == 8 && (uintptr_t)&model > UINT32_MAX);
    for (int id = 0; id < 6; id++) for (int f = 0; f < 4; f++) for (int mode = 0; mode < 3; mode++) for (int ref = 0; ref < 3; ref++) {
        checkAcquire(modelIds[id], flags[f], mode, refs[ref]);
        acquireCases++;
    }
    for (int anim = 0; anim < 2; anim++) for (int cache = 0; cache < 2; cache++) for (int id = 0; id < 3; id++)
        for (int f = 0; f < 2; f++) for (int c = 0; c < 8; c++) for (int n = 0; n < 4; n++) {
            checkReset(anim, cache, modelIds[id], flags[f], controls[c], frames[n]);
            resetCases++;
        }
    for (int refs = 0; refs < 3; refs++) for (int shaders = 0; shaders < 3; shaders++) for (int count = 0; count < 4; count++)
        for (int loaded = 0; loaded < 2; loaded++) for (int attachment = 0; attachment < 2; attachment++) for (int mode = 0; mode < 3; mode++) {
            checkRelease(refs, shaders, count, loaded, attachment, mode);
            releaseCases++;
        }
    printf("%d acquisition, %d reset and %d release cases checked\n", acquireCases, resetCases, releaseCases);
    return 0;
}
"""


def harness():
    model_header = (ROOT / "include/main/model.h").read_text()
    anim_header = (ROOT / "include/main/objanim_internal.h").read_text()
    flags_header = (ROOT / "include/main/loaded_file_flags.h").read_text()
    parts = [PRELUDE]
    parts.append(re.search(r"typedef size_t TextureReference;", (ROOT / "include/main/texture.h").read_text())[0])
    for header, name in ((model_header, "MODEL_FLAG_CACHED_ANIMATIONS"),
                         (model_header, "OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED"),
                         (anim_header, "OBJANIM_MOVE_CACHE_SLOT_COUNT"),
                         (flags_header, "LOADED_FILE_FLAG_PI_LOCKED")):
        parts.append(re.search(rf"^#define {name}\s+[^\n]+", header, re.M)[0])
    for header, kind, name in (
        (model_header, "union", "ModelTextureEntry"), (model_header, "struct", "ModelVtxAnimJob"),
        (model_header, "struct", "ModelFuzzScaleDef"), (model_header, "struct", "ModelFileHeader"),
        (model_header, "struct", "ModelRenderOpTextureRefs"), (model_header, "struct", "ModelJointWork"),
        (model_header, "struct", "ObjModel"), (anim_header, "struct", "ObjAnimFrameHeader"),
        (anim_header, "struct", "ObjAnimMoveData"), (anim_header, "struct", "ObjAnimState"),
    ):
        parts.append(re.search(rf"typedef {kind} {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    parts.append(re.search(r"struct ObjAnimCachedMove\s*\{.*?\};", anim_header, re.S)[0])
    parts.append(SERVICES)
    source = (ROOT / "src/main/model.c").read_text()
    for name in ("modelLoadInitialMove", "modelAnimResetState", "ObjModel_Release"):
        start, end = find_function_body(source, name)
        declaration = source.rfind("\n", 0, source.rfind(name, 0, start)) + 1
        parts.append(source[declaration:end + 1])
    return "\n".join(parts + [CASES])


class ModelAnimationLifecycleTests(unittest.TestCase):
    def test_native_pointers_and_resource_ownership(self):
        with tempfile.TemporaryDirectory(prefix="model-animation-lifecycle-") as directory:
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
