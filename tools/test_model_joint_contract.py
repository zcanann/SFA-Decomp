#!/usr/bin/env python3
"""Exercise the production joint-matrix callers with native pointers.

Preparation and rendering are spies: this checks the pointer contract, buffer
selection and pass routing, not the assembly kernel's matrix arithmetic.
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
typedef struct Texture Texture;
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
typedef struct Pass { int mode, channels, event; } Pass;
static Pass passes[3];
static int expectedCount, preparedCount, renderedCount, expectedFlags;
static ObjAnimState *prepared, channel;
static ModelFileHeader file;
static ObjModel model;
static ModelBone bones[3];
static ObjAnimCachedMove moves[4];
static u8 buffers[2][3 * 64];
static f32 rootTransform[12];
static s16 gModelJointScratchBuffer[0xa0];
static void modelAnimUpdateChannels(ModelFileHeader* owner, ObjAnimState* work, int count) {
    assert(owner == &file && work != &channel);
    assert(preparedCount == renderedCount && preparedCount < expectedCount);
    Pass* pass = &passes[preparedCount++];
    assert(count == pass->channels && work->eventCountdown == pass->event);
    for (int i = 0; i < count; i++) {
        int found = 0;
        for (int j = 0; j < 4; j++) found |= work->frameData[i] == (ObjAnimFrameHeader*)moves[j].moveData.frameCommands;
        assert(found);
        if (file.flags & MODEL_FLAG_CACHED_ANIMATIONS) {
            found = 0;
            for (int j = 0; j < 4; j++) found |= work->cachedMoves[work->cacheSlots[i]] == &moves[j];
            assert(found);
        }
    }
    prepared = work;
}
void modelAnimBuildJointMatrices(u8** workspace, f32* root, ObjAnimState* animState,
                                 const ModelBone* joints, int count, s16* scratch, int flags, int mode) {
    assert(preparedCount == renderedCount + 1 && renderedCount < expectedCount);
    assert(animState == prepared && joints == bones && count == 3);
    assert(root == rootTransform && scratch == gModelJointScratchBuffer);
    assert(flags == expectedFlags && mode == passes[renderedCount].mode);
    assert((uintptr_t)*workspace > UINT32_MAX);
    assert(*workspace == buffers[model.bufferFlags & 1]);
    (*workspace)[renderedCount] = 0xa0 + renderedCount;
    renderedCount++;
}
"""
CASES = r"""
static void reset(int cached, int buffer, int control, int flags) {
    memset(&file, 0, sizeof(file));
    memset(&model, 0, sizeof(model));
    memset(&channel, 0, sizeof(channel));
    memset(buffers, 0xcc, sizeof(buffers));
    file.flags = cached ? MODEL_FLAG_CACHED_ANIMATIONS : 0;
    file.jointData = (u8*)bones;
    file.jointCount = 3;
    model.file = &file;
    model.jointMatrices[0] = buffers[0];
    model.jointMatrices[1] = buffers[1];
    model.bufferFlags = 0x80 | buffer;
    channel.frameLengths[0] = 8;
    channel.frameLengths[1] = 12;
    channel.framePhases[0] = 1;
    channel.framePhases[1] = 3;
    channel.moveControlFlags = control;
    for (int i = 0; i < 4; i++) {
        channel.cacheSlots[i] = (i + 1) & 1;
        channel.cachedMoves[i] = &moves[i];
        channel.frameData[i] = (ObjAnimFrameHeader*)moves[i].moveData.frameCommands;
    }
    expectedCount = preparedCount = renderedCount = 0;
    expectedFlags = flags;
    assert(sizeof(void*) > sizeof(int));
    assert((uintptr_t)buffers[0] > UINT32_MAX && (uintptr_t)buffers[1] > UINT32_MAX);
}
static void expect(int mode, int count, int event) {
    assert(expectedCount < 3);
    passes[expectedCount++] = (Pass){mode, count, event};
}
static void verify(void) {
    assert(preparedCount == expectedCount && renderedCount == expectedCount);
    for (int b = 0; b < 2; b++) for (unsigned i = 0; i < sizeof(buffers[b]); i++) {
        int touched = b == (model.bufferFlags & 1) && i < (unsigned)expectedCount;
        assert(buffers[b][i] == (touched ? 0xa0 + i : 0xcc));
    }
}
int main(void) {
    int pairCases = 0, channelCases = 0;
    const int controls[] = {0, 1, 4, 5};
    const int modes[] = {0, 1, 7, 0x14, 0x18};
    /* Explicit pass sequences for normal, transitional and dual-pose paths. */
    const struct {
        int special, countdown, firstEvent, secondEvent, count;
        Pass passes[3];
    } scenarios[] = {
        {8, 0, 0, 0, 1, {{0x40, 2, 0}}},
        {8, 5, 3, 7, 1, {{0x40, 2, 5}}},
        {0, 0, 0, 0, 1, {{0, 1, 0}}},
        {0, 5, 0, 0, 1, {{0, 2, 5}}},
        {0, 0, 3, 0, 1, {{0, 2, 3}}},
        {0, 0, 0, 7, 1, {{0, 2, 7}}},
        {0, 0, 3, 7, 2, {{0, 2, 3}, {0, 2, 7}}},
        {0, 5, 3, 0, 2, {{4, 2, 3}, {1, 2, 5}}},
        {0, 5, 0, 7, 2, {{8, 2, 7}, {2, 2, 5}}},
        {0, 5, 3, 7, 3, {{4, 2, 3}, {8, 2, 7}, {3, 2, 5}}},
    };
    for (int cached = 0; cached < 2; cached++) for (int buffer = 0; buffer < 2; buffer++)
        for (int c = 0; c < 4; c++) for (int flag = 0; flag < 2; flag++) {
            int flags = flag ? -1 : 0x7f;
            int rootMode = ((controls[c] & 1) ? 0x10 : 0) | ((controls[c] & 4) ? 0x20 : 0);
            for (int m = 0; m < 5; m++) for (int a = 0; a < 2; a++)
                for (int b = 0; b < 2; b++) for (int blend = 0; blend < 4; blend++) for (int event = 0; event < 2; event++) {
                    reset(cached, buffer, controls[c], flags);
                    int mode = modes[m] & 15;
                    expect(mode | ((mode & 12) ? 0 : rootMode), 2, event ? 9 : 1);
                    modelAnimEvalSlotPair(rootTransform, &model, &channel, .5f, flags, a, b, blend, modes[m], event ? 9 : 0);
                    assert(channel.framePhase == ((modes[m] & 0x10) ? 4 : 1));
                    verify();
                    pairCases++;
                }
            for (unsigned s = 0; s < sizeof(scenarios) / sizeof(scenarios[0]); s++) {
                reset(cached, buffer, controls[c], flags);
                file.flags |= scenarios[s].special;
                channel.eventCountdown = scenarios[s].countdown;
                channel.eventState = scenarios[s].firstEvent;
                channel.prevEventState = scenarios[s].secondEvent;
                for (int p = 0; p < scenarios[s].count; p++) {
                    Pass pass = scenarios[s].passes[p];
                    int final = p == scenarios[s].count - 1;
                    int rootPass = scenarios[s].special || scenarios[s].countdown ||
                                   (!scenarios[s].firstEvent && !scenarios[s].secondEvent);
                    expect(pass.mode | ((final && rootPass) ? rootMode : 0), pass.channels, pass.event);
                }
                modelAnimEvalChannels(rootTransform, &model, &channel, .5f, flags);
                assert(channel.framePhase == 4);
                verify();
                channelCases++;
            }
        }
    printf("%d slot-pair and %d channel evaluations checked\n", pairCases, channelCases);
    return 0;
}
"""


def harness():
    model = (ROOT / "include/main/model.h").read_text()
    anim = (ROOT / "include/main/objanim_internal.h").read_text()
    render = (ROOT / "include/main/render_internal.h").read_text()
    parts = [PRELUDE]
    for header, name in ((model, "MODEL_FLAG_CACHED_ANIMATIONS"), (anim, "OBJANIM_MOVE_CACHE_SLOT_COUNT")):
        parts.append(re.search(rf"^#define {name}\s+[^\n]+", header, re.M)[0])
    for header, kind, name in (
        (model, "union", "ModelTextureEntry"), (model, "struct", "ModelVtxAnimJob"),
        (model, "struct", "ModelFuzzScaleDef"), (model, "struct", "ModelFileHeader"),
        (model, "struct", "ModelRenderOpTextureRefs"), (model, "struct", "ModelJointWork"),
        (model, "struct", "ObjModel"), (model, "struct", "ModelBone"),
        (anim, "struct", "ObjAnimFrameHeader"), (anim, "struct", "ObjAnimMoveData"),
        (anim, "struct", "ObjAnimState"),
    ):
        parts.append(re.search(rf"typedef {kind} {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    parts.append(re.search(r"struct ObjAnimCachedMove\s*\{.*?\};", anim, re.S)[0])
    parts.append(re.search(r"void modelAnimBuildJointMatrices\(.*?;", render, re.S)[0])
    parts.append(SERVICES)
    source = (ROOT / "src/main/model.c").read_text()
    for name in ("modelAnimEvalSlotPair", "modelAnimEvalChannels"):
        start, end = find_function_body(source, name)
        declaration = source.rfind("\n", 0, source.rfind(name, 0, start)) + 1
        parts.append(source[declaration:end + 1])
    return "\n".join(parts + [CASES])


class ModelJointContractTests(unittest.TestCase):
    def test_native_workspace_and_pass_routing(self):
        with tempfile.TemporaryDirectory(prefix="model-joint-contract-") as directory:
            source = Path(directory) / "callers.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "callers"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
