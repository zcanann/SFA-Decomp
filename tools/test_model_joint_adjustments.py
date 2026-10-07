#!/usr/bin/env python3
"""Execute the production joint-adjustment serializer with native inputs.

Input fixtures expose only fields used by the builder; target layout is checked
by the normal game builds. Pose/stream records and the builder are production
source. The oracle checks serialized words, not matrix-decoder arithmetic.
"""

from pathlib import Path
import os
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
typedef float f32;
#define STATIC_ASSERT(X) _Static_assert(X, #X)
"""
FIXTURE = r"""
typedef struct CachedMove { u8 jointMatrixSlots[128]; } CachedMove;
typedef struct ObjAnimState {
    CachedMove* moveCache[2];
    u16 moveCacheSlot, prevMoveCacheSlot;
} ObjAnimState;
typedef struct ModelFileHeader {
    u16 flags;
    u8 jointCount;
    u8* animationDataSection;
} ModelFileHeader;
typedef struct ObjDef { ObjJointBinding* jointBindings; s8 modelCount; u8 jointBindingCount; } ObjDef;
typedef struct ObjAnimComponent {
    ObjDef* modelInstance;
    s8 bankIndex;
    u8* jointPoseData;
} ObjAnimComponent;
static struct {
    u32 before;
    ModelJointAdjustmentBuffer data;
    u32 after;
} guarded;
#define gModelJointAdjustments guarded.data
"""
CASES = r"""
static s16* component(ObjJointPose* pose, int index) {
    if (index < 3) return &pose->rotation[index];
    if (index < 6) return &pose->scale[index - 3];
    return &pose->translation[index - 6];
}
static void run(int cached, int models, int bank, int slot, int skeleton, int bindings, int seed, int mask) {
    CachedMove moves[2];
    u8 shared[256];
    s8 bindingData[25];
    ObjJointPose poses[5], saved[5];
    u16 expected[160];
    const int offsets[9] = {0, 2, 4, 12, 14, 16, 24, 26, 28};
    const s16 values[] = {-32768, -1024, -1, 1, 1024, 32767};
    int stride = (skeleton + 7) & ~7;
    ObjAnimState channel = {{&moves[0], &moves[1]}, slot, 1 - slot};
    ModelFileHeader file = {cached ? MODEL_FLAG_CACHED_ANIMATIONS : 0, skeleton, shared};
    ObjDef definition = {(ObjJointBinding*)bindingData, models, bindings};
    ObjAnimComponent anim = {&definition, bank, (u8*)poses};
    for (int row = 0; row < 2; row++) for (int joint = 0; joint < 128; joint++) {
        moves[row].jointMatrixSlots[joint] = seed * 37 + row * 79 + joint * 17;
        if (joint < stride) shared[row * stride + joint] = seed * 53 + row * 97 + joint * 13 + 91;
    }
    memset(poses, 0, sizeof(poses));
    memset(bindingData, 0xff, sizeof(bindingData));
    for (int b = 0; b < bindings; b++) {
        bindingData[b * (models + 1)] = 0x80 + b; /* Binding tag is not a model joint index. */
        for (int m = 0; m < models; m++) {
            int joint = (b * 7 + m * 11 + seed) % skeleton;
            bindingData[b * (models + 1) + 1 + m] = (seed == 7 && b % 2 == 0) ? -1 : joint;
        }
        for (int c = 0; c < 9; c++) {
            int enabled = mask & (1 << c);
            if (bindings == 5 && b == 4) enabled &= c < 3; /* 39 records plus terminator. */
            *component(&poses[b], c) = enabled ? values[(seed + b + c) % 6] : 0;
        }
    }
    memcpy(saved, poses, sizeof(saved));
    memset(&guarded, 0x5a, sizeof(guarded));
    memset(expected, 0x5a, sizeof(expected));
    int word = 0;
    for (int b = 0; b < bindings; b++) {
        int joint = (u8)bindingData[b * (models + 1) + 1 + bank];
        if (joint == 255) continue;
        for (int c = 0; c < 9; c++) {
            s16 delta = *component(&poses[b], c);
            if (!delta) continue;
            for (int pass = 0; pass < 2; pass++) {
                int row = pass ? 1 - slot : slot;
                int index = cached ? moves[row].jointMatrixSlots[joint] : shared[row * stride + joint];
                if (index >= 128) index -= 256;
                expected[word++] = (u16)(index * 64 + offsets[c]);
            }
            expected[word++] = (u16)delta;
            expected[word++] = (u16)delta;
        }
    }
    assert(word <= 156);
    expected[word++] = 0x1000;
    expected[word] = 0x1000;
    modelBuildJointAdjustments(&anim, &channel, &file);
    assert(guarded.before == 0x5a5a5a5a && guarded.after == 0x5a5a5a5a);
    assert(memcmp(guarded.data.words, expected, sizeof(expected)) == 0);
    assert(memcmp(poses, saved, sizeof(saved)) == 0);
    assert(guarded.data.entries[(word - 1) / 4].byteOffsets[0] == 0x1000);
    assert(guarded.data.entries[(word - 1) / 4].byteOffsets[1] == 0x1000);
}
int main(void) {
    const int skeletons[] = {1, 8, 9, 127};
    int cases = 0;
    for (int cached = 0; cached < 2; cached++) {
        for (int models = 1; models <= 4; models++) for (int bank = 0; bank < models; bank++)
            for (int slot = 0; slot < 2; slot++) for (int size = 0; size < 4; size++)
                for (int bindings = 0; bindings <= 4; bindings++) for (int seed = 0; seed < 8; seed++) {
                    run(cached, models, bank, slot, skeletons[size], bindings, seed, seed % 2 ? 511 : 0x155);
                    cases++;
                }
        for (int mask = 0; mask < 512; mask++) {
            run(cached, 2, 1, 1, 9, 1, mask % 8, mask);
            cases++;
        }
        for (int slot = 0; slot < 2; slot++) {
            run(cached, 4, 3, slot, 127, 5, 0, 511);
            cases++;
        }
    }
    printf("%d joint-adjustment streams checked\n", cases);
    return 0;
}
"""


def harness():
    header = (ROOT / "include/main/joint_pose.h").read_text().replace('#include "global.h"', '')
    model = (ROOT / "include/main/model.h").read_text()
    matrix = re.search(r"typedef struct ObjModelJointMatrix\s*\{.*?\} ObjModelJointMatrix;", model, re.S)[0]
    flag = re.search(r"^#define MODEL_FLAG_CACHED_ANIMATIONS\s+[^\n]+", model, re.M)[0]
    source = (ROOT / "src/main/model.c").read_text()
    start, end = find_function_body(source, "modelBuildJointAdjustments")
    declaration = source.rfind("\n", 0, source.rfind("modelBuildJointAdjustments", 0, start)) + 1
    macro = source[source.index("#define APPEND_JOINT_ADJUSTMENT"):source.index("extern char sModelAnimationBufferOverflowWarning")]
    return "\n".join([PRELUDE, header, matrix, flag, FIXTURE, macro, source[declaration:end + 1], CASES])


class ModelJointAdjustmentTests(unittest.TestCase):
    def test_serialization_and_signed_slots(self):
        with tempfile.TemporaryDirectory(prefix="model-joint-adjustments-") as directory:
            source = Path(directory) / "adjustments.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "adjustments"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1"})


if __name__ == "__main__":
    unittest.main()
