#!/usr/bin/env python3
"""Execute production joint-binding lookups with native pointers.

ObjDef, binding/pose/matrix types and lookup bodies come from production.
Object/model fixtures expose the fields used here; retail layout and codegen
are checked by the game builds. World-position calls always provide a tag that
exists, as the retail function leaves its joint index uninitialized otherwise.
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
#define STATIC_ASSERT(X) _Static_assert(X, #X)
typedef struct ObjTextureSlotDef ObjTextureSlotDef;
typedef struct ObjHitReactMoveEntry ObjHitReactMoveEntry;
typedef struct ObjAttachPoint ObjAttachPoint;
typedef struct ObjDefHitVolume ObjDefHitVolume;
"""
FIXTURE = r"""
typedef struct ObjAnimComponent {
    ObjDef* modelInstance;
    s8 bankIndex;
    u8* jointPoseData;
} ObjAnimComponent;
typedef struct GameObject { ObjAnimComponent anim; } GameObject;
typedef struct ModelFileHeader { u8 jointCount, extraJointCount; } ModelFileHeader;
typedef struct ObjModel {
    ModelFileHeader* file;
    u8* jointMatrices[2];
    u16 bufferFlags;
} ObjModel;
static GameObject object;
static ModelFileHeader file = {2, 1};
static ObjModelJointMatrix matrices[2][3];
static ObjModel model = {&file, {(u8*)matrices[0], (u8*)matrices[1]}, 0};
static f32 playerMapOffsetX = 1000, playerMapOffsetZ = -2000;
static ObjModel* Obj_GetActiveModel(GameObject* obj) {
    assert(obj == &object);
    return &model;
}
"""
CASES = r"""
static int lookups, worldCalls;
static void check(int models, int bank, int count, int pattern) {
    u8 bytes[8 * 5];
    ObjJointPose poses[8];
    ObjDef definition = {0};
    const int keys[] = {-1, 0, 1, 2, 3, 128, 255, 256};
    const u8 tags[] = {0, 1, 128, 255, 0, 1, 2, 3};
    definition.jointBindings = (ObjJointBinding*)bytes;
    definition.modelCount = models;
    definition.jointBindingCount = count;
    object.anim = (ObjAnimComponent){&definition, bank, (u8*)poses};
    for (int i = 0; i < count; i++) {
        bytes[i * (models + 1)] = tags[i];
        for (int m = 0; m < models; m++)
            bytes[i * (models + 1) + 1 + m] =
                ((i + m + pattern) % 4 == 0) ? 255 : (i + m + pattern) % 5;
    }
    assert((uintptr_t)poses > UINT32_MAX && (uintptr_t)bytes > UINT32_MAX);
    for (int keyIndex = 0; keyIndex < 8; keyIndex++) {
        int key = keys[keyIndex];
        int first = -1, last = -1;
        for (int i = 0; i < count; i++) if (tags[i] == key) {
            if (first == -1) first = i;
            if (bytes[i * (models + 1) + 1 + bank] != 255) last = i;
        }
        ObjJointPose* expected = last == -1 ? NULL : &poses[last];
        assert(playerEyeAnim_FindJoint(&object.anim, key) == expected);
        assert(objFindJointVecByKey(&object, key) == (s16*)expected);
        assert(objFindJointPoseVector(&object, key) == (s16*)expected);
        lookups += 3;
        if (first != -1) for (int buffer = 0; buffer < 2; buffer++) {
            f32 output[3];
            model.bufferFlags = 0x80 | buffer;
            objGetJointWorldPosition(&object, key, output);
            int joint = bytes[first * (models + 1) + 1 + bank];
            if (joint >= 3) joint = 0; /* Actual matrix getter's existing clamp. */
            assert(output[0] == matrices[buffer][joint].translationX + playerMapOffsetX);
            assert(output[1] == matrices[buffer][joint].translationY);
            assert(output[2] == matrices[buffer][joint].translationZ + playerMapOffsetZ);
            worldCalls++;
        }
    }
}
int main(void) {
    union { max_align_t alignment; u8 bytes[1024]; } resource;
    const u32 offsets[] = {0, sizeof(ObjDef), sizeof(ObjDef) + 13, 1000};
    for (int i = 0; i < 4; i++) {
        memset(&resource, 0, sizeof(resource));
        ObjDef* definition = (ObjDef*)resource.bytes;
        definition->jointBindingsOffset = offsets[i];
        assert((uintptr_t)definition > UINT32_MAX);
        relocateBindingTable(definition);
        assert(definition->jointBindingBytes == resource.bytes + offsets[i]);
        assert((u8*)definition->jointBindings == resource.bytes + offsets[i]);
    }
    for (int b = 0; b < 2; b++) for (int j = 0; j < 3; j++) {
        matrices[b][j].translationX = b * 100 + j * 10 + 1;
        matrices[b][j].translationY = b * 100 + j * 10 + 2;
        matrices[b][j].translationZ = b * 100 + j * 10 + 3;
    }
    for (int models = 1; models <= 4; models++) for (int bank = 0; bank < models; bank++)
        for (int count = 0; count <= 8; count++) for (int pattern = 0; pattern < 4; pattern++)
            check(models, bank, count, pattern);
    object.anim.modelInstance = NULL;
    assert(playerEyeAnim_FindJoint(&object.anim, 0) == NULL);
    assert(objFindJointVecByKey(&object, 0) == NULL);
    assert(objFindJointPoseVector(&object, 0) == NULL);
    printf("%d pose lookups and %d world-position calls checked\n", lookups + 3, worldCalls);
    return 0;
}
"""


def function(source, name):
    start, end = find_function_body(source, name)
    declaration = source.rfind("\n", 0, source.rfind(name, 0, start)) + 1
    return source[declaration:end + 1]


def harness():
    pose = (ROOT / "include/main/joint_pose.h").read_text().replace('#include "global.h"', '')
    anim = (ROOT / "include/main/objanim_internal.h").read_text()
    header = (ROOT / "include/main/model.h").read_text()
    internal = (ROOT / "include/main/objprint_internal.h").read_text()
    source = (ROOT / "src/main/objexpr.c").read_text()
    parts = [PRELUDE, pose]
    for text, name in ((anim, "ObjDef"), (header, "ObjModelJointMatrix")):
        parts.append(re.search(rf"typedef struct {name}\s*\{{.*?\}} {name};", text, re.S)[0])
    parts.append(FIXTURE)
    loader = (ROOT / "src/main/object.c").read_text()
    relocation = re.search(r"^\s*buf->jointBindings = [^\n]+;", loader, re.M)[0]
    parts.append("static void relocateBindingTable(ObjDef* buf) {" + relocation + "\n}")
    parts.extend(re.findall(r"^#define OBJPRINT_.*$", internal, re.M))
    parts.append(function((ROOT / "src/main/model.c").read_text(), "ObjModel_GetJointMatrix"))
    parts.append(function(internal, "objFindJointVecByKey"))
    for name in ("playerEyeAnim_FindJoint", "objFindJointPoseVector", "objGetJointWorldPosition"):
        parts.append(function(source, name))
    return "\n".join(parts + [CASES])


class ObjectJointBindingTests(unittest.TestCase):
    def test_variable_width_and_duplicate_selection(self):
        with tempfile.TemporaryDirectory(prefix="object-joint-bindings-") as directory:
            source = Path(directory) / "bindings.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "bindings"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        # Keep the retail missing-tag warning visible; these cases only
                        # call world-position lookup with an existing tag.
                        "-Wno-error=sometimes-uninitialized",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
