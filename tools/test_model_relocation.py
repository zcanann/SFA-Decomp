#!/usr/bin/env python3
"""Check the production model relocator with explicit offsets and native pointers.

The fixtures use host-endian, native-sized records, as a native asset decoder
would provide. They do not decode a retail model file or run the game loader.
"""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]
# Independent list of the retail relocation sites, in header order. Their
# offset aliases are checked by target layout assertions in model.h.
FIELDS = (
    "unk18", "unk1C", "textureIds", "vertices", "normals", "colors", "texCoords",
    "renderOps", "jointData", "jointFuzzScales", "extraJointDefs", "hitVolumes",
    "collisionTriangles", "collisionBlocks", "vertexAnimEntries", "vertexWeightData",
    "normalAnimEntries", "normalWeightData", "displayLists", "instrs", "morphTargets",
)
JOINT_DEPENDENTS = {"unk18", "unk1C", "jointFuzzScales"}
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
typedef struct Shader Shader;
typedef struct ModelCollisionTriangle ModelCollisionTriangle;
typedef struct CollisionPolygonGroup CollisionPolygonGroup;
typedef struct ModelVtxAnimChunk ModelVtxAnimChunk;
"""
FIXTURE = r"""
typedef struct Fixture {
    ModelFileHeader file;
    ModelDisplayListEntry displayLists[510];
    ModelMorphTargetRef morphTargets[255];
    _Alignas(16) u8 payload[8192];
} Fixture;
static Fixture actual, expected;
static int cases;

static void check(u32 mask, unsigned primaryCount, unsigned shadowCount, unsigned morphCount) {
    u32 offsets[21];
    u8* base = (u8*)&actual;
    ModelFileHeader* file = &actual.file;
    int hasJoints = !!(mask & (1u << 8));
    memset(&actual, 0xA5, sizeof(actual));
    /* The decoder starts each pointer union clear, then supplies its offset. */
    SET_OFFSETS
    if (offsets[18]) offsets[18] = offsetof(Fixture, displayLists);
    if (offsets[20]) offsets[20] = offsetof(Fixture, morphTargets);
    file->displayListsOffset = offsets[18];
    file->morphTargetsOffset = offsets[20];
    file->displayListCount = offsets[18] ? primaryCount : 0;
    file->shadowDisplayListCount = offsets[18] ? shadowCount : 0;
    file->morphTargetCount = offsets[20] ? morphCount : 0;
    for (unsigned i = 0; i < 510; i++) {
        actual.displayLists[i].dlist = NULL;
        actual.displayLists[i].dlistOffset = i % 3 ? offsetof(Fixture, payload) + i * 8 : 0;
        actual.displayLists[i].dlistSize = i * 73;
    }
    for (unsigned i = 0; i < 255; i++) {
        actual.morphTargets[i].stream = NULL;
        actual.morphTargets[i].offset = i % 3 ? offsetof(Fixture, payload) + i * 16 : 0;
    }
    memcpy(&expected, &actual, sizeof(actual));
    EXPECT_POINTERS
    for (unsigned i = 0; i < (unsigned)file->displayListCount + file->shadowDisplayListCount; i++) {
        expected.displayLists[i].dlist = base + actual.displayLists[i].dlistOffset;
    }
    for (unsigned i = 0; i < file->morphTargetCount; i++) {
        expected.morphTargets[i].stream = (u16*)(base + actual.morphTargets[i].offset);
    }
    ObjModel_RelocateModelData(file);
    /* Check the entire allocation: unrelated fields, trailing table entries,
       display-list sizes, padding and payload must also remain unchanged. */
    assert(memcmp(&actual, &expected, sizeof(actual)) == 0);
    assert((uintptr_t)file->vertices > UINT32_MAX);
    cases++;
}
int main(void) {
    const u32 all = (1u << 21) - 1;
    const unsigned counts[][3] = {{0, 0, 0}, {1, 0, 1}, {0, 3, 7}, {2, 3, 4}, {255, 255, 255}};
    u32 random = 0x80028fe8;
    assert(sizeof(void*) == 8 && (uintptr_t)&actual > UINT32_MAX);
    for (unsigned n = 0; n < sizeof(counts) / sizeof(counts[0]); n++) {
        check(0, counts[n][0], counts[n][1], counts[n][2]);
        check(all, counts[n][0], counts[n][1], counts[n][2]);
        for (unsigned bit = 0; bit < 21; bit++) {
            check(1u << bit, counts[n][0], counts[n][1], counts[n][2]);
            check(all ^ (1u << bit), counts[n][0], counts[n][1], counts[n][2]);
        }
    }
    for (unsigned i = 0; i < 512; i++) {
        random = random * 1664525u + 1013904223u;
        check(random & all, (random >> 24) & 255, (random >> 16) & 255, (random >> 8) & 255);
    }
    printf("%d native model relocation cases checked\n", cases);
    return 0;
}
"""


def harness():
    header = (ROOT / "include/main/model.h").read_text()
    parts = [PRELUDE]
    for kind, name in (
        ("struct", "ModelVtxAnimJob"), ("struct", "ModelFuzzScaleDef"),
        ("struct", "ModelExtraJointDef"), ("union", "ModelMorphTargetRef"),
        ("struct", "ModelFileHeader"), ("struct", "ModelDisplayListEntry"),
    ):
        parts.append(re.search(rf"typedef {kind} {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    source = (ROOT / "src/main/model.c").read_text()
    start, end = find_function_body(source, "ObjModel_RelocateModelData")
    declaration = source.rfind("void ObjModel_RelocateModelData", 0, start)
    parts.append(source[declaration:end + 1])
    setup, expected = [], []
    for index, field in enumerate(FIELDS):
        setup.extend([
            f"file->{field} = NULL;",
            f"offsets[{index}] = (mask & (1u << {index})) ? offsetof(Fixture, payload) + {index} * 64 : 0;",
            f"file->{field}Offset = offsets[{index}];",
        ])
        condition = "1" if field == "vertices" else f"offsets[{index}]"
        if field in JOINT_DEPENDENTS:
            condition += " && hasJoints"
        expected.append(f"if ({condition}) {{ expected.file.{field} = (void*)(base + offsets[{index}]); }}")
    parts.append(FIXTURE.replace("SET_OFFSETS", "\n    ".join(setup))
                 .replace("EXPECT_POINTERS", "\n    ".join(expected)))
    return "\n".join(parts)


class ModelRelocationTests(unittest.TestCase):
    def test_explicit_offset_to_pointer_transition(self):
        with tempfile.TemporaryDirectory(prefix="model-relocation-") as directory:
            source = Path(directory) / "relocation.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "relocation"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
