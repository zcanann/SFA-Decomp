#!/usr/bin/env python3
"""Exercise model loading and shader resolution with mixed retail texture references.

Records use native pointers; runtime texture tokens retain their target 32-bit
representation. Texture IO/cache resolution is stubbed, not a native texture port.
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
typedef struct Texture { int index; } Texture;
typedef struct ModelCollisionTriangle ModelCollisionTriangle;
typedef struct CollisionPolygonGroup CollisionPolygonGroup;
typedef struct ModelVtxAnimChunk ModelVtxAnimChunk;
"""
SERVICES = r"""
enum { MLDF_FILEID_MODELIND_BIN = 0x2c };
typedef struct Fixture {
    ModelFileHeader file;
    ModelTextureEntry entries[255];
    Shader shaders[3];
    u8 animations[16];
} Fixture;
static Fixture fixture;
static Texture resolved[4];
static const u32 references[4] = {1, 0x81234560u, 0xFFFFFFFCu, 0};
static s16 gModelResourceBuffer[4];
static int modelList, *gModelList = &modelList;
static int cached, loadCalls, lookupCalls, mapCalls, animationCalls, insertCalls, sizeCalls;
static int expectedId, expectedFlags, returnSize, resolutionCalls, lastReference;

static void fileLoadToBufferOffset(int file, void* output, int offset, int size) {
    assert(file == MLDF_FILEID_MODELIND_BIN && output == gModelResourceBuffer);
    assert(offset == 12 && size == 8);
    gModelResourceBuffer[0] = expectedId;
    mapCalls++;
}
static int ModelList_getHeader(void* list, int id, ModelFileHeader** output) {
    assert(list == gModelList && id == expectedId);
    assert((uintptr_t)output > UINT32_MAX);
    lookupCalls++;
    if (cached) *output = &fixture.file;
    return cached;
}
static void* ObjModel_LoadModelData(int id) {
    assert(id == expectedId && !cached && lookupCalls == 1);
    return &fixture.file;
}
static void* textureLoad(int asset, u8 useHandle) {
    int i = loadCalls++;
    assert(i < fixture.file.textureCount && asset == -((i * 13 + 7) | 0x8000));
    assert(useHandle == 1);
    return (void*)(uintptr_t)references[i % 4];
}
static void modelLoadAnimations(ModelFileHeader* file, int id, void* output) {
    assert(file == &fixture.file && id == expectedId && output == fixture.animations);
    assert(loadCalls == file->textureCount && !cached && !insertCalls);
    animationCalls++;
}
static void modelInitModelList(void* list, int id, ModelFileHeader** file) {
    assert(list == gModelList && id == expectedId && *file == &fixture.file);
    assert(animationCalls == 1 && !cached);
    insertCalls++;
}
static int modelLoad_calcSizes(ModelFileHeader* file, int flags, ModelInstanceSizes* sizes, int unused) {
    assert(file == &fixture.file && flags == expectedFlags && unused == 0);
    assert(cached || insertCalls == 1);
    memset(sizes, 0xA5, sizeof(*sizes));
    sizeCalls++;
    return returnSize;
}
static void* textureIdxToPtr(int reference) {
    lastReference = reference;
    resolutionCalls++;
    for (int i = 0; i < 4; i++) {
        if ((u32)reference == references[i]) return reference ? &resolved[i] : NULL;
    }
    assert(0 && "unexpected runtime texture reference");
    return NULL;
}
"""
CASES = r"""
static void checkShaders(void) {
    ModelTextureEntry entries[4];
    Shader shader, expected;
    ModelFileHeader file = {0};
    const int selectors[] = {-1, -2, 0, 1, -3, INT32_MIN, INT32_MAX};
    const unsigned flags[] = {0, 4, 8, 0xC, 0x200, 0x400, 0x800, 0xE00, 0xFFFF};
    file.textureEntries = entries;
    file.renderOps = &shader;
    file.renderOpCount = 1;
    for (int i = 0; i < 4; i++) entries[i].reference = (s32)references[i];
    for (unsigned f = 0; f < sizeof(flags) / sizeof(flags[0]); f++) {
        for (unsigned mode = 0; mode < sizeof(selectors) / sizeof(selectors[0]); mode++) {
            for (int index = -1; index < 4; index++) {
                for (int layers = 0; layers <= 2; layers++) {
                    memset(&shader, 0xA5, sizeof(shader));
                    shader.layerCount = layers;
                    shader.layers[0].textureIndex = index;
                    shader.layers[1].textureIndex = index;
                    shader.auxTextureIndex = index;
                    shader.indTextureId = index;
                    shader.textureId = index;
                    shader.unk1C = selectors[mode];
                    shader.reg1Texture = &resolved[0];
                    shader.reg2Texture = &resolved[1];
                    file.shaderFlags = flags[f];
                    memcpy(&expected, &shader, sizeof(shader));
                    for (int layer = 0; layer < layers; layer++) {
                        if (index == -1) expected.layers[layer].texture = NULL;
                        else expected.layers[layer].textureIndex = (s32)references[index];
                    }
                    if (index == -1) {
                        expected.auxTexture = NULL;
                        expected.indTexture = NULL;
                        expected.textureId = 0;
                    } else {
                        expected.auxTextureIndex = references[index];
                        expected.indTextureId = (s32)references[index];
                        expected.textureId = (s32)references[index];
                    }
                    expected.unk1C = selectors[mode] != -1 && selectors[mode] != -2;
                    if (!(flags[f] & 0xC)) expected.reg1Texture = NULL;
                    if (!(flags[f] & 0xE00)) expected.reg2Texture = NULL;
                    ObjModel_ResolveRenderOpTextures(&file);
                    assert(memcmp(&shader, &expected, sizeof(shader)) == 0);
                }
            }
        }
    }
}
static void checkLoad(int count, int hit, int indirect) {
    Fixture expected;
    ModelFileHeader* file = &fixture.file;
    int size = -1;
    memset(&fixture, 0, sizeof(fixture));
    file->textureCount = count;
    file->textureEntriesOffset = offsetof(Fixture, entries);
    file->renderOpsOffset = offsetof(Fixture, shaders);
    file->renderOpCount = count ? 3 : 0;
    file->dataSize = offsetof(Fixture, animations);
    file->refCount = hit ? 17 : 1;
    file->shaderFlags = 0xFFFF;
    for (int i = 0; i < count; i++) fixture.entries[i].assetId = i * 13 + 7;
    for (int i = 0; i < 3; i++) {
        fixture.shaders[i].layerCount = 2;
        fixture.shaders[i].auxTextureIndex = -1;
        fixture.shaders[i].indTextureId = -1;
        fixture.shaders[i].textureId = -1;
        fixture.shaders[i].unk1C = -2;
    }
    cached = hit;
    expectedId = 23;
    expectedFlags = 0x8000 + count;
    returnSize = 0x4567 + count;
    loadCalls = lookupCalls = mapCalls = animationCalls = insertCalls = sizeCalls = resolutionCalls = 0;
    if (hit) {
        ObjModel_RelocateModelData(file);
        for (int i = 0; i < count; i++) fixture.entries[i].loadResult = (void*)(uintptr_t)references[i % 4];
        ObjModel_ResolveRenderOpTextures(file);
    }
    memcpy(&expected, &fixture, sizeof(fixture));
    void* result = ObjModel_Load(indirect ? 6 : -expectedId, expectedFlags, &size);
    assert(result == file && size == returnSize);
    assert(lookupCalls == 1 && mapCalls == indirect && sizeCalls == 1);
    assert(loadCalls == (hit ? 0 : count) && animationCalls == !hit && insertCalls == !hit);
    assert(file->refCount == (hit ? 18 : 1));
    assert(file->textureEntries == fixture.entries && file->renderOps == fixture.shaders);
    if (hit) {
        expected.file.refCount++;
        assert(memcmp(&expected, &fixture, sizeof(fixture)) == 0);
    }
    for (int i = 0; i < count; i++) {
        assert((uintptr_t)fixture.entries[i].loadResult == references[i % 4]);
        Texture* texture = ObjModel_GetTexture(file, i);
        assert((u32)lastReference == references[i % 4]);
        assert(texture == (references[i % 4] ? &resolved[i % 4] : NULL));
    }
    if (count) {
        for (int i = 0; i < 3; i++) {
            assert((u32)fixture.shaders[i].layers[0].textureIndex == references[0]);
            assert((u32)fixture.shaders[i].layers[1].textureIndex == references[0]);
        }
    }
}
int main(void) {
    const int counts[] = {0, 1, 3, 8, 255};
    assert(sizeof(void*) == 8 && (uintptr_t)&fixture > UINT32_MAX);
    checkShaders();
    for (unsigned i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        for (int hit = 0; hit <= 1; hit++) {
            for (int indirect = 0; indirect <= 1; indirect++) checkLoad(counts[i], hit, indirect);
        }
    }
    puts("945 shader cases and 20 model load paths checked");
    return 0;
}
"""


def harness():
    header = (ROOT / "include/main/model.h").read_text()
    parts = [PRELUDE]
    for kind, name in (
        ("struct", "ShaderLayer"), ("struct", "Shader"), ("struct", "ModelVtxAnimJob"),
        ("struct", "ModelFuzzScaleDef"), ("struct", "ModelExtraJointDef"),
        ("union", "ModelTextureEntry"), ("union", "ModelMorphTargetRef"),
        ("struct", "ModelFileHeader"), ("struct", "ModelDisplayListEntry"),
    ):
        parts.append(re.search(rf"typedef {kind} {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    source = (ROOT / "src/main/model.c").read_text()
    parts.append(re.search(r"typedef struct ModelInstanceSizes\s*\{.*?\} ModelInstanceSizes;", source, re.S)[0])
    parts.append(SERVICES)
    for name in ("ObjModel_RelocateModelData", "ObjModel_ResolveRenderOpTextures", "ObjModel_Load", "ObjModel_GetTexture"):
        start, end = find_function_body(source, name)
        declaration = source.rfind("\n", 0, source.rfind(name, 0, start)) + 1
        parts.append(source[declaration:end + 1])
    return "\n".join(parts + [CASES])


class ModelTextureReferenceTests(unittest.TestCase):
    def test_model_loading_and_shader_references(self):
        with tempfile.TemporaryDirectory(prefix="model-texture-refs-") as directory:
            source = Path(directory) / "textures.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "textures"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
