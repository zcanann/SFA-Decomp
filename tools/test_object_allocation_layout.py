#!/usr/bin/env python3
"""Run the production object allocation tail, size calculator and arena helpers.

Owned record types and C bodies come from the game. GameObject and DLL fixtures
expose only the fields used here; asset loading, textures and collision updates
are spies. Host cases use 8-byte-aligned DLL state sizes so the target's 4-byte
alignment also accommodates native pointer fields. Retail layouts and the full
loadCharacter function are verified separately by matching builds.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float f32;
typedef struct Vec3f { f32 x, y, z; } Vec3f;
typedef struct Texture Texture;
typedef struct ProjectedShadowTexture ProjectedShadowTexture;
typedef struct ObjectShadowMesh ObjectShadowMesh;
typedef struct ObjJointBinding ObjJointBinding;
typedef struct ObjHitReactEntry ObjHitReactEntry;
typedef s16 ObjAnimPackedEvent;
typedef struct ObjModel { int marker; } ObjModel;
typedef ObjModel ObjAnimBank;
typedef struct PlayerState { u8 bytes[0x8e0]; } PlayerState;
#define OBJHITBOX_CONTACT_OBJECT_COUNT 3
#define OBJHITS_PRIORITY_HIT_COUNT 3
"""
FIXTURE = r"""
typedef struct ObjectInterface { int (*getExtraSize)(void*, size_t); } ObjectInterface;
typedef struct ObjAnimComponent {
    ObjDef* modelInstance;
    ObjModel** modelBanks;
    ObjectInterface** dll;
    ObjModelState* modelState;
    ObjHitReactState* hitReactState;
    ObjHitboxTransformState* hitboxTransformState;
    ObjAnimEventTable* eventTable;
    ObjWeaponDaTable* weaponDaTable;
    u8* jointPoseData;
    ObjTextureRuntimeSlot* textureSlots;
    ObjHitVolumeRuntimeTransform* hitVolumeTransforms;
    ObjHitVolumeRuntimeBounds* hitVolumeBounds;
    struct GameObject* parent;
    s16 romDefNo;
} ObjAnimComponent;
typedef struct GameObject { ObjAnimComponent anim; void* extra; } GameObject;
static int extraSize, extraCalls, cullCalls, eventCalls, hitCalls, rotatedCalls, reactionCalls;
static int gShadowVolumesDirty;
static f32 gShadowOffsetX = 12, gShadowOffsetY = -13, gShadowOffsetZ = 14;
static int textureSentinels[3];
static void* textureLoad(int id, int flags) {
    assert(id == -23 && flags == 0);
    return &textureSentinels[0];
}
static void* newshadows_allocTexture512(void) { return &textureSentinels[1]; }
static void* newshadows_getSmallDiskTexture(void) { return &textureSentinels[2]; }
static int extraCallback(void* object, size_t position) {
    GameObject* typed = object;
    size_t tableBytes = typed->anim.modelInstance->modelCount * sizeof(ObjModel*);
    size_t expected = extraCalls == 0 ? sizeof(GameObject) + tableBytes :
        (size_t)typed->anim.modelBanks + tableBytes;
    assert(position == expected);
    extraCalls++;
    return extraSize;
}
static void objInitCullScale(GameObject* object) { assert(object); cullCalls++; }
static void ObjHits_RefreshObjectState(GameObject* object) {
    assert(object->anim.hitReactState);
    ((ObjHitsPriorityState*)object->anim.hitReactState)->shapeFlags =
        object->anim.modelInstance->primaryHitboxShapeFlags;
    hitCalls++;
}
static void ObjHitbox_UpdateRotatedBounds(ObjAnimComponent* object, int initialize) {
    ObjHitboxTransformState* state = object->hitboxTransformState;
    assert(initialize == 1 && state->contactObjectCount == 0);
    assert(state->resetFrames == OBJHITBOX_ROTATED_BOUNDS_RESET_FRAMES);
    state->activeMatrixIndex ^= 1;
    rotatedCalls++;
}
static void ObjHitReact_LoadMoveEntries(ObjAnimComponent* object, ObjAnimBank* bank,
        int type, ObjHitReactState* state, int move, int async) {
    assert(bank == object->modelBanks[0] && type == object->romDefNo);
    assert(state == object->hitReactState && state->entries && move == 0 && async == 1);
    assert(state->entryBufferByteCapacity == 300);
    memset(state->entries, 0x5a, 300);
    reactionCalls++;
}
static void ObjAnim_LoadMoveEvents(u8* raw, int type, ObjAnimEventTable* table, int move, int sync) {
    GameObject* object = (GameObject*)raw;
    assert(type == object->anim.romDefNo && table == object->anim.eventTable);
    assert(move == 0 && sync == 1 && table->entries);
    memset(table->entries, 0x3c, 80);
    eventCalls++;
}
"""
CASES = r"""
static size_t take(size_t* cursor, size_t bytes, size_t alignment) {
    size_t start = (*cursor + alignment - 1) & ~(alignment - 1);
    *cursor = start + bytes;
    return start;
}
static void expect(void* actual, u8* base, size_t* cursor, size_t bytes, size_t alignment) {
    assert(actual == base + take(cursor, bytes, alignment));
}
static void check(int mask, int variation, int extraMode) {
    const int counts[] = {0, 1, 3, 8};
    ObjDef definition = {0};
    ObjDefHitVolume volumes[8];
    ObjModel bank = {1};
    ObjectInterface interface = {extraCallback};
    ObjectInterface* table = &interface;
    GameObject template = {0}, parent = {0};
    definition.modelCount = 1 + variation % 3;
    definition.shadowType = variation;
    definition.shadowTextureId = -1;
    definition.shadowScaleBase = 2;
    definition.shadowModelScaleBase = 3;
    definition.renderFlags = mask & 4 ? OBJDEF_RENDERFLAG_PROJECTED_SHADOW : 2;
    definition.flags = mask & 2 ? OBJDEF_FLAG_HAS_EVENT : 0;
    definition.hitboxStateCount = !!(mask & 16);
    definition.primaryHitboxShapeFlags = mask & 32 ? 0x38 : 0;
    definition.hitReactStateCount = !!(mask & 64);
    definition.jointBindingCount = counts[variation];
    definition.textureSlotCount = counts[(variation + 1) % 4];
    definition.hitVolumeCount = counts[(variation + 2) % 4];
    definition.hitVolumes = volumes;
    for (int i = 0; i < 8; i++) {
        volumes[i].flags = 0x80 + i;
        for (int j = 0; j < 4; j++) volumes[i].bounds[j] = i * 4 + j;
    }
    int flags = (mask & 1 ? OBJLOAD_FLAG_ANIM_EVENTS : 0) |
        (mask & 4 ? OBJLOAD_FLAG_WEAPON_DA : 0) | (mask & 8 ? OBJLOAD_FLAG_HAS_SHADOW : 0);
    extraSize = extraMode == 1 ? 8 : extraMode == 2 ? 24 : 0;
    extraCalls = cullCalls = eventCalls = hitCalls = rotatedCalls = reactionCalls = 0;
    template.anim.modelInstance = &definition;
    template.anim.romDefNo = extraMode == 3 ? 0 : extraMode == 4 ? 0x1f : 7;
    template.anim.dll = extraMode ? &table : NULL;
    size_t capacity = objGetTotalDataSize(&template, &definition, NULL, flags);
    assert((capacity & 31) == 0);
    u8* arena = aligned_alloc(32, capacity + 32);
    assert(arena && (uintptr_t)arena > UINT32_MAX);
    memset(arena, 0, capacity);
    memset(arena + capacity, 0xab, 32);
    GameObject* object = (GameObject*)arena;
    *object = template;
    object->anim.modelBanks = (ObjModel**)(object + 1);
    object->anim.modelBanks[0] = mask & 128 ? NULL : &bank;
    layout(object, flags, &parent);
    assert(object->anim.parent == &parent && cullCalls == 1);
    assert(extraCalls == (extraMode == 1 || extraMode == 2 ? 2 : 0));
    size_t cursor = sizeof(GameObject) + definition.modelCount * sizeof(ObjModel*);
    int stateSize = extraMode >= 3 ? sizeof(PlayerState) : extraSize;
    if (stateSize) expect(object->extra, arena, &cursor, stateSize, 4);
    else assert(object->extra == NULL);
    if (mask & 3) {
        expect(object->anim.eventTable, arena, &cursor, sizeof(ObjAnimEventTable), 4);
        expect(object->anim.eventTable->entries, arena, &cursor, 80, 8);
        assert(((u8*)object->anim.eventTable->entries)[79] == 0x3c);
    } else assert(object->anim.eventTable == NULL);
    assert(eventCalls == !!(mask & 3));
    if ((mask & 4) && !(mask & 128)) {
        expect(object->anim.weaponDaTable, arena, &cursor, sizeof(ObjWeaponDaTable), 4);
        expect(object->anim.weaponDaTable->entries, arena, &cursor, 2048, 8);
    } else assert(object->anim.weaponDaTable == NULL);
    if ((mask & 8) && variation) {
        expect(object->anim.modelState, arena, &cursor, sizeof(ObjModelState), 4);
        assert(object->anim.modelState->shadowScale == 2);
        assert(object->anim.modelState->shadowModelScale == 3);
        assert(object->anim.modelState->shadowOffsetX == 12);
        assert(object->anim.modelState->shadowOffsetY == -13);
        assert(object->anim.modelState->shadowOffsetZ == 14);
    } else assert(object->anim.modelState == NULL);
    if (mask & 16) {
        expect(object->anim.hitReactState, arena, &cursor, sizeof(ObjHitsPriorityState), 4);
        ObjHitsPriorityState* state = (ObjHitsPriorityState*)object->anim.hitReactState;
        assert(state->activeHitboxMode == 1);
        assert(state->resetHitboxMode == (mask & 32 ? 2 : 0));
        if (mask & 32) {
            expect(object->anim.hitboxTransformState, arena, &cursor, sizeof(ObjHitboxTransformState), 4);
            assert(object->anim.hitboxTransformState->activeMatrixIndex == 0);
        }
    } else assert(object->anim.hitReactState == NULL);
    assert(hitCalls == !!(mask & 16));
    assert(rotatedCalls == ((mask & 48) == 48 ? 2 : 0));
    if (definition.jointBindingCount)
        expect(object->anim.jointPoseData, arena, &cursor, definition.jointBindingCount * sizeof(ObjJointPose), 4);
    else assert(object->anim.jointPoseData == NULL);
    if (definition.textureSlotCount)
        expect(object->anim.textureSlots, arena, &cursor, definition.textureSlotCount * sizeof(ObjTextureRuntimeSlot), 4);
    if (definition.hitVolumeCount)
        expect(object->anim.hitVolumeTransforms, arena, &cursor, definition.hitVolumeCount * sizeof(ObjHitVolumeRuntimeTransform), 4);
    if ((mask & 80) == 80 && !(mask & 128)) {
        expect(object->anim.hitReactState->entries, arena, &cursor, 300, 8);
        assert(((u8*)object->anim.hitReactState->entries)[299] == 0x5a);
        assert(reactionCalls == 1);
    } else assert(reactionCalls == 0);
    if (definition.hitVolumeCount) {
        expect(object->anim.hitVolumeBounds, arena, &cursor, definition.hitVolumeCount * sizeof(ObjHitVolumeRuntimeBounds), 4);
        for (int i = 0; i < definition.hitVolumeCount; i++) {
            assert(object->anim.hitVolumeBounds[i].flags == volumes[i].flags);
            assert(memcmp(object->anim.hitVolumeBounds[i].bounds, volumes[i].bounds, 4) == 0);
        }
    }
    assert(cursor <= capacity);
    for (int i = 0; i < 32; i++) assert(arena[capacity + i] == 0xab);
    free(arena);
}
int main(void) {
    size_t (*aligners[])(size_t) = {alignUp2, roundUpTo4, roundUpTo8, roundUpTo16, roundUpTo32};
    const size_t bases[] = {0, UINT32_MAX - 64, (size_t)UINT32_MAX + 1, SIZE_MAX - 64};
    for (int f = 0; f < 5; f++) for (int b = 0; b < 4; b++) for (int offset = 0; offset < 64; offset++) {
        size_t value = bases[b] + offset, mask = ((size_t)2 << f) - 1;
        assert(aligners[f](value) == ((value + mask) & ~mask));
    }
    for (int mask = 0; mask < 256; mask++) for (int v = 0; v < 4; v++)
        for (int extra = 0; extra < 5; extra++) check(mask, v, extra);
    puts("5120 allocation layouts and 1280 alignment cases checked");
    return 0;
}
"""


def function(source, name):
    start, end = find_function_body(source, name)
    declaration = source.rfind("\n", 0, source.rfind(name, 0, start)) + 1
    return source[declaration:end + 1]


def harness():
    read = lambda name: (ROOT / name).read_text()
    anim = read("include/main/objanim_internal.h")
    hit_types = read("include/main/objhits_types.h")
    reaction = read("include/main/objHitReact_types.h")
    source = read("src/main/object.c")
    parts = [PRELUDE]
    for text, names in (
        (reaction, ("ObjHitReactMoveEntry", "ObjHitReactState")),
        (anim, ("ObjDefHitVolume", "ObjHitVolumeRuntimeTransform", "ObjHitVolumeRuntimeBounds",
                "ObjTextureSlotDef", "ObjAttachPoint", "ObjTextureRuntimeSlot", "ObjDef",
                "ObjModelState", "ObjAnimEventTable", "ObjWeaponDaTable")),
        (hit_types, ("ObjHitsPriorityState", "ObjHitboxTransformState")),
        (read("include/main/joint_pose.h"), ("ObjJointPose",)),
    ):
        for name in names:
            parts.append(re.search(rf"typedef struct {name}\s*\{{.*?\}} {name};", text, re.S)[0])
    parts.append("typedef ObjDef ObjModelInstance;")
    for text in (anim, reaction, read("include/main/objhits.h"), source):
        for name in (
            "OBJECT_SHADOW_MESH_UNCACHED", "OBJ_MODEL_STATE_SHADOW_VISIBLE",
            "OBJDEF_RENDERFLAG_PROJECTED_SHADOW", "OBJDEF_FLAG_HAS_EVENT",
            "OBJHITBOX_ROTATED_BOUNDS_RESET_FRAMES", "OBJHITS_SHAPE_RESET_MODE_MASK",
            "OBJHITS_ACTIVE_HITBOX_MODE", "OBJHITS_RESET_HITBOX_MODE",
            "OBJHITREACT_ENTRY_ARENA_BYTES", "OBJHITREACT_ACTIVE_HITBOX_MODE",
            "OBJHITREACT_RESET_HITBOX_MODE", "OBJECT_SEQID_SABRE", "OBJECT_SEQID_KRYSTAL",
            "OBJLOAD_FLAG_ANIM_EVENTS", "OBJLOAD_FLAG_WEAPON_DA", "OBJLOAD_FLAG_HAS_SHADOW",
        ):
            match = re.search(rf"^#define {name}\s+[^\n]+", text, re.M)
            if match:
                parts.append(match[0])
            else:
                match = re.search(rf"\b{name}\s*=\s*([^,\n}}]+)", text)
                if match:
                    parts.append(f"enum {{ {name} = {match[1]} }};")
    parts.append(re.search(r"enum ObjShadowType \{.*?\};", anim, re.S)[0])
    for name in ("OBJ_MOVE_EVENT_BUFFER_BYTES", "OBJ_WEAPON_DA_BUFFER_BYTES"):
        value = re.search(rf"\b{name}\s*=\s*([^,\n}}]+)", source)[1]
        parts.append(f"enum {{ {name} = {value} }};")
    parts.append(FIXTURE)
    for name in ("alignUp2", "roundUpTo4", "roundUpTo8", "roundUpTo16", "roundUpTo32"):
        parts.append(function(read("src/main/mm.c"), name))
    for name in ("ObjHits_AllocObjectState", "ObjHitbox_AllocRotatedBounds", "ObjHitReact_InitState"):
        parts.append(function(read("src/main/objhits.c"), name))
    parts.append(function(read("src/main/shadow_dolphin.c"), "shadowInit"))
    parts.append(function(source, "objGetTotalDataSize"))
    body = function(source, "loadCharacter")
    tail = body[body.index("    cursor = roundUpTo4("):body.rindex("    return obj;")]
    prefix = body[:body.index("    seq = data->objectId;")]
    declarations = [re.search(rf"^    [^;\n]*\b{name}\b[^;\n]*;", prefix, re.M)[0]
                    for name in ("cursor", "base", "alignedCursor", "dllStateSize", "j", "getExtraSize", "seq2")]
    parts.append("static void layout(GameObject* obj, int loadFlags, GameObject* parent) {\n"
                 "    ObjDef* modelDef = obj->anim.modelInstance;\n" +
                 "\n".join(declarations) + "\n" + tail + "}")
    return "\n".join(parts + [CASES])


class ObjectAllocationLayoutTests(unittest.TestCase):
    def test_layout_and_native_arena_contract(self):
        with tempfile.TemporaryDirectory(prefix="object-allocation-layout-") as directory:
            source = Path(directory) / "layout.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "layout"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-fsanitize=address,undefined",
                        str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1"})


if __name__ == "__main__":
    unittest.main()
