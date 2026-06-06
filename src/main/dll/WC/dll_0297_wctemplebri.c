#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define WCTEMPLEBRI_EXTRA_SIZE 0x68
#define WCTEMPLEBRI_RENDER_TYPE_BASE 0x400
#define WCTEMPLEBRI_RENDER_TYPE_SHIFT 0xb

#define WCTEMPLEBRI_SETUP_TYPE_OFFSET 0x18
#define WCTEMPLEBRI_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCTEMPLEBRI_SETUP_SOLVED_BIT_OFFSET 0x1e

#define WCTEMPLEBRI_STATE_MAX_Y 0x00
#define WCTEMPLEBRI_STATE_SORTED_OFFSETS 0x04
#define WCTEMPLEBRI_STATE_PART_FLAGS 0x40
#define WCTEMPLEBRI_STATE_PART_COUNT 0x4f
#define WCTEMPLEBRI_STATE_PART_ALPHA 0x50
#define WCTEMPLEBRI_STATE_ACTIVE 0x5f
#define WCTEMPLEBRI_STATE_WAVE_PHASE_A 0x60
#define WCTEMPLEBRI_STATE_WAVE_PHASE_B 0x62
#define WCTEMPLEBRI_STATE_FLAGS 0x66

#define WCTEMPLEBRI_FLAG_SOLVED 1
#define WCTEMPLEBRI_GLOBAL_ACTIVE_BIT 0xedb

#define WCTEMPLEBRI_PAYLOAD_TRIGGER_OFFSET 0x80
#define WCTEMPLEBRI_PAYLOAD_TRIGGER 1
#define WCTEMPLEBRI_PAYLOAD_SUPPRESS_OFFSET 0x56
#define WCTEMPLEBRI_PAYLOAD_FLAGS_A 0x70
#define WCTEMPLEBRI_PAYLOAD_FLAGS_B 0x6e
#define WCTEMPLEBRI_PAYLOAD_BLOCK_FLAG 0x20

#define WCTEMPLEBRI_ALPHA_OPAQUE 0xff
#define WCTEMPLEBRI_WARP_WRAP 0x2710
#define WCTEMPLEBRI_UV0_V_STEP 0x14
#define WCTEMPLEBRI_UV0_U_STEP 0xa
#define WCTEMPLEBRI_UV1_V_STEP 0x1e
#define WCTEMPLEBRI_WAVE_A_STEP_SHIFT 8
#define WCTEMPLEBRI_WAVE_B_STEP_SHIFT 7
#define WCTEMPLEBRI_WAVE_WRAP 0xffff

#define WCTEMPLEBRI_STATE_MAX_Y_VALUE(state) (*(f32 *)((state) + WCTEMPLEBRI_STATE_MAX_Y))
#define WCTEMPLEBRI_PART_COUNT(state) (*(u8 *)((state) + WCTEMPLEBRI_STATE_PART_COUNT))
#define WCTEMPLEBRI_ACTIVE(state) (*(u8 *)((state) + WCTEMPLEBRI_STATE_ACTIVE))
#define WCTEMPLEBRI_WAVE_PHASE_A(state) (*(u16 *)((state) + WCTEMPLEBRI_STATE_WAVE_PHASE_A))
#define WCTEMPLEBRI_WAVE_PHASE_B(state) (*(u16 *)((state) + WCTEMPLEBRI_STATE_WAVE_PHASE_B))
#define WCTEMPLEBRI_FLAGS(state) (*(u8 *)((state) + WCTEMPLEBRI_STATE_FLAGS))

#pragma scheduling off
void wctemplebri_updateModelWarp(int obj, int p2)
{
    int tex;
    int v;

    tex = (int)objFindTexture(obj, 0, 0);
    *(s16 *)(tex + 0xa) += WCTEMPLEBRI_UV0_V_STEP;
    if (*(s16 *)(tex + 0xa) > WCTEMPLEBRI_WARP_WRAP) *(s16 *)(tex + 0xa) -= WCTEMPLEBRI_WARP_WRAP;
    *(s16 *)(tex + 8) += WCTEMPLEBRI_UV0_U_STEP;
    if (*(s16 *)(tex + 8) > WCTEMPLEBRI_WARP_WRAP) *(s16 *)(tex + 8) -= WCTEMPLEBRI_WARP_WRAP;
    tex = (int)objFindTexture(obj, 1, 0);
    *(s16 *)(tex + 0xa) += WCTEMPLEBRI_UV1_V_STEP;
    if (*(s16 *)(tex + 0xa) > WCTEMPLEBRI_WARP_WRAP) *(s16 *)(tex + 0xa) -= WCTEMPLEBRI_WARP_WRAP;
    v = WCTEMPLEBRI_WAVE_PHASE_A(p2) + (framesThisStep << WCTEMPLEBRI_WAVE_A_STEP_SHIFT);
    if (v > WCTEMPLEBRI_WAVE_WRAP) v -= WCTEMPLEBRI_WAVE_WRAP;
    WCTEMPLEBRI_WAVE_PHASE_A(p2) = (u16)v;
    v = WCTEMPLEBRI_WAVE_PHASE_B(p2) + (framesThisStep << WCTEMPLEBRI_WAVE_B_STEP_SHIFT);
    if (v > WCTEMPLEBRI_WAVE_WRAP) v -= WCTEMPLEBRI_WAVE_WRAP;
    WCTEMPLEBRI_WAVE_PHASE_B(p2) = (u16)v;
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
int wctemplebri_interactCallback(int obj, int p2, int p3)
{
    int r4c = *(int *)&((GameObject *)obj)->anim.placementData;
    int state = *(int *)&((GameObject *)obj)->extra;
    int model;
    int modelBase;
    int i;

    *(s8 *)(p3 + WCTEMPLEBRI_PAYLOAD_SUPPRESS_OFFSET) = 0;
    *(s16 *)(p3 + WCTEMPLEBRI_PAYLOAD_FLAGS_A) &= ~WCTEMPLEBRI_PAYLOAD_BLOCK_FLAG;
    *(s16 *)(p3 + WCTEMPLEBRI_PAYLOAD_FLAGS_B) &= ~WCTEMPLEBRI_PAYLOAD_BLOCK_FLAG;
    wctemplebri_updateModelWarp(obj, state);
    if (*(u8 *)(p3 + WCTEMPLEBRI_PAYLOAD_TRIGGER_OFFSET) == WCTEMPLEBRI_PAYLOAD_TRIGGER) {
        WCTEMPLEBRI_ACTIVE(state) = 1;
    }
    if (WCTEMPLEBRI_ACTIVE(state) != 0) {
        if ((WCTEMPLEBRI_FLAGS(state) & WCTEMPLEBRI_FLAG_SOLVED) == 0) {
            WCTEMPLEBRI_FLAGS(state) |= WCTEMPLEBRI_FLAG_SOLVED;
            GameBit_Set(*(s16 *)(r4c + WCTEMPLEBRI_SETUP_SOLVED_BIT_OFFSET), 1);
        }
        {
            int a = (int)((f32)(u32) * (u8 *)(obj + 0x36) + timeDelta);
            if (a < 0)
                a = 0;
            else if (a > WCTEMPLEBRI_ALPHA_OPAQUE)
                a = WCTEMPLEBRI_ALPHA_OPAQUE;
            *(u8 *)(obj + 0x36) = a;
        }
    }
    model = Obj_GetActiveModel(obj);
    modelBase = *(int *)model;
    for (i = 0; i < *(u16 *)(modelBase + 0xe4); i++) {
        int curr = ObjModel_GetCurrentVertexCoords(model, i);
        int base = ObjModel_GetBaseVertexCoords(modelBase, i);
        int idx = (u16)(int)(lbl_803E6E70 * ((f32)*(s16 *)(curr + 4) / WCTEMPLEBRI_STATE_MAX_Y_VALUE(state))) +
                  WCTEMPLEBRI_WAVE_PHASE_A(state);
        if (*(s16 *)(base + 0) > 0)
            *(s16 *)(curr + 0) =
                (int)(lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C) +
                      (f32)*(s16 *)(base + 0));
        else
            *(s16 *)(curr + 0) =
                (int)((f32)*(s16 *)(base + 0) -
                      lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C));
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wctemplebri_getExtraSize(void) { return WCTEMPLEBRI_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wctemplebri_getObjectTypeId(int obj)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    int modelIndex = *(s8 *)(*(int *)&((GameObject *)obj)->anim.placementData + WCTEMPLEBRI_SETUP_MODEL_INDEX_OFFSET);
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << WCTEMPLEBRI_RENDER_TYPE_SHIFT) | WCTEMPLEBRI_RENDER_TYPE_BASE;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemplebri_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctemplebri_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)&((GameObject *)obj)->extra;

    if (visible != 0) {
        if (WCTEMPLEBRI_ACTIVE(state) != 0) {
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E90);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemplebri_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemplebri_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemplebri_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctemplebri_update(int obj)
{
    int r4c = *(int *)&((GameObject *)obj)->anim.placementData;
    int state;
    int model;
    int modelBase;
    int i;

    Obj_GetPlayerObject();
    state = *(int *)&((GameObject *)obj)->extra;
    wctemplebri_updateModelWarp(obj, state);
    model = Obj_GetActiveModel(obj);
    modelBase = *(int *)model;
    for (i = 0; i < *(u16 *)(modelBase + 0xe4); i++) {
        int curr = ObjModel_GetCurrentVertexCoords(model, i);
        int base = ObjModel_GetBaseVertexCoords(modelBase, i);
        int idx = (u16)(int)(lbl_803E6E70 * ((f32)*(s16 *)(curr + 4) / WCTEMPLEBRI_STATE_MAX_Y_VALUE(state))) +
                  WCTEMPLEBRI_WAVE_PHASE_A(state);
        if (*(s16 *)(base + 0) > 0)
            *(s16 *)(curr + 0) =
                (int)(lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C) +
                      (f32)*(s16 *)(base + 0));
        else
            *(s16 *)(curr + 0) =
                (int)((f32)*(s16 *)(base + 0) -
                      lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C));
    }
    if (WCTEMPLEBRI_ACTIVE(state) != 0) {
        if ((WCTEMPLEBRI_FLAGS(state) & WCTEMPLEBRI_FLAG_SOLVED) == 0) {
            GameBit_Set(WCTEMPLEBRI_GLOBAL_ACTIVE_BIT, 1);
            WCTEMPLEBRI_FLAGS(state) |= WCTEMPLEBRI_FLAG_SOLVED;
            GameBit_Set(*(s16 *)(r4c + WCTEMPLEBRI_SETUP_SOLVED_BIT_OFFSET), 1);
        }
        {
            int a = (int)((f32)(u32) * (u8 *)(obj + 0x36) + timeDelta);
            if (a < 0)
                a = 0;
            else if (a > WCTEMPLEBRI_ALPHA_OPAQUE)
                a = WCTEMPLEBRI_ALPHA_OPAQUE;
            *(u8 *)(obj + 0x36) = a;
        }
        ObjHits_EnableObject(obj);
    } else {
        GameBit_Set(WCTEMPLEBRI_GLOBAL_ACTIVE_BIT, 0);
        ObjHits_DisableObject(obj);
    }
    if ((void *)Obj_GetPlayerObject() != NULL) {
        if (PSVECDistance((void *)(obj + 0x18), (void *)(Obj_GetPlayerObject() + 0x18)) >
            lbl_803E6E94) {
            GameBit_Set(WCTEMPLEBRI_GLOBAL_ACTIVE_BIT, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctemplebri_init(int obj, int initData)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    int state;
    int model;
    int i;
    int maxY;
    int modelData;
    int p, k;
    int done;

    ((GameObject *)obj)->anim.rotX = (s16)((s8)*(u8 *)(initData + WCTEMPLEBRI_SETUP_TYPE_OFFSET) << 8);
    objAnim->bankIndex = *(u8 *)(initData + WCTEMPLEBRI_SETUP_MODEL_INDEX_OFFSET);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
        objAnim->bankIndex = 0;
    ((GameObject *)obj)->unkBC = (void *)wctemplebri_interactCallback;
    state = *(int *)&((GameObject *)obj)->extra;
    maxY = 0;
    model = Obj_GetActiveModel(obj);
    modelData = *(int *)(model + 0);
    for (i = 0; i < *(u16 *)(modelData + 0xe4); i++) {
        int y = *(s16 *)(ObjModel_GetCurrentVertexCoords(model, i) + 4);
        if (y < maxY)
            maxY = y;
    }
    done = 0;
    while (done == 0) {
        done = 1;
        for (k = 0, p = state; k < WCTEMPLEBRI_PART_COUNT(state) - 1; k++) {
            f32 a = *(f32 *)(p + 4);
            f32 b = *(f32 *)(p + 8);
            if (a < b) {
                *(f32 *)(p + 4) = b;
                *(f32 *)(p + 8) = (f32)(int)a;
                done = 0;
            }
            p += 4;
        }
    }
    WCTEMPLEBRI_PART_COUNT(state) = 0xa;
    WCTEMPLEBRI_STATE_MAX_Y_VALUE(state) = (f32)maxY;
    if ((u32)GameBit_Get(*(s16 *)(initData + WCTEMPLEBRI_SETUP_SOLVED_BIT_OFFSET)) != 0) {
        WCTEMPLEBRI_ACTIVE(state) = 1;
        WCTEMPLEBRI_FLAGS(state) |= WCTEMPLEBRI_FLAG_SOLVED;
    }
    if (WCTEMPLEBRI_ACTIVE(state) != 0) {
        for (k = 0; k < WCTEMPLEBRI_PART_COUNT(state); k++) {
            *(u8 *)(state + k + WCTEMPLEBRI_STATE_PART_ALPHA) = WCTEMPLEBRI_ALPHA_OPAQUE;
            *(u8 *)(state + k + WCTEMPLEBRI_STATE_PART_FLAGS) = 1;
        }
        *(u8 *)(obj + 0x36) = WCTEMPLEBRI_ALPHA_OPAQUE;
    } else {
        ObjHits_DisableObject(obj);
        *(u8 *)(obj + 0x36) = 0;
    }
    ((GameObject *)obj)->unkB0 |= 0x6000;
    ObjModel_SetPostRenderCallback(model, postRenderSetAlphaBlendState);
}
#pragma scheduling reset
#pragma peephole reset
