#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling off
void wctemplebri_updateModelWarp(int obj, int p2)
{
    int tex;
    int v;

    tex = (int)objFindTexture(obj, 0, 0);
    *(s16 *)(tex + 0xa) += 0x14;
    if (*(s16 *)(tex + 0xa) > 0x2710) *(s16 *)(tex + 0xa) -= 0x2710;
    *(s16 *)(tex + 8) += 0xa;
    if (*(s16 *)(tex + 8) > 0x2710) *(s16 *)(tex + 8) -= 0x2710;
    tex = (int)objFindTexture(obj, 1, 0);
    *(s16 *)(tex + 0xa) += 0x1e;
    if (*(s16 *)(tex + 0xa) > 0x2710) *(s16 *)(tex + 0xa) -= 0x2710;
    v = *(u16 *)(p2 + 0x60) + (framesThisStep << 8);
    if (v > 0xffff) v -= 0xffff;
    *(u16 *)(p2 + 0x60) = (u16)v;
    v = *(u16 *)(p2 + 0x62) + (framesThisStep << 7);
    if (v > 0xffff) v -= 0xffff;
    *(u16 *)(p2 + 0x62) = (u16)v;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wctemplebri_getExtraSize(void) { return 0x68; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wctemplebri_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
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
    int state = *(int *)(obj + 0xb8);

    if (visible != 0) {
        if (*(u8 *)(state + 0x5f) != 0) {
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
int wctemplebri_interactCallback(int obj, int p2, int p3)
{
    int r4c = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int model;
    int modelBase;
    int i;

    *(s8 *)(p3 + 0x56) = 0;
    *(s16 *)(p3 + 0x70) &= ~0x20;
    *(s16 *)(p3 + 0x6e) &= ~0x20;
    wctemplebri_updateModelWarp(obj, state);
    if (*(u8 *)(p3 + 0x80) == 1) {
        *(s8 *)(state + 0x5f) = 1;
    }
    if (*(u8 *)(state + 0x5f) != 0) {
        if ((*(u8 *)(state + 0x66) & 1) == 0) {
            *(u8 *)(state + 0x66) |= 1;
            GameBit_Set(*(s16 *)(r4c + 0x1e), 1);
        }
        {
            int a = (int)((f32)(u32) * (u8 *)(obj + 0x36) + timeDelta);
            if (a < 0)
                a = 0;
            else if (a > 0xff)
                a = 0xff;
            *(u8 *)(obj + 0x36) = a;
        }
    }
    model = Obj_GetActiveModel(obj);
    modelBase = *(int *)model;
    for (i = 0; i < *(u16 *)(modelBase + 0xe4); i++) {
        int curr = ObjModel_GetCurrentVertexCoords(model, i);
        int base = ObjModel_GetBaseVertexCoords(modelBase, i);
        int idx = (u16)(int)(lbl_803E6E70 * ((f32)*(s16 *)(curr + 4) / *(f32 *)state)) +
                  *(u16 *)(state + 0x60);
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

#pragma peephole off
#pragma scheduling off
void wctemplebri_update(int obj)
{
    int r4c = *(int *)(obj + 0x4c);
    int state;
    int model;
    int modelBase;
    int i;

    Obj_GetPlayerObject();
    state = *(int *)(obj + 0xb8);
    wctemplebri_updateModelWarp(obj, state);
    model = Obj_GetActiveModel(obj);
    modelBase = *(int *)model;
    for (i = 0; i < *(u16 *)(modelBase + 0xe4); i++) {
        int curr = ObjModel_GetCurrentVertexCoords(model, i);
        int base = ObjModel_GetBaseVertexCoords(modelBase, i);
        int idx = (u16)(int)(lbl_803E6E70 * ((f32)*(s16 *)(curr + 4) / *(f32 *)state)) +
                  *(u16 *)(state + 0x60);
        if (*(s16 *)(base + 0) > 0)
            *(s16 *)(curr + 0) =
                (int)(lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C) +
                      (f32)*(s16 *)(base + 0));
        else
            *(s16 *)(curr + 0) =
                (int)((f32)*(s16 *)(base + 0) -
                      lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C));
    }
    if (*(u8 *)(state + 0x5f) != 0) {
        if ((*(u8 *)(state + 0x66) & 1) == 0) {
            GameBit_Set(0xedb, 1);
            *(u8 *)(state + 0x66) |= 1;
            GameBit_Set(*(s16 *)(r4c + 0x1e), 1);
        }
        {
            int a = (int)((f32)(u32) * (u8 *)(obj + 0x36) + timeDelta);
            if (a < 0)
                a = 0;
            else if (a > 0xff)
                a = 0xff;
            *(u8 *)(obj + 0x36) = a;
        }
        ObjHits_EnableObject(obj);
    } else {
        GameBit_Set(0xedb, 0);
        ObjHits_DisableObject(obj);
    }
    if ((void *)Obj_GetPlayerObject() != NULL) {
        if (PSVECDistance((void *)(obj + 0x18), (void *)(Obj_GetPlayerObject() + 0x18)) >
            lbl_803E6E94) {
            GameBit_Set(0xedb, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctemplebri_init(int obj, int initData)
{
    int state;
    int model;
    int modelData;
    int maxY;
    int i;
    int p, k;
    int done;

    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(initData + 0x18) << 8);
    *(u8 *)(obj + 0xad) = *(u8 *)(initData + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55))
        *(u8 *)(obj + 0xad) = 0;
    *(void **)(obj + 0xbc) = (void *)wctemplebri_interactCallback;
    state = *(int *)(obj + 0xb8);
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
        p = state;
        for (k = 0; k < *(u8 *)(state + 0x4f) - 1; k++) {
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
    *(u8 *)(state + 0x4f) = 0xa;
    *(f32 *)(state + 0) = (f32)maxY;
    if ((u32)GameBit_Get(*(s16 *)(initData + 0x1e)) != 0) {
        *(u8 *)(state + 0x5f) = 1;
        *(u8 *)(state + 0x66) |= 1;
    }
    if (*(u8 *)(state + 0x5f) != 0) {
        for (k = 0; k < *(u8 *)(state + 0x4f); k++) {
            *(u8 *)(state + k + 0x50) = 0xff;
            *(u8 *)(state + k + 0x40) = 1;
        }
        *(u8 *)(obj + 0x36) = 0xff;
    } else {
        ObjHits_DisableObject(obj);
        *(u8 *)(obj + 0x36) = 0;
    }
    *(u16 *)(obj + 0xb0) |= 0x6000;
    ObjModel_SetPostRenderCallback(model, fn_800284CC);
}
#pragma scheduling reset
#pragma peephole reset
