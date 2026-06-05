#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int wcapertures_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcapertures_getObjectTypeId(int obj)
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
#pragma scheduling off
void wcapertures_free(int obj)
{
    void *light = *(void **)(*(int *)(obj + 0xb8));

    if (light != NULL) {
        ModelLightStruct_free(light);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcapertures_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    char *state = *(char **)(obj + 0xb8);
    u8 *light;

    if (visible != 0) {
        *(u8 *)(state + 7) |= 1;
    } else {
        *(u8 *)(state + 7) &= ~1;
    }
    light = *(u8 **)state;
    if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0) {
        queueGlowRender(light);
    }
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E2C);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcapertures_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(u8 *)(state + 6) == 2) {
        f32 col[3];
        s16 ev[2];

        if ((s8)*(u8 *)(obj + 0xad) == 0)
            ev[1] = 1;
        else
            ev[1] = 0;
        col[0] = lbl_803E6E30;
        col[1] = lbl_803E6E34;
        col[2] = lbl_803E6E28;
        (*(void (**)(int, int, void *, int, int, void *))(*gPartfxInterface + 8))(
            obj, 0x805, ev, 2, -1, col);
    }
    if (*(void **)state != NULL)
        modelLightStruct_updateGlowAlpha(*(void **)state);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcapertures_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcapertures_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wcapertures_interactCallback(int obj, int p2, int p3)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        if (*(u8 *)(p3 + (i + 0x81)) == 1)
            *(u8 *)(state + 6) = 1;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcapertures_init(int obj, int initData)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(initData + 0x18) << 8);
    *(void **)(obj + 0xbc) = (void *)wcapertures_interactCallback;
    *(u8 *)(obj + 0xad) = *(u8 *)(initData + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55))
        *(u8 *)(obj + 0xad) = 0;
    if ((u32)GameBit_Get(*(s16 *)(initData + 0x20)) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(initData + 0x1e)) != 0)
            *(u8 *)(state + 6) = 2;
        else
            *(u8 *)(state + 6) = 1;
    }
    *(u8 *)(obj + 0x36) = 1;
    *(u16 *)(state + 4) = 0xff;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fn_800284CC);
    *(void **)(state + 0) = objCreateLight(obj, 1);
    if (*(void **)(state + 0) != NULL) {
        modelLightStruct_setField50(*(void **)(state + 0), 2);
        if ((s8)*(u8 *)(obj + 0xad) == 0)
            modelLightStruct_setupGlow(*(void **)(state + 0), 0, 0xff, 0xff, 0x4d, 0x96, lbl_803E6E3C);
        else
            modelLightStruct_setupGlow(*(void **)(state + 0), 0, 0x4d, 0x4d, 0xff, 0xff, lbl_803E6E3C);
        modelLightStruct_setGlowProjectionRadius(*(void **)(state + 0), lbl_803E6E40);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcapertures_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();
    void *light;
    int alpha, target;

    *(s16 *)(state + 4) = 0;
    switch (*(u8 *)(state + 6)) {
    case 0:
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
            *(u8 *)(state + 6) = 1;
        }
        break;
    case 1:
        if ((*(int (**)(void))(*gCameraInterface + 0x10))() == 68 && fn_802969F0(player) == 33) {
            *(s16 *)(state + 4) = 255;
            if (Camera_GetFovY() <= lbl_803E6E38 && (*(u16 *)(obj + 0xb0) & 0x800)) {
                GameBit_Set(*(s16 *)(setup + 0x1e), 1);
                *(u8 *)(state + 6) = 2;
            }
        }
        break;
    case 2:
        *(s16 *)(state + 4) = 0;
        break;
    }
    alpha = *(u8 *)(obj + 0x36);
    target = *(s16 *)(state + 4);
    if (alpha < target) {
        int v = alpha + framesThisStep * 4;
        if (v > target) {
            v = target;
        }
        *(u8 *)(obj + 0x36) = v;
    } else if (alpha > target) {
        int v = alpha - framesThisStep * 4;
        if (v < target) {
            v = target;
        }
        *(u8 *)(obj + 0x36) = v;
    }
    light = *(void **)(state + 0);
    if (light != NULL) {
        if (*(u8 *)(obj + 0x36) > 128) {
            lightFn_8001db6c(light, 1, lbl_803E6E2C);
        } else {
            lightFn_8001db6c(light, 0, lbl_803E6E2C);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
