#include "main/dll/dll_80220608_shared.h"

#define SFXsc_lockon2_on 199

#pragma peephole on
#pragma scheduling on
int wcpressures_getExtraSize(void) { return 0x7c; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wcpressures_tileStateCallback(int obj, int unused, int callbackData)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    u8 i;

    if (*(u8 *)(callbackData + 0x80) == 1) {
        for (i = 0; i < 10; i++) {
            if (((void **)state)[i + 1] != NULL) {
                *(f32 *)(state + 0x2c + i * 8) = *(f32 *)(((int *)state)[i + 1] + 0xc);
                *(f32 *)(state + 0x30 + i * 8) = *(f32 *)(((int *)state)[i + 1] + 0x14);
            }
        }
        *(u8 *)(callbackData + 0x80) = 0;
    } else if (*(u8 *)(callbackData + 0x80) == 2) {
        for (i = 0; i < 10; i++) {
            *(int *)(state + 4 + i * 4) = 0;
        }
        *(f32 *)(obj + 0x14) = *(f32 *)(setup + 8);
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
        *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
        GameBit_Set(*(s16 *)(setup + 0x1a), 0);
        *(u8 *)(callbackData + 0x80) = 0;
    }

    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcpressures_getObjectTypeId(int obj)
{
    int modelIndex = *(u8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wcpressures_free(int obj) { ObjGroup_RemoveObject(obj, 0x31); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcpressures_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E00);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpressures_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcpressures_update(int obj)
{
    int r4c = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int i;
    int j;
    f32 thr;

    if (*(s16 *)(r4c + 0x20) > 0 && (u32)GameBit_Get(*(s16 *)(r4c + 0x20)) == 0) {
        fn_80137948(sWCPressuresActivateFormat, *(s16 *)(r4c + 0x20));
        return;
    }
    {
        int n = *(u8 *)state - 1;
        *(s8 *)state = n;
        if ((s8)n < 0)
            *(s8 *)state = 0;
    }
    if ((s8)*(u8 *)(*(int *)(obj + 0x58) + 0x10f) > 0) {
        for (i = 0; i < (s8)*(u8 *)(*(int *)(obj + 0x58) + 0x10f); i++) {
            int ent = *(int *)(*(int *)(obj + 0x58) + (i * 4 + 0x100));
            if (*(f32 *)(ent + 0x10) - *(f32 *)(obj + 0x10) >
                (f32)(u32) * (u8 *)(r4c + 0x1d)) {
                int s2 = *(int *)(obj + 0xb8);
                int slot;

                for (j = 0; *(void **)(s2 + (u8)j * 4 + 4) != NULL || (u8)j == 9; j++)
                    ;
                slot = (u8)j;
                *(int *)(s2 + slot * 4 + 4) = ent;
                *(f32 *)(s2 + slot * 8 + 0x2c) = *(f32 *)(ent + 0xc);
                *(f32 *)(s2 + slot * 8 + 0x30) = *(f32 *)(ent + 0x14);
            }
        }
    }
    {
        int s2 = *(int *)(obj + 0xb8);
        int found = 0;

        for (j = 0; (u8)j < 0xa; j++) {
            int slot = (u8)j;
            int val = *(int *)(s2 + slot * 4 + 4);
            if ((u32)val != 0) {
                if (*(f32 *)(s2 + slot * 8 + 0x2c) == *(f32 *)(val + 0xc) &&
                    *(f32 *)(s2 + slot * 8 + 0x30) == *(f32 *)(val + 0x14)) {
                    found = 1;
                } else {
                    *(int *)(s2 + slot * 4 + 4) = 0;
                }
            }
        }
        if (found)
            *(s8 *)state = 5;
    }
    thr = *(f32 *)(r4c + 0xc) - (f32)(u32) * (u8 *)(r4c + 0x1c);
    switch ((s8)*(s8 *)(state + 1)) {
    case 0:
        if (*(s8 *)state != 0 && *(f32 *)(obj + 0x10) >= thr) {
            Sfx_PlayFromObject(obj, SFXsc_lockon2_on);
            *(s8 *)(state + 1) = 3;
        }
        break;
    case 1:
        *(f32 *)(obj + 0x10) = lbl_803E6E04 * timeDelta + *(f32 *)(obj + 0x10);
        if (*(f32 *)(obj + 0x10) > *(f32 *)(r4c + 0xc)) {
            *(f32 *)(obj + 0x10) = *(f32 *)(r4c + 0xc);
            *(s8 *)(state + 1) = 0;
        }
        break;
    case 2:
        if ((u32)GameBit_Get(*(s16 *)(r4c + 0x1a)) == 0) {
            Sfx_PlayFromObject(obj, SFXsc_lockon2_on);
            *(s8 *)(state + 1) = 1;
        }
        break;
    case 3:
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) - lbl_803E6E04 * timeDelta;
        if (*(f32 *)(obj + 0x10) < thr) {
            GameBit_Set(*(s16 *)(r4c + 0x1a), 1);
            *(s8 *)(state + 1) = 2;
            *(f32 *)(obj + 0x10) = thr;
        }
        break;
    }
    {
        int *tex = objFindTexture(obj, 0, 0);
        if (tex != 0) {
            *tex = (s8)*(s8 *)(state + 1) == 2 ? 1 : 0;
            *tex = *tex << 8;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcpressures_init(u8 *obj, u8 *setup)
{
    u8 *state = *(u8 **)(obj + 0xb8);
    s16 objType;
    u16 objFlags;
    s8 modelIndex;
    int i;

    objType = (s16)(setup[0x18] << 8);
    *(s16 *)obj = objType;
    objFlags = *(u16 *)(obj + 0xb0) | 0x6000;
    *(u16 *)(obj + 0xb0) = objFlags;
    modelIndex = (s8)setup[0x19];
    *(s8 *)(obj + 0xad) = modelIndex;
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1a)) != 0) {
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc) - (f32)*(u8 *)(setup + 0x1c);
        state[0] = 0x1e;
        state[1] = 2;
    }

    ObjGroup_AddObject((int)obj, 0x31);
    for (i = 0; i < 10; i++) {
        *(int *)(state + 4 + i * 4) = 0;
    }
    *(void **)(obj + 0xbc) = wcpressures_tileStateCallback;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpressures_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpressures_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
