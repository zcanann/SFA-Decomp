#include "ghidra_import.h"
#include "main/dll/CF/dll_163.h"

extern undefined8 ObjGroup_RemoveObject();
extern f32 lbl_803E3BBC;
extern void objRenderFn_8003b8f4(f32);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern f64 lbl_803E3BD0;
extern f32 lbl_803E3BF0;
extern f32 lbl_803E3BF4;
extern f32 lbl_803E3BF8;
extern f32 lbl_803E3BFC;

#pragma scheduling off
#pragma peephole off
void staffactivated_calcInteractionTargetXZ(int obj, f32 *outX, f32 *outZ) {
    int bMode;
    float *pfVar1;

    pfVar1 = *(float **)(obj + 0xb8);
    bMode = *(byte *)(*(int *)(obj + 0x4c) + 0x1c);

    if (bMode == 2) goto lbl_case2;
    if (bMode >= 2) goto lbl_gt2;
    if (bMode == 0) goto lbl_case0;
    goto lbl_default;

lbl_gt2:
    if (bMode >= 4) goto lbl_default;
    goto lbl_case3;

lbl_case2:
    *outX = -(lbl_803E3BF0 * fn_80293E80(lbl_803E3BF4 * (f32)(*(s16 *)obj) / lbl_803E3BF8) - pfVar1[0]);
    *outZ = -(lbl_803E3BF0 * sin(lbl_803E3BF4 * (f32)(*(s16 *)obj) / lbl_803E3BF8) - pfVar1[1]);
    goto lbl_done;

lbl_case3:
    *outX = lbl_803E3BF0 * fn_80293E80(lbl_803E3BF4 * (f32)(*(s16 *)obj) / lbl_803E3BF8) + pfVar1[0];
    *outZ = lbl_803E3BF0 * sin(lbl_803E3BF4 * (f32)(*(s16 *)obj) / lbl_803E3BF8) + pfVar1[1];
    goto lbl_done;

lbl_case0:
    *outX = lbl_803E3BFC * fn_80293E80(lbl_803E3BF4 * (f32)(*(s16 *)obj) / lbl_803E3BF8) + *(float *)(obj + 0xc);
    *outZ = lbl_803E3BFC * sin(lbl_803E3BF4 * (f32)(*(s16 *)obj) / lbl_803E3BF8) + *(float *)(obj + 0x14);
    goto lbl_done;

lbl_default:
    *outX = lbl_803E3BF0 * fn_80293E80(lbl_803E3BF4 * (f32)(*(s16 *)obj) / lbl_803E3BF8) + *(float *)(obj + 0xc);
    *outZ = lbl_803E3BF0 * sin(lbl_803E3BF4 * (f32)(*(s16 *)obj) / lbl_803E3BF8) + *(float *)(obj + 0x14);

lbl_done:;
}
#pragma peephole reset
#pragma scheduling reset

u32 cfPrisonGuard_getLiftHeight(int *obj) { return *(u32*)((char*)((int**)obj)[0xb8/4] + 0x14); }

#pragma scheduling off
#pragma peephole off
void cfPrisonGuard_setLiftHeight(int *obj, int v) {
    int *state = *(int **)((char *)obj + 0xb8);
    *(int *)((char *)state + 0x14) = v;
    *(u8 *)((char *)state + 0x1c) = 1;
}
#pragma peephole reset
#pragma scheduling reset

u8 objGetByteParam1C(int *obj) { return *(u8*)((char*)((int**)obj)[0x4c/4] + 0x1c); }

int staffactivated_getExtraSize(void)
{
  return 0x24;
}

int staffactivated_getObjectTypeId(void)
{
  return 0x40;
}

#pragma scheduling off
#pragma peephole off
void staffactivated_free(int x) { ObjGroup_RemoveObject(x, 0x41); }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void staffactivated_render(void) { objRenderFn_8003b8f4(lbl_803E3BBC); }
#pragma peephole reset
#pragma scheduling reset

extern void Obj_GetPlayerObject(void);
extern int fn_80295CE4(void);
extern int GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern int *gObjectTriggerInterface;
extern int *gPartfxInterface;
extern f32 lbl_803E3BDC;
extern f32 lbl_803E3C00;
extern f32 lbl_803E3C04;
extern void staffactivated_updateLiftHeight(int obj, int state);
extern void landed_arwing_updateHitReaction(int obj, int state);
extern void landed_arwing_updateDamageTexture(int obj, int state);

void staffactivated_update(int obj) {
    struct PartfxParams {
        int pad;
        s16 life;
        s16 extra;
        f32 ox;
        f32 oy;
        f32 oz;
        f32 ow;
    } stk;
    int param = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int mode;
    int isSet;
    int gb;

    Obj_GetPlayerObject();

    if ((*(u8 *)(state + 0x1d) >> 6) & 1) {
        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x8);
    } else {
        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & ~0x8);
    }

    if ((*(u8 *)(state + 0x1d) >> 7) & 1) {
        if (fn_80295CE4() != 0) {
            *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & ~0x10);
            goto after_bit4;
        }
    }
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
after_bit4:

    mode = *(u8 *)(param + 0x1c);
    if (mode == 2) {
        staffactivated_updateLiftHeight(obj, state);
    } else if (mode > 2) {
        if (mode >= 6) {
            goto default_case;
        } else if (mode >= 4) {
            landed_arwing_updateDamageTexture(obj, state);
        } else {
            landed_arwing_updateHitReaction(obj, state);
        }
    } else if (mode == 0) {
        if (*(u8 *)(obj + 0xaf) & 0x4) {
            if (GameBit_Get(0xd2a) == 0) {
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
                GameBit_Set(0xd2a, 1);
            }
        }
        if (GameBit_Get(0x957) == 0) {
            *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
        }
        isSet = 0;
        gb = *(s16 *)(param + 0x22);
        if (gb == -1 || GameBit_Get(gb) != 0) {
            isSet = 1;
        }
        *(u8 *)(state + 0x1d) =
            (u8)(isSet << 7) | (*(u8 *)(state + 0x1d) & 0x7f);
        if ((*(u8 *)(state + 0x1d) >> 7) & 1) {
            stk.ox = lbl_803E3BBC;
            stk.oy = lbl_803E3C00;
            stk.oz = lbl_803E3C04;
            stk.ow = lbl_803E3BDC;
            stk.life = 0x64;
            stk.extra = 0;
            (*(void (*)(int, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x7c3, &stk, 2, -1, 0);
            stk.ox = lbl_803E3BBC;
            stk.oy = lbl_803E3C00;
            stk.oz = lbl_803E3C04;
            stk.ow = lbl_803E3BDC;
            stk.life = 0xa;
            stk.extra = 5;
            (*(void (*)(int, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x7c3, &stk, 2, -1, 0);
        }
        return;
    } else {
        goto default_case;
    }
    return;
default_case:
    isSet = 0;
    gb = *(s16 *)(param + 0x22);
    if (gb == -1 || GameBit_Get(gb) != 0) {
        isSet = 1;
    }
    *(u8 *)(state + 0x1d) =
        (u8)(isSet << 7) | (*(u8 *)(state + 0x1d) & 0x7f);
}
