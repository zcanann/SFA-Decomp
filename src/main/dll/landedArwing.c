#include "ghidra_import.h"
#include "main/dll/landedArwing.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objlib.h"

extern void *Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern f32 fsin16Precise(int angle);
extern f32 fcos16Precise(int angle);

extern void fn_80165B3C(int obj, int sub);
extern void fn_80165C8C(int obj, int sub);
extern void fn_80166444(int obj, int sub);
extern void updateConstrainedChaseVelocity(int obj, f32 x, f32 y, f32 z, f32 scale);

extern void *lbl_803DCAA8;
extern u8 framesThisStep;
extern f32 timeDelta;

extern f32 lbl_803E2FD8;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E3004;
extern f32 lbl_803E3008;
extern f32 lbl_803E300C;
extern f32 lbl_803E3010;

typedef struct {
    u8 high7 : 7;
    u8 bit0 : 1;
} LandedArwingFlags;

#pragma peephole off
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: fn_8016558C
 * EN v1.0 Address: 0x8016558C
 * EN v1.0 Size: 1068b
 */
undefined4 fn_8016558C(int obj, int param_2)
{
    int playerObj;
    int sub;
    int state;
    f32 fa;
    f32 fb;
    f32 fc;
    f32 fd;
    u32 b;

    sub = *(int *)(*(int *)(obj + 0xb8) + 0x40c);
    playerObj = (int)Obj_GetPlayerObject();
    *(u8 *)(param_2 + 0x34d) = 1;

    if (*(s8 *)(param_2 + 0x27a) != 0) {
        *(f32 *)(sub + 0x60) = lbl_803E3004;
        ObjHits_EnableObject(obj);
        *(f32 *)(obj + 0x24) = -*(f32 *)(sub + 0x60) * fsin16Precise((u16)*(s16 *)obj);
        *(f32 *)(obj + 0x28) = lbl_803E2FDC;
        *(f32 *)(obj + 0x2c) = -*(f32 *)(sub + 0x60) * fcos16Precise((u16)*(s16 *)obj);
        *(u32 *)param_2 |= 0x02004000;
        ((void (*)(int, int, f32, int))ObjAnim_SetCurrentMove)(obj, 0, lbl_803E2FDC, 0);
        *(f32 *)(sub + 0x44) = lbl_803E3008;
    }

    ObjHits_SetHitVolumeSlot(obj, 9, 1, -1);
    *(u8 *)(*(int *)(obj + 0x54) + 0x6c) = 9;
    *(u8 *)(*(int *)(obj + 0x54) + 0x6d) = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);

    (*(code *)(*(int *)lbl_803DCAA8 + 0x18))(obj, param_2 + 4, (double)timeDelta);

    if (*(u8 *)(sub + 0x90) != 6) {
        if ((u32)playerObj != 0 &&
            *(f32 *)(playerObj + 0x18) >= *(f32 *)(sub + 0x48) &&
            *(f32 *)(playerObj + 0x18) <= *(f32 *)(sub + 0x4c) &&
            *(f32 *)(playerObj + 0x1c) >= *(f32 *)(sub + 0x5c) &&
            *(f32 *)(playerObj + 0x1c) <= *(f32 *)(sub + 0x58) &&
            *(f32 *)(playerObj + 0x20) >= *(f32 *)(sub + 0x54) &&
            *(f32 *)(playerObj + 0x20) <= *(f32 *)(sub + 0x50)) {
            state = 0;
        } else {
            state = 1;
        }
    } else {
        b = *(u8 *)(sub + 0x92);
        if ((b & 1) != 0) {
            state = 2;
            if ((s32)*(u16 *)(sub + 0x8e) <= (s32)framesThisStep) {
                ((LandedArwingFlags *)(sub + 0x92))->bit0 = 0;
            } else {
                *(u16 *)(sub + 0x8e) -= framesThisStep;
            }
        } else {
            state = 0;
        }
    }

    switch (state) {
    case 0:
        fa = *(f32 *)(playerObj + 0xc);
        fb = *(f32 *)(playerObj + 0x10) - lbl_803E2FD8;
        fc = *(f32 *)(playerObj + 0x14);
        fd = lbl_803E300C;
        if (GameBit_Get(0x698) != 0) {
            fd = -lbl_803E300C;
        }
        break;
    case 1:
        if ((s32)*(u16 *)(sub + 0x8c) <= (s32)framesThisStep) {
            *(f32 *)(sub + 0x64) = (f32)(s32)randomGetRange((s32)*(f32 *)(sub + 0x48), (s32)*(f32 *)(sub + 0x4c));
            *(f32 *)(sub + 0x68) = (f32)(s32)randomGetRange((s32)*(f32 *)(sub + 0x5c), (s32)*(f32 *)(sub + 0x58));
            *(f32 *)(sub + 0x6c) = (f32)(s32)randomGetRange((s32)*(f32 *)(sub + 0x54), (s32)*(f32 *)(sub + 0x50));
            *(u16 *)(sub + 0x8c) = (u16)randomGetRange(0x12c, 0x258);
        } else {
            *(u16 *)(sub + 0x8c) -= framesThisStep;
        }
        fa = *(f32 *)(sub + 0x64);
        fb = *(f32 *)(sub + 0x68);
        fc = *(f32 *)(sub + 0x6c);
        fd = lbl_803E3010;
        break;
    case 2:
        fa = *(f32 *)(sub + 0x70);
        fb = *(f32 *)(sub + 0x74);
        fc = *(f32 *)(sub + 0x78);
        fd = lbl_803E300C;
        break;
    }

    updateConstrainedChaseVelocity(obj, fa, fb, fc, fd);

    if (*(u8 *)(sub + 0x90) == 6) {
        if ((((u32)*(u8 *)(sub + 0x92)) >> 2) & 1) {
            fn_80165B3C(obj, sub);
        } else {
            fn_80166444(obj, sub);
        }
    } else {
        fn_80165C8C(obj, sub);
    }

    return 0;
}

#pragma peephole reset
#pragma scheduling reset
