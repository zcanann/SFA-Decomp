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

#define LANDED_ARWING_HIT_VOLUME_SLOT 9
#define LANDED_ARWING_HIT_VOLUME_FRAME 1

#define LANDED_ARWING_SCRIPT_MODE 6

#define LANDED_ARWING_TARGET_PLAYER 0
#define LANDED_ARWING_TARGET_WANDER 1
#define LANDED_ARWING_TARGET_SCRIPT 2

#define LANDED_ARWING_FLAG_SCRIPT_TARGET 0x01
#define LANDED_ARWING_FLAG_ALTERNATE_SCRIPT_ANIM 0x04
#define LANDED_ARWING_FLAG_LAUNCHING 0x02004000

#define LANDED_ARWING_REVERSE_CHASE_GAMEBIT 0x698
#define LANDED_ARWING_WANDER_TIME_MIN 0x12c
#define LANDED_ARWING_WANDER_TIME_MAX 0x258

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
    int objLocal;
    int stateWord;
    int playerObj;
    int sub;
    int targetMode;
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    f32 chaseScale;
    u32 scriptFlags;

    objLocal = obj;
    stateWord = param_2;
    sub = *(int *)(*(int *)(objLocal + 0xb8) + 0x40c);
    playerObj = (int)Obj_GetPlayerObject();
    *(u8 *)(stateWord + 0x34d) = 1;

    if (*(s8 *)(stateWord + 0x27a) != 0) {
        *(f32 *)(sub + 0x60) = lbl_803E3004;
        ObjHits_EnableObject(objLocal);
        *(f32 *)(objLocal + 0x24) = -*(f32 *)(sub + 0x60) * fsin16Precise((u16)*(s16 *)objLocal);
        *(f32 *)(objLocal + 0x28) = lbl_803E2FDC;
        *(f32 *)(objLocal + 0x2c) = -*(f32 *)(sub + 0x60) * fcos16Precise((u16)*(s16 *)objLocal);
        *(u32 *)stateWord |= LANDED_ARWING_FLAG_LAUNCHING;
        ((void (*)(int, int, f32, int))ObjAnim_SetCurrentMove)(objLocal, 0, lbl_803E2FDC, 0);
        *(f32 *)(sub + 0x44) = lbl_803E3008;
    }

    ObjHits_SetHitVolumeSlot(objLocal, LANDED_ARWING_HIT_VOLUME_SLOT, LANDED_ARWING_HIT_VOLUME_FRAME, -1);
    *(u8 *)(*(int *)(objLocal + 0x54) + 0x6c) = LANDED_ARWING_HIT_VOLUME_SLOT;
    *(u8 *)(*(int *)(objLocal + 0x54) + 0x6d) = LANDED_ARWING_HIT_VOLUME_FRAME;
    ObjHits_RegisterActiveHitVolumeObject(objLocal);

    (*(code *)(*(int *)lbl_803DCAA8 + 0x18))(objLocal, stateWord + 4, (double)timeDelta);

    if (*(u8 *)(sub + 0x90) != LANDED_ARWING_SCRIPT_MODE) {
        if ((u32)playerObj != 0 &&
            *(f32 *)(playerObj + 0x18) >= *(f32 *)(sub + 0x48) &&
            *(f32 *)(playerObj + 0x18) <= *(f32 *)(sub + 0x4c) &&
            *(f32 *)(playerObj + 0x1c) >= *(f32 *)(sub + 0x5c) &&
            *(f32 *)(playerObj + 0x1c) <= *(f32 *)(sub + 0x58) &&
            *(f32 *)(playerObj + 0x20) >= *(f32 *)(sub + 0x54) &&
            *(f32 *)(playerObj + 0x20) <= *(f32 *)(sub + 0x50)) {
            targetMode = LANDED_ARWING_TARGET_PLAYER;
        } else {
            targetMode = LANDED_ARWING_TARGET_WANDER;
        }
    } else {
        scriptFlags = *(u8 *)(sub + 0x92);
        if ((scriptFlags & LANDED_ARWING_FLAG_SCRIPT_TARGET) != 0) {
            targetMode = LANDED_ARWING_TARGET_SCRIPT;
            if ((s32)*(u16 *)(sub + 0x8e) <= (s32)framesThisStep) {
                ((LandedArwingFlags *)(sub + 0x92))->bit0 = 0;
            } else {
                *(u16 *)(sub + 0x8e) -= framesThisStep;
            }
        } else {
            targetMode = LANDED_ARWING_TARGET_PLAYER;
        }
    }

    switch (targetMode) {
    case LANDED_ARWING_TARGET_PLAYER:
        targetX = *(f32 *)(playerObj + 0xc);
        targetY = *(f32 *)(playerObj + 0x10) - lbl_803E2FD8;
        targetZ = *(f32 *)(playerObj + 0x14);
        chaseScale = lbl_803E300C;
        if (GameBit_Get(LANDED_ARWING_REVERSE_CHASE_GAMEBIT) != 0) {
            chaseScale = -lbl_803E300C;
        }
        break;
    case LANDED_ARWING_TARGET_WANDER:
        if ((s32)*(u16 *)(sub + 0x8c) <= (s32)framesThisStep) {
            *(f32 *)(sub + 0x64) = (f32)(s32)randomGetRange((s32)*(f32 *)(sub + 0x48), (s32)*(f32 *)(sub + 0x4c));
            *(f32 *)(sub + 0x68) = (f32)(s32)randomGetRange((s32)*(f32 *)(sub + 0x5c), (s32)*(f32 *)(sub + 0x58));
            *(f32 *)(sub + 0x6c) = (f32)(s32)randomGetRange((s32)*(f32 *)(sub + 0x54), (s32)*(f32 *)(sub + 0x50));
            *(u16 *)(sub + 0x8c) = (u16)randomGetRange(LANDED_ARWING_WANDER_TIME_MIN, LANDED_ARWING_WANDER_TIME_MAX);
        } else {
            *(u16 *)(sub + 0x8c) -= framesThisStep;
        }
        targetX = *(f32 *)(sub + 0x64);
        targetY = *(f32 *)(sub + 0x68);
        targetZ = *(f32 *)(sub + 0x6c);
        chaseScale = lbl_803E3010;
        break;
    case LANDED_ARWING_TARGET_SCRIPT:
        targetX = *(f32 *)(sub + 0x70);
        targetY = *(f32 *)(sub + 0x74);
        targetZ = *(f32 *)(sub + 0x78);
        chaseScale = lbl_803E300C;
        break;
    }

    updateConstrainedChaseVelocity(objLocal, targetX, targetY, targetZ, chaseScale);

    if (*(u8 *)(sub + 0x90) == LANDED_ARWING_SCRIPT_MODE) {
        if ((u32)((*(u8 *)(sub + 0x92) >> 2) & 1) != 0) {
            fn_80165B3C(objLocal, sub);
        } else {
            fn_80166444(objLocal, sub);
        }
    } else {
        fn_80165C8C(objLocal, sub);
    }

    return 0;
}

#pragma peephole reset
#pragma scheduling reset
