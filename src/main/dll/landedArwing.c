#include "main/dll/landedArwing.h"
#include "main/objanim.h"
#include "main/objlib.h"
#include "main/objhits_types.h"

extern void *Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern f32 fsin16Precise(u16 angle);
extern f32 fcos16Precise(u16 angle);

extern void fn_80165B3C(int obj, int sub);
extern void fn_80165C8C(int obj, int sub);
extern void fn_80166444(int obj, int sub);
extern void updateConstrainedChaseVelocity(int obj, f32 x, f32 y, f32 z, f32 scale);

extern void *gPathControlInterface;
extern u8 framesThisStep;
extern f32 timeDelta;

extern f32 lbl_803E2FD8;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E3004;
extern f32 lbl_803E3008;
extern f32 lbl_803E300C;
extern f32 lbl_803E3010;

#define LANDED_ARWING_OBJECT_PAIR_PRIORITY 9
#define LANDED_ARWING_OBJECT_PAIR_HIT_VOLUME 1

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
 * Function: LandedArwing_UpdateFlightChase
 * EN v1.0 Address: 0x8016558C
 * EN v1.0 Size: 1068b
 */
undefined4 LandedArwing_UpdateFlightChase(int obj, int state)
{
    int objLocal;
    int stateWord;
    int playerObj;
    LandedArwingState *sub;
    int targetMode;
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    f32 chaseScale;
    u32 scriptFlags;

    objLocal = obj;
    stateWord = state;
    sub = *(LandedArwingState **)(*(int *)(objLocal + 0xb8) + 0x40c);
    playerObj = (int)Obj_GetPlayerObject();
    *(u8 *)(stateWord + 0x34d) = 1;

    if (*(s8 *)(stateWord + 0x27a) != 0) {
        sub->speed = lbl_803E3004;
        ObjHits_EnableObject(objLocal);
        *(f32 *)(objLocal + 0x24) = -sub->speed * fsin16Precise(*(s16 *)objLocal);
        *(f32 *)(objLocal + 0x28) = lbl_803E2FDC;
        *(f32 *)(objLocal + 0x2c) = -sub->speed * fcos16Precise(*(s16 *)objLocal);
        *(u32 *)stateWord |= LANDED_ARWING_FLAG_LAUNCHING;
        ((void (*)(int, int, f32, int))ObjAnim_SetCurrentMove)(objLocal, 0, lbl_803E2FDC, 0);
        sub->animSpeed = lbl_803E3008;
    }

    ObjHits_SetHitVolumeSlot(objLocal, LANDED_ARWING_OBJECT_PAIR_PRIORITY, LANDED_ARWING_OBJECT_PAIR_HIT_VOLUME, -1);
    (*(ObjHitsPriorityState **)(objLocal + 0x54))->objectPairPriority = LANDED_ARWING_OBJECT_PAIR_PRIORITY;
    (*(ObjHitsPriorityState **)(objLocal + 0x54))->objectPairHitVolume = LANDED_ARWING_OBJECT_PAIR_HIT_VOLUME;
    ObjHits_RegisterActiveHitVolumeObject(objLocal);

    (*(code *)(*(int *)gPathControlInterface + 0x18))(objLocal, stateWord + 4, (double)timeDelta);

    if (sub->surfaceMode != LANDED_ARWING_SCRIPT_MODE) {
        if ((u32)playerObj != 0 &&
            *(f32 *)(playerObj + 0x18) >= sub->boundsMinX &&
            *(f32 *)(playerObj + 0x18) <= sub->boundsMaxX &&
            *(f32 *)(playerObj + 0x1c) >= sub->boundsMinY &&
            *(f32 *)(playerObj + 0x1c) <= sub->boundsMaxY &&
            *(f32 *)(playerObj + 0x20) >= sub->boundsMinZ &&
            *(f32 *)(playerObj + 0x20) <= sub->boundsMaxZ) {
            targetMode = LANDED_ARWING_TARGET_PLAYER;
        } else {
            targetMode = LANDED_ARWING_TARGET_WANDER;
        }
    } else {
        scriptFlags = sub->flags92;
        if ((scriptFlags & LANDED_ARWING_FLAG_SCRIPT_TARGET) != 0) {
            targetMode = LANDED_ARWING_TARGET_SCRIPT;
            if ((s32)sub->scriptTimer <= (s32)framesThisStep) {
                ((LandedArwingFlags *)&sub->flags92)->bit0 = 0;
            } else {
                sub->scriptTimer -= framesThisStep;
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
        if ((s32)sub->wanderTimer <= (s32)framesThisStep) {
            sub->wanderTargetX = (f32)(s32)randomGetRange((s32)sub->boundsMinX, (s32)sub->boundsMaxX);
            sub->wanderTargetY = (f32)(s32)randomGetRange((s32)sub->boundsMinY, (s32)sub->boundsMaxY);
            sub->wanderTargetZ = (f32)(s32)randomGetRange((s32)sub->boundsMinZ, (s32)sub->boundsMaxZ);
            sub->wanderTimer = (u16)randomGetRange(LANDED_ARWING_WANDER_TIME_MIN, LANDED_ARWING_WANDER_TIME_MAX);
        } else {
            sub->wanderTimer -= framesThisStep;
        }
        targetX = sub->wanderTargetX;
        targetY = sub->wanderTargetY;
        targetZ = sub->wanderTargetZ;
        chaseScale = lbl_803E3010;
        break;
    case LANDED_ARWING_TARGET_SCRIPT:
        targetX = sub->scriptTargetX;
        targetY = sub->scriptTargetY;
        targetZ = sub->scriptTargetZ;
        chaseScale = lbl_803E300C;
        break;
    }

    updateConstrainedChaseVelocity(objLocal, targetX, targetY, targetZ, chaseScale);

    if (sub->surfaceMode == LANDED_ARWING_SCRIPT_MODE) {
        if ((u32)((sub->flags92 >> 2) & 1) != 0) {
            fn_80165B3C(objLocal, (int)sub);
        } else {
            fn_80166444(objLocal, (int)sub);
        }
    } else {
        fn_80165C8C(objLocal, (int)sub);
    }

    return 0;
}

#pragma peephole reset
#pragma scheduling reset
