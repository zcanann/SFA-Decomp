/*
 * landedArwing flight-chase action (DLL 0xD3 / staffAction handler slot 1).
 *
 * One entry in gLandedArwingStateHandlers (installed from staffAction.c).
 * Picks one of three target modes per frame: player chase, wander to a random
 * in-bounds point, or scripted target (surfaceMode 6).
 */
#include "main/dll/landedArwing.h"
#include "main/dll/baddie_state.h"
#include "main/dll/path_control_interface.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/gameplay_runtime.h"

/* raw offsets — kept as-is to match staffAction.c handlers */
#define BADDIESTATE_HANDLER_TICK_FLAG 0x34d
#define BADDIESTATE_JUST_LAUNCHED 0x27a



extern f32 fsin16Precise(u16 angle);
extern f32 fcos16Precise(u16 angle);

extern void fn_80165B3C(int obj, int state);
extern void landedarwing_moveSurfaceCrawler(int obj, int sub);
extern void fn_80166444(int obj, int state);
extern void updateConstrainedChaseVelocity(int obj, f32 x, f32 y, f32 z, f32 scale);

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
#define LANDED_ARWING_FLAG_LAUNCHING 0x02004000

#define LANDED_ARWING_REVERSE_CHASE_GAMEBIT 0x698
#define LANDED_ARWING_WANDER_TIME_MIN 0x12c
#define LANDED_ARWING_WANDER_TIME_MAX 0x258

typedef struct
{
    u8 high7 : 7;
    u8 bit0 : 1;
} LandedArwingFlags;

u32 LandedArwing_UpdateFlightChase(int obj, int state)
{
    int playerObj;
    LandedArwingState* sub;
    int targetMode;
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    f32 chaseScale;
    u32 scriptFlags;

    sub = (LandedArwingState*)((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
    playerObj = (int)Obj_GetPlayerObject();
    *(u8*)(state + BADDIESTATE_HANDLER_TICK_FLAG) = 1;

    if (*(s8*)(state + BADDIESTATE_JUST_LAUNCHED) != 0)
    {
        sub->speed = lbl_803E3004;
        ObjHits_EnableObject(obj);
        ((GameObject*)obj)->anim.velocityX =
            -sub->speed * fsin16Precise(((GameObject*)obj)->anim.rotX);
        ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        ((GameObject*)obj)->anim.velocityZ =
            -sub->speed * fcos16Precise(((GameObject*)obj)->anim.rotX);
        *(u32*)state |= LANDED_ARWING_FLAG_LAUNCHING;
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2FDC, 0);
        sub->animSpeed = lbl_803E3008;
    }

    ObjHits_SetHitVolumeSlot(obj, LANDED_ARWING_OBJECT_PAIR_PRIORITY, LANDED_ARWING_OBJECT_PAIR_HIT_VOLUME, -1);
    ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->objectPairPriority = LANDED_ARWING_OBJECT_PAIR_PRIORITY;
    ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->objectPairHitVolume = LANDED_ARWING_OBJECT_PAIR_HIT_VOLUME;
    ObjHits_RegisterActiveHitVolumeObject(obj);

    (*gPathControlInterface)->advance((void*)obj, (void*)(state + 4), timeDelta);

    if (sub->surfaceMode != LANDED_ARWING_SCRIPT_MODE)
    {
        if ((u32)playerObj != 0 &&
            ((GameObject*)playerObj)->anim.worldPosX >= sub->boundsMinX &&
            ((GameObject*)playerObj)->anim.worldPosX <= sub->boundsMaxX &&
            ((GameObject*)playerObj)->anim.worldPosY >= sub->boundsMinY &&
            ((GameObject*)playerObj)->anim.worldPosY <= sub->boundsMaxY &&
            ((GameObject*)playerObj)->anim.worldPosZ >= sub->boundsMinZ &&
            ((GameObject*)playerObj)->anim.worldPosZ <= sub->boundsMaxZ)
        {
            targetMode = LANDED_ARWING_TARGET_PLAYER;
        }
        else
        {
            targetMode = LANDED_ARWING_TARGET_WANDER;
        }
    }
    else
    {
        scriptFlags = sub->flags92;
        if ((scriptFlags & LANDED_ARWING_FLAG_SCRIPT_TARGET) != 0)
        {
            targetMode = LANDED_ARWING_TARGET_SCRIPT;
            if ((s32)sub->scriptTimer <= framesThisStep)
            {
                ((LandedArwingFlags*)&sub->flags92)->bit0 = 0;
            }
            else
            {
                sub->scriptTimer -= framesThisStep;
            }
        }
        else
        {
            targetMode = LANDED_ARWING_TARGET_PLAYER;
        }
    }

    switch (targetMode)
    {
    case LANDED_ARWING_TARGET_PLAYER:
        targetX = ((GameObject*)playerObj)->anim.localPosX;
        targetY = ((GameObject*)playerObj)->anim.localPosY - lbl_803E2FD8;
        targetZ = ((GameObject*)playerObj)->anim.localPosZ;
        chaseScale = lbl_803E300C;
        if (GameBit_Get(LANDED_ARWING_REVERSE_CHASE_GAMEBIT) != 0)
        {
            chaseScale = -lbl_803E300C;
        }
        break;
    case LANDED_ARWING_TARGET_WANDER:
        if ((s32)sub->wanderTimer <= framesThisStep)
        {
            sub->wanderTargetX = (f32)(s32)randomGetRange((s32)sub->boundsMinX, sub->boundsMaxX);
            sub->wanderTargetY = (f32)(s32)randomGetRange((s32)sub->boundsMinY, sub->boundsMaxY);
            sub->wanderTargetZ = (f32)(s32)randomGetRange((s32)sub->boundsMinZ, sub->boundsMaxZ);
            sub->wanderTimer = randomGetRange(LANDED_ARWING_WANDER_TIME_MIN, LANDED_ARWING_WANDER_TIME_MAX);
        }
        else
        {
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

    updateConstrainedChaseVelocity(obj, targetX, targetY, targetZ, chaseScale);

    if (sub->surfaceMode == LANDED_ARWING_SCRIPT_MODE)
    {
        if ((u32)((sub->flags92 >> 2) & 1) != 0)
        {
            fn_80165B3C(obj, (int)sub);
        }
        else
        {
            fn_80166444(obj, (int)sub);
        }
    }
    else
    {
        landedarwing_moveSurfaceCrawler(obj, (int)sub);
    }

    return 0;
}
