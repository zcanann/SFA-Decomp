/* DLL 0x0250 */
#include "dlls/object_descriptor.h"
#include "dolphin/mtx.h"
#include "main/dll/rom_curve_def.h"
#include "main/audio/music_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera_interface.h"
#include "main/pad.h"
#include "main/vecmath.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/map_load.h"
#include "main/mapEventTypes.h"
#include "main/mm.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objprint_character_api.h"
#include "main/dll/DR/dll_0250_ktrex.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/dll_0262_drakormissile.h"
#include "main/dll/rom_curve_interface.h"
#include "main/newclouds.h"
#include "game/objects/object.h"
#include "main/object_render.h"
#include "string.h"
#include "sys/objects.h"
#include "main/resource.h"
#include "main/screen_transition.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/dll/DR/dll_0251_ktrexfloorswitch.h"
#include "main/dll/DR/dll_0252_ktlazerwall.h"
#include "main/dll/DR/dll_0254_ktfallingrocks.h"
#include "main/player_control_interface.h"
#include "main/dll/DR/dll_024F_ktrexlevel.h"
#include "main/camera_shake_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/model.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/dll/partfx_interface.h"
#include "main/model_light.h"
#include "main/shader_api.h"

GroundBaddieState* gKTRexRuntime;
KTRexArenaState* gKTRexState;
MapRomList* gKTRexMapBlock;
int gKTRexContactEffectCooldown;
StaffCollisionInterface** gKTRexResource;

KTRexWork gKTRexEffectSpawnWork;

s16 gKTRexMoveIdByLaneB05[4] = {9, 0x12, 0x12, 0};
s16 gKTRexWalkMoveIdByLane[4] = {1, 2, 3, 0};
s16 gKTRexMoveIdByVariantB04[4] = {4, 6, 6, 0};
u16 gKTRexWalkPhaseFlagsByLaneEvent4[4] = {1, 4, 0x10, 0};
u16 gKTRexWalkPhaseFlagsByLaneEvent2[4] = {2, 8, 0x20, 0};
u16 gKTRexWalkEndPhaseFlagsByLaneAlt[4] = {0x4000, 0x4000, 0x4000, 0};
u16 gKTRexWalkEndPhaseFlagsByLane[4] = {0x8000, 0x8000, 0x8000, 0};
u16 gKTRexPhaseFlagsByVariantB04[4] = {0x40, 0x80, 0x100, 0};
s16 gKTRexLaneEnabledGameBits[4] = {0x566, 0x567, 0x568, 0x569};
s16 gKTRexLaneModeGameBits[4] = {0x560, 0x561, 0x562, 0x563};

#define CAMMODE_DEFAULT 0x42 /* dll_0042 - default/release camera */

#define KTREX_OBJGROUP         0x3
#define KTREX_ADVANCE_MSG      0xe0001 /* notify the struck object to advance its hit reaction */
#define KTREX_PARTFX_HIT       0x328   /* hit-response effect spawned at the player contact point */

const KtrexMsgBlob gKTRexMsgTemplate = {{6, 0x69, 0x69, 0xFF}};

static u8 ktrex_getLaneMaskForTimer(int timer)
{
    u8 laneMasks[4] = {2, 8, 1, 4};

    timer = (timer >> 1) & 3;
    return laneMasks[timer];
}

static u8 ktrex_hasLaneLerpOvershot(void)
{
    if ((gKTRexState->currentLaneMask & gKTRexState->activeLaneMask) != 0)
    {
        if ((gKTRexState->timerFA & 1) != 0)
        {
            if (gKTRexState->laneLerpT - gKTRexState->laneFrac > 0.1f)
            {
                return 1;
            }
        }
        else
        {
            if (gKTRexState->laneFrac - gKTRexState->laneLerpT > 0.1f)
            {
                return 1;
            }
        }
    }
    return 0;
}

int ktrex_isPlayerInLaneThreatRange(GameObject* obj);

int ktrex_shouldAdvanceArenaPhase(void);
int ktrex_stateHandlerA06(GameObject* obj, GroundBaddieState* runtime);
int ktrex_stateHandlerA00(void);
int ktrex_stateHandlerB00(GameObject* obj, GroundBaddieState* runtime);
void ktrex_func0B(void);
int ktrex_getControlMode(GameObject* obj);
int ktrex_getExtraSize(void);
int ktrex_getObjectTypeId(void);
void ktrex_free(GameObject* obj);
void ktrex_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void ktrex_hitDetect(GameObject* obj);
void ktrex_update(GameObject* obj);
void ktrex_init(GameObject* obj, char* arg, int flag);
void ktrex_release(void);
void ktrex_initialise(void);

int ktrex_shouldAdvanceArenaPhase(void)
{
    u8 currentMask;
    u8 activeMask;
    KTRexArenaState* s = (KTRexArenaState*)gKTRexState;
    int r6;
    r6 = s->timerFA & 1;
    currentMask = s->currentLaneMask;
    activeMask = s->activeLaneMask;
    if ((currentMask & gKTRexState->activeLaneMask) != 0)
    {
        if (r6 != 0)
        {
            if (gKTRexState->laneLerpT < gKTRexState->laneFrac)
            {
                return 1;
            }
        }
        else
        {
            if (gKTRexState->laneLerpT > gKTRexState->laneFrac)
            {
                return 1;
            }
        }
        return 0;
    }
    if (r6 != 0)
    {
        if ((currentMask == 8 && (gKTRexState->activeLaneMask & 1)) ||
            (currentMask == 2 && (gKTRexState->activeLaneMask & 8)) ||
            (currentMask == 4 && (gKTRexState->activeLaneMask & 2)) ||
            (currentMask == 1 && (gKTRexState->activeLaneMask & 4)))
        {
            return 1;
        }
        return 0;
    }
    if ((currentMask == 1 && (gKTRexState->activeLaneMask & 8)) ||
        (currentMask == 4 && (activeMask & 1)) || (currentMask == 2 && (activeMask & 4)) ||
        (currentMask == 8 && (activeMask & 2)))
    {
        return 1;
    }
    return 0;
}

void ktrex_spawnRandomEnergyArc(GameObject* obj, int angle, f32 arcLen, int slot)
{
    int* model;
    Vec point1;
    Vec point2;
    Vec localPoint;

    if (gKTRexState->lightning[slot] != NULL)
    {
        mm_free(gKTRexState->lightning[slot]);
        gKTRexState->lightning[slot] = NULL;
    }
    model = (int*)Obj_GetActiveModel(obj);
    localPoint.x = 0.0f;
    localPoint.y = 0.0f;
    localPoint.z = 0.0f;

    PSMTXMultVec((MtxPtr)ObjModel_GetJointMatrix((u8*)model, randomGetRange(0, *(u8*)(*model + 0xf3) - 1)), &localPoint,
                 &point1);
    point1.x = point1.x + playerMapOffsetX;
    point1.y += 50.0f;
    point1.z = point1.z + playerMapOffsetZ;

    PSMTXMultVec((MtxPtr)ObjModel_GetJointMatrix((u8*)model, randomGetRange(0, *(u8*)(*model + 0xf3) - 1)), &localPoint,
                 &point2);
    point2.x = point2.x + playerMapOffsetX;
    point2.z = point2.z + playerMapOffsetZ;

    gKTRexState->lightning[slot] =
        lightningCreate(&point1, &point2, 0.1f, 0.3f, angle, 96,
                                   0);
}

int ktrex_stateHandlerA11(GameObject* obj, GroundBaddieState* runtime)
{
    int phase;
    f32 f4;
    f32 f5;
    if ((gKTRexState->timerFA & 1) != 0u)
    {
        obj->anim.rotX = (s16)(obj->anim.rotX + 0x8000);
    }
    else
    {
        obj->anim.rotX = (s16)(obj->anim.rotX - 0x8000);
    }
    gKTRexState->timerFA ^= 1;
    if ((gKTRexState->timerFA & 1) != 0)
    {
        gKTRexState->rowAX = gKTRexState->laneCX;
        gKTRexState->rowAY = gKTRexState->laneCY;
        gKTRexState->rowAZ = gKTRexState->laneCZ;
        gKTRexState->rowBX = gKTRexState->laneDX;
        gKTRexState->rowBY = gKTRexState->laneDY;
        gKTRexState->rowBZ = gKTRexState->laneDZ;
    }
    else
    {
        gKTRexState->rowAX = gKTRexState->laneAX;
        gKTRexState->rowAY = gKTRexState->laneAY;
        gKTRexState->rowAZ = gKTRexState->laneAZ;
        gKTRexState->rowBX = gKTRexState->laneBX;
        gKTRexState->rowBY = gKTRexState->laneBY;
        gKTRexState->rowBZ = gKTRexState->laneBZ;
    }
    phase = (gKTRexState->timerFA >> 1) & 3;
    f5 = gKTRexState->rowBX[phase] -
         gKTRexState->rowAX[phase];
    f4 = gKTRexState->rowBZ[phase] -
         gKTRexState->rowAZ[phase];
    if (__fabs(f5) > __fabs(f4))
    {
        f4 = (obj->anim.localPosX - gKTRexState->rowAX[phase]) / f5;
    }
    else
    {
        f4 = (obj->anim.localPosZ - gKTRexState->rowAZ[phase]) / f4;
    }
    gKTRexState->laneLerpT = f4;
    gKTRexState->timerFA |= 0x40;
    return 3;
}

int ktrex_stateHandlerA10(GameObject* obj, GroundBaddieState* runtime)
{
    void* p;
    u16 flags;
    int phase;
    int laneBit;
    p = (obj)->anim.placementData;
    flags = gKTRexState->timerFA;
    phase = (flags >> 1) & 3;
    laneBit = flags & 1;
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 1);
        gKTRexState->laneIndex = 2;
        {
            u8* row = (u8*)p + 0x38;
            runtime->baddie.animSpeedC =
                *(f32*)(row + gKTRexState->laneIndex * 4) / 1000.0f;
        }
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        int push = 0xa;
        if (Stack_IsFull(gKTRexState->stack) == 0)
        {
            Stack_Push(gKTRexState->stack, &push);
        }
        return 4;
    }
    if ((u8)ktrex_shouldAdvanceArenaPhase() != 0)
    {
        (*gCameraInterface)->loadTriggeredCamAction(3, 0, 0);
    }
    if (RandomTimer_UpdateRangeTrigger(&gKTRexState->breathSfxTimer, 2.0f, 4.0f) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexbreathout11);
    }
    {
        f32 u4 = gKTRexState->stateTimer - timeDelta;
        gKTRexState->stateTimer = u4;
        if (u4 <= 0.0f)
        {
            gKTRexState->stateTimer = 0.0f;
        }
    }
    if (gKTRexState->stateTimer <= 0.0f &&
        gKTRexState->lastPhase == phase &&
        ((laneBit == 0 && gKTRexState->laneLerpT >= 0.75f) ||
         (laneBit != 0 && gKTRexState->laneLerpT <= 0.25f)))
    {
        if ((gKTRexState->timerFA & 8) != 0)
        {
            u8 cond;
            u8 fe;
            gKTRexState->phaseCounter += 1;
            mainSetBits(GAMEBIT_DR_KTrexPhaseCounter, gKTRexState->phaseCounter);
            gKTRexState->moveVariant = 0;
            gKTRexState->timerFA &= ~0x8;
            fe = gKTRexState->currentLaneMask;
            if (fe == 1)
            {
                cond = gKTRexState->activeLaneMask == 2;
            }
            else if (fe == 2)
            {
                cond = gKTRexState->activeLaneMask == 1;
            }
            else if (fe == 4)
            {
                cond = gKTRexState->activeLaneMask == 8;
            }
            else
            {
                cond = gKTRexState->activeLaneMask == 4;
            }
            if (cond && (gKTRexState->timerFA & 0x40) == 0)
            {
                int push = 0xb;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
            }
            else
            {
                int push = 2;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
            }
            {
                int push = 4;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
            }
        }
        else
        {
            int push;
            gKTRexState->phaseCounter -= 1;
            push = 2;
            if (Stack_IsFull(gKTRexState->stack) == 0)
            {
                Stack_Push(gKTRexState->stack, &push);
            }
        }
        ktrexlevel_updatePathGameBits();
        (*gCameraInterface)->loadTriggeredCamAction(3, 0, 0);
        mainSetBits(GAMEBIT_DR_KTrexPhaseCounter, gKTRexState->phaseCounter);
        {
            int popped = 0;
            if (Stack_IsEmpty(gKTRexState->stack) == 0)
            {
                Stack_Pop(gKTRexState->stack, &popped);
            }
            return popped + 1;
        }
    }
    return 0;
}

int ktrex_stateHandlerA09(GameObject* obj, GroundBaddieState* runtime)
{
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 8);
        if ((*gCameraInterface)->getMode() == CAMMODE_DEFAULT)
        {
            (*gCameraInterface)->loadTriggeredCamAction(2, 0, 0);
        }
    }
    else if (runtime->baddie.moveDone != 0)
    {
        gKTRexState->lastPhase = (gKTRexState->timerFA >> 1) & 3;
        gKTRexState->stateTimer = 300.0f;
        Music_Trigger(MUSICTRIG_menu_page, 0);
        Music_Trigger(MUSICTRIG_guard_theme, 1);
        return 11;
    }
    return 0;
}

int ktrex_stateHandlerA08(GameObject* obj, GroundBaddieState* runtime)
{
    void* p;
    p = obj->anim.placementData;
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 7);
        {
            u8* row = (u8*)p + 0x4a;
            gKTRexState->stateTimer =
                (f32)(u32) * (u16*)(row + (gKTRexState->phaseCounter & ~1));
        }
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    }
    else
    {
        if ((gKTRexState->timerFA & 8) != 0 || (gKTRexState->stateTimer -= timeDelta) <= 0.0f)
        {
            if ((gKTRexState->timerFA & 8) != 0)
            {
                gKTRexState->phaseCountdown -= 1;
                runtime->baddie.hitPoints = 3;
            }
            gKTRexState->timerFA &= ~0x10;
            if (gKTRexState->phaseCountdown == 0)
            {
                return 2;
            }
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            return 10;
        }
    }
    return 0;
}

int ktrex_stateHandlerA07(GameObject* obj, GroundBaddieState* runtime)
{
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 6);
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        gKTRexState->phaseCounter += 1;
        ktrexlevel_clearPathGameBits();
        mainSetBits(GAMEBIT_DR_KTrexPhaseCounter, gKTRexState->phaseCounter);
        gKTRexState->timerFA |= 0x10;
        gKTRexState->timerFA &= ~8;
        Music_Trigger(MUSICTRIG_guard_theme, 0);
        Music_Trigger(MUSICTRIG_mammoth_walk, 0);
        Music_Trigger(MUSICTRIG_menu_page, 1);
    }
    else if (runtime->baddie.moveDone != 0 || (gKTRexState->timerFA & 8) != 0)
    {
        return 9;
    }
    return 0;
}

int ktrex_stateHandlerA06(GameObject* obj, GroundBaddieState* runtime)
{
    int slot;
    if (runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 5);
    }
    else if (runtime->baddie.moveDone != 0)
    {
        slot = 0;
        if (Stack_IsEmpty(gKTRexState->stack) == 0)
        {
            Stack_Pop(gKTRexState->stack, &slot);
        }
        return slot + 1;
    }
    return 0;
}

int ktrex_stateHandlerA05(GameObject* obj, GroundBaddieState* runtime)
{
    void* p;
    int pushLo;
    int pushHi;
    p = (obj)->anim.placementData;
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 1);
        gKTRexState->laneIndex = 1;
        p = (char*)p + gKTRexState->laneIndex * 4;
        runtime->baddie.animSpeedC = ((KtrexPlacement*)p)->laneSpeeds[0] / 1000.0f;
    }
    if (RandomTimer_UpdateRangeTrigger(&gKTRexState->breathSfxTimer, 2.0f, 4.0f) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexbreathout11);
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        gKTRexState->pathCountdown -= 1;
        if (gKTRexState->pathCountdown <= 0)
        {
            pushLo = 2;
            if (Stack_IsFull(gKTRexState->stack) == 0)
            {
                Stack_Push(gKTRexState->stack, &pushLo);
            }
        }
        else
        {
            pushHi = 5;
            if (Stack_IsFull(gKTRexState->stack) == 0)
            {
                Stack_Push(gKTRexState->stack, &pushHi);
            }
        }
        return 4;
    }
    if (ktrex_isPlayerInLaneThreatRange(obj) != 0)
    {
        return 8;
    }
    return 0;
}

int ktrex_stateHandlerA04(GameObject* obj, GroundBaddieState* runtime)
{
    void* p;
    int popped;
    f32 timer;
    p = obj->anim.placementData;
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 4);
        gKTRexState->stateTimer =
            (f32)(u32)((u16*)((char*)p + 0x44))[gKTRexState->moveVariant];
    }
    else
    {
        timer = gKTRexState->stateTimer - timeDelta;
        gKTRexState->stateTimer = timer;
        if (timer < 0.0f)
        {
            gKTRexState->stateTimer = 0.0f;
        }
        if (runtime->baddie.moveDone != 0)
        {
            if (gKTRexState->stateTimer <= 0.0f)
            {
                popped = 0;
                if (Stack_IsEmpty(gKTRexState->stack) == 0)
                {
                    Stack_Pop(gKTRexState->stack, &popped);
                }
                return popped + 1;
            }
        }
    }
    return 0;
}

int ktrex_stateHandlerA03(GameObject* obj, GroundBaddieState* runtime)
{
    int phase;
    f32 f4;
    f32 f5;
    int popped;
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 2);
    }
    else if (runtime->baddie.moveDone != 0)
    {
        phase = (gKTRexState->timerFA >> 1) & 3;
        f5 = gKTRexState->rowBX[phase] -
             gKTRexState->rowAX[phase];
        f4 = gKTRexState->rowBZ[phase] -
             gKTRexState->rowAZ[phase];
        if (__fabs(f5) > __fabs(f4))
        {
            f4 = (obj->anim.localPosX - gKTRexState->rowAX[phase]) /
                 f5;
        }
        else
        {
            f4 = (obj->anim.localPosZ - gKTRexState->rowAZ[phase]) /
                 f4;
        }
        gKTRexState->laneLerpT = f4;
        popped = 0;
        if (Stack_IsEmpty(gKTRexState->stack) == 0)
        {
            Stack_Pop(gKTRexState->stack, &popped);
        }
        return popped + 1;
    }
    return 0;
}

int ktrex_stateHandlerA02(GameObject* obj, GroundBaddieState* runtime)
{
    void* p;
    u16 flags;
    u8 phase;
    int idx;
    int flag1;
    u8* pb;
    p = obj->anim.placementData;
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        (*gPlayerInterface)->setState(obj, runtime, 1);
        gKTRexState->laneIndex = 0;
        gKTRexState->timerFA &= ~0x20;
        {
            u8* row = (u8*)p + 0x38;
            runtime->baddie.animSpeedC =
                *(f32*)(row + gKTRexState->laneIndex * 4) / 1000.0f;
        }
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        int push = 2;
        if (Stack_IsFull(gKTRexState->stack) == 0)
        {
            Stack_Push(gKTRexState->stack, &push);
        }
        return 4;
    }
    flags = gKTRexState->timerFA;
    flag1 = flags & 1;
    if (gKTRexState->laneIndex == 0 &&
        (phase = gKTRexState->phaseCounter) >= 2 && (flags & 0x20) == 0 &&
        ((flag1 == 0 && gKTRexState->laneLerpT >= 0.7f) ||
         (flag1 != 0 && gKTRexState->laneLerpT <= 0.3f)))
    {
        idx = phase >> 1;
        pb = (u8*)p;
        if (randomGetRange(0, 0x64) <= pb[idx + 0x56])
        {
            int push;
            gKTRexState->pathCountdown = 2;
            push = 5;
            if (Stack_IsFull(gKTRexState->stack) == 0)
            {
                Stack_Push(gKTRexState->stack, &push);
            }
            gKTRexState->moveVariant = 1;
            return 5;
        }
        if (randomGetRange(0, 0x64) <= pb[idx + 0x52])
        {
            u8 cond;
            u8 fe = gKTRexState->currentLaneMask;
            if (fe == 1)
            {
                cond = gKTRexState->activeLaneMask == 2;
            }
            else if (fe == 2)
            {
                cond = gKTRexState->activeLaneMask == 1;
            }
            else if (fe == 4)
            {
                cond = gKTRexState->activeLaneMask == 8;
            }
            else
            {
                cond = gKTRexState->activeLaneMask == 4;
            }
            if (cond && (gKTRexState->timerFA & 0x40) == 0)
            {
                int push;
                gKTRexState->moveVariant = 0;
                push = 0xb;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
                return 5;
            }
        }
        gKTRexState->timerFA |= 0x20;
    }
    if ((gKTRexState->currentLaneMask & gKTRexState->activeLaneMask) != 0)
    {
        gKTRexState->timerFA &= ~0x40;
        {
            if (ktrex_hasLaneLerpOvershot() != 0)
            {
                int push;
                gKTRexState->pathCountdown = 1;
                push = 5;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
                gKTRexState->moveVariant = 1;
                return 5;
            }
        }
    }
    return 0;
}

int ktrex_stateHandlerA01(GameObject* obj, GroundBaddieState* runtime)
{
    if ((s8)runtime->baddie.moveJustStartedB != 0)
    {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        runtime->baddie.hasTarget = 0;
        runtime->baddie.physicsActive = 0;
        gKTRexState->stateTimer = 60.0f;
    }
    else
    {
        gKTRexState->stateTimer -= timeDelta;
        if (gKTRexState->stateTimer <= 30.0f)
        {
            if (obj->userData2 != 3)
            {
                (*gScreenTransitionInterface)->start(30, SCREEN_TRANSITION_BLACK);
                obj->userData2 = 3;
            }
        }
        if (gKTRexState->stateTimer <= 0.0f)
        {
            Obj_SetModelColorFadeRecursive(Obj_GetPlayerObject(), 0, 0, 0, 0, 0);
            Music_Trigger(MUSICTRIG_mammoth_walk, 0);
            Music_Trigger(MUSICTRIG_menu_page, 0);
            Music_Trigger(MUSICTRIG_guard_theme, 0);
            (&obj->anim)->bankIndex = 1;
            mainSetBits(GAMEBIT_WC_Unk0564, 1);
            mainSetBits(GAMEBIT_WC_ObjGroups, 0);
            (*gMapEventInterface)->setObjGroupStatus(13, 0, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 1, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 5, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 10, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 11, 1);
            mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
            unlockLevel(53, 1, 0);
            mainSetBits(GAMEBIT_ITEM_FireSpellStone2_Got, 1);
            (*gMapEventInterface)->setMapAct(4, 2);
        }
    }
    return 0;
}

int ktrex_stateHandlerA00(void)
{
    return 0x0;
}

int ktrex_stateHandlerB08(GameObject* obj, GroundBaddieState* runtime)
{
    if (runtime->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 13, 0.0f, 0);
        runtime->baddie.moveSpeed =
            0.0017f + 0.0012f * (f32)(int)(gKTRexState->phaseCounter >> 1);
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexroarlng11);
    }
    if ((gKTRexRuntime->baddie.eventFlags & 1) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~1;
        gKTRexState->phaseFlags |= 0x2000;
    }
    return 0;
}

int ktrex_stateHandlerB07(GameObject* obj, GroundBaddieState* runtime)
{
    if (runtime->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 12, 0.0f, 0);
        runtime->baddie.moveSpeed = 0.01f;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 1) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~1;
        gKTRexState->phaseFlags |= 0x2000;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 0x80) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~0x80;
        gKTRexState->phaseFlags |= 0x40000LL;
    }
    return 0;
}

int ktrex_stateHandlerB06(GameObject* obj, GroundBaddieState* runtime)
{
    f32 z;
    if (runtime->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 11, 0.0f, 0);
        Sfx_PlayFromObject(obj, SFXTRIG_rexelctro11);
        runtime->baddie.moveSpeed = 0.006f;
        z = 0.0f;
        runtime->baddie.animSpeedA = z;
        runtime->baddie.animSpeedB = z;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 1) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~1;
        gKTRexState->phaseFlags |= 0x80000LL;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 0x80) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~0x80;
        gKTRexState->phaseFlags |= 0x20000LL;
    }
    return 0;
}

int ktrex_stateHandlerB05(GameObject* obj, GroundBaddieState* runtime)
{
    f32 z;
    if (runtime->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gKTRexMoveIdByLaneB05[gKTRexState->laneIndex], 0.0f, 0);
        runtime->baddie.moveSpeed = 0.005f;
        z = 0.0f;
        runtime->baddie.animSpeedA = z;
        runtime->baddie.animSpeedB = z;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 1) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~1;
        gKTRexState->phaseFlags |= 0x200;
    }
    return 0;
}

int ktrex_stateHandlerB04(GameObject* obj, GroundBaddieState* runtime)
{
    f32 z;
    u16 mask;
    if (runtime->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gKTRexMoveIdByVariantB04[gKTRexState->moveVariant], 0.0f, 0);
        runtime->baddie.moveSpeed = gKTRexCurvePhaseByVariantB04[gKTRexState->moveVariant];
        z = 0.0f;
        runtime->baddie.animSpeedA = z;
        runtime->baddie.animSpeedB = z;
    }
    mask = gKTRexPhaseFlagsByVariantB04[gKTRexState->moveVariant];
    if ((gKTRexRuntime->baddie.eventFlags & 1) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~1;
        gKTRexState->phaseFlags |= mask;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 0x200) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~0x200;
        gKTRexState->phaseFlags |= 0x800;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 0x400) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~0x400;
        gKTRexState->phaseFlags |= 0x1000;
    }
    return 0;
}

int ktrex_stateHandlerB03(GameObject* obj, GroundBaddieState* runtime)
{
    f32 z;
    u16 dir;
    dir = gKTRexState->timerFA & 1;
    if (runtime->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 15, 0.0f, 0);
        runtime->baddie.moveSpeed = 0.005f;
        z = 0.0f;
        runtime->baddie.animSpeedA = z;
        runtime->baddie.animSpeedB = z;
        gKTRexState->homeYaw = (obj)->anim.rotX;
    }
    if (dir != 0)
    {
        (obj)->anim.rotX =
            32768.0f * (obj)->anim.currentMoveProgress + (f32)(int)gKTRexState->homeYaw;
    }
    else
    {
        (obj)->anim.rotX =
            (f32)(int)gKTRexState->homeYaw - 32768.0f * (obj)->anim.currentMoveProgress;
    }
    return 0;
}

int ktrex_stateHandlerB02(GameObject* obj, GroundBaddieState* runtime)
{
    u16 dir;
    f32 tmpY;
    int lane;
    MatrixTransform pos;
    f32 mtx[16];

    dir = gKTRexState->timerFA & 1;
    if (runtime->baddie.moveJustStartedA != 0)
    {
        lane = gKTRexState->laneIndex * 2;
        ObjAnim_SetCurrentMove(obj, gKTRexTurnMoveIdByLaneAndDir[lane + dir], 0.0f, 0);
        runtime->baddie.moveSpeed = gKTRexTurnCurvePhaseByLane[gKTRexState->laneIndex];
        gKTRexState->homeYaw = (obj)->anim.rotX;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 4) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~4;
        gKTRexState->phaseFlags |= 1;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 2) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~2;
        gKTRexState->phaseFlags |= 2;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 1) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~1;
        gKTRexState->phaseFlags |= 0x40;
    }
    if ((gKTRexRuntime->baddie.eventFlags & 0x80) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~0x80;
        gKTRexState->phaseFlags |= 0x10000LL;
    }
    runtime->baddie.movementFlags |= 1;
    (*gPlayerInterface)->updateAnimRootMotion(obj, runtime, timeDelta, 3);
    pos.rotX = gKTRexState->homeYaw;
    pos.rotY = 0;
    pos.rotZ = 0;
    pos.scale = 1.0f;
    pos.x = 0.0f;
    pos.y = 0.0f;
    pos.z = 0.0f;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, runtime->baddie.animSpeedB, 0.0f,
                          -runtime->baddie.animSpeedA, &(obj)->anim.velocityX, &tmpY,
                          &(obj)->anim.velocityZ);
    if (dir != 0)
    {
        (obj)->anim.rotX =
            16384.0f * (obj)->anim.currentMoveProgress + (f32)(int)gKTRexState->homeYaw;
    }
    else
    {
        (obj)->anim.rotX =
            (f32)(int)gKTRexState->homeYaw - 16384.0f * (obj)->anim.currentMoveProgress;
    }
    return 0;
}

int ktrex_stateHandlerB01(GameObject* obj, GroundBaddieState* runtime)
{
    f32 z;
    u16 mask;
    int maskI;
    f32 dx;
    f32 dz;
    if (runtime->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gKTRexWalkMoveIdByLane[gKTRexState->laneIndex], 0.0f, 0);
        z = 0.0f;
        runtime->baddie.animSpeedA = z;
        runtime->baddie.animSpeedB = z;
    }
    mask = gKTRexWalkPhaseFlagsByLaneEvent4[gKTRexState->laneIndex];
    if ((gKTRexRuntime->baddie.eventFlags & 4) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~4;
        gKTRexState->phaseFlags |= mask;
    }
    mask = gKTRexWalkPhaseFlagsByLaneEvent2[gKTRexState->laneIndex];
    if ((gKTRexRuntime->baddie.eventFlags & 2) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~2;
        gKTRexState->phaseFlags |= mask;
    }
    if (gKTRexState->laneAltSelect != 0)
    {
        mask = gKTRexWalkEndPhaseFlagsByLaneAlt[gKTRexState->laneIndex];
    }
    else
    {
        mask = gKTRexWalkEndPhaseFlagsByLane[gKTRexState->laneIndex];
    }
    maskI = mask;
    if ((gKTRexRuntime->baddie.eventFlags & 1) != 0)
    {
        gKTRexRuntime->baddie.eventFlags &= ~1;
        gKTRexState->phaseFlags |= maskI;
    }
    dx = oneOverTimeDelta * (gKTRexState->posX - (obj)->anim.localPosX);
    dz = oneOverTimeDelta * (gKTRexState->posZ - (obj)->anim.localPosZ);
    ObjAnim_SampleRootCurvePhase(&obj->anim, sqrtf(dx * dx + dz * dz),
                                 &runtime->baddie.moveSpeed);
    (obj)->anim.localPosX = gKTRexState->posX;
    (obj)->anim.localPosZ = gKTRexState->posZ;
    return 0;
}

int ktrex_stateHandlerB00(GameObject* obj, GroundBaddieState* runtime)
{
    if (runtime->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
    }
    runtime->baddie.moveSpeed = 0.01f;
    return 0;
}

static inline f32* KTRex_GetActiveContactPointTable(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    u8* model = (u8*)objAnim->banks[objAnim->bankIndex];
    return *(f32**)(model + 0x50);
}

void ktrex_updateContactEffects(GameObject* obj, GroundBaddieState* runtime)
{
    int hitType;
    u32 hitC;
    GameObject* hitA;
    KtrexMsgBlob msg;
    int hit;
    f32* contactPoints;
    f32* pt;
    msg = gKTRexMsgTemplate;
    if (gKTRexContactEffectCooldown != 0)
    {
        gKTRexContactEffectCooldown -= 1;
    }
    if (gKTRexRuntime->glowAlpha > 0.0f)
    {
        gKTRexRuntime->glowAlpha =
            timeDelta * gKTRexRuntime->glowRate + gKTRexRuntime->glowAlpha;
        if (gKTRexRuntime->glowAlpha < 0.0f)
        {
            gKTRexRuntime->glowAlpha = 0.0f;
        }
        else if (gKTRexRuntime->glowAlpha > 120.0f)
        {
            gKTRexRuntime->glowAlpha =
                120.0f - (gKTRexRuntime->glowAlpha - 120.0f);
            gKTRexRuntime->glowRate = -gKTRexRuntime->glowRate;
        }
    }
    hit = ObjHits_GetPriorityHit(obj, &hitA, &hitType, &hitC);
    if (hit == 0)
    {
        return;
    }
    contactPoints = *(f32**)((u8*)(&obj->anim)->banks[(&obj->anim)->bankIndex] + 0x50);
    if (runtime->baddie.hitPoints != 0 && (hitType == 3 || hitType == 2) &&
        (gKTRexState->timerFA & 0x10) != 0 && hit == 5)
    {
        gKTRexEffectSpawnWork.posX = playerMapOffsetX + (pt = contactPoints + hitType * 4)[1];
        gKTRexEffectSpawnWork.posY = pt[2];
        gKTRexEffectSpawnWork.posZ = playerMapOffsetZ + pt[3];
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexhurt12);
        Sfx_PlayFromObject(obj, SFXTRIG_wp_stftest122);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4b2, &gKTRexEffectSpawnWork, 0x200001, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4b3, &gKTRexEffectSpawnWork, 0x200001, -1, NULL);
        if (hit == 0xe)
        {
            runtime->baddie.hitPoints -= 1;
        }
        else
        {
            runtime->baddie.hitPoints = 0;
        }
        if (runtime->baddie.hitPoints <= 0)
        {
            runtime->baddie.hitPoints = 0;
            gKTRexState->timerFA &= ~0x10;
            gKTRexState->timerFA |= 0x8;
        }
        runtime->baddie.lastHitPriority = hit;
    }
    else if (gKTRexContactEffectCooldown == 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_95);
        contactPoints = KTRex_GetActiveContactPointTable(obj);
        gKTRexEffectSpawnWork.posX = contactPoints[hitType * 4 + 1] + playerMapOffsetX;
        gKTRexEffectSpawnWork.posY = contactPoints[hitType * 4 + 2];
        gKTRexEffectSpawnWork.posZ = contactPoints[hitType * 4 + 3] + playerMapOffsetZ;
        (*gPartfxInterface)->spawnObject((void*)obj, KTREX_PARTFX_HIT, &gKTRexEffectSpawnWork, 0x200001, -1, NULL);
        gKTRexEffectSpawnWork.posX -= obj->anim.worldPosX;
        gKTRexEffectSpawnWork.posY -= obj->anim.worldPosY;
        gKTRexEffectSpawnWork.posZ -= obj->anim.worldPosZ;
        gKTRexEffectSpawnWork.unk8 = 1.0f;
        gKTRexEffectSpawnWork.unk0 = 0;
        gKTRexEffectSpawnWork.unk2 = 0;
        gKTRexEffectSpawnWork.unk4 = 0;
        msg.w[1] += randomGetRange(0, 0x9b);
        msg.w[2] += randomGetRange(0, 0x9b);
        (*gKTRexResource)
            ->spawn(obj, 0, (PartFxSpawnParams*)&gKTRexEffectSpawnWork, 1, -1,
                    (StaffCollisionColorArgs*)msg.w);
        gKTRexContactEffectCooldown = 0x3c;
    }
    if (runtime->baddie.hitPoints < 1)
    {
        runtime->baddie.hitPoints = 0;
    }
    ObjMsg_SendToObject(hitA, KTREX_ADVANCE_MSG, obj, 0);
}

void ktrex_updateAttackEffects(GameObject* obj)
{
    int i;
    f32 mag;
    mag = 1.0f - gKTRexRuntime->baddie.targetDistance / 2000.0f;
    if (mag < 0.0f)
    {
        mag = 0.0f;
    }
    else if (mag > 1.0f)
    {
        mag = 1.0f;
    }
    if ((gKTRexState->phaseFlags & 0x40) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexroarsht11);
    }
    if ((gKTRexState->phaseFlags & 0x80) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexroarmed11);
    }
    if ((gKTRexState->phaseFlags & 0x100) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexroarlng11);
    }
    if ((gKTRexState->phaseFlags & 0x200) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexexhale16);
    }
    if ((gKTRexState->phaseFlags & 0x10000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_en_fireup_c);
    }
    if ((gKTRexState->phaseFlags & 0x40000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexthrash11);
    }
    if ((gKTRexState->phaseFlags & 0x80000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexhurt12);
    }
    if ((gKTRexState->phaseFlags & 0x2000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexhurt12);
    }
    if ((gKTRexState->phaseFlags & 0x1000) != 0)
    {
        gKTRexState->phaseFlags &= ~0x1800LL;
    }
    if ((gKTRexState->phaseFlags & 0x20000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_en_fireup_c);
        CameraShake_Enable();
        CameraShake_SetOffset(2.0f * mag);
    }
    if ((gKTRexState->timerFA & 0x10) != 0)
    {
        for (i = 0; i < KTREX_LIGHTNING_COUNT; i++)
        {
            if (randomGetRange(0, 5) == 0 && gKTRexState->lightning[i] == NULL)
            {
                ((void (*)(GameObject*, int, f32, int))ktrex_spawnRandomEnergyArc)(obj, randomGetRange(8, 0xc), 100.0f, i);
            }
        }
    }
    if ((gKTRexState->phaseFlags & 0x4000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexbreathin11);
        gKTRexState->laneAltSelect ^= 1;
    }
    if ((gKTRexState->phaseFlags & 0x8000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexbreathout11);
        gKTRexState->laneAltSelect ^= 1;
    }
    if ((gKTRexState->phaseFlags & 0x3) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexfoot11);
        doRumble(4.0f);
        if (mag > 0.1f)
        {
            CameraShake_Enable();
            CameraShake_SetOffset(mag);
            mainSetBits(0x554, 1);
        }
    }
    if ((gKTRexState->phaseFlags & 0xc) != 0)
    {
        doRumble(8.0f);
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexfoot11_91);
        if (mag > 0.1f)
        {
            CameraShake_Enable();
            CameraShake_SetOffset(2.0f * mag);
            mainSetBits(0x554, 1);
        }
    }
    if ((gKTRexState->phaseFlags & 0x30) != 0)
    {
        doRumble(12.0f);
        Sfx_PlayFromObject(obj, SFXTRIG_dn_rexfoot11_92);
        if (mag > 0.1f)
        {
            CameraShake_Enable();
            CameraShake_SetOffset(3.0f * mag);
            mainSetBits(0x554, 1);
        }
    }
    if ((gKTRexState->phaseFlags & 0x100000) == 0)
    {
        gKTRexState->phaseFlags &= 0x1800LL;
        return;
    }
    if ((gKTRexState->phaseFlags & 0x1) != 0)
    {
        gKTRexState->spawnWork[1].unk8 = 1.0f;
        for (i = 0; i < 10; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x2) != 0)
    {
        gKTRexState->spawnWork[2].unk8 = 1.0f;
        for (i = 0; i < 10; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x4) != 0)
    {
        gKTRexState->spawnWork[1].unk8 = 1.5f;
        for (i = 0; i < 13; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x8) != 0)
    {
        gKTRexState->spawnWork[2].unk8 = 1.5f;
        for (i = 0; i < 13; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x10) != 0)
    {
        gKTRexState->spawnWork[1].unk8 = 2.0f;
        for (i = 0; i < 16; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, &gKTRexState->spawnWork[1], 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x20) != 0)
    {
        gKTRexState->spawnWork[2].unk8 = 2.0f;
        for (i = 0; i < 16; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, &gKTRexState->spawnWork[2], 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x800) != 0)
    {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, 0x487, &gKTRexState->spawnWork[0], 0x200001, -1, &gKTRexState->vecX);
    }
    gKTRexState->phaseFlags &= 0x1800LL;
    if (((ObjHitsPriorityState*)(obj)->anim.hitReactState)->lastHitObject == (int)Obj_GetPlayerObject())
    {
        Sfx_PlayFromObject(Obj_GetPlayerObject(), SFXTRIG_mv_bflconc1_2b9);
    }
}

int ktrex_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    int i;
    animUpdate->movementState = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            gKTRexState->phaseFlags |= 4;
            break;
        case 2:
            gKTRexState->phaseFlags |= 8;
            break;
        case 3:
            gKTRexState->phaseFlags |= 0x800;
            break;
        case 4:
            gKTRexState->phaseFlags |= 0x1000;
            break;
        case 5:
            gKTRexState->phaseFlags |= 0x20000LL;
            break;
        case 6:
            if (gKTRexState->light != NULL)
            {
                ModelLightStruct_free(gKTRexState->light);
                gKTRexState->light = NULL;
            }
            break;
        }
    }
    ktrex_updateAttackEffects(obj);
    if ((obj)->userData2 == 0)
    {
        (obj)->userData2 = 1;
    }
    else if ((obj)->userData2 == 3)
    {
        (obj)->userData2 = 4;
    }
    return 0;
}

int ktrex_updateArenaPathProgress(GroundBaddieState* runtime)
{
    u16 flags;
    int phase;
    int dir;
    f32 speed;
    int changed;

    changed = 0;
    flags = gKTRexState->timerFA;
    dir = flags & 1;
    phase = (flags >> 1) & 3;
    if (dir != 0)
    {
        speed = -runtime->baddie.animSpeedC;
    }
    else
    {
        speed = runtime->baddie.animSpeedC;
    }
    gKTRexState->laneLerpT = speed * timeDelta + gKTRexState->laneLerpT;
    if ((gKTRexState->laneLerpT > gKTRexLaneTuning.speedMax[gKTRexState->laneIndex] &&
         speed > 0.0f) ||
        (gKTRexState->laneLerpT < gKTRexLaneSpeedMin[gKTRexState->laneIndex] &&
         speed < 0.0f))
    {
        if (dir != 0)
        {
            phase--;
            if (phase < 0)
            {
                phase = 3;
            }
        }
        else
        {
            phase++;
            if (phase >= 4)
            {
                phase = 0;
            }
        }
        gKTRexState->timerFA = gKTRexState->timerFA & ~6;
        gKTRexState->timerFA = gKTRexState->timerFA | (phase << 1);
        if (gKTRexState->laneLerpT > gKTRexLaneTuning.speedMax[gKTRexState->laneIndex])
        {
            gKTRexState->laneLerpT = gKTRexLaneTuning.speedMax[gKTRexState->laneIndex];
        }
        else if (gKTRexState->laneLerpT <
                 gKTRexLaneSpeedMin[gKTRexState->laneIndex])
        {
            gKTRexState->laneLerpT = gKTRexLaneSpeedMin[gKTRexState->laneIndex];
        }
        changed = 1;
    }
    gKTRexState->posX =
        gKTRexState->laneLerpT * (gKTRexState->rowBX[phase] -
                                                      gKTRexState->rowAX[phase]) +
        gKTRexState->rowAX[phase];
    gKTRexState->posY =
        gKTRexState->laneLerpT * (gKTRexState->rowBY[phase] -
                                                      gKTRexState->rowAY[phase]) +
        gKTRexState->rowAY[phase];
    gKTRexState->posZ =
        gKTRexState->laneLerpT * (gKTRexState->rowBZ[phase] -
                                                      gKTRexState->rowAZ[phase]) +
        gKTRexState->rowAZ[phase];
    return changed;
}

int ktrex_isPlayerInLaneThreatRange(GameObject* obj)
{
    u8 state = gKTRexState->laneMode;
    f32 center;
    f32 lo;
    f32 hi;
    if (state == 0)
    {
        return 0;
    }
    switch (state)
    {
    case 1:
    case 2:
        center = obj->anim.localPosZ;
        lo = (center - 175.0f) - gKTRexMapBlock->worldZ;
        hi = (175.0f + center) - gKTRexMapBlock->worldZ;
        if (lo > -640.0f || hi < -640.0f)
        {
            return 0;
        }
        return 1;
    case 4:
    case 8:
        center = obj->anim.localPosX;
        lo = (center - 175.0f) - gKTRexMapBlock->worldX;
        hi = (175.0f + center) - gKTRexMapBlock->worldX;
        if (lo > 640.0f || hi < 640.0f)
        {
            return 0;
        }
        return 1;
    }
    return 0;
}

void ktrex_func0B(void)
{
}

int ktrex_getControlMode(GameObject* obj)
{
    KtrexState* p = obj->extra;
    gKTRexRuntime = (GroundBaddieState*)p;
    return p->controlMode;
}

int ktrex_getExtraSize(void)
{
    return 0x5a4;
}

int ktrex_getObjectTypeId(void)
{
    return 0x49;
}

void ktrex_free(GameObject* obj)
{
    int i;
    gKTRexRuntime = obj->extra;
    objFreeObjectType(obj, KTREX_OBJGROUP);
    (*gBaddieControlInterface)->releaseState(obj, gKTRexRuntime, 0);
    Stack_Free(gKTRexState->stack);
    if (gKTRexResource != NULL)
    {
        Resource_Release(gKTRexResource);
    }
    if (gKTRexState->light != 0)
    {
        ModelLightStruct_free(gKTRexState->light);
    }
    for (i = 0; i < KTREX_LIGHTNING_COUNT; i++)
    {
        void* m = gKTRexState->lightning[i];
        if (m != 0)
        {
            mm_free(m);
        }
    }
    gKTRexResource = NULL;
    Music_Trigger(MUSICTRIG_mammoth_walk, 0);
    Music_Trigger(MUSICTRIG_menu_page, 0);
    Music_Trigger(MUSICTRIG_guard_theme, 0);
}

void ktrex_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    f32 m[12];
    f32 zero = 0.0f;
    void* e;
    int i;

    gKTRexRuntime = (obj)->extra;
    if (visible == 0)
    {
        return;
    }
    switch ((obj)->userData1)
    {
    case 0:
        break;
    default:
        return;
    }
    if (gKTRexState->light != NULL)
    {
        queueGlowRender(gKTRexState->light);
    }
    for (i = 0; i < KTREX_LIGHTNING_COUNT; i++)
    {
        e = gKTRexState->lightning[i];
        if (e != NULL)
        {
            lightningRender((LightningEffect*)e);
            ((LightningEffect*)gKTRexState->lightning[i])->timer =
                (f32)(u32)((LightningEffect*)gKTRexState->lightning[i])->timer + timeDelta;
            if (((LightningEffect*)gKTRexState->lightning[i])->timer >=
                ((LightningEffect*)gKTRexState->lightning[i])->lifetime)
            {
                mm_free(gKTRexState->lightning[i]);
                gKTRexState->lightning[i] = NULL;
            }
        }
    }
    if (gKTRexRuntime->glowAlpha != zero)
    {
        objSetGlowColor(200, 0, 0, (int)gKTRexRuntime->glowAlpha);
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    ObjPath_GetPointWorldPosition(obj, 1, &gKTRexState->spawnWork[1].posX, &gKTRexState->spawnWork[1].posY,
                                  &gKTRexState->spawnWork[1].posZ, 0);
    ObjPath_GetPointWorldPosition(obj, 2, &gKTRexState->spawnWork[2].posX, &gKTRexState->spawnWork[2].posY,
                                  &gKTRexState->spawnWork[2].posZ, 0);
    ObjPath_GetPointWorldPosition(obj, 3, &gKTRexState->spawnWork[3].posX, &gKTRexState->spawnWork[3].posY,
                                  &gKTRexState->spawnWork[3].posZ, 0);
    ObjPath_GetPointWorldPosition(obj, 0, &gKTRexState->spawnWork[0].posX, &gKTRexState->spawnWork[0].posY,
                                  &gKTRexState->spawnWork[0].posZ, 0);
    memcpy(m, (void*)ObjPath_GetPointModelMtx(obj, 4), 48);
    gKTRexState->vecX = 0.1f * (f32)randomGetRange(-50, 50);
    gKTRexState->vecY = 0.1f * (f32)randomGetRange(60, 120);
    gKTRexState->vecZ = -0.25f * (f32)randomGetRange(100, 150);
    PSMTXMultVecSR((MtxPtr)m, (Vec*)&gKTRexState->vecX, (Vec*)&gKTRexState->vecX);
    gKTRexState->phaseFlags |= 0x100000LL;
}

void ktrex_hitDetect(GameObject* obj)
{
    f32 z, y, x;
    if (gKTRexState->light != 0)
    {
        ObjPath_GetPointWorldPosition(obj, 5, &x, &y, &z, 0);
        modelLightStruct_setPosition(gKTRexState->light, x, y, z);
        modelLightStruct_updateGlowAlpha(gKTRexState->light);
    }
}

void ktrex_update(GameObject* obj)
{
    GroundBaddieState* runtime;
    GameObject* player;
    f32 d[3];
    f32* dp;
    int zc[1];
    u8 zm[1];
    s16* bitA;
    s16* bitB;
    int flags;
    int mm;
    int phase;
    f32 dx, dz, frac;

    if (obj->userData1 != 0)
    {
        return;
    }
    gKTRexRuntime = obj->extra;
    runtime = gKTRexRuntime;
    if (obj->userData2 == 1)
    {
        Music_Trigger(MUSICTRIG_mammoth_walk, 1);
        obj->userData2 = 2;
        runtime->baddie.substate = 11;
        runtime->baddie.moveJustStartedB = 1;
    }
    ObjHits_RegisterActiveHitVolumeObject(obj);
    runtime->baddie.targetObj = Obj_GetPlayerObject();
    if (runtime->baddie.targetObj != NULL)
    {
        player = runtime->baddie.targetObj;
        dp = d;
        for (zc[0] = 0; zc[0] < 3; zc[0]++)
        {
            dp[zc[0]] = (&player->anim.worldPosX)[zc[0]] - (&obj->anim.worldPosX)[zc[0]];
        }
        runtime->baddie.targetDistance = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
    characterDoEyeAnims(obj, &gKTRexRuntime->eyeAnimState);
    zm[0] = 0;
    zc[0] = zm[0];
    bitA = gKTRexLaneEnabledGameBits;
    for (; zc[0] < 4; zc[0]++)
    {
        if (mainGetBit(*bitA) != 0)
        {
            zm[0] |= 1 << zc[0];
        }
        bitA++;
    }
    gKTRexState->activeLaneMask = zm[0];
    player = runtime->baddie.targetObj;
    {
        KTRexArenaState* st = (KTRexArenaState*)gKTRexState;
        phase = (st->timerFA >> 1) & 3;
        dz = st->rowBX[phase] - st->rowAX[phase];
        dx = st->rowBZ[phase] - st->rowAZ[phase];
        if (__fabs(dz) > __fabs(dx))
        {
            frac = (player->anim.localPosX - st->rowAX[phase]) / dz;
        }
        else
        {
            frac = (player->anim.localPosZ - st->rowAZ[phase]) / dx;
        }
    }
    gKTRexState->laneFrac = frac;
    {
        KTRexArenaState* st = (KTRexArenaState*)gKTRexState;

        st->currentLaneMask = ktrex_getLaneMaskForTimer(st->timerFA);
    }
    zm[0] = 0;
    zc[0] = zm[0];
    bitB = gKTRexLaneModeGameBits;
    flags = gKTRexState->currentLaneMask;
    for (; zc[0] < 4; zc[0]++)
    {
        mm = 1 << zc[0];
        if ((flags & mm) != 0 && mainGetBit(*bitB) != 0)
        {
            zm[0] |= mm;
        }
        bitB++;
    }
    gKTRexState->laneMode = zm[0];
    (*gBaddieControlInterface)
        ->processMessages(obj, runtime, &gKTRexRuntime->routeNav, gKTRexRuntime->gameBitB,
                          &gKTRexRuntime->subMode, 2, 2, 0);
    ktrex_updateContactEffects(obj, runtime);
    ktrex_updateAttackEffects(obj);
    (*gBaddieControlInterface)->updateGravity(obj, runtime, 0.0f, 0);
    ObjHits_SetHitVolumeMasks(&obj->anim, 24, 2, 0x1fffff);
    (*gPlayerInterface)->update((void*)obj, runtime, timeDelta, timeDelta, gKTRexStateHandlersB,
                                gKTRexStateHandlersA);
    obj->anim.localPosY = gKTRexState->posY;
}

void ktrex_init(GameObject* obj, char* arg, int flag)
{
    int* base = (int*)gKTRexTurnMoveIdByLaneAndDir;
    int* pA;
    int iv;
    int* pB;
    int* pC;
    GroundBaddieState* rt;
    int i;
    RomCurveDef* cp;
    u8 spawnFlags;
    s16 yaw;
    gKTRexRuntime = (obj)->extra;
    spawnFlags = 0x10;
    if (flag != 0)
    {
        spawnFlags |= 1;
    }
    (*gBaddieControlInterface)
        ->initGroundBaddie(obj, (u8*)arg, (u8*)gKTRexRuntime, 9, 0xc, 0x100, spawnFlags, 20.0f);
    (obj)->animEventCallback = ktrex_animEventCallback;
    rt = (GroundBaddieState*)gKTRexRuntime;
    (*gPlayerInterface)->setState(obj, rt, 0);
    rt->baddie.substate = 2;
    rt->baddie.targetObj = 0;
    rt->baddie.physicsActive = 0;
    rt->baddie.hasTarget = 0;
    (obj)->anim.resetHitboxFlags |= 0x88;
    ObjHits_EnableObject(obj);
    if ((obj)->anim.modelState != NULL)
    {
        (obj)->anim.modelState->flags |= 0x810;
    }
    gKTRexState = gKTRexRuntime->control;
    gKTRexState->stack = Queue_Alloc(4, 4);
    yaw = (s16)((s8)arg[0x2a] << 8);
    (obj)->anim.rotX = yaw;
    gKTRexState->homeYaw = yaw;
    i = 0;
    pA = base + 0x4c / 4;
    iv = 0;
    pB = base + 0x3c / 4;
    pC = base + 0x6c / 4;
    base = base + 0x5c / 4;
    for (; i < 4; i++)
    {
        cp = (RomCurveDef*)(*gRomCurveInterface)->getById(*pA);
        if (cp != NULL)
        {
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneAX[0] = cp->x;
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneAY[0] = cp->y;
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneAZ[0] = cp->z;
            cp = (RomCurveDef*)(*gRomCurveInterface)->getById(*pB);
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneBX[0] = cp->x;
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneBY[0] = cp->y;
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneBZ[0] = cp->z;
            cp = (RomCurveDef*)(*gRomCurveInterface)->getById(*pC);
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneCX[0] = cp->x;
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneCY[0] = cp->y;
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneCZ[0] = cp->z;
            cp = (RomCurveDef*)(*gRomCurveInterface)->getById(*base);
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneDX[0] = cp->x;
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneDY[0] = cp->y;
            ((KTRexArenaState*)((char*)gKTRexState + iv))->laneDZ[0] = cp->z;
        }
        pA++;
        iv += 4;
        pB++;
        pC++;
        base++;
    }
    gKTRexState->rowAX = gKTRexState->laneAX;
    gKTRexState->rowAY = gKTRexState->laneAY;
    gKTRexState->rowAZ = gKTRexState->laneAZ;
    gKTRexState->rowBX = gKTRexState->laneBX;
    gKTRexState->rowBY = gKTRexState->laneBY;
    gKTRexState->rowBZ = gKTRexState->laneBZ;
    gKTRexState->phaseCountdown = 4;
    rt->baddie.hitPoints = 3;
    gKTRexResource = Resource_Acquire(0x5a, 1);
    (obj)->userData2 = 0;
    gKTRexMapBlock = mapGetCurrentRomList();
    gKTRexState->light = objCreateLight(0, 1);
    if (gKTRexState->light != 0)
    {
        modelLightStruct_setLightKind(gKTRexState->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(gKTRexState->light, (obj)->anim.localPosX,
                                     (obj)->anim.localPosY, (obj)->anim.localPosZ);
        modelLightStruct_setDiffuseColor(gKTRexState->light, 0xff, 0, 0, 0);
        modelLightStruct_setDistanceAttenuation(gKTRexState->light, 10.0f, 30.0f);
        modelLightStruct_setupGlow(gKTRexState->light, 0, 0xff, 0, 0, 0x50, 30.0f);
        modelLightStruct_setGlowProjectionRadius(gKTRexState->light, 50.0f);
    }
    Music_StopChannelsByPriorityGroup(3, MUSIC_CHANNEL_STOP_FADE, 0x1f4);
}

void ktrex_release(void)
{
}

void ktrex_initialise(void)
{
    ktrex_initialiseStateHandlerTables();
}

void ktrex_initialiseStateHandlerTables(void)
{
    gKTRexStateHandlersB[0] = ktrex_stateHandlerB00;
    gKTRexStateHandlersB[1] = ktrex_stateHandlerB01;
    gKTRexStateHandlersB[2] = ktrex_stateHandlerB02;
    gKTRexStateHandlersB[3] = ktrex_stateHandlerB03;
    gKTRexStateHandlersB[4] = ktrex_stateHandlerB04;
    gKTRexStateHandlersB[5] = ktrex_stateHandlerB05;
    gKTRexStateHandlersB[6] = ktrex_stateHandlerB06;
    gKTRexStateHandlersB[7] = ktrex_stateHandlerB07;
    gKTRexStateHandlersB[8] = ktrex_stateHandlerB08;
    gKTRexStateHandlersA[0] = ktrex_stateHandlerA00;
    gKTRexStateHandlersA[1] = ktrex_stateHandlerA01;
    gKTRexStateHandlersA[2] = ktrex_stateHandlerA02;
    gKTRexStateHandlersA[3] = ktrex_stateHandlerA03;
    gKTRexStateHandlersA[4] = ktrex_stateHandlerA04;
    gKTRexStateHandlersA[5] = ktrex_stateHandlerA05;
    gKTRexStateHandlersA[6] = ktrex_stateHandlerA06;
    gKTRexStateHandlersA[7] = ktrex_stateHandlerA07;
    gKTRexStateHandlersA[8] = ktrex_stateHandlerA08;
    gKTRexStateHandlersA[9] = ktrex_stateHandlerA09;
    gKTRexStateHandlersA[10] = ktrex_stateHandlerA10;
    gKTRexStateHandlersA[11] = ktrex_stateHandlerA11;
}

void* gKTRexStateHandlersB[10];

void* gKTRexStateHandlersA[12];

s16 gKTRexTurnMoveIdByLaneAndDir[6] = {8, 14, 16, 17, 16, 17};
f32 gKTRexCurvePhaseByVariantB04[3] = {0.006f, 0.003f, 0.003f};
f32 gKTRexTurnCurvePhaseByLane[3] = {0.0055f, 0.012f, 0.012f};

f32 gKTRexLaneSpeedMin[3] = {0.0f, 0.025f, 0.025f};

KTRexLaneTuning gKTRexLaneTuning = {
    {1.0f, 0.975f, 0.975f},
    {
        {205110, 205117, 205096, 205103},
        {205104, 205111, 205091, 205097},
        {205671, 205673, 205674, 205669},
        {205106, 205113, 205092, 205099},
    },
};

ObjectDescriptor12WithPadding gKtRexObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
        (ObjectDescriptorCallback)ktrex_initialise,
        (ObjectDescriptorCallback)ktrex_release,
        0,
        (ObjectDescriptorCallback)ktrex_init,
        (ObjectDescriptorCallback)ktrex_update,
        (ObjectDescriptorCallback)ktrex_hitDetect,
        (ObjectDescriptorCallback)ktrex_render,
        (ObjectDescriptorCallback)ktrex_free,
        (ObjectDescriptorCallback)ktrex_getObjectTypeId,
        ktrex_getExtraSize,
        (ObjectDescriptorCallback)ktrex_getControlMode,
        (ObjectDescriptorCallback)ktrex_func0B,
    },
    0,
};
