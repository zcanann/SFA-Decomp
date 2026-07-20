/* DLL 0x1AD - SHThorntail [801D58E4-801D5ED4) */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/objprint_character_api.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/obj_trigger.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"
#include "main/frustum.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/SH/shthorntail_ai.h"
#include "main/dll/SH/dll_01B0_shswapston.h"
#include "main/newshadows_audio_api.h"
#include "main/dll/path_control_interface.h"

typedef struct SHthorntailTailSwingEffectScratch
{
    u8 particleParams[12];
    Vec position;
} SHthorntailTailSwingEffectScratch;

#define THORNTAIL_OBJGROUP 0x4d

#define SHTHORNTAIL_OBJFLAG_RENDERED 0x800
#define SHTHORNTAIL_PARTFX_TAILSWING 0x7f0 /* tail-swing effect (SHthorntailTailSwingEffectScratch) */

#define SHTHORNTAIL_LEVEL_MODE1_GATE_OPEN_GAMEBIT            0x13E
#define SHTHORNTAIL_LEVEL_MODE1_FREEZE_GAMEBIT               0x168
#define SHTHORNTAIL_LEVEL_MODE1_PRIMARY_TRIGGER_GAMEBIT      0xCD5
#define SHTHORNTAIL_LEVEL_MODE1_SECONDARY_TRIGGER_GAMEBIT    0xCD6
#define SHTHORNTAIL_LEVEL_MODE1_CLOSE_ATTACK_DISABLE_GAMEBIT 0x1AB
#define SHTHORNTAIL_LEVEL_MODE0_LOCOMOTION2_GAMEBIT          0x09E
#define SHTHORNTAIL_LEVELCONTROL_AUDIO_CHANNEL               0x7F
#define SHTHORNTAIL_LEVELCONTROL_COLLISION_FLAG              0x40

#define SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES_OFFSET 0x0A0
#define SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES_OFFSET  0x294
#define SHTHORNTAIL_STATE_MOVE_IDS_OFFSET           0x488
#define SHTHORNTAIL_STATE_MOVE_STEP_SCALES_OFFSET   0x4AC
#define SHTHORNTAIL_STATE_FLAGS_OFFSET              0x4F0
#define SHTHORNTAIL_STATE_TRIGGER0_SFX_OFFSET       0x504
#define SHTHORNTAIL_STATE_TRIGGER7_SFX_OFFSET       0x528

#define SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES(tables)                                                                   \
    ((ObjHitReactEntry*)((tables) + SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES_OFFSET))
#define SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES(tables)                                                                    \
    ((ObjHitReactEntry*)((tables) + SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES_OFFSET))
#define SHTHORNTAIL_STATE_MOVE_IDS(tables)         ((s16*)((tables) + SHTHORNTAIL_STATE_MOVE_IDS_OFFSET))
#define SHTHORNTAIL_STATE_MOVE_STEP_SCALES(tables) ((f32*)((tables) + SHTHORNTAIL_STATE_MOVE_STEP_SCALES_OFFSET))
#define SHTHORNTAIL_STATE_FLAGS(tables)            ((u8*)((tables) + SHTHORNTAIL_STATE_FLAGS_OFFSET))
#define SHTHORNTAIL_STATE_TRIGGER0_SFX(tables)     ((u16*)((tables) + SHTHORNTAIL_STATE_TRIGGER0_SFX_OFFSET))
#define SHTHORNTAIL_STATE_TRIGGER7_SFX(tables)     ((u8*)((tables) + SHTHORNTAIL_STATE_TRIGGER7_SFX_OFFSET))

extern f32 SHTHORNTAIL_TIMER_DONE_THRESHOLD;
extern f32 SHTHORNTAIL_CLOSE_ATTACK_DISTANCE;
extern u32 lbl_803E5410;
void SHthorntail_updateLevelControlMode1(u32 objectId, SHthorntailRuntime* runtime, SHthorntailConfig* config)
{
    int playerObj;
    int randomIdleWait;
    u8 closeToPlayer;
    u32 gameBit;
    int triggerIsSet;

    runtime->impactSfxTable = gSHthorntailLevelControlMode1ImpactSfxTable;
    playerObj = (int)Obj_GetPlayerObject();
    {
        int cmp = (double)getXZDistance((f32*)(objectId + 0x18), (f32*)(playerObj + 0x18)) < (double)SHTHORNTAIL_CLOSE_ATTACK_DISTANCE;
        closeToPlayer = cmp;
    }
    if (config->impactSfxVariant == 0)
    {
        gameBit = mainGetBit(SHTHORNTAIL_LEVEL_MODE1_GATE_OPEN_GAMEBIT);
        if (gameBit != 0)
        {
            gameBit = mainGetBit(SHTHORNTAIL_LEVEL_MODE1_FREEZE_GAMEBIT);
            if (gameBit != 0)
            {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_FREEZE_MOTION;
                runtime->freezeFrameCounter = 0;
                closeToPlayer = FALSE;
            }
            else
            {
                triggerIsSet = ObjTrigger_IsSet(objectId);
                if (triggerIsSet != 0)
                {
                    runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
                    mainSetBits(SHTHORNTAIL_LEVEL_MODE1_SECONDARY_TRIGGER_GAMEBIT, 1);
                }
            }
        }
        else
        {
            triggerIsSet = ObjTrigger_IsSet(objectId);
            if (triggerIsSet != 0)
            {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
                mainSetBits(SHTHORNTAIL_LEVEL_MODE1_PRIMARY_TRIGGER_GAMEBIT, 1);
            }
        }
    }
    else
    {
        gameBit = mainGetBit(SHTHORNTAIL_LEVEL_MODE1_CLOSE_ATTACK_DISABLE_GAMEBIT);
        if (gameBit != 0)
        {
            closeToPlayer = FALSE;
        }
    }
    switch (runtime->behaviorState)
    {
    case SHTHORNTAIL_STATE_IDLE:
        if (!closeToPlayer)
        {
            runtime->idleTimer = SHTHORNTAIL_IDLE_COUNTDOWN_TIME;
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
        }
        break;
    case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
        if (closeToPlayer)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        }
        else
        {
            runtime->idleTimer = runtime->idleTimer - timeDelta;
            if (runtime->idleTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD)
            {
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
            }
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING_READY:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
        {
            if (closeToPlayer)
            {
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
            }
            else
            {
                runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
            }
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING:
        if (closeToPlayer)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
        }
        else
        {
            SHthorntail_updateTailSwing(objectId, runtime);
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING_RECOVER:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomIdleWait;
        }
        break;
    }
}

void SHthorntail_updateLevelControlMode0(SHthorntailObject* obj, SHthorntailRuntime* runtime, SHthorntailConfig* config)
{
    int linkedEventPending;
    u32 gameBit;
    int randomIdleWait;
    SHthorntailDataTables* dataTables;

    dataTables = (SHthorntailDataTables*)&gSHthorntailDataTables;
    runtime->impactSfxTable = dataTables->levelMode0DefaultImpactSfxTable;
    switch (runtime->locomotionMode)
    {
    case SHTHORNTAIL_LOCOMOTION_1:
        runtime->impactSfxTable =
            (u8*)dataTables->levelMode0Locomotion1ImpactSfxVariants + config->impactSfxVariant * 2;
        break;
    case SHTHORNTAIL_LOCOMOTION_2:
        gameBit = mainGetBit(SHTHORNTAIL_LEVEL_MODE0_LOCOMOTION2_GAMEBIT);
        if (gameBit != 0)
        {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion2SetImpactSfxVariants + config->impactSfxVariant * 2;
        }
        else
        {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion2ClearImpactSfxVariants + config->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_3:
        gameBit = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT);
        if (gameBit != 0)
        {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion3SetImpactSfxVariants + config->impactSfxVariant * 2;
        }
        else
        {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion3ClearImpactSfxVariants + config->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_5:
        gameBit = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT);
        if (gameBit == 0)
        {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion5ClearImpactSfxVariants + config->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_6:
        linkedEventPending = SHthorntail_HasNearbyPendingEventObject(obj);
        if (linkedEventPending != 0)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
            return;
        }
        if (runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE)
        {
            Sfx_PlayFromObject(0, SHTHORNTAIL_EVENT_RESUME_VOLUME_ID);
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomIdleWait;
        }
        gameBit = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT);
        if (gameBit == 0)
        {
            runtime->impactSfxTable = gSHthorntailLevelControlMode0Locomotion6ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_8:
        runtime->impactSfxTable =
            (u8*)dataTables->levelMode0Locomotion8ImpactSfxVariants + config->impactSfxVariant * 2;
        break;
    }
    SHthorntail_updateState(obj, runtime);
}

u32 SHthorntail_updateLevelControlState(SHthorntailObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    SHthorntailRuntime* runtime;
    int randomIdleWait;
    int impactHandled;
    int levelControlReady;
    int impactPending;

    runtime = obj->runtime;
    levelControlReady = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_LEVELCONTROL_READY);
    if (levelControlReady == 0)
    {
        Sfx_StopObjectChannel((u32)obj, SHTHORNTAIL_LEVELCONTROL_AUDIO_CHANNEL);
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (float)randomIdleWait;
        runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
        runtime->behaviorFlags =
            runtime->behaviorFlags | (SHTHORNTAIL_FLAG_LEVELCONTROL_READY | SHTHORNTAIL_FLAG_FREEZE_MOTION);
        runtime->freezeFrameCounter = 0;
        obj->statusFlags = obj->statusFlags | SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
    }
    impactPending = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_IMPACT_PENDING);
    if (impactPending != 0)
    {
        impactHandled = dll_2E_func07((GameObject*)obj, (ObjSeqState*)animUpdate, (MoveLibState*)runtime, 0, 0);
        if (impactHandled != 0)
        {
            return 0;
        }
        animUpdate->hitVolumePair &= ~SHTHORNTAIL_LEVELCONTROL_COLLISION_FLAG;
        characterDoEyeAnims((GameObject*)obj, runtime->collisionShapeState);
    }
    runtime->activeMoveValid = 0;
    objAudioFn_8006ef38((GameObject*)obj, &animUpdate->animEvents, 8, runtime->renderPathPoints,
                        runtime->moveScratch, 1.0f, 1.0f);
    return 0;
}

int SHthorntail_getExtraSize(void)
{
    return SHTHORNTAIL_EXTRA_STATE_BYTES;
}

void SHthorntail_free(SHthorntailObject* obj)
{
    u32 activeConfigToken;

    activeConfigToken = gSHthorntailActiveConfigToken;
    if (activeConfigToken == obj->config->configToken)
    {
        gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
    }
    ObjGroup_RemoveObject((int)obj, THORNTAIL_OBJGROUP);
}

void SHthorntail_render(SHthorntailObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SHthorntailRuntime* runtime;
    int pointIndex;

    runtime = obj->runtime;
    objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
    dll_2E_func06((GameObject*)obj, (MoveLibState*)runtime, 0);
    pointIndex = 0;
    do
    {
        ObjPath_GetPointWorldPosition((GameObject*)obj, pointIndex, &runtime->renderPathPoints[0].x,
                                      &runtime->renderPathPoints[0].y,
                                      &runtime->renderPathPoints[0].z, 0);
        runtime = (SHthorntailRuntime*)((int)runtime + sizeof(Vec));
        pointIndex = pointIndex + 1;
    } while (pointIndex < SHTHORNTAIL_RENDER_PATH_POINT_COUNT);
}

void SHthorntail_update(int obj)
{
    u8* stateTables;
    SHthorntailRuntime* runtime;
    SHthorntailConfig* config;
    int i;
    s8* eventId;
    u8 hitResult;
    u8 mode;
    ObjHitReactEntry* hitReactEntries;
    int val;
    u32 uval;
    int ref;
    s32 activeConfigToken;
    f32 facingAngleRadians;
    f32 negSinFacing;
    f32 negCosFacing;
    f32 leashDistance;
    ObjAnimEventList animEvents;
    SHthorntailTailSwingEffectScratch effectScratch;

    stateTables = (u8*)&gSHthorntailDataTables;
    runtime = ((SHthorntailObject*)obj)->runtime;
    config = ((SHthorntailObject*)obj)->config;
    if (runtime->behaviorState == '\f')
    {
        if (runtime->effectTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD)
        {
            if ((((SHthorntailObject*)obj)->objectFlags & SHTHORNTAIL_OBJFLAG_RENDERED) != 0)
            {
                ObjPath_GetPointWorldPosition((GameObject*)obj, 4, &effectScratch.position.x, &effectScratch.position.y,
                                              &effectScratch.position.z, 0);
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, SHTHORNTAIL_PARTFX_TAILSWING, effectScratch.particleParams, 0x200001, -1, NULL);
            }
            runtime->effectTimer = 30.0f;
        }
        runtime->effectTimer = runtime->effectTimer - timeDelta;
    }
    runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_LEVELCONTROL_READY;
    if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] & SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT) != 0)
    {
        hitReactEntries = SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES(stateTables);
    }
    else
    {
        hitReactEntries = SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES(stateTables);
    }
    val = 0x19;
    hitResult = runtime->hitReactState =
        ObjHitReact_Update(obj, hitReactEntries, val, runtime->hitReactState, (float*)runtime->hitReactScratch);
    if (hitResult == 0)
    {
        mode = (*gMapEventInterface)->getMapAct((int)((SHthorntailObject*)obj)->animObjId);
        runtime->locomotionMode = mode;
        switch (config->controlMode)
        {
        case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
            SHthorntail_updateLevelControlMode0((SHthorntailObject*)obj, runtime, config);
            break;
        case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
            SHthorntail_updateLevelControlMode1(obj, runtime, config);
            break;
        case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
            SHthorntail_updateRootControlMode2((SHthorntailObject*)obj, runtime);
            break;
        case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
            SHthorntail_updateRootControlMode3((SHthorntailObject*)obj, runtime);
            break;
        }
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] & SHTHORNTAIL_STATE_FLAG_STATUS_ACTIVE) != 0)
        {
            ((SHthorntailObject*)obj)->statusFlags |= SHTHORNTAIL_OBJECT_STATUS_ACTIVE;
        }
        else
        {
            ((SHthorntailObject*)obj)->statusFlags &= ~SHTHORNTAIL_OBJECT_STATUS_ACTIVE;
            ((SHthorntailObject*)obj)->statusFlags &= ~SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
        }
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_FREEZE_MOTION) != 0)
        {
            if (++runtime->freezeFrameCounter > 0xa)
            {
                runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_FREEZE_MOTION;
            }
            else
            {
                ((SHthorntailObject*)obj)->statusFlags |= SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
            }
        }
        if ((int)((SHthorntailObject*)obj)->currentMove != SHTHORNTAIL_STATE_MOVE_IDS(stateTables)[runtime->behaviorState])
        {
            ObjAnim_SetCurrentMove(obj, SHTHORNTAIL_STATE_MOVE_IDS(stateTables)[runtime->behaviorState],
                                   SHTHORNTAIL_TIMER_DONE_THRESHOLD, 0);
            runtime->storedFacingAngle = ((SHthorntailObject*)obj)->facingAngle;
        }
        val = ObjAnim_AdvanceCurrentMove(
            obj, SHTHORNTAIL_STATE_MOVE_STEP_SCALES(stateTables)[runtime->behaviorState], timeDelta, &animEvents);
        if (val != 0)
        {
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        }
        else
        {
            runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        }
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] & SHTHORNTAIL_STATE_FLAG_APPLY_ROOT_MOTION) !=
            0)
        {
            if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
            {
                runtime->storedFacingAngle = ((SHthorntailObject*)obj)->facingAngle;
            }
            facingAngleRadians = (3.1415927f * (f32)(s32)runtime->storedFacingAngle) / 32768.0f;
            negSinFacing = -mathSinf(facingAngleRadians);
            facingAngleRadians = (3.1415927f * (f32)(s32)runtime->storedFacingAngle) / 32768.0f;
            negCosFacing = -mathCosf(facingAngleRadians);
            ((SHthorntailObject*)obj)->modelPos.x = negSinFacing * -animEvents.rootDeltaZ + ((SHthorntailObject*)obj)->modelPos.x;
            ((SHthorntailObject*)obj)->modelPos.z = negCosFacing * -animEvents.rootDeltaZ + ((SHthorntailObject*)obj)->modelPos.z;
            ((SHthorntailObject*)obj)->modelPos.x = negCosFacing * -animEvents.rootDeltaX + ((SHthorntailObject*)obj)->modelPos.x;
            ((SHthorntailObject*)obj)->modelPos.z = negSinFacing * animEvents.rootDeltaX + ((SHthorntailObject*)obj)->modelPos.z;
            ((SHthorntailObject*)obj)->facingAngle += animEvents.rootPitch;
        }
        for (i = 0, eventId = (s8*)&animEvents; i < animEvents.triggerCount; i = i + 1)
        {
            if (eventId[0x13] == '\0')
            {
                if (SHTHORNTAIL_STATE_TRIGGER0_SFX(stateTables)[runtime->behaviorState] != 0)
                {
                    Sfx_PlayFromObject(obj, SHTHORNTAIL_STATE_TRIGGER0_SFX(stateTables)[runtime->behaviorState]);
                }
            }
            else if ((eventId[0x13] == '\a') &&
                     (SHTHORNTAIL_STATE_TRIGGER7_SFX(stateTables)[runtime->behaviorState] != 0))
            {
                Sfx_PlayFromObject(obj, SHTHORNTAIL_STATE_TRIGGER7_SFX(stateTables)[runtime->behaviorState]);
            }
            eventId++;
        }
        objAudioFn_8006ef38((GameObject*)obj, &animEvents, 8, runtime->renderPathPoints, runtime->moveScratch, 1.0f,
                            1.0f);
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
             SHTHORNTAIL_STATE_FLAG_DISABLE_MOVE_CONTROL) != 0)
        {
            runtime->movementControlFlags = runtime->movementControlFlags & ~1;
        }
        else
        {
            runtime->movementControlFlags = runtime->movementControlFlags | 1;
        }
        dll_2E_func03((GameObject*)obj, (MoveLibState*)runtime);
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] & SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT) !=
            0)
        {
            fn_8003B228((GameObject*)obj, runtime->collisionShapeState);
        }
        else
        {
            characterDoEyeAnims((GameObject*)obj, runtime->collisionShapeState);
        }
        runtime->behaviorFlags = runtime->behaviorFlags & ~2;
        if (((runtime->behaviorFlags & 4) == 0) && (val = ObjTrigger_IsSet(obj), val != 0))
        {
            uval = randomGetRange(1, (u32)*runtime->impactSfxTable);
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_IMPACT_PENDING;
            (*gObjectTriggerInterface)->runSequence(*(u8*)(runtime->impactSfxTable + uval), (void*)obj, -1);
        }
        if (config->leashRadiusByte != '\0')
        {
            leashDistance = getXZDistance(&((SHthorntailObject*)obj)->pos.x, (float*)&config->homePos);
            if ((leashDistance > (f32)(s32)((u32)config->leashRadiusByte * (u32)config->leashRadiusByte)) &&
                (ref = ViewFrustum_IsSphereVisible(&((SHthorntailObject*)obj)->modelPos.x, ((SHthorntailObject*)obj)->cullRadius * ((SHthorntailObject*)obj)->modelScale), ref == 0))
            {
                ref = getAngle(((SHthorntailObject*)obj)->modelPos.x - config->homePos.x, ((SHthorntailObject*)obj)->modelPos.z - config->homePos.z);
                ((SHthorntailObject*)obj)->facingAngle = ref;
            }
        }
        runtime->activeMoveValid = 1;
        activeConfigToken = gSHthorntailActiveConfigToken;
        if (activeConfigToken == SHTHORNTAIL_CONFIG_TOKEN_NONE)
        {
            gSHthorntailActiveConfigToken = ((SHthorntailObject*)obj)->config->configToken;
            ((SHthorntailObject*)obj)->velocityY = -(0.17f * timeDelta - ((SHthorntailObject*)obj)->velocityY);
            (*gPathControlInterface)->update((void*)obj, runtime->moveScratch, timeDelta);
            (*gPathControlInterface)->apply((void*)obj, runtime->moveScratch);
            (*gPathControlInterface)->advance((void*)obj, runtime->moveScratch, timeDelta);
            ((SHthorntailObject*)obj)->pitch = runtime->moveControlPitch;
            ((SHthorntailObject*)obj)->roll = runtime->moveControlRoll;
        }
        else
        {
            if ((u32)activeConfigToken == (u32)((SHthorntailObject*)obj)->config->configToken)
            {
                gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
            }
            if (('\x02' <= runtime->behaviorState) && (runtime->behaviorState <= '\x06'))
            {
                ((SHthorntailObject*)obj)->velocityY = -(0.17f * timeDelta - ((SHthorntailObject*)obj)->velocityY);
                (*gPathControlInterface)->update((void*)obj, runtime->moveScratch, timeDelta);
                (*gPathControlInterface)->apply((void*)obj, runtime->moveScratch);
                (*gPathControlInterface)->advance((void*)obj, runtime->moveScratch, timeDelta);
                ((SHthorntailObject*)obj)->pitch = runtime->moveControlPitch;
                ((SHthorntailObject*)obj)->roll = runtime->moveControlRoll;
            }
            else
            {
                (*gPathControlInterface)->attachObject((void*)obj, runtime->moveScratch);
            }
        }
    }
    return;
}

void SHthorntail_init(SHthorntailObject* obj, SHthorntailConfig* config)
{
    SHthorntailRuntime* runtime;
    ObjModel* model;
    u32 randomTime;
    u8* moveScratch;
    u32 outA[2];
    u32 outB;
    u32 stackPad;

    runtime = obj->runtime;
    outA[0] = lbl_803E5410;
    obj->facingAngle = (short)((int)config->initialFacingByte << 8);
    switch (config->controlMode)
    {
    case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)randomTime;
        break;
    case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
        runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
        break;
    case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)randomTime;
        break;
    case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)randomTime;
        break;
    }
    obj->modelScale = *(float*)((int)obj->anim.modelInstance + 4) * ((float)config->initScale / 1000.0f);
    model = Obj_GetActiveModel((GameObject*)obj);
    modelInitBones(obj->modelScale, model);
    moveScratch = runtime->moveScratch;
    (*gPathControlInterface)->init(moveScratch, SHTHORNTAIL_PATH_CONTROL_MODE, SHTHORNTAIL_PATH_CONTROL_FLAGS, 0);
    (*gPathControlInterface)
        ->setup(moveScratch, SHTHORNTAIL_PATH_CHANNEL, gSHthorntailPathHeaders, gSHthorntailPathData, outA);
    (*gPathControlInterface)->attachObject(obj, moveScratch);
    obj->animEventCallback = SHthorntail_updateLevelControlState;
    dll_2E_func05((GameObject*)obj, (MoveLibState*)runtime, 0xffffdc72, 0x2aaa, 3);
    dll_2E_func08((MoveLibState*)runtime, 400, 0x78);
    ObjGroup_AddObject((int)obj, THORNTAIL_OBJGROUP);
}

/* descriptor/ptr table auto 0x80327560-0x80327598 */
u32 gWarpStoneObjDescriptor[14] = {0x00000000,
                                   0x00000000,
                                   0x00000000,
                                   0x00090000,
                                   (u32)warpstone_initialise,
                                   (u32)warpstone_release,
                                   0x00000000,
                                   (u32)warpstone_init,
                                   (u32)warpstone_update,
                                   (u32)warpstone_hitDetect,
                                   (u32)warpstone_render,
                                   (u32)warpstone_free,
                                   (u32)warpstone_getObjectTypeId,
                                   (u32)warpstone_getExtraSize};
