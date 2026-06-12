/* === merged from main/dll/SH/SHroot.c [801D58E4-801D5ED4) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern void Sfx_PlayFromObject(SHthorntailObject* obj, u16 volumeId);
extern void Sfx_StopObjectChannel(int obj, u16 volumeId);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern undefined8 ObjGroup_RemoveObject();
extern int ObjTrigger_IsSet();
extern void characterDoEyeAnims(int obj, int collisionShapeState);
extern void objAudioFn_8006ef38(int obj, int joint, int pointCount, int pathPoints, int scratch, f32 scaleX,
                                f32 scaleY);
extern int dll_2E_func07();
extern int SHthorntail_HasNearbyPendingEventObject(SHthorntailObject * obj);

extern f32 timeDelta;
extern f32 SHTHORNTAIL_TIMER_DONE_THRESHOLD;
extern f32 SHTHORNTAIL_CLOSE_ATTACK_DISTANCE;
extern f64 lbl_803E5428;
extern f32 SHTHORNTAIL_IDLE_COUNTDOWN_TIME;
extern f32 lbl_803E5448;
extern SHthorntailDataTables gSHthorntailDataTables;

#define SHTHORNTAIL_LEVEL_MODE1_GATE_OPEN_GAMEBIT 0x13E
#define SHTHORNTAIL_LEVEL_MODE1_FREEZE_GAMEBIT 0x168
#define SHTHORNTAIL_LEVEL_MODE1_PRIMARY_TRIGGER_GAMEBIT 0xCD5
#define SHTHORNTAIL_LEVEL_MODE1_SECONDARY_TRIGGER_GAMEBIT 0xCD6
#define SHTHORNTAIL_LEVEL_MODE1_CLOSE_ATTACK_DISABLE_GAMEBIT 0x1AB
#define SHTHORNTAIL_LEVEL_MODE0_LOCOMOTION2_GAMEBIT 0x09E
#define SHTHORNTAIL_LEVELCONTROL_AUDIO_CHANNEL 0x7F
#define SHTHORNTAIL_LEVELCONTROL_COLLISION_FLAG 0x40

/*
 * --INFO--
 *
 * Function: SHthorntail_updateLevelControlMode1
 * EN v1.0 Address: 0x801D58E4
 * EN v1.0 Size: 644b
 * EN v1.1 Address: 0x801D5ED4
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_updateLevelControlMode1(uint objectId, SHthorntailRuntime* runtime,
                                         SHthorntailConfig* config)
{
    extern int Obj_GetPlayerObject(); /* #57 */
    extern u32 randomGetRange(int min, int max); /* #57 */
    extern f32 getXZDistance(int posA, int posB); /* #57 */
    int playerObj;
    int randomIdleWait;
    u8 closeToPlayer;
    uint gameBit;
    int triggerIsSet;

    runtime->impactSfxTable = &gSHthorntailLevelControlMode1ImpactSfxTable;
    playerObj = Obj_GetPlayerObject();
    {
        int cmp = (double)getXZDistance(objectId + 0x18, playerObj + 0x18) <
            (double)SHTHORNTAIL_CLOSE_ATTACK_DISTANCE;
        closeToPlayer = cmp;
    }
    if (config->impactSfxVariant == 0)
    {
        gameBit = GameBit_Get(SHTHORNTAIL_LEVEL_MODE1_GATE_OPEN_GAMEBIT);
        if (gameBit != 0)
        {
            gameBit = GameBit_Get(SHTHORNTAIL_LEVEL_MODE1_FREEZE_GAMEBIT);
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
                    GameBit_Set(SHTHORNTAIL_LEVEL_MODE1_SECONDARY_TRIGGER_GAMEBIT, 1);
                }
            }
        }
        else
        {
            triggerIsSet = ObjTrigger_IsSet(objectId);
            if (triggerIsSet != 0)
            {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
                GameBit_Set(SHTHORNTAIL_LEVEL_MODE1_PRIMARY_TRIGGER_GAMEBIT, 1);
            }
        }
    }
    else
    {
        gameBit = GameBit_Get(SHTHORNTAIL_LEVEL_MODE1_CLOSE_ATTACK_DISABLE_GAMEBIT);
        if (gameBit != 0)
        {
            closeToPlayer = FALSE;
        }
    }
    switch ((s8)runtime->behaviorState)
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

/*
 * --INFO--
 *
 * Function: SHthorntail_updateLevelControlMode0
 * EN v1.0 Address: 0x801D5B68
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x801D6158
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_updateLevelControlMode0(SHthorntailObject* obj, SHthorntailRuntime* runtime,
                                         SHthorntailConfig* config)
{
    extern u32 randomGetRange(int min, int max); /* #57 */
    int linkedEventPending;
    uint gameBit;
    int randomIdleWait;
    SHthorntailDataTables* dataTables;

    dataTables = &gSHthorntailDataTables;
    runtime->impactSfxTable = dataTables->levelMode0DefaultImpactSfxTable;
    switch (runtime->locomotionMode)
    {
    case SHTHORNTAIL_LOCOMOTION_1:
        runtime->impactSfxTable =
            dataTables->levelMode0Locomotion1ImpactSfxVariants + config->impactSfxVariant * 2;
        break;
    case SHTHORNTAIL_LOCOMOTION_2:
        gameBit = GameBit_Get(SHTHORNTAIL_LEVEL_MODE0_LOCOMOTION2_GAMEBIT);
        if (gameBit != 0)
        {
            runtime->impactSfxTable =
                dataTables->levelMode0Locomotion2SetImpactSfxVariants + config->impactSfxVariant * 2;
        }
        else
        {
            runtime->impactSfxTable =
                dataTables->levelMode0Locomotion2ClearImpactSfxVariants + config->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_3:
        gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT);
        if (gameBit != 0)
        {
            runtime->impactSfxTable =
                dataTables->levelMode0Locomotion3SetImpactSfxVariants + config->impactSfxVariant * 2;
        }
        else
        {
            runtime->impactSfxTable =
                dataTables->levelMode0Locomotion3ClearImpactSfxVariants + config->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_5:
        gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT);
        if (gameBit == 0)
        {
            runtime->impactSfxTable =
                dataTables->levelMode0Locomotion5ClearImpactSfxVariants + config->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_6:
        linkedEventPending = SHthorntail_HasNearbyPendingEventObject(obj);
        if (linkedEventPending != 0)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
            return;
        }
        if ((s8)runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE)
        {
            Sfx_PlayFromObject(0, SHTHORNTAIL_EVENT_RESUME_VOLUME_ID);
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomIdleWait;
        }
        gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT);
        if (gameBit == 0)
        {
            runtime->impactSfxTable = &gSHthorntailLevelControlMode0Locomotion6ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_8:
        runtime->impactSfxTable =
            dataTables->levelMode0Locomotion8ImpactSfxVariants + config->impactSfxVariant * 2;
        break;
    }
    SHthorntail_updateState(obj, runtime);
}

/*
 * --INFO--
 *
 * Function: SHthorntail_updateLevelControlState
 * EN v1.0 Address: 0x801D5D48
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x801D6338
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 SHthorntail_updateLevelControlState(SHthorntailObject* obj, int unused,
                                               ObjAnimUpdateState* animUpdate)
{
    extern u32 randomGetRange(int min, int max); /* #57 */
    SHthorntailRuntime* runtime;
    int randomIdleWait;
    int impactHandled;
    int levelControlReady;
    int impactPending;

    runtime = obj->runtime;
    levelControlReady = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_LEVELCONTROL_READY);
    if (levelControlReady == 0)
    {
        Sfx_StopObjectChannel((int)obj,SHTHORNTAIL_LEVELCONTROL_AUDIO_CHANNEL);
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (float)randomIdleWait;
        runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
        runtime->behaviorFlags = runtime->behaviorFlags | (SHTHORNTAIL_FLAG_LEVELCONTROL_READY |
            SHTHORNTAIL_FLAG_FREEZE_MOTION);
        runtime->freezeFrameCounter = 0;
        obj->statusFlags = obj->statusFlags | SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
    }
    impactPending = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_IMPACT_PENDING);
    if (impactPending != 0)
    {
        impactHandled = dll_2E_func07((int)obj, (int)animUpdate, (int)runtime, 0, 0);
        if (impactHandled != 0)
        {
            return 0;
        }
        animUpdate->hitVolumePair &= ~SHTHORNTAIL_LEVELCONTROL_COLLISION_FLAG;
        characterDoEyeAnims((int)obj, (int)runtime->collisionShapeState);
    }
    runtime->activeMoveValid = 0;
    objAudioFn_8006ef38((int)obj, (int)&animUpdate->animEvents, 8, (int)runtime->renderPathPoints,
                        (int)runtime->moveScratch, lbl_803E5448, *(f32*)&lbl_803E5448);
    return 0;
}

/*
 * --INFO--
 *
 * Function: SHthorntail_getExtraSize
 * EN v1.0 Address: 0x801D5E8C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int SHthorntail_getExtraSize(void)
{
    return SHTHORNTAIL_EXTRA_STATE_BYTES;
}

/*
 * --INFO--
 *
 * Function: SHthorntail_free
 * EN v1.0 Address: 0x801D5E94
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_free(SHthorntailObject* obj)
{
    u32 activeConfigToken;

    activeConfigToken = (u32)gSHthorntailActiveConfigToken;
    if (activeConfigToken == (u32)obj->config->configToken)
    {
        gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
    }
    ObjGroup_RemoveObject((int)obj, 0x4d);
}

/* === merged from main/dll/SC/SClevelcontrol.c [801D5ED4-801D5F58) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/SC/SClevelcontrol.h"

extern void ObjPath_GetPointWorldPosition(SHthorntailObject* obj, int pointIndex, f32* x, f32* y, f32* z, int param_6);
extern void objRenderFn_8003b8f4(f32 scale);
extern void dll_2E_func06(SHthorntailObject* obj, SHthorntailRuntime* runtime, int param_3);


/*
 * --INFO--
 *
 * Function: SHthorntail_render
 * EN v1.0 Address: 0x801D5ED4
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801D64C4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_render(SHthorntailObject* obj)
{
    SHthorntailRuntime* runtime;
    int pointIndex;

    runtime = obj->runtime;
    objRenderFn_8003b8f4(lbl_803E5448);
    dll_2E_func06(obj, runtime, 0);
    pointIndex = 0;
    do
    {
        ObjPath_GetPointWorldPosition(obj, pointIndex, &runtime->renderPathPoints[0].x, &runtime->renderPathPoints[0].y,
                                      &runtime->renderPathPoints[0].z, 0);
        runtime = (SHthorntailRuntime*)((int)runtime + sizeof(Vec));
        pointIndex = pointIndex + 1;
    }
    while (pointIndex < SHTHORNTAIL_RENDER_PATH_POINT_COUNT);
}

#include "main/dll/SH/SHroot.h"
#include "main/dll/SC/SCchieflightfoot.h"
#include "main/effect_interfaces.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern undefined4 Obj_GetActiveModel();
extern undefined4 modelInitBones();
extern undefined4 ObjGroup_AddObject();
extern void fn_8003B228(int obj, int collisionShapeState);
extern int ViewFrustum_IsSphereVisible(f32* pos, f32 radius);
extern undefined4 dll_2E_func05();
extern undefined4 dll_2E_func08();
extern void dll_2E_func03(SHthorntailObject * obj, SHthorntailRuntime * runtime);
extern undefined4 FUN_80286888();
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

extern u8 gSHthorntailPathHeaders[0x30];
extern u8 gSHthorntailPathData[0x4AC];
extern undefined4 lbl_803E5410;
extern EffectInterface** gPartfxInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern SHthorntailPathControlInterface** gPathControlInterface;
extern f64 lbl_803E5440;
extern f32 lbl_803E544C;
extern f32 lbl_803E5450;
extern f32 lbl_803E5454;
extern f32 lbl_803E5458;
extern f32 lbl_803E545C;
extern f32 lbl_803E5460;
extern f32 lbl_803E5464;
extern f32 lbl_803E5468;
extern f32 lbl_803E546C;
extern f32 lbl_803E5470;
extern f32 lbl_803E5474;
extern f32 lbl_803E5478;
extern f32 lbl_803E547C;
extern f32 lbl_803E5480;
extern f32 lbl_803E5484;
extern f32 lbl_803E5488;
extern f64 lbl_803E5490;

#define gSHthorntailPathControlInterface gPathControlInterface

#define SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES_OFFSET 0x0A0
#define SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES_OFFSET 0x294
#define SHTHORNTAIL_STATE_MOVE_IDS_OFFSET 0x488
#define SHTHORNTAIL_STATE_MOVE_STEP_SCALES_OFFSET 0x4AC
#define SHTHORNTAIL_STATE_FLAGS_OFFSET 0x4F0
#define SHTHORNTAIL_STATE_TRIGGER0_SFX_OFFSET 0x504
#define SHTHORNTAIL_STATE_TRIGGER7_SFX_OFFSET 0x528

#define SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES(tables) \
  ((ObjHitReactEntry *)((tables) + SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES_OFFSET))
#define SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES(tables) \
  ((ObjHitReactEntry *)((tables) + SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES_OFFSET))
#define SHTHORNTAIL_STATE_MOVE_IDS(tables) ((s16 *)((tables) + SHTHORNTAIL_STATE_MOVE_IDS_OFFSET))
#define SHTHORNTAIL_STATE_MOVE_STEP_SCALES(tables) \
  ((f32 *)((tables) + SHTHORNTAIL_STATE_MOVE_STEP_SCALES_OFFSET))
#define SHTHORNTAIL_STATE_FLAGS(tables) ((u8 *)((tables) + SHTHORNTAIL_STATE_FLAGS_OFFSET))
#define SHTHORNTAIL_STATE_TRIGGER0_SFX(tables) \
  ((u16 *)((tables) + SHTHORNTAIL_STATE_TRIGGER0_SFX_OFFSET))
#define SHTHORNTAIL_STATE_TRIGGER7_SFX(tables) \
  ((u8 *)((tables) + SHTHORNTAIL_STATE_TRIGGER7_SFX_OFFSET))

typedef struct SHthorntailDustEffectParams
{
    undefined2 flags;
    undefined2 count;
    undefined2 effectType;
    undefined2 radius;
    f32 scale;
    Vec position;
} SHthorntailDustEffectParams;

typedef struct SHthorntailTailSwingEffectScratch
{
    undefined particleParams[12];
    Vec position;
} SHthorntailTailSwingEffectScratch;

/*
 * --INFO--
 *
 * Function: SHthorntail_update
 * EN v1.0 Address: 0x801D5F58
 * EN v1.0 Size: 1928b
 * EN v1.1 Address: 0x801D6548
 * EN v1.1 Size: 1928b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_update(SHthorntailObject* obj)
{
    extern int randomGetRange(int min, int max); /* #57 */
    extern f32 getXZDistance(f32 * posA, f32 * posB); /* #57 */
    SHthorntailConfig* config;
    SHthorntailRuntime* runtime;
    byte byteVal;
    char hitResult;
    undefined mode;
    ObjHitReactEntry* hitReactEntries;
    int val;
    uint uval;
    float* scratch;
    int ref;
    s8* eventId;
    u8* stateTables;
    f32 facingAngleRadians;
    f32 facingCos;
    f32 facingSin;
    f32 leashDistance;
    ObjAnimEventList animEvents;
    SHthorntailTailSwingEffectScratch effectScratch;

    stateTables = (u8*)&gSHthorntailDataTables;
    runtime = obj->runtime;
    config = obj->config;
    ref = (int)config;
    if (runtime->behaviorState == '\f')
    {
        if (runtime->effectTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD)
        {
            if ((obj->objectFlags & 0x800U) != 0)
            {
                ObjPath_GetPointWorldPosition(obj, 4, &effectScratch.position.x, &effectScratch.position.y,
                                              &effectScratch.position.z, 0);
                (*gPartfxInterface)->spawnObject(obj, 0x7f0, effectScratch.particleParams,
                                                 0x200001, -1, NULL);
            }
            runtime->effectTimer = lbl_803E5450;
        }
        runtime->effectTimer = runtime->effectTimer - timeDelta;
    }
    runtime->behaviorFlags = runtime->behaviorFlags & 0xf7;
    if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
        SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT) == 0)
    {
        hitReactEntries = SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES(stateTables);
    }
    else
    {
        hitReactEntries = SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES(stateTables);
    }
    val = 0x19;
    uval = (uint)runtime->hitReactState;
    scratch = (float*)runtime->hitReactScratch;
    hitResult = ObjHitReact_Update((int)obj, hitReactEntries, 0x19, uval, scratch);
    runtime->hitReactState = hitResult;
    if (hitResult == '\0')
    {
        mode = (*gMapEventInterface)->getMode((int)obj->animObjId);
        runtime->locomotionMode = mode;
        byteVal = config->controlMode;
        switch (byteVal)
        {
        case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
            SHthorntail_updateLevelControlMode0(obj, runtime, config);
            break;
        case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
            SHthorntail_updateLevelControlMode1((uint)obj, runtime, config);
            break;
        case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
            SHthorntail_updateRootControlMode2(obj, runtime);
            break;
        case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
            SHthorntail_updateRootControlMode3(obj, runtime);
            break;
        }
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
            SHTHORNTAIL_STATE_FLAG_STATUS_ACTIVE) == 0)
        {
            obj->statusFlags &= ~SHTHORNTAIL_OBJECT_STATUS_ACTIVE;
            obj->statusFlags &= ~SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
        }
        else
        {
            obj->statusFlags |= SHTHORNTAIL_OBJECT_STATUS_ACTIVE;
        }
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_FREEZE_MOTION) != 0)
        {
            byteVal = runtime->freezeFrameCounter + 1;
            runtime->freezeFrameCounter = byteVal;
            if (byteVal < 0xb)
            {
                obj->statusFlags |= SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
            }
            else
            {
                runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_FREEZE_MOTION;
            }
        }
        if ((int)obj->currentMove !=
            (int)SHTHORNTAIL_STATE_MOVE_IDS(stateTables)[runtime->behaviorState])
        {
            ObjAnim_SetCurrentMove((int)obj,
                                   (int)SHTHORNTAIL_STATE_MOVE_IDS(stateTables)
                                   [runtime->behaviorState],
                                   SHTHORNTAIL_TIMER_DONE_THRESHOLD, 0);
            runtime->storedFacingAngle = obj->facingAngle;
        }
        val = ObjAnim_AdvanceCurrentMove(
            SHTHORNTAIL_STATE_MOVE_STEP_SCALES(stateTables)[runtime->behaviorState], timeDelta,
            (int)obj, &animEvents);
        if (val == 0)
        {
            runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        }
        else
        {
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        }
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
            SHTHORNTAIL_STATE_FLAG_APPLY_ROOT_MOTION) != 0)
        {
            if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
            {
                runtime->storedFacingAngle = obj->facingAngle;
            }
            facingAngleRadians =
                (lbl_803E5454 * (f32)(s32)
            runtime->storedFacingAngle
            )
            /
            lbl_803E5458;
            facingCos = -mathSinf(facingAngleRadians);
            facingAngleRadians =
                (lbl_803E5454 * (f32)(s32)
            runtime->storedFacingAngle
            )
            /
            lbl_803E5458;
            facingSin = -mathCosf(facingAngleRadians);
            obj->modelPos.x = facingCos * -animEvents.rootDeltaZ + obj->modelPos.x;
            obj->modelPos.z = -facingSin * -animEvents.rootDeltaZ + obj->modelPos.z;
            obj->modelPos.x = -facingSin * animEvents.rootDeltaX + obj->modelPos.x;
            obj->modelPos.z = facingCos * animEvents.rootDeltaX + obj->modelPos.z;
            obj->facingAngle = obj->facingAngle + animEvents.rootPitch;
        }
        eventId = animEvents.triggeredIds;
        for (val = 0; val < animEvents.triggerCount; val = val + 1)
        {
            if (*eventId == '\0')
            {
                if (SHTHORNTAIL_STATE_TRIGGER0_SFX(stateTables)[runtime->behaviorState] != 0)
                {
                    Sfx_PlayFromObject(
                        obj,SHTHORNTAIL_STATE_TRIGGER0_SFX(stateTables)[runtime->behaviorState]);
                }
            }
            else if ((*eventId == '\a') &&
                (SHTHORNTAIL_STATE_TRIGGER7_SFX(stateTables)[runtime->behaviorState] != 0))
            {
                Sfx_PlayFromObject(
                    obj, (ushort)SHTHORNTAIL_STATE_TRIGGER7_SFX(stateTables)[runtime->behaviorState]);
            }
            eventId++;
        }
        objAudioFn_8006ef38((int)obj, (int)&animEvents, 8, (int)runtime->renderPathPoints,
                            (int)runtime->moveScratch, lbl_803E5448, lbl_803E5448);
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
            SHTHORNTAIL_STATE_FLAG_DISABLE_MOVE_CONTROL) == 0)
        {
            runtime->movementControlFlags = runtime->movementControlFlags | 1;
        }
        else
        {
            runtime->movementControlFlags = runtime->movementControlFlags & 0xfe;
        }
        dll_2E_func03(obj, runtime);
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
            SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT) == 0)
        {
            fn_8003B228((int)obj, (int)runtime->collisionShapeState);
        }
        else
        {
            characterDoEyeAnims((int)obj, (int)runtime->collisionShapeState);
        }
        runtime->behaviorFlags = runtime->behaviorFlags & 0xfd;
        if (((runtime->behaviorFlags & 4) == 0) && (val = ObjTrigger_IsSet((int)obj), val != 0))
        {
            uval = randomGetRange(1, (uint) * runtime->impactSfxTable);
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_IMPACT_PENDING;
            (*gObjectTriggerInterface)->runSequence(*(u8*)(runtime->impactSfxTable + uval), obj, -1);
        }
        if (config->leashRadiusByte != '\0')
        {
            leashDistance = getXZDistance(&obj->pos.x, (float*)&config->homePos);
            if ((leashDistance > (f32)(s32)((uint)config->leashRadiusByte *
                    (uint)config->leashRadiusByte)) &&
                (ref = ViewFrustum_IsSphereVisible(&obj->modelPos.x,
                                                     obj->cullRadius * obj->modelScale),
                    ref == 0))
            {
                ref = getAngle(obj->modelPos.x - config->homePos.x,
                                 obj->modelPos.z - config->homePos.z);
                obj->facingAngle = (short)ref;
            }
        }
        runtime->activeMoveValid = 1;
        if (gSHthorntailActiveConfigToken == SHTHORNTAIL_CONFIG_TOKEN_NONE)
        {
            gSHthorntailActiveConfigToken = config->configToken;
            obj->modelScale = -(lbl_803E544C * timeDelta - obj->modelScale);
            (*gSHthorntailPathControlInterface)->advanceControl(obj, runtime->moveScratch, timeDelta);
            (*gSHthorntailPathControlInterface)->applyControl(obj, runtime->moveScratch);
            (*gSHthorntailPathControlInterface)->finishControl(obj, runtime->moveScratch, timeDelta);
            obj->pitch = runtime->moveControlPitch;
            obj->roll = runtime->moveControlRoll;
        }
        else
        {
            if (gSHthorntailActiveConfigToken == config->configToken)
            {
                gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
            }
            if ((runtime->behaviorState < '\x02') || ('\x06' < runtime->behaviorState))
            {
                (*gSHthorntailPathControlInterface)->bindObject(obj, (int)runtime->moveScratch);
            }
            else
            {
                obj->modelScale = -(lbl_803E544C * timeDelta - obj->modelScale);
                (*gSHthorntailPathControlInterface)->advanceControl(obj, runtime->moveScratch, timeDelta);
                (*gSHthorntailPathControlInterface)->applyControl(obj, runtime->moveScratch);
                (*gSHthorntailPathControlInterface)->finishControl(obj, runtime->moveScratch, timeDelta);
                obj->pitch = runtime->moveControlPitch;
                obj->roll = runtime->moveControlRoll;
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: SHthorntail_init
 * EN v1.0 Address: 0x801D66E0
 * EN v1.0 Size: 564b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_init(SHthorntailObject* obj, SHthorntailConfig* config)
{
    extern int randomGetRange(int min, int max); /* #57 */
    SHthorntailRuntime* runtime;
    uint randomTime;
    int moveScratch;
    undefined4 outA[2];
    undefined4 outB;
    uint uStack_1c;

    runtime = obj->runtime;
    outA[0] = lbl_803E5410;
    *(short*)obj = (short)((int)config->initialFacingByte << 8);
    switch (config->controlMode)
    {
    case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)
        randomTime;
        break;
    case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
        runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
        break;
    case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)
        randomTime;
        break;
    case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)
        randomTime;
        break;
    }
    *(float*)((int)obj + 8) = *(float*)(*(int*)((int)obj + 0x50) + 4) *
        ((float)config->initScale / lbl_803E545C);
    Obj_GetActiveModel((int)obj);
    modelInitBones((double)*(float*)((int)obj + 8));
    moveScratch = (int)runtime->moveScratch;
    (*gSHthorntailPathControlInterface)->initControl(moveScratch, SHTHORNTAIL_PATH_CONTROL_MODE,
                                                     SHTHORNTAIL_PATH_CONTROL_FLAGS, 0);
    (*gSHthorntailPathControlInterface)->attachPathData(moveScratch, SHTHORNTAIL_PATH_CHANNEL,
                                                        gSHthorntailPathHeaders,
                                                        gSHthorntailPathData, outA);
    (*gSHthorntailPathControlInterface)->bindObject(obj, moveScratch);
    obj->animEventCallback = (void*)SHthorntail_updateLevelControlState;
    dll_2E_func05((int)obj, (int)runtime, 0xffffdc72, 0x2aaa, 3);
    dll_2E_func08((int)runtime, 400, 0x78);
    ObjGroup_AddObject((int)obj, 0x4d);
}

/*
 * --INFO--
 *
 * Function: SHthorntail_updateDustEffects
 * EN v1.0 Address: 0x801D6914
 * EN v1.0 Size: 752b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
