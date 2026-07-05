/* DLL 0x1AD - SHThorntail [801D58E4-801D5ED4) */
#include "main/audio/sfx.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"
#include "main/effect_interfaces.h"
#include "main/frustum.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/SH/shthorntail_ai.h"

extern void warpstone_getExtraSize(void);

extern void warpstone_getObjectTypeId(void);

extern void warpstone_free(void);

extern void warpstone_render(void);

extern void warpstone_hitDetect(void);

extern void warpstone_update(void);

extern void warpstone_init(void);

extern void warpstone_release(void);

extern void warpstone_initialise(void);

#define THORNTAIL_OBJGROUP 0x4d

#define SHTHORNTAIL_OBJFLAG_RENDERED 0x800
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern u32 ObjTrigger_IsSet(int obj);
extern void characterDoEyeAnims(int obj, int p2);
extern void objAudioFn_8006ef38(int obj, int joint, int pointCount, int pathPoints, int scratch, f32 scaleX,
                                f32 scaleY);

extern f32 timeDelta;
extern f32 SHTHORNTAIL_TIMER_DONE_THRESHOLD;
extern f32 SHTHORNTAIL_CLOSE_ATTACK_DISTANCE;
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

extern void ObjPath_GetPointWorldPosition(SHthorntailObject* obj, int pointIndex, f32* x, f32* y, f32* z, int useInputPosition);
extern void objRenderFn_8003b8f4(SHthorntailObject* obj, int p2, int p3, int p4, int p5, f32 scale);
extern void dll_2E_func06(SHthorntailObject* obj, SHthorntailRuntime* runtime, int point);
extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern u32 Obj_GetActiveModel();
extern u32 modelInitBones();
extern void ObjGroup_AddObject(u32 obj, int group);
extern void fn_8003B228(int obj, int p2);
extern u32 dll_2E_func05();
extern void dll_2E_func08(int obj, int v1, int v2);
extern void dll_2E_func03(SHthorntailObject * obj, SHthorntailRuntime * runtime);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern u8 gSHthorntailPathHeaders[0x30];
extern u8 gSHthorntailPathData[0x4AC];
extern u32 lbl_803E5410;
extern SHthorntailPathControlInterface** gPathControlInterface;
extern f32 lbl_803E544C;
extern f32 lbl_803E5450;
extern f32 lbl_803E5454;
extern f32 lbl_803E5458;
extern f32 lbl_803E545C;

void SHthorntail_updateLevelControlMode1(u32 objectId, SHthorntailRuntime* runtime,
                                         SHthorntailConfig* config)
{
    extern int Obj_GetPlayerObject(); /* #57 */
    extern int randomGetRange(int lo, int hi); /* #57 */
    extern f32 getXZDistance(int posA, int posB); /* #57 */
    int playerObj;
    int randomIdleWait;
    u8 closeToPlayer;
    u32 gameBit;
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

void SHthorntail_updateLevelControlMode0(SHthorntailObject* obj, SHthorntailRuntime* runtime,
                                         SHthorntailConfig* config)
{
    extern int randomGetRange(int lo, int hi); /* #57 */
    int linkedEventPending;
    u32 gameBit;
    int randomIdleWait;
    SHthorntailDataTables* dataTables;

    dataTables = &gSHthorntailDataTables;
    runtime->impactSfxTable = dataTables->levelMode0DefaultImpactSfxTable;
    switch (runtime->locomotionMode)
    {
    case SHTHORNTAIL_LOCOMOTION_1:
        runtime->impactSfxTable =
            (u8*)dataTables->levelMode0Locomotion1ImpactSfxVariants + config->impactSfxVariant * 2;
        break;
    case SHTHORNTAIL_LOCOMOTION_2:
        gameBit = GameBit_Get(SHTHORNTAIL_LEVEL_MODE0_LOCOMOTION2_GAMEBIT);
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
        gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT);
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
        gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT);
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
        gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT);
        if (gameBit == 0)
        {
            runtime->impactSfxTable = &gSHthorntailLevelControlMode0Locomotion6ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_8:
        runtime->impactSfxTable =
            (u8*)dataTables->levelMode0Locomotion8ImpactSfxVariants + config->impactSfxVariant * 2;
        break;
    }
    SHthorntail_updateState(obj, runtime);
}

u32 SHthorntail_updateLevelControlState(SHthorntailObject* obj, int unused,
                                               ObjAnimUpdateState* animUpdate)
{
    extern int randomGetRange(int lo, int hi); /* #57 */
    SHthorntailRuntime* runtime;
    int randomIdleWait;
    int impactHandled;
    int levelControlReady;
    int impactPending;

    runtime = obj->runtime;
    levelControlReady = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_LEVELCONTROL_READY);
    if (levelControlReady == 0)
    {
        Sfx_StopObjectChannel((u32)obj,SHTHORNTAIL_LEVELCONTROL_AUDIO_CHANNEL);
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
        impactHandled = dll_2E_func07((int)obj, (ObjSeqState*)animUpdate, (char*)runtime, 0, 0);
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
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E5448);
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

typedef struct SHthorntailTailSwingEffectScratch
{
    u8 particleParams[12];
    Vec position;
} SHthorntailTailSwingEffectScratch;

#pragma optimization_level 3
#pragma opt_loop_invariants off
#pragma opt_common_subs off
void SHthorntail_update(SHthorntailObject* obj)
{
    extern int randomGetRange(int lo, int hi); /* #57 */
    extern f32 getXZDistance(f32 * posA, f32 * posB); /* #57 */
    extern u8 ObjHitReact_Update(int obj, ObjHitReactEntry* table, u32 count, u8 state, float* scratch);
    u8* stateTables;
    s8* eventId;
    SHthorntailRuntime* runtime;
    SHthorntailConfig* config;
    int i;
    u8 hitResult;
    u8 mode;
    ObjHitReactEntry* hitReactEntries;
    int val;
    u32 uval;
    int ref;
    s32 activeConfigToken;
    f32 facingAngleRadians;
    f32 facingCos;
    f32 facingSin;
    f32 leashDistance;
    ObjAnimEventList animEvents;
    SHthorntailTailSwingEffectScratch effectScratch;

    stateTables = (u8*)&gSHthorntailDataTables;
    runtime = obj->runtime;
    config = obj->config;
    if (runtime->behaviorState == '\f')
    {
        if (runtime->effectTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD)
        {
            if ((obj->objectFlags & SHTHORNTAIL_OBJFLAG_RENDERED) != 0)
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
    runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_LEVELCONTROL_READY;
    if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
        SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT) != 0)
    {
        hitReactEntries = SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES(stateTables);
    }
    else
    {
        hitReactEntries = SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES(stateTables);
    }
    val = 0x19;
    hitResult = runtime->hitReactState = ObjHitReact_Update((int)obj, hitReactEntries, val, runtime->hitReactState, (float*)runtime->hitReactScratch);
    if (hitResult == 0)
    {
        mode = (*gMapEventInterface)->getMapAct((int)obj->animObjId);
        runtime->locomotionMode = mode;
        switch (config->controlMode)
        {
        case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
            SHthorntail_updateLevelControlMode0(obj, runtime, config);
            break;
        case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
            SHthorntail_updateLevelControlMode1((u32)obj, runtime, config);
            break;
        case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
            SHthorntail_updateRootControlMode2(obj, runtime);
            break;
        case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
            SHthorntail_updateRootControlMode3(obj, runtime);
            break;
        }
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
            SHTHORNTAIL_STATE_FLAG_STATUS_ACTIVE) != 0)
        {
            obj->statusFlags |= SHTHORNTAIL_OBJECT_STATUS_ACTIVE;
        }
        else
        {
            obj->statusFlags &= ~SHTHORNTAIL_OBJECT_STATUS_ACTIVE;
            obj->statusFlags &= ~SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
        }
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_FREEZE_MOTION) != 0)
        {
            if (++runtime->freezeFrameCounter > 0xa)
            {
                runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_FREEZE_MOTION;
            }
            else
            {
                obj->statusFlags |= SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
            }
        }
        if ((int)obj->currentMove !=
            SHTHORNTAIL_STATE_MOVE_IDS(stateTables)[runtime->behaviorState])
        {
            ObjAnim_SetCurrentMove((int)obj,
                                   SHTHORNTAIL_STATE_MOVE_IDS(stateTables)
                                   [runtime->behaviorState],
                                   SHTHORNTAIL_TIMER_DONE_THRESHOLD, 0);
            runtime->storedFacingAngle = obj->facingAngle;
        }
        val = ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
            (int)obj, SHTHORNTAIL_STATE_MOVE_STEP_SCALES(stateTables)[runtime->behaviorState],
            timeDelta, &animEvents);
        if (val != 0)
        {
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        }
        else
        {
            runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_MOVE_COMPLETE;
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
            obj->modelPos.z = facingSin * -animEvents.rootDeltaZ + obj->modelPos.z;
            obj->modelPos.x = facingSin * -animEvents.rootDeltaX + obj->modelPos.x;
            obj->modelPos.z = facingCos * animEvents.rootDeltaX + obj->modelPos.z;
            obj->facingAngle += animEvents.rootPitch;
        }
        for (i = 0, eventId = (s8*)&animEvents; i < animEvents.triggerCount; i = i + 1)
        {
            if (eventId[0x13] == '\0')
            {
                if (SHTHORNTAIL_STATE_TRIGGER0_SFX(stateTables)[runtime->behaviorState] != 0)
                {
                    Sfx_PlayFromObject(
                        (u32)obj,SHTHORNTAIL_STATE_TRIGGER0_SFX(stateTables)[runtime->behaviorState]);
                }
            }
            else if ((eventId[0x13] == '\a') &&
                (SHTHORNTAIL_STATE_TRIGGER7_SFX(stateTables)[runtime->behaviorState] != 0))
            {
                Sfx_PlayFromObject(
                    (u32)obj, SHTHORNTAIL_STATE_TRIGGER7_SFX(stateTables)[runtime->behaviorState]);
            }
            eventId++;
        }
        objAudioFn_8006ef38((int)obj, (int)&animEvents, 8, (int)runtime->renderPathPoints,
                            (int)runtime->moveScratch, lbl_803E5448, lbl_803E5448);
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
            SHTHORNTAIL_STATE_FLAG_DISABLE_MOVE_CONTROL) != 0)
        {
            runtime->movementControlFlags = runtime->movementControlFlags & ~1;
        }
        else
        {
            runtime->movementControlFlags = runtime->movementControlFlags | 1;
        }
        dll_2E_func03(obj, runtime);
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
            SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT) != 0)
        {
            fn_8003B228((int)obj, (int)runtime->collisionShapeState);
        }
        else
        {
            characterDoEyeAnims((int)obj, (int)runtime->collisionShapeState);
        }
        runtime->behaviorFlags = runtime->behaviorFlags & ~2;
        if (((runtime->behaviorFlags & 4) == 0) && (val = ObjTrigger_IsSet((int)obj), val != 0))
        {
            uval = randomGetRange(1, (u32) * runtime->impactSfxTable);
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_IMPACT_PENDING;
            (*gObjectTriggerInterface)->runSequence(*(u8*)(runtime->impactSfxTable + uval), obj, -1);
        }
        if (config->leashRadiusByte != '\0')
        {
            leashDistance = getXZDistance(&obj->pos.x, (float*)&config->homePos);
            if ((leashDistance > (f32)(s32)((u32)config->leashRadiusByte *
                    (u32)config->leashRadiusByte)) &&
                (ref = ViewFrustum_IsSphereVisible(&obj->modelPos.x,
                                                     obj->cullRadius * obj->modelScale),
                    ref == 0))
            {
                ref = getAngle(obj->modelPos.x - config->homePos.x,
                                 obj->modelPos.z - config->homePos.z);
                obj->facingAngle = ref;
            }
        }
        runtime->activeMoveValid = 1;
        activeConfigToken = gSHthorntailActiveConfigToken;
        if (activeConfigToken == SHTHORNTAIL_CONFIG_TOKEN_NONE)
        {
            gSHthorntailActiveConfigToken = obj->config->configToken;
            obj->velocityY = -(lbl_803E544C * timeDelta - obj->velocityY);
            (*gSHthorntailPathControlInterface)->advanceControl(obj, runtime->moveScratch, timeDelta);
            (*gSHthorntailPathControlInterface)->applyControl(obj, runtime->moveScratch);
            (*gSHthorntailPathControlInterface)->finishControl(obj, runtime->moveScratch, timeDelta);
            obj->pitch = runtime->moveControlPitch;
            obj->roll = runtime->moveControlRoll;
        }
        else
        {
            if ((u32)activeConfigToken == (u32)obj->config->configToken)
            {
                gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
            }
            if (('\x02' <= runtime->behaviorState) && (runtime->behaviorState <= '\x06'))
            {
                obj->velocityY = -(lbl_803E544C * timeDelta - obj->velocityY);
                (*gSHthorntailPathControlInterface)->advanceControl(obj, runtime->moveScratch, timeDelta);
                (*gSHthorntailPathControlInterface)->applyControl(obj, runtime->moveScratch);
                (*gSHthorntailPathControlInterface)->finishControl(obj, runtime->moveScratch, timeDelta);
                obj->pitch = runtime->moveControlPitch;
                obj->roll = runtime->moveControlRoll;
            }
            else
            {
                (*gSHthorntailPathControlInterface)->bindObject(obj, (int)runtime->moveScratch);
            }
        }
    }
    return;
}
#pragma opt_common_subs reset
#pragma opt_loop_invariants reset
#pragma optimization_level reset

void SHthorntail_init(SHthorntailObject* obj, SHthorntailConfig* config)
{
    extern int randomGetRange(int lo, int hi); /* #57 */
    SHthorntailRuntime* runtime;
    u32 randomTime;
    int moveScratch;
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
    obj->modelScale = *(float*)((int)obj->anim.modelInstance + 4) *
        ((float)config->initScale / lbl_803E545C);
    Obj_GetActiveModel((int)obj);
    modelInitBones((double)obj->modelScale);
    moveScratch = (int)runtime->moveScratch;
    (*gSHthorntailPathControlInterface)->initControl(moveScratch, SHTHORNTAIL_PATH_CONTROL_MODE,
                                                     SHTHORNTAIL_PATH_CONTROL_FLAGS, 0);
    (*gSHthorntailPathControlInterface)->attachPathData(moveScratch, SHTHORNTAIL_PATH_CHANNEL,
                                                        gSHthorntailPathHeaders,
                                                        gSHthorntailPathData, outA);
    (*gSHthorntailPathControlInterface)->bindObject(obj, moveScratch);
    obj->animEventCallback = SHthorntail_updateLevelControlState;
    dll_2E_func05((int)obj, runtime, 0xffffdc72, 0x2aaa, 3);
    dll_2E_func08((int)runtime, 400, 0x78);
    ObjGroup_AddObject((int)obj, THORNTAIL_OBJGROUP);
}

/* descriptor/ptr table auto 0x80327560-0x80327598 */
u32 gWarpStoneObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)warpstone_initialise, (u32)warpstone_release, 0x00000000, (u32)warpstone_init, (u32)warpstone_update, (u32)warpstone_hitDetect, (u32)warpstone_render, (u32)warpstone_free, (u32)warpstone_getObjectTypeId, (u32)warpstone_getExtraSize };
