#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern void Sfx_PlayFromObject(SHthorntailObject* obj, u16 volumeId);
extern void Sfx_StopObjectChannel(int obj, u16 volumeId);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern f32 getXZDistance(int posA, int posB);
extern u32 randomGetRange(int min, int max);
extern int Obj_GetPlayerObject();
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
