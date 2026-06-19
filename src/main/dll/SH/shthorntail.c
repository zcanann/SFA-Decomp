/*
 * shthorntail - the ThornTail Hollow herd-dinosaur behaviour driver.
 *
 * SHthorntail_updateState runs the per-frame behaviour state machine
 * (idle, wandering moves, the close-attack combo, and the tail-swing
 * sequence). The two root-control entry points pick the locomotion
 * impact-sfx table for the current movement mode and apply the
 * level-script overrides (root-control mode 2 = scripted/event-driven,
 * mode 3 = the SnowHorn area's gated locomotion set) before delegating
 * to the shared state machine.
 */
#include "dolphin/os.h"
#include "main/dll/SH/SHthorntail.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
#include "main/vecmath.h"

extern int SHthorntail_HasNearbyPendingEventObject(SHthorntailObject * obj);

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 SHTHORNTAIL_TIMER_DONE_THRESHOLD;
extern f32 SHTHORNTAIL_PROXIMITY_ALERT_MIN_TIME;
extern f32 SHTHORNTAIL_PROXIMITY_ALERT_MAX_TIME;
extern f32 SHTHORNTAIL_IDLE_COUNTDOWN_TIME;
extern char sSHthorntailSourceFile[];
extern char sThorntailEnteredInvalidState[];
extern SHthorntailEventInterface** gMapEventInterface;

void SHthorntail_updateState(SHthorntailObject* obj, SHthorntailRuntime* runtime)
{
    int alertTriggered;
    int tailSwingQueued;
    int nextState;
    int randomValue;

    switch (runtime->behaviorState)
    {
    case SHTHORNTAIL_STATE_IDLE:
        alertTriggered =
            RandomTimer_UpdateRangeTrigger(&runtime->proximityAlertState,
                                           SHTHORNTAIL_PROXIMITY_ALERT_MIN_TIME,
                                           SHTHORNTAIL_PROXIMITY_ALERT_MAX_TIME);
        if (alertTriggered != 0)
        {
            Sfx_PlayFromObject((u32)obj, SHTHORNTAIL_ALERT_VOLUME_ID);
        }
        runtime->idleTimer = runtime->idleTimer - timeDelta;
        if (runtime->idleTimer <= SHTHORNTAIL_IDLE_COUNTDOWN_TIME)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
        }
        break;
    case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
        runtime->idleTimer = runtime->idleTimer - timeDelta;
        if (runtime->idleTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD)
        {
            tailSwingQueued = (*gSkyInterface)->getSunPosition(0);
            if (tailSwingQueued != 0)
            {
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
            }
            else
            {
                nextState = SHthorntail_chooseNextState(obj, runtime, obj->config);
                runtime->behaviorState = (s8)nextState;
            }
        }
        break;
    case SHTHORNTAIL_STATE_MOVE_2:
    case SHTHORNTAIL_STATE_MOVE_3:
    case SHTHORNTAIL_STATE_MOVE_4:
    case SHTHORNTAIL_STATE_MOVE_5:
    case SHTHORNTAIL_STATE_TURN_HOME:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
        {
            tailSwingQueued = (*gSkyInterface)->getSunPosition(0);
            if (tailSwingQueued != 0)
            {
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
            }
            else
            {
                nextState = SHthorntail_chooseNextState(obj, runtime, obj->config);
                runtime->behaviorState = (s8)nextState;
            }
        }
        break;
    case SHTHORNTAIL_STATE_CLOSE_ATTACK:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT;
            randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_WAIT_MIN, SHTHORNTAIL_CLOSE_ATTACK_WAIT_MAX);
            runtime->comboTimer = (float)randomValue;
            randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MIN, SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MAX);
            runtime->comboRepeatCount = (s8)randomValue;
        }
        break;
    case SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT:
        runtime->comboTimer = runtime->comboTimer -
            (float)framesThisStep;
        if (runtime->comboTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD)
        {
            if (runtime->comboRepeatCount <= 0)
            {
                runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER;
            }
            else
            {
                runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_REPEAT;
            }
        }
        break;
    case SHTHORNTAIL_STATE_CLOSE_ATTACK_REPEAT:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT;
            randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_WAIT_MIN, SHTHORNTAIL_CLOSE_ATTACK_WAIT_MAX);
            runtime->comboTimer = (float)randomValue;
            runtime->comboRepeatCount--;
        }
        break;
    case SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomValue = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomValue;
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING_READY:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
        {
            runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
            runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING:
        SHthorntail_updateTailSwing((u32)obj, runtime);
        if (((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) &&
            (tailSwingQueued = (*gSkyInterface)->getSunPosition(0), tailSwingQueued == 0))
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING_RECOVER:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)
        {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomValue = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomValue;
        }
        break;
    default:
        OSPanic(sSHthorntailSourceFile, SHTHORNTAIL_INVALID_STATE_PANIC_LINE,
                sThorntailEnteredInvalidState);
    }
    return;
}

void SHthorntail_updateRootControlMode3(SHthorntailObject* obj, SHthorntailRuntime* runtime)
{
    int randomIdleWait;
    u32 gameBitValue;

    runtime->impactSfxTable = &gSHthorntailRootControlMode3LocomotionDefaultImpactSfxTable;
    switch (runtime->locomotionMode)
    {
    case SHTHORNTAIL_LOCOMOTION_1:
        runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion1ImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_2:
        gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION2_GAMEBIT);
        if (gameBitValue != 6)
        {
            runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion2ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_3:
        gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT);
        if (gameBitValue == 0)
        {
            runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion3ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_4:
        runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion4ImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_5:
        gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_GATE_GAMEBIT);
        if (gameBitValue == 0)
        {
            gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_EVENT_GAMEBIT);
            if (gameBitValue != 0)
            {
                (*gMapEventInterface)->triggerEvent(SHTHORNTAIL_ROOT_MODE3_TRIGGER_EVENT,
                                                    SHTHORNTAIL_ROOT_MODE3_TRIGGER_ARG);
                runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5EventImpactSfxTable;
            }
            else
            {
                gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT);
                if (gameBitValue != 0)
                {
                    if (runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE3_WAIT)
                    {
                        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
                        randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
                        runtime->idleTimer = (float)randomIdleWait;
                    }
                    runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5PlayerImpactSfxTable;
                }
                else
                {
                    runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5IdleImpactSfxTable;
                    runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE3_WAIT;
                    return;
                }
            }
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_6:
        gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT);
        if (gameBitValue == 0)
        {
            runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion6ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_7:
        gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT);
        if (gameBitValue == 0)
        {
            runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion7ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_8:
        runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion8ImpactSfxTable;
    }
    SHthorntail_updateState(obj, runtime);
}

void SHthorntail_updateRootControlMode2(SHthorntailObject* obj, SHthorntailRuntime* runtime)
{
    int linkedEventPending;
    int objectTriggerIsSet;
    u32 triggerIsSet;
    u32 triggerEventId;
    int randomTime;

    runtime->impactSfxTable = gSHthorntailLevelControlMode0DefaultImpactSfxTable;
    switch (runtime->locomotionMode)
    {
    case SHTHORNTAIL_LOCOMOTION_1:
        runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_2:
        runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_3:
        runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_4:
        runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_5:
        runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
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
            randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomTime;
        }
        runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_7:
        if (runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE2_EVENT)
        {
            triggerEventId = GameBit_Get(SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT);
            triggerIsSet = GameBit_Get(triggerEventId);
            if (triggerIsSet != 0)
            {
                (*gMapEventInterface)->setAnimEvent((int)obj->animObjId, SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT, 0);
                runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
                randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
                runtime->idleTimer = (float)randomTime;
            }
            else
            {
                return;
            }
        }
        else
        {
            triggerIsSet = GameBit_Get(SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT);
            if ((triggerIsSet == 0) &&
                (objectTriggerIsSet = ObjTrigger_IsSet((int)obj), objectTriggerIsSet != 0))
            {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
                runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE2_EVENT;
                (*gMapEventInterface)->setAnimEvent((int)obj->animObjId, SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT, 1);
                GameBit_Set(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT, 1);
                return;
            }
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_8:
        runtime->impactSfxTable = gSHthorntailRootControlMode2Locomotion8ImpactSfxTable + 6;
    }
    SHthorntail_updateState(obj, runtime);
}
