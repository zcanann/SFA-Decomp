#include "ghidra_import.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern void Sfx_PlayFromObject(SHthorntailObject *obj,u16 volumeId);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern u32 fn_8002208C(f32 *state,f32 min,f32 max);
extern int randomGetRange(int min,int max);
extern int ObjTrigger_IsSet(int obj);
extern int SHthorntail_HasNearbyPendingEventObject(SHthorntailObject *obj);
extern void OSPanic(const char *file,int line,const char *msg,...);

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5418;
extern f64 lbl_803E5428;
extern f32 lbl_803E5430;
extern f32 lbl_803E5434;
extern f32 lbl_803E5438;
extern f64 lbl_803E5440;
extern char sSHthorntailSourceFile[];
extern char sThorntailEnteredInvalidState[];
extern SHthorntailEventInterface **lbl_803DCAAC;

/*
 * --INFO--
 *
 * Function: SHthorntail_updateState
 * EN v1.0 Address: 0x801D5174
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801D5764
 * EN v1.1 Size: 920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SHthorntail_updateState(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  int alertTriggered;
  int tailSwingQueued;
  int nextState;
  int randomValue;

  switch((s8)runtime->behaviorState) {
  case SHTHORNTAIL_STATE_IDLE:
    alertTriggered = fn_8002208C(&runtime->proximityAlertState,lbl_803E5430,lbl_803E5434);
    if (alertTriggered != 0) {
      Sfx_PlayFromObject(obj,SHTHORNTAIL_ALERT_VOLUME_ID);
    }
    runtime->idleTimer = runtime->idleTimer - timeDelta;
    if (runtime->idleTimer <= lbl_803E5438) {
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
    }
    break;
  case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
    runtime->idleTimer = runtime->idleTimer - timeDelta;
    if (runtime->idleTimer <= lbl_803E5418) {
      tailSwingQueued = (*gSHthorntailAnimationInterface)->isTailSwingQueued(0);
      if (tailSwingQueued != 0) {
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
      }
      else {
        nextState = SHthorntail_chooseNextState(obj,runtime,obj->config);
        runtime->behaviorState = (s8)nextState;
      }
    }
    break;
  case SHTHORNTAIL_STATE_MOVE_2:
  case SHTHORNTAIL_STATE_MOVE_3:
  case SHTHORNTAIL_STATE_MOVE_4:
  case SHTHORNTAIL_STATE_MOVE_5:
  case SHTHORNTAIL_STATE_TURN_HOME:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      tailSwingQueued = (*gSHthorntailAnimationInterface)->isTailSwingQueued(0);
      if (tailSwingQueued != 0) {
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
      }
      else {
        nextState = SHthorntail_chooseNextState(obj,runtime,obj->config);
        runtime->behaviorState = (s8)nextState;
      }
    }
    break;
  case SHTHORNTAIL_STATE_CLOSE_ATTACK:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT;
      randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_WAIT_MIN,SHTHORNTAIL_CLOSE_ATTACK_WAIT_MAX);
      runtime->comboTimer = (float)randomValue;
      randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MIN,SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MAX);
      runtime->comboRepeatCount = (s8)randomValue;
    }
    break;
  case SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT:
    runtime->comboTimer = runtime->comboTimer -
                          (float)framesThisStep;
    if (runtime->comboTimer <= lbl_803E5418) {
      if ((s8)runtime->comboRepeatCount <= 0) {
        runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER;
      }
      else {
        runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_REPEAT;
      }
    }
    break;
  case SHTHORNTAIL_STATE_CLOSE_ATTACK_REPEAT:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT;
      randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_WAIT_MIN,SHTHORNTAIL_CLOSE_ATTACK_WAIT_MAX);
      runtime->comboTimer = (float)randomValue;
      runtime->comboRepeatCount--;
    }
    break;
  case SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomValue = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
      runtime->idleTimer = (float)randomValue;
    }
    break;
  case SHTHORNTAIL_STATE_TAIL_SWING_READY:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
      runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
    }
    break;
  case SHTHORNTAIL_STATE_TAIL_SWING:
    SHthorntail_updateTailSwing((uint)obj,runtime);
    if (((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) &&
       (tailSwingQueued = (*gSHthorntailAnimationInterface)->isTailSwingQueued(0), tailSwingQueued == 0)) {
      runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
    }
    break;
  case SHTHORNTAIL_STATE_TAIL_SWING_RECOVER:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomValue = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
      runtime->idleTimer = (float)randomValue;
    }
    break;
  default:
    OSPanic(sSHthorntailSourceFile,SHTHORNTAIL_INVALID_STATE_PANIC_LINE,
            sThorntailEnteredInvalidState);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: SHthorntail_updateRootControlMode3
 * EN v1.0 Address: 0x801D550C
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x801D5AFC
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SHthorntail_updateRootControlMode3(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  int randomIdleWait;
  uint gameBitValue;

  runtime->impactSfxTable = &gSHthorntailRootControlMode3LocomotionDefaultImpactSfxTable;
  switch(runtime->locomotionMode) {
  case SHTHORNTAIL_LOCOMOTION_1:
    runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion1ImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_2:
    gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION2_GAMEBIT);
    if (gameBitValue != 6) {
      runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion2ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_3:
    gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT);
    if (gameBitValue == 0) {
      runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion3ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_4:
    runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion4ImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_5:
    gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_GATE_GAMEBIT);
    if (gameBitValue == 0) {
      gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_EVENT_GAMEBIT);
      if (gameBitValue != 0) {
        (*lbl_803DCAAC)->triggerEvent(SHTHORNTAIL_ROOT_MODE3_TRIGGER_EVENT,
                                      SHTHORNTAIL_ROOT_MODE3_TRIGGER_ARG);
        runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5EventImpactSfxTable;
      }
      else {
        gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT);
        if (gameBitValue != 0) {
          if ((s8)runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE3_WAIT) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomIdleWait;
          }
          runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5PlayerImpactSfxTable;
        }
        else {
          runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5IdleImpactSfxTable;
          runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE3_WAIT;
          return;
        }
      }
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_6:
    gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT);
    if (gameBitValue == 0) {
      runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion6ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_7:
    gameBitValue = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT);
    if (gameBitValue == 0) {
      runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion7ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_8:
    runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion8ImpactSfxTable;
  }
  SHthorntail_updateState(obj,runtime);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: SHthorntail_updateRootControlMode2
 * EN v1.0 Address: 0x801D56C4
 * EN v1.0 Size: 544b
 * EN v1.1 Address: 0x801D5CB4
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SHthorntail_updateRootControlMode2(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  int linkedEventPending;
  int objectTriggerIsSet;
  uint triggerIsSet;
  uint triggerEventId;
  int randomTime;

  runtime->impactSfxTable = gSHthorntailLevelControlMode0DefaultImpactSfxTable;
  switch(runtime->locomotionMode) {
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
    if (linkedEventPending != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
      return;
    }
    if ((s8)runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE) {
      Sfx_PlayFromObject(0,SHTHORNTAIL_EVENT_RESUME_VOLUME_ID);
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
      runtime->idleTimer = (float)randomTime;
    }
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_7:
    if ((s8)runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE2_EVENT) {
      triggerEventId = GameBit_Get(SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT);
      triggerIsSet = GameBit_Get(triggerEventId);
      if (triggerIsSet == 0) {
        return;
      }
      (*lbl_803DCAAC)->setAnimEvent((int)obj->animObjId,SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT,0);
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
      runtime->idleTimer = (float)randomTime;
    }
    else {
      triggerIsSet = GameBit_Get(SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT);
      if ((triggerIsSet == 0) &&
          (objectTriggerIsSet = ObjTrigger_IsSet((int)obj), objectTriggerIsSet != 0)) {
        runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
        runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE2_EVENT;
        (*lbl_803DCAAC)->setAnimEvent((int)obj->animObjId,SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT,1);
        GameBit_Set(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT,1);
        return;
      }
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_8:
    runtime->impactSfxTable = gSHthorntailRootControlMode2Locomotion8ImpactSfxTable + 6;
  }
  SHthorntail_updateState(obj,runtime);
}
#pragma peephole reset
#pragma scheduling reset
