#include "ghidra_import.h"
#include "main/dll/SH/dll_1E7.h"
#include "main/dll/SH/dll_1E8.h"

extern void fn_8000BB18(SHthorntailObject *obj,u16 volumeId);
extern uint GameBit_Get(int eventId);
extern u32 fn_8002208C(f32 *state,f32 min,f32 max);
extern int fn_800221A0(int min,int max);
extern void OSPanic(const char *file,int line,const char *msg,...);

extern u8 lbl_803DB410;
extern f32 lbl_803DB414;
extern undefined4* lbl_803DCAAC;
extern f32 lbl_803E5418;
extern f64 lbl_803E5428;
extern f32 lbl_803E5430;
extern f32 lbl_803E5434;
extern f32 lbl_803E5438;
extern f64 lbl_803E5440;
extern char sSHthorntailSourceFile[];
extern char sThorntailEnteredInvalidState[];

typedef struct SHthorntailAnimationInterface {
  u8 pad00[0x24];
  int (*isTailSwingQueued)(int);
} SHthorntailAnimationInterface;

extern SHthorntailAnimationInterface **lbl_803DCA58;

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
void SHthorntail_updateState(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  int iVar1;
  int iVar2;
  
  switch((s8)runtime->behaviorState) {
  case SHTHORNTAIL_STATE_IDLE:
    iVar2 = fn_8002208C(&runtime->proximityAlertState,lbl_803E5430,lbl_803E5434);
    if (iVar2 != 0) {
      fn_8000BB18(obj,0x410);
    }
    runtime->idleTimer = runtime->idleTimer - lbl_803DB414;
    if (runtime->idleTimer <= lbl_803E5438) {
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
    }
    break;
  case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
    runtime->idleTimer = runtime->idleTimer - lbl_803DB414;
    if (runtime->idleTimer <= lbl_803E5418) {
      iVar1 = (*lbl_803DCA58)->isTailSwingQueued(0);
      if (iVar1 != 0) {
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
      }
      else {
        iVar2 = SHthorntail_chooseNextState(obj,runtime,obj->config);
        runtime->behaviorState = (s8)iVar2;
      }
    }
    break;
  case SHTHORNTAIL_STATE_MOVE_2:
  case SHTHORNTAIL_STATE_MOVE_3:
  case SHTHORNTAIL_STATE_MOVE_4:
  case SHTHORNTAIL_STATE_MOVE_5:
  case SHTHORNTAIL_STATE_TURN_HOME:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      iVar1 = (*lbl_803DCA58)->isTailSwingQueued(0);
      if (iVar1 != 0) {
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
      }
      else {
        iVar2 = SHthorntail_chooseNextState(obj,runtime,obj->config);
        runtime->behaviorState = (s8)iVar2;
      }
    }
    break;
  case SHTHORNTAIL_STATE_CLOSE_ATTACK:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT;
      iVar2 = fn_800221A0(500,800);
      runtime->comboTimer = (float)iVar2;
      iVar2 = fn_800221A0(1,3);
      runtime->comboRepeatCount = (s8)iVar2;
    }
    break;
  case SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT:
    runtime->comboTimer = runtime->comboTimer -
                          (float)lbl_803DB410;
    if (runtime->comboTimer <= lbl_803E5418) {
      if (runtime->comboRepeatCount < '\x01') {
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
      iVar2 = fn_800221A0(500,800);
      runtime->comboTimer = (float)iVar2;
      runtime->comboRepeatCount = runtime->comboRepeatCount + -1;
    }
    break;
  case SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      iVar2 = fn_800221A0(1000,2000);
      runtime->idleTimer = (float)iVar2;
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
       (iVar1 = (*lbl_803DCA58)->isTailSwingQueued(0), iVar1 == 0)) {
      runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
    }
    break;
  case SHTHORNTAIL_STATE_TAIL_SWING_RECOVER:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      iVar2 = fn_800221A0(1000,2000);
      runtime->idleTimer = (float)iVar2;
    }
    break;
  default:
    OSPanic(sSHthorntailSourceFile,0x6cd,sThorntailEnteredInvalidState);
  }
  return;
}
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
void SHthorntail_updateRootControlMode3(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  int randomTime;
  uint eventIsSet;

  runtime->impactSfxTable = &gSHthorntailRootControlMode3LocomotionDefaultImpactSfxTable;
  switch(runtime->locomotionMode) {
  case SHTHORNTAIL_LOCOMOTION_1:
    runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion1ImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_2:
    eventIsSet = GameBit_Get(0xc2);
    if (eventIsSet != 6) {
      runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion2ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_3:
    eventIsSet = GameBit_Get(0x193);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion3ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_4:
    runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion4ImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_5:
    eventIsSet = GameBit_Get(0x23c);
    if (eventIsSet == 0) {
      eventIsSet = GameBit_Get(0x5bd);
      if (eventIsSet == 0) {
        eventIsSet = GameBit_Get(0x23d);
        if (eventIsSet == 0) {
          runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5IdleImpactSfxTable;
          runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE3_WAIT;
          return;
        }
        if (runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE3_WAIT) {
          runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
          randomTime = fn_800221A0(1000,2000);
          runtime->idleTimer = (float)randomTime;
        }
        runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5PlayerImpactSfxTable;
      }
      else {
        (*(code *)(*lbl_803DCAAC + 0x44))(0x1d,3);
        runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion5EventImpactSfxTable;
      }
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_6:
    eventIsSet = GameBit_Get(0x13f);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion6ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_7:
    eventIsSet = GameBit_Get(0x199);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion7ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_8:
    runtime->impactSfxTable = &gSHthorntailRootControlMode3Locomotion8ImpactSfxTable;
  }
  SHthorntail_updateState(obj,runtime);
}
#pragma scheduling reset
