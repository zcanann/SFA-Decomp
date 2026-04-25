#include "ghidra_import.h"
#include "main/dll/SH/dll_1E7.h"
#include "main/dll/SH/dll_1E8.h"

extern undefined4 FUN_80006824();
extern int fn_8001FFB4();
extern undefined4 fn_800221A0();
extern uint FUN_80017758();
extern uint FUN_80017760();
extern undefined4 FUN_80242fc0();

extern undefined4 DAT_803dc070;
extern undefined4* lbl_803DCAAC;
extern undefined4* DAT_803dd6d8;
extern u8 lbl_803DC008[];
extern u8 lbl_803DC010[];
extern u8 lbl_803DC014[];
extern u8 lbl_803DC018[];
extern u8 lbl_803DC01C[];
extern u8 lbl_803DC020[];
extern u8 lbl_803DC024[];
extern u8 lbl_803DC028[];
extern u8 lbl_803DC02C[];
extern u8 lbl_803DC030[];
extern u8 lbl_803DC034[];
extern f64 lbl_803E5428;
extern f64 DOUBLE_803e60c0;
extern f64 DOUBLE_803e60d8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60c8;
extern f32 FLOAT_803e60cc;
extern f32 FLOAT_803e60d0;
extern char sSHthorntailSourceFile[];
extern char sThorntailEnteredInvalidState[];

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
void SHthorntail_updateState(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  SHthorntailConfig *config;
  int iVar1;
  uint uVar2;
  
  config = obj->config;
  switch(runtime->behaviorState) {
  case 0:
    uVar2 = FUN_80017758((double)FLOAT_803e60c8,(double)FLOAT_803e60cc,
                         &runtime->proximityAlertState);
    if (uVar2 != 0) {
      FUN_80006824((uint)obj,0x410);
    }
    runtime->idleTimer = runtime->idleTimer - FLOAT_803dc074;
    if (runtime->idleTimer <= FLOAT_803e60d0) {
      runtime->behaviorState = 1;
    }
    break;
  case 1:
    runtime->idleTimer = runtime->idleTimer - FLOAT_803dc074;
    if (runtime->idleTimer <= FLOAT_803e60b0) {
      iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
      if (iVar1 == 0) {
        uVar2 = SHthorntail_chooseNextState((short *)obj,runtime,config);
        runtime->behaviorState = (char)uVar2;
      }
      else {
        runtime->behaviorState = 0xb;
      }
    }
    break;
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
      if (iVar1 == 0) {
        uVar2 = SHthorntail_chooseNextState((short *)obj,runtime,config);
        runtime->behaviorState = (char)uVar2;
      }
      else {
        runtime->behaviorState = 0xb;
      }
    }
    break;
  case 7:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = 8;
      uVar2 = FUN_80017760(500,800);
      runtime->comboTimer = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                    DOUBLE_803e60c0);
      uVar2 = FUN_80017760(1,3);
      runtime->comboRepeatCount = (char)uVar2;
    }
    break;
  case 8:
    runtime->comboTimer = runtime->comboTimer -
                          (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) -
                                  DOUBLE_803e60d8);
    if (runtime->comboTimer <= FLOAT_803e60b0) {
      if (runtime->comboRepeatCount < '\x01') {
        runtime->behaviorState = 10;
      }
      else {
        runtime->behaviorState = 9;
      }
    }
    break;
  case 9:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = 8;
      uVar2 = FUN_80017760(500,800);
      runtime->comboTimer = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                    DOUBLE_803e60c0);
      runtime->comboRepeatCount = runtime->comboRepeatCount + -1;
    }
    break;
  case 10:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = 0;
      uVar2 = FUN_80017760(1000,2000);
      runtime->idleTimer = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                   DOUBLE_803e60c0);
    }
    break;
  case 0xb:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->tailSwingState = 2;
      runtime->behaviorState = 0xc;
    }
    break;
  case 0xc:
    SHthorntail_updateTailSwing((uint)obj,runtime);
    if (((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) &&
       (iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0), iVar1 == 0)) {
      runtime->behaviorState = 0xd;
    }
    break;
  case 0xd:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = 0;
      uVar2 = FUN_80017760(1000,2000);
      runtime->idleTimer = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                   DOUBLE_803e60c0);
    }
    break;
  default:
    FUN_80242fc0(sSHthorntailSourceFile,0x6cd,sThorntailEnteredInvalidState);
  }
  return;
}

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
void SHthorntail_updateRootControlMode3(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  uint randomTime;
  int eventIsSet;

  runtime->impactSfxTable = lbl_803DC008;
  switch(runtime->locomotionMode) {
  case 1:
    runtime->impactSfxTable = lbl_803DC010;
    break;
  case 2:
    eventIsSet = fn_8001FFB4(0xc2);
    if (eventIsSet != 6) {
      runtime->impactSfxTable = lbl_803DC014;
    }
    break;
  case 3:
    eventIsSet = fn_8001FFB4(0x193);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = lbl_803DC018;
    }
    break;
  case 4:
    runtime->impactSfxTable = lbl_803DC01C;
    break;
  case 5:
    eventIsSet = fn_8001FFB4(0x23c);
    if (eventIsSet == 0) {
      eventIsSet = fn_8001FFB4(0x5bd);
      if (eventIsSet == 0) {
        eventIsSet = fn_8001FFB4(0x23d);
        if (eventIsSet == 0) {
          runtime->impactSfxTable = lbl_803DC020;
          runtime->behaviorState = 0x10;
          return;
        }
        if (runtime->behaviorState == 0x10) {
          runtime->behaviorState = 0;
          randomTime = fn_800221A0(1000,2000);
          runtime->idleTimer =
              (float)((double)CONCAT44(0x43300000,randomTime ^ 0x80000000) - lbl_803E5428);
        }
        runtime->impactSfxTable = lbl_803DC024;
      }
      else {
        (**(code **)(*lbl_803DCAAC + 0x44))(0x1d,3);
        runtime->impactSfxTable = lbl_803DC028;
      }
    }
    break;
  case 6:
    eventIsSet = fn_8001FFB4(0x13f);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = lbl_803DC02C;
    }
    break;
  case 7:
    eventIsSet = fn_8001FFB4(0x199);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = lbl_803DC030;
    }
    break;
  case 8:
    runtime->impactSfxTable = lbl_803DC034;
  }
  SHthorntail_updateState(obj,runtime);
}
