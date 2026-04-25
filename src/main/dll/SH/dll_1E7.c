#include "ghidra_import.h"
#include "main/dll/SH/dll_1E7.h"

extern undefined4 FUN_80006824();
extern double FUN_80017708();
extern int FUN_80017730();
extern uint FUN_80017690();
extern uint FUN_80017758();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80037008();
extern int FUN_800384ec();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b444();
extern undefined4 FUN_801d4810();
extern undefined4 FUN_801d4814();
extern int FUN_800575b4();
extern undefined4 FUN_800723a0();

extern undefined4 DAT_80327a58;
extern undefined4 DAT_80327a64;
extern undefined4 DAT_803dcc30;
extern undefined4 DAT_803dcc34;
extern undefined4 DAT_803dcc3c;
extern undefined4 DAT_803dcc48;
extern undefined4 DAT_803dcc4c;
extern undefined4 DAT_803dcc50;
extern undefined4 DAT_803dcc54;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6090;
extern f32 FLOAT_803e609c;
extern f32 FLOAT_803e60a0;
extern f64 DOUBLE_803e60c0;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60b4;
extern f32 FLOAT_803e60b8;
extern f32 FLOAT_803e60bc;

/*
 * --INFO--
 *
 * Function: FUN_801d4cd0
 * EN v1.0 Address: 0x801D4CD0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D4D8C
 * EN v1.1 Size: 1280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d4cd0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: SHthorntail_updateTailSwing
 * EN v1.0 Address: 0x801D4E80
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801D5470
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_updateTailSwing(uint objectId,SHthorntailRuntime *runtime)
{
  byte bVar1;

  bVar1 = runtime->tailSwingState;
  if (bVar1 == SHTHORNTAIL_TAIL_SWING_WINDUP) {
    runtime->tailSwingTimer = runtime->tailSwingTimer - FLOAT_803dc074;
    if (runtime->tailSwingTimer <= FLOAT_803e60b0) {
      FUN_80006824(objectId,0xa8);
      runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
    }
  }
  else if (bVar1 == SHTHORNTAIL_TAIL_SWING_READY) {
    runtime->tailSwingTimer = runtime->tailSwingTimer - FLOAT_803dc074;
    if (runtime->tailSwingTimer <= FLOAT_803e60b0) {
      FUN_80006824(objectId,0xa9);
      runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_WINDUP;
      runtime->tailSwingTimer = FLOAT_803e60b4;
    }
  }
  else if ((bVar1 < SHTHORNTAIL_TAIL_SWING_STATE_COUNT) &&
           ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)) {
    runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_READY;
    runtime->tailSwingTimer = FLOAT_803e60b8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: SHthorntail_chooseNextState
 * EN v1.0 Address: 0x801D4F68
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801D5558
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint SHthorntail_chooseNextState(SHthorntailObject *object,SHthorntailRuntime *runtime,
                                 SHthorntailConfig *config)
{
  short *obj;
  short sVar1;
  int iVar2;
  uint uVar3;
  double dVar4;

  obj = (short *)object;
  if (config->leashRadiusByte == '\0') {
    uVar3 = SHTHORNTAIL_STATE_CLOSE_ATTACK;
  }
  else {
    iVar2 = FUN_80017a98();
    dVar4 = FUN_80017708((float *)(obj + 0xc),(float *)(iVar2 + 0x18));
    if ((double)FLOAT_803e60bc <= dVar4) {
      dVar4 = FUN_80017708((float *)(obj + 0xc),(float *)&config->homePos);
      if ((double)(float)((double)CONCAT44(0x43300000,
                                           (uint)config->leashRadiusByte *
                                           (uint)config->leashRadiusByte ^ 0x80000000) -
                         DOUBLE_803e60c0) < dVar4) {
        iVar2 = FUN_80017730();
        sVar1 = (short)iVar2 - *obj;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        iVar2 = (int)sVar1;
        if (iVar2 < 0) {
          iVar2 = -iVar2;
        }
        if (0x20 < iVar2) {
          FUN_80017730();
          FUN_800723a0();
          if ((SHTHORNTAIL_STATE_IDLE_COUNTDOWN < runtime->behaviorState) &&
              (runtime->behaviorState < SHTHORNTAIL_STATE_TURN_HOME)) {
            return SHTHORNTAIL_STATE_TURN_HOME;
          }
          return SHTHORNTAIL_STATE_CLOSE_ATTACK;
        }
      }
      iVar2 = FUN_800575b4((double)(*(float *)(obj + 0x54) * *(float *)(obj + 4)),
                           (float *)(obj + 6));
      if (iVar2 == 0) {
        uVar3 = SHTHORNTAIL_STATE_CLOSE_ATTACK;
      }
      else if ((runtime->behaviorState < SHTHORNTAIL_STATE_MOVE_2) ||
               (SHTHORNTAIL_STATE_MOVE_5 < runtime->behaviorState)) {
        uVar3 = SHTHORNTAIL_STATE_MOVE_2;
      }
      else {
        uVar3 = FUN_80017760(SHTHORNTAIL_STATE_MOVE_3,SHTHORNTAIL_STATE_MOVE_5);
        uVar3 = uVar3 & 0xff;
      }
    }
    else if ((runtime->behaviorState < SHTHORNTAIL_STATE_MOVE_2) ||
             (SHTHORNTAIL_STATE_MOVE_5 < runtime->behaviorState)) {
      uVar3 = SHTHORNTAIL_STATE_CLOSE_ATTACK;
    }
    else {
      uVar3 = SHTHORNTAIL_STATE_TURN_HOME;
    }
  }
  return uVar3;
}
