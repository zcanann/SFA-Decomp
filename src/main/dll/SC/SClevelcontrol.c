#include "ghidra_import.h"
#include "main/dll/SH/dll_1E8.h"
#include "main/dll/SH/SHthorntail.h"
#include "main/dll/SC/SClevelcontrol.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern int FUN_800384ec();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8006ef38();
extern int FUN_801149b8();

extern undefined4 DAT_80328014;
extern undefined4 DAT_803dcc64;
extern undefined4 DAT_803dcc6c;
extern f64 DOUBLE_803e60c0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60bc;
extern f32 FLOAT_803e60d0;
extern f32 FLOAT_803e60e0;

/*
 * --INFO--
 *
 * Function: SHthorntail_updateLevelControlMode1
 * EN v1.0 Address: 0x801D5ED4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D5ED4
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_updateLevelControlMode1(uint objectId,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config)
{
}

/*
 * --INFO--
 *
 * Function: SHthorntail_updateLevelControlMode0
 * EN v1.0 Address: 0x801D5ED8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D6158
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_updateLevelControlMode0(double param_1,undefined8 param_2,undefined8 param_3,
                                         undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                         undefined8 param_7,undefined8 param_8,
                                         SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config,uint param_12,float *param_13,
                                         undefined4 param_14,
                                         undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: SHthorntail_updateLevelControlState
 * EN v1.0 Address: 0x801D5EDC
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x801D6338
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
SHthorntail_updateLevelControlState(double param_1,double param_2,double param_3,undefined8 param_4,
                                    undefined8 param_5,undefined8 param_6,undefined8 param_7,
                                    undefined8 param_8,SHthorntailObject *obj,undefined4 param_10,
                                    int param_11,undefined4 param_12,undefined4 param_13,
                                    undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  SHthorntailRuntime *runtime;
  uint uVar1;
  int iVar2;
  
  runtime = obj->runtime;
  if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_LEVELCONTROL_READY) == 0) {
    FUN_8000680c((int)obj,0x7f);
    runtime->behaviorState = 0;
    uVar1 = FUN_80017760(1000,2000);
    param_1 = DOUBLE_803e60c0;
    runtime->idleTimer = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e60c0);
    runtime->behaviorFlags = runtime->behaviorFlags & 0xfb;
    runtime->behaviorFlags = runtime->behaviorFlags | (SHTHORNTAIL_FLAG_LEVELCONTROL_READY |
                                                       SHTHORNTAIL_FLAG_FREEZE_MOTION);
    runtime->freezeFrameCounter = 0;
    *(byte *)((int)obj + 0xaf) = *(byte *)((int)obj + 0xaf) | 8;
  }
  if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_IMPACT_PENDING) != 0) {
    iVar2 = FUN_801149b8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)obj,
                         param_11,runtime,0,0,param_14,param_15,param_16);
    if (iVar2 != 0) {
      return 0;
    }
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffbf;
    FUN_8003b280((int)obj,(int)runtime->collisionShapeState);
  }
  runtime->activeMoveValid = 0;
  FUN_8006ef38((double)FLOAT_803e60e0,(double)FLOAT_803e60e0,(int)obj,param_11 + 0xf0,8,
               (int)runtime->renderPathPoints,(int)runtime->moveScratch);
  return 0;
}
