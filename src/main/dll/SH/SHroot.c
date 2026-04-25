#include "ghidra_import.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern int fn_8000BB18();
extern undefined4 fn_8000B7BC();
extern int fn_8001FFB4();
extern undefined4 fn_800200E8();
extern f32 fn_8002166C();
extern undefined4 fn_800221A0();
extern int fn_8002B9EC();
extern undefined4 fn_80036FA4();
extern int fn_80038024();
extern undefined4 fn_8003B310();
extern undefined4 fn_8006EF38();
extern int fn_80114BB0();
extern int fn_801D4CD0();

extern u8 lbl_803273D4[];
extern s32 lbl_803DBFF8;
extern u8 lbl_803DBFFC[];
extern u8 lbl_803DC004[];
extern f32 lbl_803DB414;
extern f32 lbl_803E5418;
extern f32 lbl_803E5424;
extern f64 lbl_803E5428;
extern f32 lbl_803E5438;
extern f64 DOUBLE_803e60c0;
extern f32 FLOAT_803e60e0;

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
void SHthorntail_updateLevelControlMode1(uint objectId,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config)
{
  int playerObj;
  uint randomTime;
  BOOL closeToPlayer;

  runtime->impactSfxTable = lbl_803DBFFC;
  playerObj = fn_8002B9EC();
  closeToPlayer = (double)fn_8002166C(objectId + 0x18,playerObj + 0x18) < (double)lbl_803E5424;
  if (config->impactSfxVariant == 0) {
    playerObj = fn_8001FFB4(0x13e);
    if (playerObj == 0) {
      playerObj = fn_80038024(objectId);
      if (playerObj != 0) {
        runtime->behaviorFlags = runtime->behaviorFlags | 4;
        fn_800200E8(0xcd5,1);
      }
    }
    else {
      playerObj = fn_8001FFB4(0x168);
      if (playerObj == 0) {
        playerObj = fn_80038024(objectId);
        if (playerObj != 0) {
          runtime->behaviorFlags = runtime->behaviorFlags | 4;
          fn_800200E8(0xcd6,1);
        }
      }
      else {
        runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_FREEZE_MOTION;
        runtime->hitReactState = 0;
        closeToPlayer = FALSE;
      }
    }
  }
  else {
    playerObj = fn_8001FFB4(0x1ab);
    if (playerObj != 0) {
      closeToPlayer = FALSE;
    }
  }
  if (runtime->behaviorState == 0xb) {
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      if (closeToPlayer) {
        runtime->behaviorState = 0xd;
      }
      else {
        runtime->tailSwingState = 2;
        runtime->behaviorState = 0xc;
      }
    }
  }
  else if (runtime->behaviorState < 0xb) {
    if (runtime->behaviorState == 1) {
      if (closeToPlayer) {
        runtime->behaviorState = 0;
      }
      else {
        runtime->idleTimer = runtime->idleTimer - lbl_803DB414;
        if (runtime->idleTimer <= lbl_803E5418) {
          runtime->behaviorState = 0xb;
        }
      }
    }
    else if ((runtime->behaviorState < 1) && ((s8)runtime->behaviorState > -1) &&
             !closeToPlayer) {
      runtime->idleTimer = lbl_803E5438;
      runtime->behaviorState = 1;
    }
  }
  else if (runtime->behaviorState == 0xd) {
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = 0;
      randomTime = fn_800221A0(1000,2000);
      runtime->idleTimer =
          (float)((double)CONCAT44(0x43300000,randomTime ^ 0x80000000) - lbl_803E5428);
    }
  }
  else if (runtime->behaviorState < 0xd) {
    if (closeToPlayer) {
      runtime->behaviorState = 0xd;
    }
    else {
      SHthorntail_updateTailSwing(objectId,runtime);
    }
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
void SHthorntail_updateLevelControlMode0(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config)
{
  int eventIsSet;
  uint randomTime;

  runtime->impactSfxTable = lbl_803273D4;
  switch(runtime->locomotionMode) {
  case 1:
    runtime->impactSfxTable = lbl_803273D4 + 0x10 + config->impactSfxVariant * 2;
    break;
  case 2:
    eventIsSet = fn_8001FFB4(0x9e);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = lbl_803273D4 + 0x1c + config->impactSfxVariant * 2;
    }
    else {
      runtime->impactSfxTable = lbl_803273D4 + 0x28 + config->impactSfxVariant * 2;
    }
    break;
  case 3:
    eventIsSet = fn_8001FFB4(0x193);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = lbl_803273D4 + 0x34 + config->impactSfxVariant * 2;
    }
    else {
      runtime->impactSfxTable = lbl_803273D4 + 0x40 + config->impactSfxVariant * 2;
    }
    break;
  case 5:
    eventIsSet = fn_8001FFB4(0x23d);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = lbl_803273D4 + 0x4c + config->impactSfxVariant * 2;
    }
    break;
  case 6:
    eventIsSet = fn_801D4CD0();
    if (eventIsSet != 0) {
      runtime->behaviorState = 0xe;
      return;
    }
    if (runtime->behaviorState == 0xe) {
      fn_8000BB18(0,0x409);
      runtime->behaviorState = 0;
      randomTime = fn_800221A0(1000,2000);
      runtime->idleTimer =
          (float)((double)CONCAT44(0x43300000,randomTime ^ 0x80000000) - lbl_803E5428);
    }
    eventIsSet = fn_8001FFB4(0x13f);
    if (eventIsSet == 0) {
      runtime->impactSfxTable = lbl_803DC004;
    }
    break;
  case 8:
    runtime->impactSfxTable = lbl_803273D4 + 0x58 + config->impactSfxVariant * 2;
    break;
  }
  SHthorntail_updateState(obj,runtime);
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
undefined4 SHthorntail_updateLevelControlState(int obj,undefined4 param_2,int param_3)
{
  SHthorntailRuntime *runtime;
  uint uVar1;
  int iVar2;

  runtime = *(SHthorntailRuntime **)(obj + 0xb8);
  if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_LEVELCONTROL_READY) == 0) {
    fn_8000B7BC(obj,0x7f);
    runtime->behaviorState = 0;
    uVar1 = fn_800221A0(1000,2000);
    runtime->idleTimer = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                 DOUBLE_803e60c0);
    runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_IMPACT_PENDING;
    runtime->behaviorFlags = runtime->behaviorFlags | (SHTHORNTAIL_FLAG_LEVELCONTROL_READY |
                                                       SHTHORNTAIL_FLAG_FREEZE_MOTION);
    runtime->freezeFrameCounter = 0;
    *(byte *)(obj + 0xaf) = *(byte *)(obj + 0xaf) | 8;
  }
  if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_IMPACT_PENDING) != 0) {
    iVar2 = fn_80114BB0(obj,param_3,(int)runtime,0,0);
    if (iVar2 != 0) {
      return 0;
    }
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
    fn_8003B310(obj,(int)runtime->collisionShapeState);
  }
  runtime->activeMoveValid = 0;
  fn_8006EF38((double)FLOAT_803e60e0,(double)FLOAT_803e60e0,obj,param_3 + 0xf0,8,
              (int)runtime->renderPathPoints,(int)runtime->moveScratch);
  return 0;
}

/*
 * --INFO--
 *
 * Function: sh_thorntail_getExtraSize
 * EN v1.0 Address: 0x801D5E8C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_thorntail_getExtraSize(void)
{
  return SHTHORNTAIL_EXTRA_STATE_BYTES;
}

/*
 * --INFO--
 *
 * Function: sh_thorntail_free
 * EN v1.0 Address: 0x801D5E94
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sh_thorntail_free(SHthorntailObject *obj)
{
  if (lbl_803DBFF8 == obj->config->configToken) {
    lbl_803DBFF8 = SHTHORNTAIL_CONFIG_TOKEN_NONE;
  }
  fn_80036FA4((int)obj,0x4d);
}
