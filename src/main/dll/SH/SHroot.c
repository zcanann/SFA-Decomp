#include "ghidra_import.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern void fn_8000BB18(SHthorntailObject *obj,u16 volumeId);
extern void fn_8000B7BC(int obj,u16 volumeId);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern f32 fn_8002166C(int posA,int posB);
extern u32 fn_800221A0(int min,int max);
extern int fn_8002B9EC();
extern void fn_80036FA4(int obj,u16 volumeId);
extern int fn_80038024();
extern void fn_8003B310(int obj,int collisionShapeState);
extern void fn_8006EF38(double scaleX,double scaleY,int obj,int joint,int pointCount,int pathPoints,
                        int scratch);
extern int fn_80114BB0();
extern int fn_801D4CD0(SHthorntailObject *obj);

extern f32 lbl_803DB414;
extern f32 lbl_803E5418;
extern f32 lbl_803E5424;
extern f64 lbl_803E5428;
extern f32 lbl_803E5438;
extern f32 lbl_803E5448;

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
  int randomTime;
  BOOL closeToPlayer;

  runtime->impactSfxTable = &gSHthorntailLevelControlMode1ImpactSfxTable;
  playerObj = fn_8002B9EC();
  closeToPlayer = (double)fn_8002166C(objectId + 0x18,playerObj + 0x18) < (double)lbl_803E5424;
  if (config->impactSfxVariant == 0) {
    playerObj = GameBit_Get(0x13e);
    if (playerObj == 0) {
      playerObj = fn_80038024(objectId);
      if (playerObj != 0) {
        runtime->behaviorFlags = runtime->behaviorFlags | 4;
        GameBit_Set(0xcd5,1);
      }
    }
    else {
      playerObj = GameBit_Get(0x168);
      if (playerObj == 0) {
        playerObj = fn_80038024(objectId);
        if (playerObj != 0) {
          runtime->behaviorFlags = runtime->behaviorFlags | 4;
          GameBit_Set(0xcd6,1);
        }
      }
      else {
        runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_FREEZE_MOTION;
        runtime->freezeFrameCounter = 0;
        closeToPlayer = FALSE;
      }
    }
  }
  else {
    playerObj = GameBit_Get(0x1ab);
    if (playerObj != 0) {
      closeToPlayer = FALSE;
    }
  }
  switch((s8)runtime->behaviorState) {
  case SHTHORNTAIL_STATE_IDLE:
    if (!closeToPlayer) {
      runtime->idleTimer = lbl_803E5438;
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
    }
    break;
  case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
    if (closeToPlayer) {
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
    }
    else {
      runtime->idleTimer = runtime->idleTimer - lbl_803DB414;
      if (runtime->idleTimer <= lbl_803E5418) {
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
      }
    }
    break;
  case SHTHORNTAIL_STATE_TAIL_SWING_READY:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      if (closeToPlayer) {
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
      }
      else {
        runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
      }
    }
    break;
  case SHTHORNTAIL_STATE_TAIL_SWING:
    if (closeToPlayer) {
      runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
    }
    else {
      SHthorntail_updateTailSwing(objectId,runtime);
    }
    break;
  case SHTHORNTAIL_STATE_TAIL_SWING_RECOVER:
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomTime = fn_800221A0(1000,2000);
      runtime->idleTimer = (float)randomTime;
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
void SHthorntail_updateLevelControlMode0(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config)
{
  int eventIsSet;
  uint gameBit;
  int randomTime;

  runtime->impactSfxTable = gSHthorntailLevelControlMode0DefaultImpactSfxTable;
  switch(runtime->locomotionMode) {
  case SHTHORNTAIL_LOCOMOTION_1:
    runtime->impactSfxTable =
        gSHthorntailLevelControlMode0DefaultImpactSfxTable + 0x10 + config->impactSfxVariant * 2;
    break;
  case SHTHORNTAIL_LOCOMOTION_2:
    gameBit = GameBit_Get(0x9e);
    if (gameBit == 0) {
      runtime->impactSfxTable =
          gSHthorntailLevelControlMode0DefaultImpactSfxTable + 0x1c +
          config->impactSfxVariant * 2;
    }
    else {
      runtime->impactSfxTable =
          gSHthorntailLevelControlMode0DefaultImpactSfxTable + 0x28 +
          config->impactSfxVariant * 2;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_3:
    gameBit = GameBit_Get(0x193);
    if (gameBit == 0) {
      runtime->impactSfxTable =
          gSHthorntailLevelControlMode0DefaultImpactSfxTable + 0x34 +
          config->impactSfxVariant * 2;
    }
    else {
      runtime->impactSfxTable =
          gSHthorntailLevelControlMode0DefaultImpactSfxTable + 0x40 +
          config->impactSfxVariant * 2;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_5:
    gameBit = GameBit_Get(0x23d);
    if (gameBit == 0) {
      runtime->impactSfxTable =
          gSHthorntailLevelControlMode0DefaultImpactSfxTable + 0x4c +
          config->impactSfxVariant * 2;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_6:
    eventIsSet = fn_801D4CD0(obj);
    if (eventIsSet != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
      return;
    }
    if (runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE) {
      fn_8000BB18(0,0x409);
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomTime = fn_800221A0(1000,2000);
      runtime->idleTimer = (float)randomTime;
    }
    gameBit = GameBit_Get(0x13f);
    if (gameBit == 0) {
      runtime->impactSfxTable = &gSHthorntailLevelControlMode0Locomotion6ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_8:
    runtime->impactSfxTable =
        gSHthorntailLevelControlMode0DefaultImpactSfxTable + 0x58 + config->impactSfxVariant * 2;
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
undefined4 SHthorntail_updateLevelControlState(SHthorntailObject *obj,undefined4 param_2,int param_3)
{
  SHthorntailRuntime *runtime;
  int randomTime;
  int iVar2;

  runtime = obj->runtime;
  if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_LEVELCONTROL_READY) == 0) {
    fn_8000B7BC((int)obj,0x7f);
    runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
    randomTime = fn_800221A0(1000,2000);
    runtime->idleTimer = (float)randomTime;
    runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_IMPACT_PENDING;
    runtime->behaviorFlags = runtime->behaviorFlags | (SHTHORNTAIL_FLAG_LEVELCONTROL_READY |
                                                       SHTHORNTAIL_FLAG_FREEZE_MOTION);
    runtime->freezeFrameCounter = 0;
    obj->statusFlags = obj->statusFlags | SHTHORNTAIL_OBJECT_STATUS_08;
  }
  if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_IMPACT_PENDING) != 0) {
    iVar2 = fn_80114BB0((int)obj,param_3,(int)runtime,0,0);
    if (iVar2 != 0) {
      return 0;
    }
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
    fn_8003B310((int)obj,(int)runtime->collisionShapeState);
  }
  runtime->activeMoveValid = 0;
  fn_8006EF38((double)lbl_803E5448,(double)lbl_803E5448,(int)obj,param_3 + 0xf0,8,
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
  u32 activeConfigToken;

  activeConfigToken = (u32)gSHthorntailActiveConfigToken;
  if (activeConfigToken == (u32)obj->config->configToken) {
    gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
  }
  fn_80036FA4((int)obj,0x4d);
}
