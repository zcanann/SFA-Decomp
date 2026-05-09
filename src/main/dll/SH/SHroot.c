#include "ghidra_import.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern void Sfx_PlayFromObject(SHthorntailObject *obj,u16 volumeId);
extern void Sfx_StopObjectChannel(int obj,u16 volumeId);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern f32 getXZDistance(int posA,int posB);
extern u32 randomGetRange(int min,int max);
extern int Obj_GetPlayerObject();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjTrigger_IsSet();
extern void characterDoEyeAnims(int obj,int collisionShapeState);
extern void objAudioFn_8006ef38(double scaleX,double scaleY,int obj,int joint,int pointCount,int pathPoints,
                        int scratch);
extern int fn_80114BB0();
extern int SHthorntail_HasNearbyPendingEventObject(SHthorntailObject *obj);

extern f32 timeDelta;
extern f32 lbl_803E5418;
extern f32 lbl_803E5424;
extern f64 lbl_803E5428;
extern f32 lbl_803E5438;
extern f32 lbl_803E5448;
extern u8 lbl_80326E98[];

#define SHTHORNTAIL_LEVEL_MODE0_SFX_BASE 0x53C
#define SHTHORNTAIL_LEVEL_MODE0_SFX_LOC1 0x54C
#define SHTHORNTAIL_LEVEL_MODE0_SFX_LOC2_CLEAR 0x558
#define SHTHORNTAIL_LEVEL_MODE0_SFX_LOC2_SET 0x564
#define SHTHORNTAIL_LEVEL_MODE0_SFX_LOC3_CLEAR 0x570
#define SHTHORNTAIL_LEVEL_MODE0_SFX_LOC3_SET 0x57C
#define SHTHORNTAIL_LEVEL_MODE0_SFX_LOC5_CLEAR 0x588
#define SHTHORNTAIL_LEVEL_MODE0_SFX_LOC8 0x594

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
#pragma scheduling off
#pragma peephole off
void SHthorntail_updateLevelControlMode1(uint objectId,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config)
{
  int playerObj;
  int randomIdleWait;
  u8 closeToPlayer;
  uint gameBit;
  int triggerIsSet;

  runtime->impactSfxTable = &gSHthorntailLevelControlMode1ImpactSfxTable;
  playerObj = Obj_GetPlayerObject();
  {
    int cmp = (double)getXZDistance(objectId + 0x18,playerObj + 0x18) < (double)lbl_803E5424;
    closeToPlayer = cmp;
  }
  if (config->impactSfxVariant == 0) {
    gameBit = GameBit_Get(0x13e);
    if (gameBit != 0) {
      gameBit = GameBit_Get(0x168);
      if (gameBit != 0) {
        runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_FREEZE_MOTION;
        runtime->freezeFrameCounter = 0;
        closeToPlayer = FALSE;
      }
      else {
        triggerIsSet = ObjTrigger_IsSet(objectId);
        if (triggerIsSet != 0) {
          runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
          GameBit_Set(0xcd6,1);
        }
      }
    }
    else {
      triggerIsSet = ObjTrigger_IsSet(objectId);
      if (triggerIsSet != 0) {
        runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
        GameBit_Set(0xcd5,1);
      }
    }
  }
  else {
    gameBit = GameBit_Get(0x1ab);
    if (gameBit != 0) {
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
      runtime->idleTimer = runtime->idleTimer - timeDelta;
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
      randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
      runtime->idleTimer = (float)randomIdleWait;
    }
    break;
  }
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
void SHthorntail_updateLevelControlMode0(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config)
{
  int linkedEventPending;
  uint gameBit;
  int randomIdleWait;
  u8 *levelControlTables;

  levelControlTables = lbl_80326E98;
  runtime->impactSfxTable = levelControlTables + SHTHORNTAIL_LEVEL_MODE0_SFX_BASE;
  switch(runtime->locomotionMode) {
  case SHTHORNTAIL_LOCOMOTION_1:
    runtime->impactSfxTable =
        levelControlTables + SHTHORNTAIL_LEVEL_MODE0_SFX_LOC1 + config->impactSfxVariant * 2;
    break;
  case SHTHORNTAIL_LOCOMOTION_2:
    gameBit = GameBit_Get(0x9e);
    if (gameBit != 0) {
      runtime->impactSfxTable =
          levelControlTables + SHTHORNTAIL_LEVEL_MODE0_SFX_LOC2_SET +
          config->impactSfxVariant * 2;
    }
    else {
      runtime->impactSfxTable =
          levelControlTables + SHTHORNTAIL_LEVEL_MODE0_SFX_LOC2_CLEAR +
          config->impactSfxVariant * 2;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_3:
    gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT);
    if (gameBit != 0) {
      runtime->impactSfxTable =
          levelControlTables + SHTHORNTAIL_LEVEL_MODE0_SFX_LOC3_SET +
          config->impactSfxVariant * 2;
    }
    else {
      runtime->impactSfxTable =
          levelControlTables + SHTHORNTAIL_LEVEL_MODE0_SFX_LOC3_CLEAR +
          config->impactSfxVariant * 2;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_5:
    gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT);
    if (gameBit == 0) {
      runtime->impactSfxTable =
          levelControlTables + SHTHORNTAIL_LEVEL_MODE0_SFX_LOC5_CLEAR +
          config->impactSfxVariant * 2;
    }
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
      randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
      runtime->idleTimer = (float)randomIdleWait;
    }
    gameBit = GameBit_Get(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT);
    if (gameBit == 0) {
      runtime->impactSfxTable = &gSHthorntailLevelControlMode0Locomotion6ImpactSfxTable;
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_8:
    runtime->impactSfxTable =
        levelControlTables + SHTHORNTAIL_LEVEL_MODE0_SFX_LOC8 + config->impactSfxVariant * 2;
    break;
  }
  SHthorntail_updateState(obj,runtime);
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
undefined4 SHthorntail_updateLevelControlState(SHthorntailObject *obj,undefined4 param_2,int param_3)
{
  SHthorntailRuntime *runtime;
  int randomIdleWait;
  int impactHandled;
  int levelControlReady;
  int impactPending;

  runtime = obj->runtime;
  levelControlReady = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_LEVELCONTROL_READY);
  if (levelControlReady == 0) {
    Sfx_StopObjectChannel((int)obj,0x7f);
    runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
    randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
    runtime->idleTimer = (float)randomIdleWait;
    runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
    runtime->behaviorFlags = runtime->behaviorFlags | (SHTHORNTAIL_FLAG_LEVELCONTROL_READY |
                                                       SHTHORNTAIL_FLAG_FREEZE_MOTION);
    runtime->freezeFrameCounter = 0;
    obj->statusFlags = obj->statusFlags | SHTHORNTAIL_OBJECT_STATUS_08;
  }
  impactPending = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_IMPACT_PENDING);
  if (impactPending != 0) {
    impactHandled = fn_80114BB0((int)obj,param_3,(int)runtime,0,0);
    if (impactHandled != 0) {
      return 0;
    }
    *(short *)(param_3 + 0x6e) = *(short *)(param_3 + 0x6e) & ~0x40;
    characterDoEyeAnims((int)obj,(int)runtime->collisionShapeState);
  }
  runtime->activeMoveValid = 0;
  objAudioFn_8006ef38((double)lbl_803E5448,(double)lbl_803E5448,(int)obj,param_3 + 0xf0,8,
              (int)runtime->renderPathPoints,(int)runtime->moveScratch);
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
void SHthorntail_free(SHthorntailObject *obj)
{
  u32 activeConfigToken;

  activeConfigToken = (u32)gSHthorntailActiveConfigToken;
  if (activeConfigToken == (u32)obj->config->configToken) {
    gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
  }
  ObjGroup_RemoveObject((int)obj,0x4d);
}
#pragma peephole reset
#pragma scheduling reset
