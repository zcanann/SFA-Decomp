#include "ghidra_import.h"
#include "main/dll/SH/dll_1E7.h"

extern void Sfx_PlayFromObject(uint objectId,u16 volumeId);
extern f32 fn_8002166C(Vec *a,Vec *b);
extern f32 fn_800216D0(Vec *a,Vec *b);
extern s16 getAngle(f32 deltaX,f32 deltaZ);
extern int randomGetRange(int min,int max);
extern int Obj_GetPlayerObject(void);
extern SHthorntailObject **ObjGroup_GetObjects(int group,int *countOut);
extern int fn_8005A10C(Vec *pos,f32 radius);
extern void fn_8014C66C(SHthorntailObject *obj,SHthorntailObject *other);
extern void OSReport(const char *msg,...);
extern uint FUN_80017690();
extern uint FUN_80017758();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b444();
extern undefined4 FUN_801d4810();
extern undefined4 FUN_801d4814();

extern undefined4 DAT_80327a58;
extern u32 lbl_80326E98[][4];
extern char sSHthorntailAngleYawDebug[];
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
extern f32 timeDelta;
extern f32 lbl_803E5418;
extern f32 lbl_803E5414;
extern f32 lbl_803E541C;
extern f32 lbl_803E5420;
extern f32 lbl_803E5424;
extern f64 lbl_803E5428;
extern f32 lbl_803DC074;
extern f32 lbl_803E6090;
extern f32 lbl_803E609C;
extern f32 lbl_803E60A0;
extern f32 lbl_803E60B0;
extern f32 lbl_803E60B4;
extern f32 lbl_803E60B8;

/*
 * --INFO--
 *
 * Function: SHthorntail_HasNearbyPendingEventObject
 * EN v1.0 Address: 0x801D4CD0
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x801D4D8C
 * EN v1.1 Size: 1280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int SHthorntail_HasNearbyPendingEventObject(SHthorntailObject *obj)
{
  SHthorntailObject **objects;
  u32 configToken;
  int count;
  int index;
  s8 groupIndex;
  s8 matchCount;
  int linkedEventPending;

  linkedEventPending = 0;
  groupIndex = -1;
  matchCount = 0;
  configToken = obj->config->configToken;
  if (configToken == lbl_80326E98[0][0]) {
    groupIndex = 0;
  }
  else if (configToken == lbl_80326E98[1][0]) {
    groupIndex = 1;
  }
  else if (configToken == lbl_80326E98[2][0]) {
    groupIndex = 2;
  }
  else if (configToken == lbl_80326E98[3][0]) {
    groupIndex = 3;
  }
  else if (configToken == lbl_80326E98[4][0]) {
    groupIndex = 4;
  }
  else if (configToken == lbl_80326E98[5][0]) {
    groupIndex = 5;
  }
  objects = ObjGroup_GetObjects(3,&count);
  for (index = 0; index < count; index++) {
    if (((*objects)->objType == 0x4d7) &&
        (((*objects)->config->configToken == lbl_80326E98[groupIndex][1]) ||
         ((*objects)->config->configToken == lbl_80326E98[groupIndex][2]) ||
         ((*objects)->config->configToken == lbl_80326E98[groupIndex][3]))) {
      fn_8014C66C(*objects,obj);
      if ((fn_800216D0(&(*objects)->pos,&obj->pos) < lbl_803E5414) &&
          (GameBit_Get(SHthorntail_GetLinkedGameBit((*objects)->config)) == 0)) {
        linkedEventPending = 1;
      }
      matchCount++;
      if (matchCount == 3) {
        break;
      }
    }
    objects++;
  }
  return linkedEventPending;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
void SHthorntail_updateTailSwing(uint objectId,SHthorntailRuntime *runtime)
{
  u8 tailSwingState;
  int moveComplete;

  tailSwingState = runtime->tailSwingState;
  switch(tailSwingState) {
  case SHTHORNTAIL_TAIL_SWING_READY:
    runtime->tailSwingTimer = runtime->tailSwingTimer - timeDelta;
    if (runtime->tailSwingTimer <= lbl_803E5418) {
      Sfx_PlayFromObject(objectId,SHTHORNTAIL_TAIL_SWING_WINDUP_VOLUME_ID);
      runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_WINDUP;
      runtime->tailSwingTimer = lbl_803E541C;
    }
    break;
  case SHTHORNTAIL_TAIL_SWING_WINDUP:
    runtime->tailSwingTimer = runtime->tailSwingTimer - timeDelta;
    if (runtime->tailSwingTimer <= lbl_803E5418) {
      Sfx_PlayFromObject(objectId,SHTHORNTAIL_TAIL_SWING_ACTIVE_VOLUME_ID);
      runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
    }
    break;
  case SHTHORNTAIL_TAIL_SWING_ACTIVE:
    moveComplete = runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE;
    if (moveComplete != 0) {
      runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_READY;
      runtime->tailSwingTimer = lbl_803E5420;
    }
    break;
  default:
    break;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
uint SHthorntail_chooseNextState(SHthorntailObject *object,SHthorntailRuntime *runtime,
                                 SHthorntailConfig *config)
{
  short angleDelta;
  int value;
  uint nextState;
  s16 facingAngle;
  s8 behaviorState;
  f32 distanceSq;
  short *objWords;

  objWords = (short *)object;
  if (config->leashRadiusByte != '\0') {
    value = Obj_GetPlayerObject();
    distanceSq = fn_8002166C((Vec *)(objWords + 0xc),(Vec *)(value + 0x18));
    if (distanceSq < lbl_803E5424) {
      behaviorState = runtime->behaviorState;
      if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) &&
          (behaviorState <= SHTHORNTAIL_STATE_MOVE_5)) {
        nextState = SHTHORNTAIL_STATE_TURN_HOME;
      }
      else {
        nextState = SHTHORNTAIL_STATE_CLOSE_ATTACK;
      }
      return nextState;
    }
    distanceSq = fn_8002166C((Vec *)(objWords + 0xc),&config->homePos);
    if (distanceSq > (float)(s32)(config->leashRadiusByte * config->leashRadiusByte)) {
      value = getAngle(*(float *)(objWords + 6) - config->homePos.x,
                          *(float *)(objWords + 10) - config->homePos.z);
      facingAngle = *objWords;
      angleDelta = (short)value - (u16)facingAngle;
      if (0x8000 < angleDelta) {
        angleDelta = angleDelta - 0xFFFF;
      }
      if (angleDelta < -0x8000) {
        angleDelta = angleDelta + 0xFFFF;
      }
      value = (int)angleDelta;
      if (value < 0) {
        value = -value;
      }
      if (0x20 < value) {
        value = getAngle(*(float *)(objWords + 6) - config->homePos.x,
                            *(float *)(objWords + 10) - config->homePos.z);
        OSReport(sSHthorntailAngleYawDebug,(u16)value,facingAngle);
        behaviorState = runtime->behaviorState;
        if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) &&
            (behaviorState <= SHTHORNTAIL_STATE_MOVE_5)) {
          return SHTHORNTAIL_STATE_TURN_HOME;
        }
        return SHTHORNTAIL_STATE_CLOSE_ATTACK;
      }
    }
    value = fn_8005A10C((Vec *)(objWords + 6),
                        *(float *)(objWords + 0x54) * *(float *)(objWords + 4));
    if (value == 0) {
      nextState = SHTHORNTAIL_STATE_CLOSE_ATTACK;
    }
    else {
      behaviorState = runtime->behaviorState;
      if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) &&
          (behaviorState <= SHTHORNTAIL_STATE_MOVE_5)) {
        nextState = randomGetRange(SHTHORNTAIL_STATE_MOVE_3,SHTHORNTAIL_STATE_MOVE_5);
        nextState = nextState & 0xff;
      }
      else {
        nextState = SHTHORNTAIL_STATE_MOVE_2;
      }
    }
    return nextState;
  }
  return SHTHORNTAIL_STATE_CLOSE_ATTACK;
}
#pragma peephole reset
#pragma scheduling reset
