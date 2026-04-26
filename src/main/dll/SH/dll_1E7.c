#include "ghidra_import.h"
#include "main/dll/SH/dll_1E7.h"

extern void fn_8000BB18(uint objectId,u16 volumeId);
extern f32 fn_8002166C(Vec *a,Vec *b);
extern f32 fn_800216D0(Vec *a,Vec *b);
extern s16 fn_800217C0(f32 deltaX,f32 deltaZ);
extern int fn_800221A0(int min,int max);
extern int fn_8002B9EC(void);
extern SHthorntailObject **fn_80036F50(int group,int *countOut);
extern int fn_8005A10C(Vec *pos,f32 radius);
extern void fn_8014C66C(SHthorntailObject *obj,SHthorntailObject *other);
extern void OSReport(const char *msg,...);
extern uint FUN_80017690();
extern uint FUN_80017758();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80037008();
extern int FUN_800384ec();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b444();
extern undefined4 FUN_801d4810();
extern undefined4 FUN_801d4814();

extern undefined4 DAT_80327a58;
extern u32 lbl_80326E98[][4];
extern char lbl_80327470[];
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
extern f32 lbl_803DB414;
extern f32 lbl_803E5418;
extern f32 lbl_803E5414;
extern f32 lbl_803E541C;
extern f32 lbl_803E5420;
extern f32 lbl_803E5424;
extern f64 lbl_803E5428;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6090;
extern f32 FLOAT_803e609c;
extern f32 FLOAT_803e60a0;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60b4;
extern f32 FLOAT_803e60b8;

/*
 * --INFO--
 *
 * Function: fn_801D4CD0
 * EN v1.0 Address: 0x801D4CD0
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x801D4D8C
 * EN v1.1 Size: 1280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_801D4CD0(SHthorntailObject *obj)
{
  SHthorntailObject **objects;
  SHthorntailObject *otherObj;
  u32 configToken;
  int count;
  int index;
  s8 groupIndex;
  s8 matchCount;
  int eventIsSet;

  eventIsSet = 0;
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
  objects = fn_80036F50(3,&count);
  for (index = 0; index < count; index++) {
    otherObj = *objects;
    if ((otherObj->objType == 0x4d7) &&
        ((otherObj->config->configToken == lbl_80326E98[groupIndex][1]) ||
         (otherObj->config->configToken == lbl_80326E98[groupIndex][2]) ||
         (otherObj->config->configToken == lbl_80326E98[groupIndex][3]))) {
      fn_8014C66C(otherObj,obj);
      if ((fn_800216D0(&otherObj->pos,&obj->pos) < lbl_803E5414) &&
          (GameBit_Get(*(s16 *)&otherObj->config->controlMode) == 0)) {
        eventIsSet = 1;
      }
      matchCount++;
      if (matchCount == 3) {
        break;
      }
    }
    objects++;
  }
  return eventIsSet;
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
#pragma scheduling off
void SHthorntail_updateTailSwing(uint objectId,SHthorntailRuntime *runtime)
{
  byte bVar1;

  bVar1 = runtime->tailSwingState;
  if (bVar1 == SHTHORNTAIL_TAIL_SWING_WINDUP) {
    runtime->tailSwingTimer = runtime->tailSwingTimer - lbl_803DB414;
    if (runtime->tailSwingTimer <= lbl_803E5418) {
      fn_8000BB18(objectId,0xa8);
      runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
    }
  }
  else if (bVar1 == SHTHORNTAIL_TAIL_SWING_READY) {
    runtime->tailSwingTimer = runtime->tailSwingTimer - lbl_803DB414;
    if (runtime->tailSwingTimer <= lbl_803E5418) {
      fn_8000BB18(objectId,0xa9);
      runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_WINDUP;
      runtime->tailSwingTimer = lbl_803E541C;
    }
  }
  else if ((bVar1 < SHTHORNTAIL_TAIL_SWING_STATE_COUNT) &&
           ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)) {
    runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_READY;
    runtime->tailSwingTimer = lbl_803E5420;
  }
  return;
}
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
uint SHthorntail_chooseNextState(SHthorntailObject *object,SHthorntailRuntime *runtime,
                                 SHthorntailConfig *config)
{
  short *obj;
  short sVar1;
  int iVar2;
  uint uVar3;
  s16 facingAngle;
  s8 behaviorState;
  f32 distanceSq;

  obj = (short *)object;
  if (config->leashRadiusByte == '\0') {
    uVar3 = SHTHORNTAIL_STATE_CLOSE_ATTACK;
  }
  else {
    iVar2 = fn_8002B9EC();
    distanceSq = fn_8002166C((Vec *)(obj + 0xc),(Vec *)(iVar2 + 0x18));
    if (distanceSq < lbl_803E5424) {
      behaviorState = runtime->behaviorState;
      if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) &&
          (behaviorState <= SHTHORNTAIL_STATE_MOVE_5)) {
        uVar3 = SHTHORNTAIL_STATE_TURN_HOME;
      }
      else {
        uVar3 = SHTHORNTAIL_STATE_CLOSE_ATTACK;
      }
    }
    else {
      distanceSq = fn_8002166C((Vec *)(obj + 0xc),&config->homePos);
      if ((float)(s32)(config->leashRadiusByte * config->leashRadiusByte) < distanceSq) {
        iVar2 = fn_800217C0(*(float *)(obj + 6) - config->homePos.x,
                            *(float *)(obj + 10) - config->homePos.z);
        facingAngle = *obj;
        sVar1 = (short)iVar2 - facingAngle;
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
          iVar2 = fn_800217C0(*(float *)(obj + 6) - config->homePos.x,
                              *(float *)(obj + 10) - config->homePos.z);
          OSReport(lbl_80327470,(u16)iVar2,facingAngle);
          behaviorState = runtime->behaviorState;
          if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) &&
              (behaviorState <= SHTHORNTAIL_STATE_MOVE_5)) {
            return SHTHORNTAIL_STATE_TURN_HOME;
          }
          return SHTHORNTAIL_STATE_CLOSE_ATTACK;
        }
      }
      iVar2 = fn_8005A10C((Vec *)(obj + 6),*(float *)(obj + 0x54) * *(float *)(obj + 4));
      if (iVar2 == 0) {
        uVar3 = SHTHORNTAIL_STATE_CLOSE_ATTACK;
      }
      else {
        behaviorState = runtime->behaviorState;
        if ((behaviorState < SHTHORNTAIL_STATE_MOVE_2) ||
            (SHTHORNTAIL_STATE_MOVE_5 < behaviorState)) {
          uVar3 = SHTHORNTAIL_STATE_MOVE_2;
        }
        else {
          uVar3 = fn_800221A0(SHTHORNTAIL_STATE_MOVE_3,SHTHORNTAIL_STATE_MOVE_5);
          uVar3 = uVar3 & 0xff;
        }
      }
    }
  }
  return uVar3;
}
#pragma scheduling reset
