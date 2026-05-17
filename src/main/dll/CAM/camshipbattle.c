#include "ghidra_import.h"
#include "main/dll/CAM/camshipbattle.h"

extern u32 getButtonsJustPressed(int port);
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017814();
extern undefined4 camcontrol_buildPathAngles();
extern undefined4 FUN_80286834();
extern undefined4 FUN_80286880();
extern int objFn_802962b4(int obj);
extern int objFn_80296700(int obj);

extern int *lbl_803DCA50;
extern u8 *lbl_803DD538;
extern f64 DOUBLE_803e23d0;

#define gCamcontrolPathState lbl_803DD538

/*
 * --INFO--
 *
 * Function: camcontrol_buildPathPoints
 * EN v1.0 Address: 0x80106F78
 * EN v1.0 Size: 560b
 * EN v1.1 Address: 0x80107020
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_buildPathPoints(undefined8 param_1,double param_2,double param_3,double param_4,
                                double param_5,double param_6,undefined4 param_7,
                                undefined4 param_8,int *param_9)
{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ushort *puVar5;
  double extraout_f1;
  double in_f25;
  double dVar6;
  double in_f26;
  double dVar7;
  double in_f27;
  double dVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double in_f31;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int6 iVar11;
  ushort local_e8 [2];
  ushort local_e4 [4];
  float local_dc;
  float local_d8;
  float local_d4;
  undefined auStack_d0 [2];
  ushort local_ce [19];
  undefined4 local_a8;
  uint uStack_a4;
  undefined4 local_a0;
  uint uStack_9c;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  iVar11 = FUN_80286834();
  sVar1 = (short)((uint6)iVar11 >> 0x20);
  if (iVar11 < 0) {
    sVar1 = -sVar1;
  }
  local_e8[0] = 0;
  dVar10 = extraout_f1;
  camcontrol_buildPathAngles(auStack_d0,local_e8,0,sVar1,(int)iVar11);
  dVar8 = (double)(float)(param_3 - dVar10);
  dVar7 = (double)(float)(param_6 - param_4);
  dVar6 = (double)(float)(param_5 - param_2);
  iVar2 = 3;
  puVar5 = local_ce;
  iVar4 = 0xc;
  dVar9 = DOUBLE_803e23d0;
  for (iVar3 = 1; iVar3 < (int)(uint)local_e8[0]; iVar3 = iVar3 + 1) {
    local_dc = (float)dVar8;
    local_d8 = (float)dVar7;
    local_d4 = (float)dVar6;
    if (iVar11 < 0) {
      local_e4[0] = *puVar5;
    }
    else {
      local_e4[0] = -*puVar5;
    }
    local_e4[1] = 0;
    local_e4[2] = 0;
    FUN_80017748(local_e4,&local_dc);
    *(float *)(gCamcontrolPathState + iVar4 + 0x1c) = (float)(dVar10 + (double)local_dc);
    uStack_a4 = (int)(short)*puVar5 ^ 0x80000000U;
    local_a8 = 0x43300000;
    uStack_9c = (int)sVar1 ^ 0x80000000U;
    local_a0 = 0x43300000;
    *(float *)(gCamcontrolPathState + iVar4 + 0x6c) =
         (float)(dVar7 * (double)((float)((double)CONCAT44(0x43300000,
                                                           (int)(short)*puVar5 ^ 0x80000000U) -
                                         dVar9) /
                                 (float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000U) -
                                        dVar9)) + param_4);
    *(float *)(gCamcontrolPathState + iVar4 + 0xbc) = (float)(param_2 + (double)local_d4);
    puVar5 = puVar5 + 1;
    iVar4 = iVar4 + 4;
    iVar2 = iVar2 + 1;
  }
  *param_9 = iVar2;
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_updatePathTargetAction
 * EN v1.0 Address: 0x801071A8
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80107214
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_updatePathTargetAction(int param_1,int param_2)
{
  short sVar1;
  u16 buttons;
  u8 *targetObj;
  struct {
    f32 x;
    f32 z;
    s16 y;
  } local_28;
  
  if (*(u32 *)(param_2 + 0xc0) == 0) {
    buttons = getButtonsJustPressed(0);
    targetObj = *(u8 **)(param_1 + 0x124);
    if (targetObj != NULL) {
      sVar1 = *(short *)(targetObj + 0x44);
      if (sVar1 == 0x1c) {
        goto checkActiveTarget;
      }
      if (sVar1 != 0x2a) {
        goto checkOverrideFlag;
      }
checkActiveTarget:
      if (*(short *)(param_2 + 0x44) != 1) {
        goto checkOverrideFlag;
      }
      if (objFn_80296700(param_2) != 0) {
        goto sendFollowAction;
      }
    }
checkOverrideFlag:
    if ((*(byte *)(param_1 + 0x141) & 2) != 0) {
sendFollowAction:
      (*(code *)(*lbl_803DCA50 + 0x1c))(0x49,1,0,4,param_1 + 0x124,0x3c,0xff);
      goto done;
    }
    if ((((buttons & 0x10) != 0) && (*(short *)(param_2 + 0x44) == 1)) &&
        (objFn_802962b4(param_2) != 0)) {
      local_28.x = *(float *)(lbl_803DD538 + 4);
      local_28.z = *(float *)(lbl_803DD538 + 0xc);
      local_28.y = (s16)*(float *)(lbl_803DD538 + 0x10);
      (*(code *)(*lbl_803DCA50 + 0x1c))(0x44,1,0,0xc,&local_28,0,0xff);
    }
  }
done:
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: camcontrol_releasePathState
 * EN v1.0 Address: 0x801072F0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010736C
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_releasePathState(void)
{
  FUN_80017814(gCamcontrolPathState);
  gCamcontrolPathState = 0;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeStaffAnim_func06_nop(void) {}
