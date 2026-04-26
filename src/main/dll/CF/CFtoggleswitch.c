#include "ghidra_import.h"
#include "main/dll/CF/CFtoggleswitch.h"

extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined8 FUN_80006b8c();
extern undefined4 FUN_80006b90();
extern undefined4 FUN_80006b94();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern double FUN_80017714();
extern int FUN_80017a98();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int FUN_80037008();
extern int FUN_800384ec();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern uint FUN_80044404();
extern undefined4 FUN_80053c98();
extern undefined8 FUN_80080f14();
extern undefined4 FUN_800810ec();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_8011e868();
extern undefined8 FUN_8016d994();
extern uint FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern int FUN_80294cf8();
extern undefined4 FUN_80294d1c();

extern undefined4 DAT_802c2a30;
extern undefined4 DAT_802c2a34;
extern undefined4 DAT_802c2a38;
extern undefined4 DAT_802c2a3c;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803de760;
extern undefined4 DAT_803de764;
extern f64 DOUBLE_803e4908;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e48b8;
extern f32 FLOAT_803e48c0;
extern f32 FLOAT_803e48c4;
extern f32 FLOAT_803e48c8;
extern f32 FLOAT_803e48cc;
extern f32 FLOAT_803e48d0;
extern f32 FLOAT_803e48d4;
extern f32 FLOAT_803e48d8;
extern f32 FLOAT_803e48dc;
extern f32 FLOAT_803e48e0;
extern f32 FLOAT_803e48e4;
extern f32 FLOAT_803e48e8;
extern f32 FLOAT_803e48ec;
extern f32 FLOAT_803e48f0;
extern f32 FLOAT_803e48f4;
extern f32 FLOAT_803e48f8;
extern f32 FLOAT_803e48fc;
extern f32 FLOAT_803e4900;
extern f32 FLOAT_803e4904;

/*
 * --INFO--
 *
 * Function: magiccavebottom_update
 * EN v1.0 Address: 0x8018ADF0
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x8018AE14
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void magiccavebottom_update(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  int iVar6;
  
  iVar2 = FUN_80286840();
  iVar5 = *(int *)(iVar2 + 0x4c);
  pbVar4 = *(byte **)(iVar2 + 0xb8);
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
    bVar1 = *(byte *)(param_3 + iVar6 + 0x81);
    if (bVar1 == 3) {
      *pbVar4 = *pbVar4 & 0xdf;
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        iVar3 = (int)*(short *)(iVar5 + 0x1c);
        if (iVar3 != 0) {
          (**(code **)(*DAT_803dd6e8 + 0x38))(iVar3,200,0x8c,0);
        }
      }
      else if (bVar1 != 0) {
        *pbVar4 = *pbVar4 & 0xdf | 0x20;
      }
    }
    else if (bVar1 < 5) {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      ObjHits_DisableObject(iVar2);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018aee4
 * EN v1.0 Address: 0x8018AEE4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8018AF1C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018aee4(void)
{
  FUN_80006b0c(DAT_803de760);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018af08
 * EN v1.0 Address: 0x8018AF08
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8018AF40
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018af08(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018af28
 * EN v1.0 Address: 0x8018AF28
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8018AF64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018af28(int param_1)
{
  if ((**(byte **)(param_1 + 0xb8) >> 5 & 1) != 0) {
    FUN_800810ec(param_1,2,*(byte *)(*(int *)(param_1 + 0x4c) + 0x19) + 6 & 0xff,4,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018af74
 * EN v1.0 Address: 0x8018AF74
 * EN v1.0 Size: 684b
 * EN v1.1 Address: 0x8018AFB8
 * EN v1.1 Size: 632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018af74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  undefined4 uStack_48;
  int local_44;
  uint uStack_40;
  float local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  undefined4 uStack_18;
  float local_14 [2];
  
  pbVar3 = *(byte **)(param_9 + 0xb8);
  iVar2 = *(int *)(param_9 + 0x4c);
  local_3c = FLOAT_803e48c0;
  if (((*pbVar3 >> 6 & 1) != 0) && ((char)*pbVar3 < '\0')) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    FUN_800305f8((double)FLOAT_803e48c4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  if (-1 < (char)*pbVar3) {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      iVar1 = FUN_80017a98();
      FUN_80294d1c(iVar1,1);
      iVar1 = FUN_80037008(4,param_9,&local_3c);
      if (iVar1 == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x7c))((int)*(short *)(iVar2 + 0x1a),0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x7c))((int)*(short *)(iVar1 + 0x46),0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
      FUN_80017698((int)*(short *)(iVar2 + 0x1e),1);
      *pbVar3 = *pbVar3 & 0x7f | 0x80;
      ObjHits_DisableObject(param_9);
    }
    *pbVar3 = *pbVar3 & 0xbf;
    local_38 = DAT_802c2a30;
    local_34 = DAT_802c2a34;
    local_30 = DAT_802c2a38;
    local_2c = DAT_802c2a3c;
    local_44 = -1;
    iVar2 = ObjHits_GetPriorityHitWithPosition(param_9,&uStack_48,&local_44,&uStack_40,&local_1c,&uStack_18,local_14);
    if ((iVar2 != 0) && (iVar2 != 0xe)) {
      local_1c = local_1c + FLOAT_803dda58;
      local_14[0] = local_14[0] + FLOAT_803dda5c;
      local_20 = FLOAT_803e48b8;
      local_24 = 0;
      local_26 = 0;
      local_28 = 0;
      if (DAT_803de764 == 0) {
        (**(code **)(*DAT_803de760 + 4))(0,1,&local_28,0x401,0xffffffff,&local_38);
        DAT_803de764 = 0x3c;
      }
    }
    if (DAT_803de764 != 0) {
      DAT_803de764 = DAT_803de764 + -1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018b220
 * EN v1.0 Address: 0x8018B220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018B230
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b220(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018b224
 * EN v1.0 Address: 0x8018B224
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8018B314
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b224(void)
{
  FUN_80017698(0xefb,0);
  FUN_800067c0((int *)0x2f,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018b258
 * EN v1.0 Address: 0x8018B258
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x8018B348
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b258(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  undefined8 uVar6;
  
  iVar5 = *(int *)(param_9 + 0x26);
  pbVar4 = *(byte **)(param_9 + 0x5c);
  *param_9 = (ushort)*(byte *)(iVar5 + 0x1a) << 8;
  bVar1 = *pbVar4;
  if (bVar1 == 2) {
    if ((*(byte *)((int)param_9 + 0xaf) & 4) != 0) {
      FUN_8011e868(0x19);
    }
    iVar2 = FUN_800384ec((int)param_9);
    if (iVar2 == 0) {
      FUN_800400b0();
    }
    else {
      *pbVar4 = 3;
      if (*(char *)(iVar5 + 0x1b) == '\0') {
        (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      uVar6 = FUN_80017698(0xefb,1);
      uVar6 = FUN_80080f14(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
      uVar6 = FUN_80006728(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x2c,0,param_13,param_14,param_15,param_16);
      FUN_80006728(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x2d,0,param_13,param_14,param_15,param_16);
      *pbVar4 = 1;
      if (*(char *)(iVar5 + 0x1b) == '\0') {
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
      }
    }
    else {
      FUN_800067c0((int *)0x2f,1);
      *pbVar4 = 2;
    }
  }
  else if (bVar1 < 4) {
    uVar6 = FUN_80017698(0x91e,1);
    uVar3 = FUN_80017690(0x1b8);
    FUN_80053c98(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,'\0',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018b5a0
 * EN v1.0 Address: 0x8018B5A0
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x8018B528
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b5a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  int iVar2;
  char *pcVar3;
  undefined8 uVar4;
  
  pcVar3 = *(char **)(param_9 + 0xb8);
  iVar2 = *(int *)(param_9 + 0x4c);
  uVar4 = FUN_80006b8c();
  iVar1 = FUN_80017a98();
  if ((iVar1 != 0) && (iVar1 = FUN_80294cf8(iVar1), iVar1 != 0)) {
    uVar4 = FUN_8016d994(iVar1,5,0);
  }
  if ((*pcVar3 == '\x01') && (*(char *)(iVar2 + 0x22) == '\0')) {
    FUN_80044404((uint)*(byte *)(iVar2 + 0x1f));
    FUN_80043030(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018b6ac
 * EN v1.0 Address: 0x8018B6AC
 * EN v1.0 Size: 2004b
 * EN v1.1 Address: 0x8018B5AC
 * EN v1.1 Size: 1720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b6ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar8;
  int iVar9;
  byte *pbVar10;
  double dVar11;
  undefined8 uVar12;
  double in_f31;
  double in_ps31_1;
  undefined auStack_48 [12];
  float local_3c;
  float local_38;
  float local_34;
  undefined8 local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar3 = FUN_8028683c();
  iVar4 = FUN_80017a98();
  pbVar10 = *(byte **)(uVar3 + 0xb8);
  iVar9 = *(int *)(uVar3 + 0x4c);
  uVar8 = 0;
  if (iVar4 != 0) {
    uVar8 = FUN_80017690(0x91e);
    if (uVar8 != 0) {
      FUN_80017698(0x91e,0);
      (**(code **)(*DAT_803dd72c + 0x50))
                (*(undefined *)(iVar9 + 0x1f),*(undefined *)(iVar9 + 0x1a),0);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar3,0xffffffff);
      FUN_80042b9c(0,0,1);
      *pbVar10 = 3;
      goto LAB_8018bc44;
    }
    uVar5 = FUN_80044404((uint)*(byte *)(iVar9 + 0x1f));
    dVar11 = FUN_80017714((float *)(iVar4 + 0x18),(float *)(uVar3 + 0x18));
    uVar8 = FUN_80017690((int)*(short *)(iVar9 + 0x1c));
    bVar1 = *pbVar10;
    if (bVar1 == 2) {
      uVar12 = FUN_80017698(0x1b8,(int)*(char *)(iVar9 + 0x21));
      if (*(char *)(iVar9 + 0x22) == '\0') {
        uVar7 = 1;
        FUN_80042b9c(0,0,1);
        uVar6 = FUN_80044404((int)*(char *)(uVar3 + 0xac));
        FUN_80042bec(uVar6,0);
        FUN_80042bec(uVar5 & 0xff,1);
      }
      else {
        uVar7 = 1;
        FUN_80042b9c(0,0,1);
        FUN_80042bec((uint)*(byte *)(iVar9 + 0x1e),0);
        FUN_80042bec((uint)*(byte *)(iVar9 + 0x1e),1);
      }
      if (*(char *)(uVar3 + 0xac) == '\r') {
        uVar12 = FUN_80017698(0xe05,0);
      }
      FUN_80053c98(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)*(char *)(iVar9 + 0x20),'\0',uVar7,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar2 = (uint)*(byte *)(iVar9 + 0x19) * 2;
        local_30 = (double)CONCAT44(0x43300000,iVar2 * iVar2 ^ 0x80000000);
        if (dVar11 < (double)(float)(local_30 - DOUBLE_803e4908)) {
          if (*(char *)(iVar9 + 0x22) == '\0') {
            FUN_80041ff8(DOUBLE_803e4908,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (uint)*(byte *)(iVar9 + 0x1f));
          }
          *pbVar10 = 1;
        }
      }
      else {
        iVar2 = (uint)*(byte *)(iVar9 + 0x18) * 2;
        local_30 = (double)CONCAT44(0x43300000,iVar2 * iVar2 ^ 0x80000000);
        if (dVar11 <= (double)(float)(local_30 - DOUBLE_803e4908)) {
          if ((dVar11 < (double)FLOAT_803e48c8) && (uVar8 != 0)) {
            *pbVar10 = 2;
            (**(code **)(*DAT_803dd72c + 0x50))
                      (*(undefined *)(iVar9 + 0x1f),*(undefined *)(iVar9 + 0x1a),1);
            (**(code **)(*DAT_803dd72c + 0x44))
                      (*(undefined *)(iVar9 + 0x1f),*(undefined *)(iVar9 + 0x1b));
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,uVar3,0xffffffff);
            (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
          }
        }
        else {
          if (*(char *)(iVar9 + 0x22) == '\0') {
            FUN_80043030(DOUBLE_803e4908,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          }
          *pbVar10 = 0;
        }
      }
    }
    else if ((bVar1 < 4) && ((double)FLOAT_803e48c8 < dVar11)) {
      *pbVar10 = 1;
    }
    bVar1 = pbVar10[1];
    if ((bVar1 & 4) == 0) {
      if (dVar11 < (double)FLOAT_803e48cc) {
        if ((bVar1 & 2) == 0) {
          if ((bVar1 & 1) == 0) {
            if (dVar11 < (double)FLOAT_803e48cc) {
              FUN_80006b94((double)FLOAT_803e48dc);
              if ((iVar4 != 0) && (iVar4 = FUN_80294cf8(iVar4), iVar4 != 0)) {
                FUN_8016d994(iVar4,5,2);
              }
              pbVar10[1] = pbVar10[1] | 1;
              *(float *)(pbVar10 + 8) = *(float *)(pbVar10 + 8) + FLOAT_803dc074;
            }
          }
          else {
            if ((double)FLOAT_803e48d4 <= dVar11) {
              if ((double)FLOAT_803e48d8 <= dVar11) {
                FUN_80006b8c();
                if ((iVar4 != 0) && (iVar4 = FUN_80294cf8(iVar4), iVar4 != 0)) {
                  FUN_8016d994(iVar4,5,0);
                }
                pbVar10[2] = 1;
              }
              else if (pbVar10[2] == 1) {
                FUN_80006b90();
                if ((iVar4 != 0) && (iVar4 = FUN_80294cf8(iVar4), iVar4 != 0)) {
                  FUN_8016d994(iVar4,5,0);
                }
                pbVar10[2] = 0;
              }
              else {
                FUN_80006b8c();
                if ((iVar4 != 0) && (iVar4 = FUN_80294cf8(iVar4), iVar4 != 0)) {
                  FUN_8016d994(iVar4,5,0);
                }
                pbVar10[2] = 1;
              }
            }
            else {
              FUN_80006b90();
              if ((iVar4 != 0) && (iVar4 = FUN_80294cf8(iVar4), iVar4 != 0)) {
                FUN_8016d994(iVar4,5,0);
              }
              pbVar10[2] = 0;
            }
            pbVar10[1] = pbVar10[1] & 0xfe;
            *(float *)(pbVar10 + 8) = *(float *)(pbVar10 + 8) + FLOAT_803dc074;
          }
          if (FLOAT_803e48e0 < *(float *)(pbVar10 + 8)) {
            pbVar10[1] = pbVar10[1] | 2;
          }
        }
      }
      else {
        *(float *)(pbVar10 + 8) = FLOAT_803e48d0;
        pbVar10[1] = pbVar10[1] & 0xfd;
        if ((iVar4 != 0) && (iVar4 = FUN_80294cf8(iVar4), iVar4 != 0)) {
          FUN_8016d994(iVar4,5,0);
        }
      }
    }
  }
  if (uVar8 == 0) {
    *(undefined *)(uVar3 + 0x36) = 0;
  }
  else {
    if (FLOAT_803e48d0 == *(float *)(pbVar10 + 4)) {
      FUN_80006824(uVar3,0x4a2);
    }
    *(float *)(pbVar10 + 4) = *(float *)(pbVar10 + 4) + FLOAT_803dc074;
    if (*(float *)(pbVar10 + 4) <= FLOAT_803e48e4) {
      iVar4 = (int)(FLOAT_803e48e8 * (*(float *)(pbVar10 + 4) / FLOAT_803e48e4));
      local_30 = (double)(longlong)iVar4;
      *(char *)(uVar3 + 0x36) = (char)iVar4;
    }
    else {
      *(float *)(pbVar10 + 4) = FLOAT_803e48e4;
      *(undefined *)(uVar3 + 0x36) = 0xff;
    }
  }
  if (*(char *)(uVar3 + 0x36) != '\0') {
    local_3c = FLOAT_803e48d0;
    local_38 = FLOAT_803e48ec;
    local_34 = FLOAT_803e48d0;
    if ((pbVar10[1] & 8) == 0) {
      FUN_800810f8((double)FLOAT_803e48f0,(double)FLOAT_803e48f4,(double)FLOAT_803e48f8,
                   (double)FLOAT_803e48fc,uVar3,1,2,2,0x32,(int)auStack_48,0);
      local_38 = FLOAT_803e4900;
      dVar11 = (double)FLOAT_803e4904;
      FUN_800810f8((double)FLOAT_803e48f0,dVar11,dVar11,dVar11,uVar3,5,2,2,0x14,(int)auStack_48,0);
    }
    else {
      FUN_800810f8((double)FLOAT_803e48f0,(double)FLOAT_803e48f4,(double)FLOAT_803e48f8,
                   (double)FLOAT_803e48fc,uVar3,1,5,2,0x32,(int)auStack_48,0);
      local_38 = FLOAT_803e4900;
      dVar11 = (double)FLOAT_803e4904;
      FUN_800810f8((double)FLOAT_803e48f0,dVar11,dVar11,dVar11,uVar3,5,5,2,0x14,(int)auStack_48,0);
    }
  }
LAB_8018bc44:
  FUN_80286888();
  return;
}
