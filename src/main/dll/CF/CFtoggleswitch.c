#include "ghidra_import.h"
#include "main/dll/CF/CFtoggleswitch.h"

extern undefined8 FUN_80008cbc();
extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern undefined8 FUN_80014a54();
extern undefined4 FUN_80014a90();
extern undefined4 FUN_80014acc();
extern uint FUN_80020078();
extern undefined8 FUN_800201ac();
extern double FUN_80021794();
extern int FUN_8002bac4();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035ff8();
extern int FUN_80036868();
extern int FUN_80036f50();
extern int FUN_8003811c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80041110();
extern undefined4 FUN_80043070();
extern undefined4 FUN_80043604();
extern undefined4 FUN_80043658();
extern undefined4 FUN_80043938();
extern uint FUN_8004832c();
extern undefined4 FUN_80055464();
extern undefined8 FUN_80088a84();
extern undefined4 FUN_800972fc();
extern undefined4 FUN_800979c0();
extern undefined4 FUN_8011f6d0();
extern undefined8 FUN_8016de98();
extern uint FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern int FUN_80296e2c();
extern undefined4 FUN_80296f40();

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
 * Function: FUN_8018ae14
 * EN v1.0 Address: 0x8018AE14
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018ae14(undefined4 param_1,undefined4 param_2,int param_3)
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
      FUN_80035ff8(iVar2);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018af1c
 * EN v1.0 Address: 0x8018AF1C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018af1c(void)
{
  FUN_80013e4c(DAT_803de760);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018af40
 * EN v1.0 Address: 0x8018AF40
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018af40(int param_1)
{
  FUN_8003b9ec(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018af64
 * EN v1.0 Address: 0x8018AF64
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018af64(int param_1)
{
  if ((**(byte **)(param_1 + 0xb8) >> 5 & 1) != 0) {
    FUN_800972fc(param_1,2,*(byte *)(*(int *)(param_1 + 0x4c) + 0x19) + 6 & 0xff,4,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018afb8
 * EN v1.0 Address: 0x8018AFB8
 * EN v1.0 Size: 632b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018afb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
    FUN_8003042c((double)FLOAT_803e48c4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  if (-1 < (char)*pbVar3) {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      iVar1 = FUN_8002bac4();
      FUN_80296f40(iVar1,1);
      iVar1 = FUN_80036f50(4,param_9,&local_3c);
      if (iVar1 == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x7c))((int)*(short *)(iVar2 + 0x1a),0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x7c))((int)*(short *)(iVar1 + 0x46),0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
      FUN_800201ac((int)*(short *)(iVar2 + 0x1e),1);
      *pbVar3 = *pbVar3 & 0x7f | 0x80;
      FUN_80035ff8(param_9);
    }
    *pbVar3 = *pbVar3 & 0xbf;
    local_38 = DAT_802c2a30;
    local_34 = DAT_802c2a34;
    local_30 = DAT_802c2a38;
    local_2c = DAT_802c2a3c;
    local_44 = -1;
    iVar2 = FUN_80036868(param_9,&uStack_48,&local_44,&uStack_40,&local_1c,&uStack_18,local_14);
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
 * Function: FUN_8018b230
 * EN v1.0 Address: 0x8018B230
 * EN v1.0 Size: 228b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b230(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018b314
 * EN v1.0 Address: 0x8018B314
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b314(void)
{
  FUN_800201ac(0xefb,0);
  FUN_8000a538((int *)0x2f,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018b348
 * EN v1.0 Address: 0x8018B348
 * EN v1.0 Size: 480b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b348(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
      FUN_8011f6d0(0x19);
    }
    iVar2 = FUN_8003811c((int)param_9);
    if (iVar2 == 0) {
      FUN_80041110();
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
      uVar6 = FUN_800201ac(0xefb,1);
      uVar6 = FUN_80088a84(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x2c,0,param_13,param_14,param_15,param_16);
      FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
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
      FUN_8000a538((int *)0x2f,1);
      *pbVar4 = 2;
    }
  }
  else if (bVar1 < 4) {
    uVar6 = FUN_800201ac(0x91e,1);
    uVar3 = FUN_80020078(0x1b8);
    FUN_80055464(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,'\0',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018b528
 * EN v1.0 Address: 0x8018B528
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b528(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  int iVar2;
  char *pcVar3;
  undefined8 uVar4;
  
  pcVar3 = *(char **)(param_9 + 0xb8);
  iVar2 = *(int *)(param_9 + 0x4c);
  uVar4 = FUN_80014a54();
  iVar1 = FUN_8002bac4();
  if ((iVar1 != 0) && (iVar1 = FUN_80296e2c(iVar1), iVar1 != 0)) {
    uVar4 = FUN_8016de98(iVar1,5,0);
  }
  if ((*pcVar3 == '\x01') && (*(char *)(iVar2 + 0x22) == '\0')) {
    FUN_8004832c((uint)*(byte *)(iVar2 + 0x1f));
    FUN_80043938(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018b5ac
 * EN v1.0 Address: 0x8018B5AC
 * EN v1.0 Size: 1720b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018b5ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
  iVar4 = FUN_8002bac4();
  pbVar10 = *(byte **)(uVar3 + 0xb8);
  iVar9 = *(int *)(uVar3 + 0x4c);
  uVar8 = 0;
  if (iVar4 != 0) {
    uVar8 = FUN_80020078(0x91e);
    if (uVar8 != 0) {
      FUN_800201ac(0x91e,0);
      (**(code **)(*DAT_803dd72c + 0x50))
                (*(undefined *)(iVar9 + 0x1f),*(undefined *)(iVar9 + 0x1a),0);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar3,0xffffffff);
      FUN_80043604(0,0,1);
      *pbVar10 = 3;
      goto LAB_8018bc44;
    }
    uVar5 = FUN_8004832c((uint)*(byte *)(iVar9 + 0x1f));
    dVar11 = FUN_80021794((float *)(iVar4 + 0x18),(float *)(uVar3 + 0x18));
    uVar8 = FUN_80020078((int)*(short *)(iVar9 + 0x1c));
    bVar1 = *pbVar10;
    if (bVar1 == 2) {
      uVar12 = FUN_800201ac(0x1b8,(int)*(char *)(iVar9 + 0x21));
      if (*(char *)(iVar9 + 0x22) == '\0') {
        uVar7 = 1;
        FUN_80043604(0,0,1);
        uVar6 = FUN_8004832c((int)*(char *)(uVar3 + 0xac));
        FUN_80043658(uVar6,0);
        FUN_80043658(uVar5 & 0xff,1);
      }
      else {
        uVar7 = 1;
        FUN_80043604(0,0,1);
        FUN_80043658((uint)*(byte *)(iVar9 + 0x1e),0);
        FUN_80043658((uint)*(byte *)(iVar9 + 0x1e),1);
      }
      if (*(char *)(uVar3 + 0xac) == '\r') {
        uVar12 = FUN_800201ac(0xe05,0);
      }
      FUN_80055464(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)*(char *)(iVar9 + 0x20),'\0',uVar7,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar2 = (uint)*(byte *)(iVar9 + 0x19) * 2;
        local_30 = (double)CONCAT44(0x43300000,iVar2 * iVar2 ^ 0x80000000);
        if (dVar11 < (double)(float)(local_30 - DOUBLE_803e4908)) {
          if (*(char *)(iVar9 + 0x22) == '\0') {
            FUN_80043070(DOUBLE_803e4908,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
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
            FUN_80043938(DOUBLE_803e4908,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
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
              FUN_80014acc((double)FLOAT_803e48dc);
              if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                FUN_8016de98(iVar4,5,2);
              }
              pbVar10[1] = pbVar10[1] | 1;
              *(float *)(pbVar10 + 8) = *(float *)(pbVar10 + 8) + FLOAT_803dc074;
            }
          }
          else {
            if ((double)FLOAT_803e48d4 <= dVar11) {
              if ((double)FLOAT_803e48d8 <= dVar11) {
                FUN_80014a54();
                if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                  FUN_8016de98(iVar4,5,0);
                }
                pbVar10[2] = 1;
              }
              else if (pbVar10[2] == 1) {
                FUN_80014a90();
                if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                  FUN_8016de98(iVar4,5,0);
                }
                pbVar10[2] = 0;
              }
              else {
                FUN_80014a54();
                if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                  FUN_8016de98(iVar4,5,0);
                }
                pbVar10[2] = 1;
              }
            }
            else {
              FUN_80014a90();
              if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
                FUN_8016de98(iVar4,5,0);
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
        if ((iVar4 != 0) && (iVar4 = FUN_80296e2c(iVar4), iVar4 != 0)) {
          FUN_8016de98(iVar4,5,0);
        }
      }
    }
  }
  if (uVar8 == 0) {
    *(undefined *)(uVar3 + 0x36) = 0;
  }
  else {
    if (FLOAT_803e48d0 == *(float *)(pbVar10 + 4)) {
      FUN_8000bb38(uVar3,0x4a2);
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
      FUN_800979c0((double)FLOAT_803e48f0,(double)FLOAT_803e48f4,(double)FLOAT_803e48f8,
                   (double)FLOAT_803e48fc,uVar3,1,2,2,0x32,(int)auStack_48,0);
      local_38 = FLOAT_803e4900;
      dVar11 = (double)FLOAT_803e4904;
      FUN_800979c0((double)FLOAT_803e48f0,dVar11,dVar11,dVar11,uVar3,5,2,2,0x14,(int)auStack_48,0);
    }
    else {
      FUN_800979c0((double)FLOAT_803e48f0,(double)FLOAT_803e48f4,(double)FLOAT_803e48f8,
                   (double)FLOAT_803e48fc,uVar3,1,5,2,0x32,(int)auStack_48,0);
      local_38 = FLOAT_803e4900;
      dVar11 = (double)FLOAT_803e4904;
      FUN_800979c0((double)FLOAT_803e48f0,dVar11,dVar11,dVar11,uVar3,5,5,2,0x14,(int)auStack_48,0);
    }
  }
LAB_8018bc44:
  FUN_80286888();
  return;
}
