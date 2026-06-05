#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIM2flameburst.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8000696c();
extern undefined4 FUN_80006974();
extern ushort FUN_80006998();
extern ushort FUN_800069a0();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017924();
extern uint FUN_80017944();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern undefined4 FUN_80017a78();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002fc3c();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8003f9f8();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80053754();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_800631d4();
extern int FUN_800632e8();
extern undefined4 FUN_8006fb1c();
extern undefined4 FUN_80242114();
extern undefined4 FUN_80247618();
extern undefined4 PSVECDotProduct();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80259000();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_80286828();
extern undefined8 FUN_80286834();
extern uint FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924b4();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern int FUN_80294cb0();
extern short SUB42();

extern undefined4 DAT_802c2aa8;
extern undefined4 DAT_802c2aac;
extern undefined4 DAT_802c2ab0;
extern undefined4 DAT_802c2ab4;
extern undefined4 DAT_80326168;
extern undefined4 DAT_8032616c;
extern undefined4 DAT_80326170;
extern int DAT_803ad5c0;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern undefined4 DAT_803de7d8;
extern undefined4 DAT_803de7f8;
extern undefined4 DAT_803e55c0;
extern undefined4 DAT_803e90e8;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803e55e0;
extern f64 DOUBLE_803e5600;
extern f64 DOUBLE_803e5610;
extern f64 DOUBLE_803e5618;
extern f64 DOUBLE_803e5628;
extern f64 DOUBLE_803e56a8;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DE7DC;
extern f32 lbl_803DE7E0;
extern f32 lbl_803DE7E4;
extern f32 lbl_803DE7E8;
extern f32 lbl_803DE7EC;
extern f32 lbl_803DE7F0;
extern f32 lbl_803E55A0;
extern f32 lbl_803E55A8;
extern f32 lbl_803E55C4;
extern f32 lbl_803E55C8;
extern f32 lbl_803E55CC;
extern f32 lbl_803E55D0;
extern f32 lbl_803E55D8;
extern f32 lbl_803E55F0;
extern f32 lbl_803E55F4;
extern f32 lbl_803E55F8;
extern f32 lbl_803E5608;
extern f32 lbl_803E560C;
extern f32 lbl_803E5620;
extern f32 lbl_803E5630;
extern f32 lbl_803E5634;
extern f32 lbl_803E5638;
extern f32 lbl_803E563C;
extern f32 lbl_803E5640;
extern f32 lbl_803E5644;
extern f32 lbl_803E5648;
extern f32 lbl_803E564C;
extern f32 lbl_803E5650;
extern f32 lbl_803E5654;
extern f32 lbl_803E5658;
extern f32 lbl_803E565C;
extern f32 lbl_803E5660;
extern f32 lbl_803E5664;
extern f32 lbl_803E566C;
extern f32 lbl_803E5670;
extern f32 lbl_803E5674;
extern f32 lbl_803E5678;
extern f32 lbl_803E567C;
extern f32 lbl_803E5684;
extern f32 lbl_803E5688;
extern f32 lbl_803E568C;
extern f32 lbl_803E5690;
extern f32 lbl_803E5694;
extern f32 lbl_803E569C;

/*
 * --INFO--
 *
 * Function: FUN_801b3de4
 * EN v1.0 Address: 0x801B3DE4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801B401C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3de4(undefined4 param_1,uint param_2)
{
  (**(code **)(*DAT_803dd6d4 + 0x48))((param_2 ^ 1) + 2,param_1,0xffffffff);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3e28
 * EN v1.0 Address: 0x801B3E28
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801B4060
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_801b3e28(int param_1)
{
  bool bVar1;
  int iVar2;
  float *pfVar3;
  
  iVar2 = FUN_80017a98();
  pfVar3 = *(float **)(param_1 + 0xb8);
  bVar1 = pfVar3[3] +
          pfVar3[2] * *(float *)(iVar2 + 0x14) +
          *pfVar3 * *(float *)(iVar2 + 0xc) + pfVar3[1] * *(float *)(iVar2 + 0x10) < lbl_803E55A0;
  (**(code **)(*DAT_803dd6d4 + 0x48))(bVar1,param_1,0xffffffff);
  return bVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3ec0
 * EN v1.0 Address: 0x801B3EC0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801B4114
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3ec0(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x13);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3ee4
 * EN v1.0 Address: 0x801B3EE4
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801B4138
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3ee4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if ((visible == 0) || (*(int *)(param_1 + 0xf8) != 0)) {
    if (*(int *)(param_1 + 0xf8) != 0) {
      FUN_800400b0();
    }
  }
  else {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3f2c
 * EN v1.0 Address: 0x801B3F2C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801B418C
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3f2c(int param_1)
{
  int iVar1;
  uint uVar2;
  float local_18 [4];
  
  local_18[0] = lbl_803E55A8;
  iVar1 = ObjGroup_FindNearestObject(10,param_1,local_18);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  uVar2 = GameBit_Get(0x3e3);
  if (uVar2 == 0) {
    *(undefined *)(param_1 + 0xe4) = 0;
    if ((iVar1 == 0) ||
       (iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x20))(iVar1,param_1), iVar1 == 0)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
  }
  else {
    *(undefined *)(param_1 + 0xe4) = 1;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0)) {
    FUN_800400b0();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b4020
 * EN v1.0 Address: 0x801B4020
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x801B4294
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b4020(undefined2 *param_1,int param_2)
{
  float *pfVar1;
  double dVar2;
  
  ObjGroup_AddObject((int)param_1,0x13);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar1 = *(float **)(param_1 + 0x5c);
  dVar2 = (double)FUN_80293f90();
  *pfVar1 = (float)dVar2;
  pfVar1[1] = lbl_803E55A0;
  dVar2 = (double)FUN_80294964();
  pfVar1[2] = (float)dVar2;
  pfVar1[3] = -(pfVar1[2] * *(float *)(param_1 + 10) +
               *pfVar1 * *(float *)(param_1 + 6) + pfVar1[1] * *(float *)(param_1 + 8));
  *(undefined4 *)(param_1 + 0x7c) = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b40f0
 * EN v1.0 Address: 0x801B40F0
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x801B4398
 * EN v1.1 Size: 724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b40f0(undefined8 param_1,double param_2,double param_3,double param_4)
{
  byte bVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  undefined extraout_r4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  
  uVar4 = FUN_8028683c();
  iVar5 = *(int *)(uVar4 + 0x4c);
  iVar6 = *(int *)(uVar4 + 0xb8);
  bVar1 = *(byte *)(iVar6 + 0xa58);
  *(byte *)(iVar6 + 0xa58) = bVar1 + 1;
  iVar7 = (uint)bVar1 * 0x30;
  *(float *)(iVar6 + iVar7) = (float)param_2;
  iVar8 = iVar6 + iVar7;
  *(float *)(iVar8 + 4) = (float)param_3;
  *(float *)(iVar8 + 8) = (float)param_4;
  *(float *)(iVar8 + 0x18) = lbl_803E55C4;
  *(undefined4 *)(iVar8 + 0xc) = *(undefined4 *)(iVar6 + 0x18);
  *(float *)(iVar8 + 0x1c) = (float)extraout_f1;
  *(undefined *)(iVar8 + 0x2d) = extraout_r4;
  *(undefined4 *)(iVar8 + 0x10) = 0;
  dVar9 = FUN_80293900(extraout_f1);
  *(int *)(iVar8 + 0x14) = (int)((double)lbl_803E55C8 * dVar9);
  iVar3 = *(int *)(iVar8 + 0x14);
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  else if (0x3c < iVar3) {
    iVar3 = 0x3c;
  }
  *(int *)(iVar8 + 0x14) = iVar3;
  if ((*(char *)(iVar8 + 0x2d) != '\0') || (cVar2 = *(char *)(iVar5 + 0x19), cVar2 == '\0'))
  goto LAB_801b44d4;
  if (cVar2 == '\x02') {
    FUN_80006824(uVar4,0x4bf);
    goto LAB_801b44d4;
  }
  if (cVar2 == '\x03') {
    FUN_80006824(uVar4,0x4c2);
    goto LAB_801b44d4;
  }
  cVar2 = *(char *)(uVar4 + 0xac);
  if (cVar2 < ':') {
    if (cVar2 == ',') {
LAB_801b44b4:
      FUN_800067e8(uVar4,0x4b8,2);
      goto LAB_801b44d4;
    }
  }
  else if (cVar2 < '?') goto LAB_801b44b4;
  FUN_80006824(uVar4,SFXthorntail_annoyed2);
LAB_801b44d4:
  uVar4 = randomGetRange(0,0xffff);
  *(short *)(iVar6 + iVar7 + 0x28) = (short)uVar4;
  uVar4 = randomGetRange(200,300);
  iVar3 = iVar6 + iVar7;
  *(short *)(iVar3 + 0x2a) = (short)uVar4;
  uVar4 = randomGetRange(0,1);
  if (uVar4 != 0) {
    *(short *)(iVar3 + 0x2a) = -*(short *)(iVar3 + 0x2a);
  }
  uVar4 = randomGetRange(0,3);
  *(char *)(iVar6 + iVar7 + 0x2c) = (char)uVar4;
  dVar10 = (double)*(float *)(iVar8 + 0x1c);
  dVar9 = (double)FUN_802924b4();
  *(float *)(iVar8 + 0xc) =
       -(float)((double)lbl_803DE7F0 *
                (double)(float)((double)(float)(dVar10 - (double)*(float *)(iVar8 + 0x18)) * dVar9)
               - dVar10);
  dVar9 = (double)FUN_802924b4();
  iVar6 = iVar6 + iVar7;
  *(char *)(iVar6 + 0x2e) =
       (char)(int)-(float)((double)lbl_803DE7EC * (double)(float)((double)lbl_803E55D0 * dVar9)
                          - (double)lbl_803E55D0);
  *(int *)(iVar6 + 0x20) = (int)lbl_803E55D8;
  *(undefined4 *)(iVar6 + 0x24) = *(undefined4 *)(iVar6 + 0x20);
  *(undefined *)(iVar6 + 0x2f) = 1;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b43a8
 * EN v1.0 Address: 0x801B43A8
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801B466C
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b43a8(byte param_1,undefined *param_2)
{
  undefined uVar1;
  undefined uVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  double dVar6;
  
  dVar6 = (double)FUN_802924b4();
  sVar3 = 0xff - ((ushort)(int)(lbl_803DE7E4 * (float)((double)lbl_803E55D0 * dVar6)) & 0xff);
  dVar6 = (double)FUN_802924b4();
  sVar4 = 0xff - ((ushort)(int)(lbl_803DE7E0 * (float)((double)lbl_803E55D0 * dVar6)) & 0xff);
  dVar6 = (double)FUN_802924b4();
  sVar5 = 0xff - ((ushort)(int)(lbl_803DE7DC * (float)((double)lbl_803E55D0 * dVar6)) & 0xff);
  if (sVar3 < 1) {
    sVar3 = 1;
  }
  else if (0xff < sVar3) {
    sVar3 = 0xff;
  }
  if (sVar4 < 1) {
    sVar4 = 1;
  }
  else if (0xff < sVar4) {
    sVar4 = 0xff;
  }
  if (sVar5 < 1) {
    sVar5 = 1;
  }
  else if (0xff < sVar5) {
    sVar5 = 0xff;
  }
  uVar2 = (undefined)sVar3;
  uVar1 = (undefined)sVar5;
  if (param_1 == 2) {
    *param_2 = uVar1;
    param_2[1] = uVar2;
    param_2[2] = uVar1;
  }
  else if (param_1 < 2) {
    if (param_1 == 0) {
      *param_2 = uVar2;
      param_2[1] = (char)sVar4;
      param_2[2] = uVar1;
    }
    else {
      *param_2 = uVar2;
      param_2[1] = uVar1;
      param_2[2] = uVar1;
    }
  }
  else if (param_1 < 4) {
    *param_2 = uVar1;
    param_2[1] = uVar1;
    param_2[2] = uVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b457c
 * EN v1.0 Address: 0x801B457C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801B48B4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b457c(int param_1)
{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 0xa40);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b45ac
 * EN v1.0 Address: 0x801B45AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B48E4
 * EN v1.1 Size: 1240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b45ac(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b45b0
 * EN v1.0 Address: 0x801B45B0
 * EN v1.0 Size: 2480b
 * EN v1.1 Address: 0x801B4DBC
 * EN v1.1 Size: 2124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b45b0(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  short sVar2;
  uint uVar3;
  float *pfVar4;
  float fVar5;
  uint uVar6;
  float fVar7;
  int iVar8;
  float *pfVar9;
  int iVar10;
  float *pfVar11;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps31_1;
  undefined local_e8;
  undefined local_e7;
  undefined local_e6;
  float local_e4;
  float local_e0;
  float local_dc;
  short local_d8;
  short local_d6;
  short local_d4;
  short local_d2;
  short local_d0;
  short local_ce;
  float afStack_cc [12];
  undefined auStack_9c [8];
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_60;
  float fStack_5c;
  undefined4 local_58;
  float fStack_54;
  undefined4 local_50;
  float fStack_4c;
  undefined8 local_48;
  undefined4 local_40;
  float fStack_3c;
  undefined8 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar3 = FUN_8028683c();
  pfVar9 = *(float **)(uVar3 + 0xb8);
  DAT_803de7d8 = DAT_803de7d8 + 1;
  pfVar9[0x293] = (float)((int)pfVar9[0x293] + (uint)DAT_803dc070);
  pfVar11 = pfVar9;
  for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(pfVar9 + 0x296); iVar10 = iVar10 + 1) {
    pfVar11[4] = (float)((int)pfVar11[4] + (uint)DAT_803dc070);
    if (*(char *)((int)pfVar11 + 0x2f) != '\0') {
      dVar13 = (double)pfVar11[7];
      param_3 = (double)lbl_803E55CC;
      fStack_5c = -pfVar11[5];
      local_60 = 0x43300000;
      fStack_54 = -pfVar11[4];
      local_58 = 0x43300000;
      local_50 = 0x43300000;
      fStack_4c = fStack_5c;
      dVar12 = (double)FUN_802924b4();
      pfVar11[3] = -(float)((double)lbl_803DE7F0 *
                            (double)(float)((double)(float)(dVar13 - (double)pfVar11[6]) * dVar12) -
                           dVar13);
      local_48 = (double)CONCAT44(0x43300000,-pfVar11[4]);
      fStack_3c = -pfVar11[5];
      local_40 = 0x43300000;
      dVar12 = (double)FUN_802924b4();
      param_2 = (double)lbl_803E55D0;
      iVar8 = (int)-(float)((double)lbl_803DE7EC * (double)(float)(param_2 * dVar12) - param_2);
      local_38 = (double)(longlong)iVar8;
      *(char *)((int)pfVar11 + 0x2e) = (char)iVar8;
      if ((int)pfVar11[4] < (int)pfVar11[5]) {
        *(ushort *)(pfVar11 + 10) =
             *(short *)(pfVar11 + 10) + (ushort)DAT_803dc070 * *(short *)((int)pfVar11 + 0x2a);
        if (3 < *(byte *)(pfVar11 + 0xb)) {
          *(byte *)(pfVar11 + 0xb) = *(byte *)(pfVar11 + 0xb) - 4;
        }
        dVar12 = DOUBLE_803e55e0;
        if (*(byte *)((int)pfVar11 + 0x2d) < 5) {
          local_38 = (double)CONCAT44(0x43300000,-pfVar11[4]);
          fStack_3c = -pfVar11[5];
          local_40 = 0x43300000;
          param_2 = dVar12;
          if (((float)(local_38 - DOUBLE_803e55e0) /
               (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e55e0) < lbl_803E5630)
             && (pfVar11[8] = (float)((int)pfVar11[8] - (uint)DAT_803dc070), (int)pfVar11[8] < 1)) {
            dVar12 = (double)pfVar11[7];
            iVar8 = *(int *)(uVar3 + 0xb8);
            uVar6 = randomGetRange(0xfffffffb,3);
            param_2 = (double)(f32)(s32)(uVar6);
            local_e4 = pfVar11[3] *
                       (float)((double)lbl_803E55F4 * param_2 + (double)lbl_803E55C4);
            local_e0 = lbl_803E55F8;
            local_dc = lbl_803E55F8;
            fStack_3c = (float)randomGetRange(0,0xffff);
            fStack_3c = -fStack_3c;
            local_40 = 0x43300000;
            PSVECDotProduct((double)(float)(DOUBLE_803e5600 *
                                        (double)((float)((double)CONCAT44(0x43300000,fStack_3c) -
                                                        DOUBLE_803e55e0) / lbl_803E5608)),
                         afStack_cc,0x7a);
            pfVar4 = (float *)FUN_8000696c();
            FUN_80247618(pfVar4,afStack_cc,afStack_cc);
            FUN_80247cd8(afStack_cc,&local_e4,&local_e4);
            local_e4 = local_e4 + *pfVar11;
            local_e0 = local_e0 + pfVar11[1];
            local_dc = local_dc + pfVar11[2];
            uVar6 = randomGetRange(0xc0,0x100);
            if (*(byte *)(iVar8 + 0xa58) < 0x32) {
              param_2 = (double)local_e4;
              param_3 = (double)local_e0;
              param_4 = (double)local_dc;
              FUN_801b40f0((double)((float)(dVar12 * (double)(f32)(s32)(uVar6)) *
                                   lbl_803E560C),param_2,param_3,param_4);
            }
            pfVar11[8] = pfVar11[9];
          }
        }
      }
      else {
        *(undefined *)((int)pfVar11 + 0x2f) = 0;
      }
    }
    pfVar11 = pfVar11 + 0xc;
  }
  dVar12 = (double)FUN_80003494((uint)auStack_9c,uVar3,0x38);
  local_94 = lbl_803E55C4;
  local_78 = lbl_803E55F8;
  local_74 = lbl_803E55F8;
  local_70 = lbl_803E55F8;
  pfVar11 = pfVar9;
  for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)((int)pfVar9 + 0xa5a); iVar10 = iVar10 + 1) {
    dVar13 = param_4;
    if (*(char *)(pfVar11 + 0x261) != '\0') {
      pfVar11[0x25f] = (float)((int)pfVar11[0x25f] + (uint)DAT_803dc070);
      dVar13 = DOUBLE_803e5628;
      if ((int)pfVar11[0x25f] < (int)pfVar11[0x260]) {
        uVar6 = (uint)DAT_803dc070;
        local_38 = (double)CONCAT44(0x43300000,uVar6);
        param_5 = (double)pfVar11[0x25d];
        param_6 = -(double)(float)((double)pfVar9[0x28f] *
                                   (double)(float)(local_38 - DOUBLE_803e5628) - param_5);
        param_3 = (double)lbl_803E5634;
        fStack_3c = -(float)(uVar6 * uVar6);
        local_40 = 0x43300000;
        local_48 = (double)CONCAT44(0x43300000,uVar6);
        pfVar11[0x25a] =
             -(float)(param_3 * (double)(float)((double)pfVar9[0x28f] *
                                               (double)(float)((double)CONCAT44(0x43300000,fStack_3c
                                                                               ) - DOUBLE_803e55e0))
                     - (double)(float)(param_5 * (double)(float)(local_48 - DOUBLE_803e5628) +
                                      (double)pfVar11[0x25a]));
        pfVar11[0x25d] = (float)param_6;
        fStack_4c = (float)(uint)DAT_803dc070;
        local_50 = 0x43300000;
        pfVar11[0x259] =
             pfVar11[0x25c] * (float)((double)CONCAT44(0x43300000,fStack_4c) - dVar13) +
             pfVar11[0x259];
        fStack_54 = (float)(uint)DAT_803dc070;
        local_58 = 0x43300000;
        pfVar11[0x25b] =
             pfVar11[0x25e] * (float)((double)CONCAT44(0x43300000,fStack_54) - dVar13) +
             pfVar11[0x25b];
        if (((*(char *)(pfVar9 + 0x297) != '\0') && (pfVar11[0x25a] < pfVar9[600])) &&
           (pfVar11[0x25d] < lbl_803E55F8)) {
          pfVar11[0x25d] = lbl_803E5638 * -pfVar11[0x25d];
        }
        local_90 = pfVar11[0x259];
        param_2 = (double)local_90;
        local_8c = pfVar11[0x25a];
        dVar12 = (double)local_8c;
        local_88 = pfVar11[0x25b];
        local_84 = local_90;
        local_80 = local_8c;
        local_7c = local_88;
        if ((DAT_803de7d8 & 1) != 0) {
          fVar5 = pfVar11[0x25f];
          if ((int)fVar5 < 0x40) {
            local_d0 = (short)((int)fVar5 << 6);
            local_d8 = -1 - local_d0;
            local_d4 = -0x8000;
            local_d2 = -0x4000 - local_d0;
            local_d0 = -0x6000 - local_d0;
            local_d6 = local_d8;
          }
          else if ((int)fVar5 < 0x80) {
            local_d6 = (short)((int)fVar5 << 6);
            local_d8 = -0x4000 - local_d6;
            local_d6 = -0x6000 - local_d6;
            local_d4 = 0;
            local_d2 = -0x8000;
            local_d0 = 0;
          }
          else {
            local_d8 = -0x6000;
            local_d6 = 0;
            local_d4 = 0;
            local_d2 = 0;
            local_d0 = 0;
          }
          sVar2 = local_d4;
          local_ce = 0;
          bVar1 = *(byte *)((int)pfVar9 + 0xa5d);
          if (bVar1 == 2) {
            local_d6 = local_d8;
            local_d0 = local_d2;
            local_d8 = local_d4;
            local_d2 = 0;
          }
          else if (bVar1 < 2) {
            if (bVar1 != 0) {
              local_d6 = local_d4;
              local_d0 = 0;
            }
          }
          else if (bVar1 < 4) {
            local_d6 = local_d4;
            local_d0 = 0;
            local_d4 = local_d8;
            local_ce = local_d2;
            local_d8 = sVar2;
            local_d2 = 0;
          }
          dVar12 = (double)(**(code **)(*DAT_803dd708 + 8))
                                     (uVar3,0x5e,auStack_9c,0x200001,0xffffffff,&local_d8);
        }
      }
      else {
        *(undefined *)(pfVar11 + 0x261) = 0;
        dVar13 = param_4;
      }
    }
    pfVar11 = pfVar11 + 9;
    param_4 = dVar13;
  }
  fVar5 = pfVar9[0x293];
  fVar7 = pfVar9[0x294];
  if ((int)fVar7 << 1 < (int)fVar5) {
    FUN_80017ac8(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3);
  }
  else {
    if ((int)fVar7 < (int)fVar5) {
      if (pfVar9[0x290] != 0.0) {
        FUN_800175cc((double)lbl_803E55F8,(int)pfVar9[0x290],'\0');
      }
    }
    else {
      local_38 = (double)CONCAT44(0x43300000,-fVar5);
      fStack_3c = -fVar7;
      local_40 = 0x43300000;
      FUN_801b43a8(*(byte *)((int)pfVar9 + 0xa5d),&local_e8);
      if (pfVar9[0x290] != 0.0) {
        FUN_8001759c((int)pfVar9[0x290],local_e8,local_e7,local_e6,0xff);
      }
    }
    local_38 = (double)CONCAT44(0x43300000,-pfVar9[0x293]);
    fStack_3c = -pfVar9[0x294];
    local_40 = 0x43300000;
    fVar5 = (float)(local_38 - DOUBLE_803e55e0) /
            (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e55e0);
    *(float *)(uVar3 + 8) = lbl_803E563C * fVar5 * pfVar9[0x295];
    iVar10 = (int)-(lbl_803E55D0 * fVar5 - lbl_803E55D0);
    local_48 = (double)(longlong)iVar10;
    *(char *)(uVar3 + 0x36) = (char)iVar10;
    if ((*(char *)((int)pfVar9 + 0xa5b) == '\0') && ((int)pfVar9[0x294] >> 1 <= (int)pfVar9[0x293]))
    {
      uVar3 = randomGetRange(0x1000,0x6000);
      local_d8 = (short)uVar3;
      local_d2 = SUB42(pfVar9[5],0);
      uVar3 = 0;
      while (local_38 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000),
            (float)(local_38 - DOUBLE_803e55e0) < pfVar9[0x295]) {
        uVar3 = uVar3 + 1;
      }
      *(undefined *)((int)pfVar9 + 0xa5b) = 1;
      local_d6 = local_d8;
      local_d4 = local_d8;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b4f60
 * EN v1.0 Address: 0x801B4F60
 * EN v1.0 Size: 1632b
 * EN v1.1 Address: 0x801B5608
 * EN v1.1 Size: 1532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b4f60(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  undefined8 uVar12;
  float local_b8;
  float local_b4;
  float local_b0;
  float afStack_ac [12];
  float afStack_7c [13];
  undefined8 local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined8 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar12 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar2 = (int)uVar12;
  iVar8 = *(int *)(iVar3 + 0xb8);
  *(undefined *)(iVar8 + 0xa58) = 0;
  if ((int)*(short *)(iVar2 + 0x1a) == 0) {
    dVar11 = (double)lbl_803E5640;
  }
  else {
    dVar11 = (double)((f32)(s32)((int)*(short *)(iVar2 + 0x1a)) * lbl_803E560C);
    if ((double)lbl_803E5640 < dVar11) {
      dVar11 = (double)lbl_803E5640;
    }
  }
  FUN_801b40f0((double)(float)((double)lbl_803E5644 * dVar11),(double)*(float *)(iVar3 + 0xc),
               (double)*(float *)(iVar3 + 0x10),(double)*(float *)(iVar3 + 0x14));
  *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x2000;
  *(byte *)(iVar8 + 0xa5d) = (byte)*(undefined2 *)(iVar2 + 0x1c) & 3;
  FUN_80017a78(iVar3,(uint)*(byte *)(iVar8 + 0xa5d));
  if ((*(ushort *)(iVar2 + 0x1c) & 4) == 0) {
    *(float *)(iVar8 + 0xa3c) = lbl_803E55F8;
  }
  else {
    *(float *)(iVar8 + 0xa3c) = lbl_803E563C;
  }
  *(undefined *)(iVar8 + 0xa5c) = 0;
  iVar4 = FUN_800632e8((double)*(float *)(iVar3 + 0xc),
                       (double)(lbl_803E5648 + *(float *)(iVar3 + 0x10)),
                       (double)*(float *)(iVar3 + 0x14),iVar3,(float *)(iVar8 + 0x960),0);
  if (iVar4 == 0) {
    if (*(float *)(iVar8 + 0x960) < lbl_803E564C) {
      *(undefined *)(iVar8 + 0xa5c) = 1;
    }
    *(float *)(iVar8 + 0x960) = *(float *)(iVar3 + 0x10) - *(float *)(iVar8 + 0x960);
  }
  else {
    *(undefined4 *)(iVar8 + 0x960) = *(undefined4 *)(iVar3 + 0x10);
  }
  if ((*(ushort *)(iVar2 + 0x1c) & 0x10) == 0) {
    *(undefined *)(iVar8 + 0xa5a) = 0;
  }
  else {
    iVar4 = (int)((float)((double)lbl_803E5650 * dVar11) / lbl_803E5640);
    local_48 = (double)(longlong)iVar4;
    iVar9 = iVar8;
    for (iVar7 = 0; iVar7 < iVar4; iVar7 = iVar7 + 1) {
      if (*(char *)(iVar8 + 0xa5c) == '\0') {
        uVar6 = randomGetRange(0x14,0x28);
        local_b0 = lbl_803E5654 * lbl_803E5658 * (f32)(s32)(uVar6) +
                   lbl_803E5654;
        iVar1 = iVar7 >> 0x1f;
        uVar6 = (iVar1 * 4 | (uint)(iVar7 * 0x40000000 + iVar1) >> 0x1e) - iVar1 & 0xff;
        local_b8 = local_b0 * (float)(&DAT_80326168)[uVar6 * 3];
        local_b4 = local_b0 * (float)(&DAT_8032616c)[uVar6 * 3];
        local_b0 = local_b0 * (float)(&DAT_80326170)[uVar6 * 3];
        uStack_3c = randomGetRange(0,0x8000);
        PSVECDotProduct((double)(float)(DOUBLE_803e5600 *
                                    (double)(((float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                     DOUBLE_803e55e0) - lbl_803E5660) /
                                            lbl_803E565C)),afStack_7c,0x7a);
        uVar6 = randomGetRange(0,0x8000);
        PSVECDotProduct((double)(float)(DOUBLE_803e5600 *
                                    (double)(((f32)(s32)(uVar6) - lbl_803E5660)
                                            / lbl_803E565C)),afStack_ac,0x78);
        FUN_80247618(afStack_ac,afStack_7c,afStack_7c);
        FUN_80247cd8(afStack_7c,&local_b8,&local_b8);
      }
      else {
        uVar6 = randomGetRange(0x14,0x28);
        local_b8 = lbl_803E5654 * lbl_803E5658 * (f32)(s32)(uVar6) +
                   lbl_803E5654;
        local_b4 = lbl_803E55F8;
        local_b0 = lbl_803E55F8;
        uStack_3c = randomGetRange(0x2000,0x6000);
        PSVECDotProduct((double)(float)(DOUBLE_803e5600 *
                                    (double)((float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                    DOUBLE_803e55e0) / lbl_803E565C)),afStack_7c,
                     0x7a);
        uVar6 = randomGetRange(0,0xffff);
        PSVECDotProduct((double)(float)(DOUBLE_803e5600 *
                                    (double)((f32)(s32)(uVar6) / lbl_803E5608)),
                     afStack_ac,0x79);
        FUN_80247618(afStack_ac,afStack_7c,afStack_7c);
        FUN_80247cd8(afStack_7c,&local_b8,&local_b8);
      }
      *(undefined4 *)(iVar9 + 0x964) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(iVar9 + 0x968) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(iVar9 + 0x96c) = *(undefined4 *)(iVar3 + 0x14);
      *(float *)(iVar9 + 0x970) = local_b8;
      *(float *)(iVar9 + 0x974) = local_b4;
      *(float *)(iVar9 + 0x978) = local_b0;
      *(undefined4 *)(iVar9 + 0x97c) = 0;
      uVar6 = randomGetRange(0x28,0x32);
      *(uint *)(iVar9 + 0x980) = uVar6;
      *(undefined *)(iVar9 + 0x984) = 1;
      iVar9 = iVar9 + 0x24;
    }
    *(char *)(iVar8 + 0xa5a) = (char)iVar7;
  }
  *(undefined4 *)(iVar8 + 0xa40) = 0;
  if ((*(ushort *)(iVar2 + 0x1c) & 0x20) != 0) {
    piVar5 = FUN_80017624(0,'\x01');
    *(int **)(iVar8 + 0xa40) = piVar5;
    if (*(int *)(iVar8 + 0xa40) != 0) {
      FUN_800175b0(*(int *)(iVar8 + 0xa40),2);
      FUN_800175ec((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                   (double)*(float *)(iVar3 + 0x20),*(int **)(iVar8 + 0xa40));
      FUN_800175d8(*(int *)(iVar8 + 0xa40),1);
      FUN_800175cc((double)lbl_803E55F8,*(int *)(iVar8 + 0xa40),'\x01');
      FUN_800175d0((double)(float)((double)lbl_803E5664 * dVar11),
                   (double)(float)((double)lbl_803E55F0 * dVar11),*(int *)(iVar8 + 0xa40));
      FUN_8001759c(*(int *)(iVar8 + 0xa40),0xff,0xeb,0xa0,0xff);
    }
  }
  *(undefined *)(iVar3 + 0x36) = 0xff;
  if ((*(ushort *)(iVar2 + 0x1c) & 8) == 0) {
    *(undefined *)(iVar8 + 0xa59) = 0;
  }
  else if (*(char *)(iVar8 + 0xa5c) == '\0') {
    *(undefined *)(iVar8 + 0xa59) = 2;
    uVar6 = randomGetRange(0,0x4000);
    *(short *)(iVar8 + 0xa44) = (short)uVar6;
    uVar6 = randomGetRange(0,0x8000);
    *(short *)(iVar8 + 0xa46) = (short)uVar6;
    *(short *)(iVar8 + 0xa48) = *(short *)(iVar8 + 0xa44) + 0x4000;
    *(undefined2 *)(iVar8 + 0xa4a) = *(undefined2 *)(iVar8 + 0xa46);
  }
  else {
    *(undefined *)(iVar8 + 0xa59) = 1;
    *(undefined2 *)(iVar8 + 0xa44) = 0;
    *(undefined2 *)(iVar8 + 0xa46) = 0;
  }
  *(undefined *)(iVar8 + 0xa5b) = 0;
  *(undefined4 *)(iVar8 + 0xa4c) = 0;
  dVar10 = FUN_80293900(dVar11);
  local_38 = (double)(longlong)(int)((double)lbl_803E55C8 * dVar10);
  *(int *)(iVar8 + 0xa50) = (int)((double)lbl_803E55C8 * dVar10);
  iVar2 = *(int *)(iVar8 + 0xa50);
  if (iVar2 < 0) {
    iVar2 = 0;
  }
  else if (0x3c < iVar2) {
    iVar2 = 0x3c;
  }
  *(int *)(iVar8 + 0xa50) = iVar2;
  *(float *)(iVar8 + 0xa54) = (float)dVar11;
  *(float *)(iVar3 + 8) = lbl_803E55F8;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b55c0
 * EN v1.0 Address: 0x801B55C0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801B5C04
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b55c0(void)
{
  int iVar1;
  int *piVar2;
  
  iVar1 = 0;
  piVar2 = &DAT_803ad5c0;
  do {
    if (*piVar2 != 0) {
      FUN_80053754();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5624
 * EN v1.0 Address: 0x801B5624
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B5C6C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5624(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b5628
 * EN v1.0 Address: 0x801B5628
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B5D84
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5628(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: explosion_release
 * EN v1.0 Address: 0x801B5650
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B5DB8
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void textureFree(int tex);
extern int lbl_803AC960[4];

#pragma scheduling off
#pragma peephole off
void explosion_release(uint param_1)
{
    int i;
    int** p;

    i = 0;
    p = (int**)lbl_803AC960;
    for (; i < 4; i++) {
        if (*p != NULL) {
            textureFree((int)*p);
            *p = NULL;
        }
        p++;
    }
}
#pragma peephole reset
#pragma scheduling reset

void fn_explosion_release_v11_unused(uint param_1)
{
  short sVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  short *psVar7;

  psVar7 = *(short **)(param_1 + 0x4c);
  pcVar6 = *(char **)(param_1 + 0xb8);
  FUN_8002fc3c((double)*(float *)(pcVar6 + 4),(double)lbl_803DC074);
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + *(float *)(pcVar6 + 8);
  fVar2 = lbl_803E566C;
  if (*(float *)(pcVar6 + 8) != lbl_803E566C) {
    *(float *)(pcVar6 + 8) = *(float *)(pcVar6 + 8) * lbl_803E5670;
    if (*(float *)(pcVar6 + 8) < fVar2) {
      fVar2 = *(float *)(pcVar6 + 8);
    }
    *(float *)(pcVar6 + 8) = fVar2;
  }
  if ((('\0' < *pcVar6) || (*psVar7 != 0x338)) || (*(float *)(param_1 + 0x98) <= lbl_803E5674)) {
    bVar3 = false;
    iVar5 = 0;
    iVar4 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
    if (0 < iVar4) {
      do {
        sVar1 = *(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) + 0x46);
        if ((sVar1 == 399) || (sVar1 == 0x1d6)) {
          bVar3 = true;
          break;
        }
        iVar5 = iVar5 + 4;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    if (bVar3) {
      *(float *)(pcVar6 + 4) = lbl_803E5678;
      *(float *)(pcVar6 + 8) = lbl_803E567C;
      *pcVar6 = '\0';
      GameBit_Set((int)psVar7[0xf],1);
      FUN_80006824(param_1,0x3e1);
    }
  }
  else {
    iVar4 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -0x10;
    if (iVar4 < 0) {
      iVar4 = 0;
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & ~1;
    *(char *)(param_1 + 0x36) = (char)iVar4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b57b4
 * EN v1.0 Address: 0x801B57B4
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x801B5F38
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b57b4(undefined2 *param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  undefined *puVar3;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  puVar3 = *(undefined **)(param_1 + 0x5c);
  *puVar3 = 3;
  fVar1 = lbl_803E566C;
  *(float *)(puVar3 + 4) = lbl_803E566C;
  *(float *)(puVar3 + 8) = fVar1;
  uVar2 = GameBit_Get((int)*(short *)(param_2 + 0x1e));
  if (uVar2 != 0) {
    *puVar3 = 0;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & ~1;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5844
 * EN v1.0 Address: 0x801B5844
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B5FEC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5844(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b5848
 * EN v1.0 Address: 0x801B5848
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B6020
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5848(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5870
 * EN v1.0 Address: 0x801B5870
 * EN v1.0 Size: 656b
 * EN v1.1 Address: 0x801B6054
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5870(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  short sVar1;
  bool bVar2;
  int iVar3;
  char cVar4;
  uint uVar5;
  undefined2 *puVar6;
  int iVar7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar8;
  int iVar9;
  double dVar10;
  
  iVar9 = *(int *)(param_9 + 0x26);
  pfVar8 = *(float **)(param_9 + 0x5c);
  if (*(char *)(param_9 + 0x1b) != '\0') {
    if ((*(char *)((int)pfVar8 + 9) < '\x01') &&
       (*(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & ~1, *(char *)(pfVar8 + 2) == '\x01')
       ) {
      param_2 = (double)pfVar8[1];
      *pfVar8 = (float)(param_2 * (double)lbl_803DC074 + (double)*pfVar8);
      if (*pfVar8 <= lbl_803E5684) {
        if (*pfVar8 < lbl_803E568C) {
          *pfVar8 = lbl_803E568C;
          pfVar8[1] = lbl_803E5690;
        }
      }
      else {
        *pfVar8 = lbl_803E5684;
        pfVar8[1] = lbl_803E5688;
      }
    }
    if (param_9[0x23] != 0x334) {
      bVar2 = false;
      iVar7 = 0;
      iVar3 = (int)*(char *)(*(int *)(param_9 + 0x2c) + 0x10f);
      if (0 < iVar3) {
        do {
          sVar1 = *(short *)(*(int *)(*(int *)(param_9 + 0x2c) + iVar7 + 0x100) + 0x46);
          if ((sVar1 == 399) || (sVar1 == 0x1d6)) {
            bVar2 = true;
            break;
          }
          iVar7 = iVar7 + 4;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
      if ((bVar2) &&
         (cVar4 = *(char *)((int)pfVar8 + 9) + -1, *(char *)((int)pfVar8 + 9) = cVar4,
         cVar4 < '\x01')) {
        GameBit_Set((int)*(short *)(iVar9 + 0x1e),1);
        *(undefined *)(pfVar8 + 2) = 1;
        uVar5 = GameBit_Get(0x46d);
        if (((int)*(short *)(iVar9 + 0x1a) == uVar5) &&
           (uVar5 = FUN_80017ae8(), (uVar5 & 0xff) != 0)) {
          puVar6 = FUN_80017aa4(0x30,0x246);
          *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(iVar9 + 8);
          dVar10 = (double)lbl_803E5694;
          *(float *)(puVar6 + 6) = (float)(dVar10 + (double)*(float *)(iVar9 + 0xc));
          *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(iVar9 + 0x10);
          *(undefined *)(puVar6 + 2) = *(undefined *)(iVar9 + 4);
          *(undefined *)((int)puVar6 + 5) = *(undefined *)(iVar9 + 5);
          *(undefined *)(puVar6 + 3) = *(undefined *)(iVar9 + 6);
          *(undefined *)((int)puVar6 + 7) = *(undefined *)(iVar9 + 7);
          puVar6[0xe] = 0x17f;
          puVar6[0x12] = 0xffff;
          puVar6[0x16] = 0xffff;
          *(undefined *)(puVar6 + 0xd) = 5;
          *(char *)((int)puVar6 + 0x1b) = (char)((ushort)*param_9 >> 8);
          FUN_80017ae4(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,
                       *(undefined *)(param_9 + 0x56),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5b00
 * EN v1.0 Address: 0x801B5B00
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801B625C
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5b00(undefined2 *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x2000;
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 9) = 1;
  uVar1 = GameBit_Get((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    *(undefined *)(iVar2 + 9) = 0;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & ~1;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  *(float *)(iVar2 + 4) = lbl_803E5688;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5b8c
 * EN v1.0 Address: 0x801B5B8C
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801B62FC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5b8c(void)
{
  int iVar1;
  int *piVar2;
  undefined2 *puVar3;
  short *psVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  double dVar9;
  undefined8 uVar10;
  undefined8 local_58;
  undefined8 local_50;
  
  uVar10 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  piVar2 = (int *)FUN_80017a54(iVar1);
  iVar6 = *piVar2;
  for (iVar7 = 0; uVar8 = (uint)*(ushort *)(iVar6 + 0xe4), iVar7 < (int)uVar8; iVar7 = iVar7 + 1) {
    puVar3 = (undefined2 *)FUN_80017944((int)piVar2,iVar7);
    psVar4 = (short *)FUN_80017924(iVar6,iVar7);
    if (*psVar4 < 1) {
      dVar9 = (double)FUN_80293f90();
      local_50 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)-(float)((double)lbl_803E569C * dVar9 -
                                    (double)(float)(local_50 - DOUBLE_803e56a8));
    }
    else {
      dVar9 = (double)FUN_80293f90();
      local_58 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)((double)lbl_803E569C * dVar9 +
                            (double)(float)(local_58 - DOUBLE_803e56a8));
    }
  }
  uVar5 = FUN_80017944((int)piVar2,0);
  FUN_80242114(uVar5,uVar8 * 6);
  *(undefined *)(iVar1 + 0x36) = *(undefined *)((int)uVar10 + 0x51);
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5d00
 * EN v1.0 Address: 0x801B5D00
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801B64D0
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5d00(int param_1,int param_2)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_80039520(param_1,0);
  *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + 0x14;
  if (10000 < *(short *)(iVar1 + 10)) {
    *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + -10000;
  }
  *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + 10;
  if (10000 < *(short *)(iVar1 + 8)) {
    *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + -10000;
  }
  iVar1 = FUN_80039520(param_1,1);
  *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + 0x1e;
  if (10000 < *(short *)(iVar1 + 10)) {
    *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + -10000;
  }
  uVar2 = (uint)*(ushort *)(param_2 + 0x60) + (uint)DAT_803dc070 * 0x100;
  if (0xffff < uVar2) {
    uVar2 = uVar2 - 0xffff;
  }
  *(short *)(param_2 + 0x60) = (short)uVar2;
  uVar2 = (uint)*(ushort *)(param_2 + 0x62) + (uint)DAT_803dc070 * 0x80;
  if (0xffff < uVar2) {
    uVar2 = uVar2 - 0xffff;
  }
  *(short *)(param_2 + 0x62) = (short)uVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5df0
 * EN v1.0 Address: 0x801B5DF0
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x801B65E0
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801b5df0(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & ~0x40;
  FUN_801b5d00(param_1,iVar4);
  if (*(char *)(param_3 + 0x80) == '\x01') {
    *(undefined *)(param_3 + 0x80) = 0;
    *(undefined *)(iVar4 + 0x5f) = 1;
  }
  if (*(char *)(iVar4 + 0x5f) != '\0') {
    *(ushort *)(iVar4 + 100) = *(short *)(iVar4 + 100) - (ushort)DAT_803dc070;
    if (*(short *)(iVar4 + 100) < 1) {
      *(undefined2 *)(iVar4 + 100) = 0x10;
      for (iVar2 = 1;
          (*(char *)(iVar4 + iVar2 + 0x40) != '\0' && (iVar2 < (int)(uint)*(byte *)(iVar4 + 0x4f)));
          iVar2 = iVar2 + 1) {
      }
      *(undefined *)(iVar4 + iVar2 + 0x40) = 1;
    }
    for (iVar2 = 1; iVar2 < (int)(uint)*(byte *)(iVar4 + 0x4f); iVar2 = iVar2 + 1) {
      iVar3 = iVar4 + iVar2;
      if (*(char *)(iVar3 + 0x40) != '\0') {
        uVar1 = (uint)*(byte *)(iVar3 + 0x50) + (uint)DAT_803dc070;
        if (0xff < uVar1) {
          uVar1 = 0xff;
        }
        *(char *)(iVar3 + 0x50) = (char)uVar1;
      }
    }
  }
  FUN_801b5b8c();
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801b6108
 * EN v1.0 Address: 0x801B6108
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B672C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b6108(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b6130
 * EN v1.0 Address: 0x801B6130
 * EN v1.0 Size: 656b
 * EN v1.1 Address: 0x801B6760
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b6130(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar1 = FUN_80017a98();
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_801b5d00(param_1,iVar3);
  FUN_801b5b8c();
  if (*(char *)(iVar3 + 0x5f) == '\0') {
    uVar2 = GameBit_Get(0x1ef);
    if ((uVar2 != 0) && (iVar1 = FUN_80294cb0(iVar1), iVar1 != 0)) {
      GameBit_Set(0x1e8,1);
    }
  }
  else {
    FUN_800631d4(0x11,0,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b63c0
 * EN v1.0 Address: 0x801B63C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B6808
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b63c0(void)
{
}


/* Trivial 4b 0-arg blr leaves. */
void explosion_hitDetect(void) {}
void dimwooddoor2_free(void) {}
void dimwooddoor2_hitDetect(void) {}
void dimwooddoor2_release(void) {}
void dimwooddoor2_initialise(void) {}
void dll_1CE_hitDetect(void) {}
void dll_1CE_release(void) {}
void dll_1CE_initialise(void) {}
void dimmagicbridge_free(void) {}
void dimmagicbridge_hitDetect(void) {}
void dimmagicbridge_release(void) {}
void dimmagicbridge_initialise(void) {}

extern f32 lbl_803E4A10;
extern int dimmagicbridge_flameSeqFn(int* obj, int p2, u8* p3);
extern int Obj_GetActiveModel(int obj);
extern int ObjModel_GetCurrentVertexCoords(int model, int idx);
extern void fn_80065574(int a, int b, int c);

#pragma peephole off
#pragma scheduling off
void dimmagicbridge_init(u8* obj, u8* params) {
    u8* sub;
    int model;
    int modelData;
    s32 minY;
    int i;
    int j;
    int stable;
    f32* p;
    f32 a, b;
    int v;
    s16 hh;

    *(s16*)obj = (s16)(((s16)(s8)params[0x18]) << 8);
    *(void**)(obj + 0xbc) = (void*)&dimmagicbridge_flameSeqFn;
    sub = *(u8**)(obj + 0xb8);
    minY = 0;
    model = Obj_GetActiveModel((int)obj);
    modelData = *(int*)model;

    i = 0;
    while (i < *(u16*)(modelData + 0xe4)) {
        v = ObjModel_GetCurrentVertexCoords(model, i);
        hh = *(s16*)(v + 4);
        if (hh < minY) {
            minY = hh;
        }
        i++;
    }

    stable = 0;
    while (stable == 0) {
        stable = 1;
        j = 0;
        p = (f32*)sub;
        while (j < (int)sub[0x4f] - 1) {
            a = p[1];
            b = p[2];
            if (a < b) {
                p[1] = b;
                p[2] = (f32)(s32)a;
                stable = 0;
            }
            p++;
            j++;
        }
    }

    sub[0x4f] = 0xa;
    *(f32*)sub = (f32)minY;

    if (GameBit_Get(0x1e9) != 0) {
        sub[0x5f] = 1;
    }
    if (sub[0x5f] != 0) {
        for (i = 0; i < (int)sub[0x4f]; i++) {
            sub[0x50 + i] = 0xff;
            sub[0x40 + i] = 1;
            fn_80065574(0x11, 0, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

/* 8b "li r3, N; blr" returners. */
int explosion_getExtraSize(void) { return 0xa60; }
int dimwooddoor2_getExtraSize(void) { return 0xc; }
int dimwooddoor2_getObjectTypeId(void) { return 0x0; }
int dll_1CE_getExtraSize(void) { return 0xc; }
int dll_1CE_getObjectTypeId(void) { return 0x0; }
int dimmagicbridge_getExtraSize(void) { return 0x68; }
int dimmagicbridge_getObjectTypeId(void) { return 0x0; }
int dim_levelcontrol_getExtraSize(void) { return 0x10; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E49D0;
extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 v);
extern f32 lbl_803E49E8;
extern f32 lbl_803E4A18;
extern f32 lbl_803E4A20;
#pragma peephole off
void dimwooddoor2_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E49D0); }
void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E49E8); }
void dimmagicbridge_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E4A18); }
void dim_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E4A20); }
#pragma peephole reset

/* conditional init/free pair. */
extern u32 lbl_803DDB78;
extern void Resource_Release(u32);
#pragma scheduling off
#pragma peephole off
void dll_1CE_free(void) {
    if (lbl_803DDB78 != 0) {
        Resource_Release(lbl_803DDB78);
    }
    lbl_803DDB78 = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */
extern f32 lbl_803E49D4;
extern f32 lbl_803E49F0;
extern void* Obj_GetPlayerObject(void);
extern void dimmagicbridge_scrollTextureChannels(int obj, u8* sub);
extern void dimmagicbridge_updateVertexWave(int obj, u8* sub);
extern int EmissionController_IsLingering(void* player);
extern void fn_80065574(int a, int b, int c);

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */
#pragma scheduling off
void dimmagicbridge_update(int obj)
{
    u8* sub;
    void* player;
    player = Obj_GetPlayerObject();
    sub = *(u8**)((u8*)obj + 0xb8);
    dimmagicbridge_scrollTextureChannels(obj, sub);
    dimmagicbridge_updateVertexWave(obj, sub);
    if (sub[0x5f] == 0) {
        if (GameBit_Get(0x1ef) != 0) {
            if (EmissionController_IsLingering(player) != 0) {
                GameBit_Set(0x1e8, 1);
            }
        }
    } else {
        fn_80065574(0x11, 0, 0);
    }
}
#pragma scheduling reset

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */
#pragma peephole off
#pragma scheduling off
void dimwooddoor2_init(u8* obj, u8* params)
{
    u8* sub;
    f32 fz;
    *(s16*)obj = (s16)(((s16)(s8)params[0x18]) << 8);
    *(u16*)(obj + 0xb0) = (u16)(*(u16*)(obj + 0xb0) | 0x6000);
    sub = *(u8**)(obj + 0xb8);
    sub[0] = 3;
    fz = lbl_803E49D4;
    *(f32*)(sub + 4) = fz;
    *(f32*)(sub + 8) = fz;
    if (GameBit_Get(*(s16*)(params + 0x1e)) != 0) {
        sub[0] = 0;
        *(s16*)(*(u8**)(obj + 0x54) + 0x60) = (s16)(*(s16*)(*(u8**)(obj + 0x54) + 0x60) & ~1);
        *(u8*)(obj + 0x36) = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_1CE_init(u8* obj, u8* params)
{
    u8* sub;
    *(s16*)obj = (s16)(((s16)(s8)params[0x18]) << 8);
    *(u16*)(obj + 0xb0) = (u16)(*(u16*)(obj + 0xb0) | 0x2000);
    sub = *(u8**)(obj + 0xb8);
    sub[9] = 1;
    if (GameBit_Get(*(s16*)(params + 0x1e)) != 0) {
        sub[9] = 0;
        *(s16*)(*(u8**)(obj + 0x54) + 0x60) = (s16)(*(s16*)(*(u8**)(obj + 0x54) + 0x60) & ~1);
        *(u8*)(obj + 0x36) = 0;
    }
    *(f32*)(sub + 4) = lbl_803E49F0;
}
#pragma scheduling reset
#pragma peephole reset

/* explosion_free: model-light release if present. */
extern void ModelLightStruct_free(void *);
void explosion_free(int obj)
{
    void *p = *(void **)(*(int *)(obj + 0xb8) + 0xa40);
    if (p != NULL) {
        ModelLightStruct_free(p);
    }
}

/* explosion_getObjectTypeId: tile/index lookup capped by table count. */
#pragma scheduling off
int explosion_getObjectTypeId(int obj)
{
    int idx = (int)*(short *)(*(int *)(obj + 0x4c) + 0x1c) & 3;
    if (idx >= (int)*(char *)(*(int *)(obj + 0x50) + 0x55)) {
        idx = 0;
    }
    return (idx << 11) | 0x400;
}
#pragma scheduling reset

/* dim_levelcontrol_free: gameplay music + time-of-day reset. */
extern void Music_Trigger(s32 triggerId, s32 mode);
extern void timeOfDayFn_80055000(void);
#pragma scheduling off
void dim_levelcontrol_free(int p1)
{
    Music_Trigger(0xa1, 0);
    Music_Trigger(0xed, 0);
    timeOfDayFn_80055000();
}
#pragma scheduling reset

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
extern void *objFindTexture(int obj, int a, int b);
extern u8 framesThisStep;
#pragma scheduling off
#pragma dont_inline on
void dimmagicbridge_scrollTextureChannels(int param_1, u8* obj)
{
    u8* tex;
    s32 v;

    tex = (u8*)objFindTexture(param_1, 0, 0);
    *(s16*)(tex + 10) = (s16)(*(s16*)(tex + 10) + 0x14);
    if (*(s16*)(tex + 10) > 10000) {
        *(s16*)(tex + 10) = (s16)(*(s16*)(tex + 10) - 10000);
    }
    *(s16*)(tex + 8) = (s16)(*(s16*)(tex + 8) + 10);
    if (*(s16*)(tex + 8) > 10000) {
        *(s16*)(tex + 8) = (s16)(*(s16*)(tex + 8) - 10000);
    }
    tex = (u8*)objFindTexture(param_1, 1, 0);
    *(s16*)(tex + 10) = (s16)(*(s16*)(tex + 10) + 0x1e);
    if (*(s16*)(tex + 10) > 10000) {
        *(s16*)(tex + 10) = (s16)(*(s16*)(tex + 10) - 10000);
    }
    v = (s32)*(u16*)(obj + 0x60) + (s32)framesThisStep * 0x100;
    if (v > 0xffff) v = v - 0xffff;
    *(u16*)(obj + 0x60) = (u16)v;
    v = (s32)*(u16*)(obj + 0x62) + (s32)framesThisStep * 0x80;
    if (v > 0xffff) v = v - 0xffff;
    *(u16*)(obj + 0x62) = (u16)v;
}
#pragma dont_inline reset
#pragma scheduling reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */
#pragma scheduling off
#pragma peephole off
int dimmagicbridge_flameSeqFn(int* obj, int p2, u8* p3)
{
    u8* sub = *(u8**)((char*)obj + 0xb8);
    int j;
    int i;
    p3[0x56] = 0;
    *(s16*)(p3 + 0x6e) = (s16)(*(s16*)(p3 + 0x6e) & ~0x40);
    dimmagicbridge_scrollTextureChannels((int)obj, sub);
    if (p3[0x80] == 1) {
        p3[0x80] = 0;
        sub[0x5f] = 1;
    }
    if (sub[0x5f] != 0) {
        *(s16*)(sub + 0x64) = *(s16*)(sub + 0x64) - framesThisStep;
        if (*(s16*)(sub + 0x64) <= 0) {
            *(s16*)(sub + 0x64) = 0x10;
            for (j = 1; sub[0x40 + j] != 0 && j < sub[0x4f]; j++) {
            }
            sub[0x40 + j] = 1;
        }
        for (i = 1; i < sub[0x4f]; i++) {
            if (sub[0x40 + i] != 0) {
                int v = sub[0x50 + i] + framesThisStep;
                if (v > 0xff) v = 0xff;
                sub[0x50 + i] = (u8)v;
            }
        }
    }
    dimmagicbridge_updateVertexWave((int)obj, sub);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int ObjAnim_AdvanceCurrentMove(f32 moveStepScale, f32 deltaTime, int objAnim, void* events);
extern f32 lbl_803E49D8;
extern f32 lbl_803E49DC;
extern f32 lbl_803E49E0;
extern f32 lbl_803E49E4;

/* EN v1.0 0x801B5804  size: 380b  dimwooddoor2_update: advance the door's
 * shake anim and decay its wobble; while idle near map-cue 0x338 bleed off
 * alpha, otherwise scan the nearby objects and, if a key object is present,
 * snap the door open (reset wobble, ring the gamebit, play the open sfx). */
#pragma scheduling off
#pragma peephole off
void dimwooddoor2_update(int* obj)
{
    int* q = *(int**)((char*)obj + 0x4c);
    u8* sub = *(u8**)((char*)obj + 0xb8);
    ObjAnim_AdvanceCurrentMove(*(f32*)(sub + 4), timeDelta, (int)obj, 0);
    *(f32*)((char*)obj + 0x14) = *(f32*)((char*)obj + 0x14) + *(f32*)(sub + 8);
    if (*(f32*)(sub + 8) != lbl_803E49D4) {
        *(f32*)(sub + 8) = *(f32*)(sub + 8) * lbl_803E49D8;
        if (*(f32*)(sub + 8) > lbl_803E49D4) {
            *(f32*)(sub + 8) = lbl_803E49D4;
        }
    }
    if ((s8)sub[0] <= 0 && *(s16*)q == 0x338 && *(f32*)((char*)obj + 0x98) > lbl_803E49DC) {
        int v = *(u8*)((char*)obj + 0x36) - framesThisStep * 16;
        int* q2 = *(int**)((char*)obj + 0x54);
        if (v < 0) v = 0;
        *(s16*)((char*)q2 + 0x60) = (s16)(*(s16*)((char*)q2 + 0x60) & ~1);
        *(u8*)((char*)obj + 0x36) = (u8)v;
    } else {
        int found = 0;
        int i;
        int* list = *(int**)((char*)obj + 0x58);
        int n = (s8)*(s8*)((char*)list + 0x10f);
        for (i = 0; i < n; i++) {
            int* o = *(int**)((char*)list + 0x100 + i * 4);
            if (*(s16*)((char*)o + 0x46) == 0x18f || *(s16*)((char*)o + 0x46) == 0x1d6) {
                found = 1;
                break;
            }
        }
        if (found) {
            *(f32*)(sub + 4) = lbl_803E49E0;
            *(f32*)(sub + 8) = lbl_803E49E4;
            sub[0] = 0;
            GameBit_Set(*(s16*)((char*)q + 0x1e), 1);
            Sfx_PlayFromObject((int)obj, 0x3e1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int Obj_IsLoadingLocked(void);
extern int *Obj_AllocObjectSetup(int a, int b);
extern void Obj_SetupObject(int *obj, int a, int b, int c, int d);
extern f32 lbl_803E49EC;
extern f32 lbl_803E49F0;
extern f32 lbl_803E49F4;
extern f32 lbl_803E49F8;
extern f32 lbl_803E49FC;

/* EN v1.0 0x801B5AA0  size: 496b  dll_1CE_update: hatch-door logic - coast
 * the lid open with clamped velocity while idle, and once a key object is
 * nearby, count down then ring the gamebit and (if the load isn't locked)
 * spawn the contents object seeded from the door's transform. */
#pragma scheduling off
#pragma peephole off
void dll_1CE_update(int* obj)
{
    int* q = *(int**)((char*)obj + 0x4c);
    u8* sub = *(u8**)((char*)obj + 0xb8);
    if (*(u8*)((char*)obj + 0x36) == 0) return;
    if ((s8)sub[9] <= 0) {
        int* q2 = *(int**)((char*)obj + 0x54);
        *(s16*)((char*)q2 + 0x60) = (s16)(*(s16*)((char*)q2 + 0x60) & ~1);
        if (sub[8] == 1) {
            *(f32*)(sub + 0) = *(f32*)(sub + 4) * timeDelta + *(f32*)(sub + 0);
            if (*(f32*)(sub + 0) > lbl_803E49EC) {
                *(f32*)(sub + 0) = lbl_803E49EC;
                *(f32*)(sub + 4) = lbl_803E49F0;
            } else if (*(f32*)(sub + 0) < lbl_803E49F4) {
                *(f32*)(sub + 0) = lbl_803E49F4;
                *(f32*)(sub + 4) = lbl_803E49F8;
            }
        }
    }
    if (*(s16*)((char*)obj + 0x46) == 0x334) return;
    {
        int found = 0;
        int i;
        int* list = *(int**)((char*)obj + 0x58);
        int n = (s8)*(s8*)((char*)list + 0x10f);
        for (i = 0; i < n; i++) {
            int* o = *(int**)((char*)list + 0x100 + i * 4);
            if (*(s16*)((char*)o + 0x46) == 0x18f || *(s16*)((char*)o + 0x46) == 0x1d6) {
                found = 1;
                break;
            }
        }
        if (!found) return;
    }
    sub[9] = sub[9] - 1;
    if ((s8)sub[9] > 0) return;
    GameBit_Set(*(s16*)((char*)q + 0x1e), 1);
    sub[8] = 1;
    if ((s16)*(s16*)((char*)q + 0x1a) != (int)GameBit_Get(0x46d)) return;
    if (Obj_IsLoadingLocked() == 0) return;
    {
        int* no = Obj_AllocObjectSetup(0x30, 0x246);
        *(f32*)((char*)no + 8) = *(f32*)((char*)q + 8);
        *(f32*)((char*)no + 0xc) = lbl_803E49FC + *(f32*)((char*)q + 0xc);
        *(f32*)((char*)no + 0x10) = *(f32*)((char*)q + 0x10);
        *(u8*)((char*)no + 4) = *(u8*)((char*)q + 4);
        *(u8*)((char*)no + 5) = *(u8*)((char*)q + 5);
        *(u8*)((char*)no + 6) = *(u8*)((char*)q + 6);
        *(u8*)((char*)no + 7) = *(u8*)((char*)q + 7);
        *(s16*)((char*)no + 0x1c) = 0x17f;
        *(s16*)((char*)no + 0x24) = -1;
        *(s16*)((char*)no + 0x2c) = -1;
        *(u8*)((char*)no + 0x1a) = 5;
        *(u8*)((char*)no + 0x1b) = (u8)((s16)*(s16*)obj >> 8);
        Obj_SetupObject(no, 5, (s8)*(s8*)((char*)obj + 0xac), -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

typedef union {
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} FbWGPipe;
volatile FbWGPipe GXWGFifo : (0xCC008000);

typedef struct {
    int v[4];
} FbTexTbl;

extern f32 lbl_803E492C;
extern f32 lbl_803E4930;
extern f32 lbl_803E4934;
extern f32 lbl_803E4938;
extern f32 lbl_803E493C;
extern f32 lbl_803E4940;
extern f32 lbl_803E4950;
extern f32 lbl_803E4954;
extern f32 lbl_803E4958;
extern f32 lbl_803E495C;
extern f32 lbl_803E4960;
extern f64 lbl_803E4968;
extern f32 lbl_803E4970;
extern f32 lbl_803E4974;
extern f64 lbl_803E4978;
extern f64 lbl_803E4980;
extern f32 lbl_803E4988;
extern f32 lbl_803E4998;
extern f32 lbl_803E499C;
extern f32 lbl_803E49A0;
extern f32 lbl_803E49A4;
extern f32 lbl_803E49A8;
extern f32 lbl_803E49AC;
extern f32 lbl_803E49B0;
extern f32 lbl_803E49B4;
extern f32 lbl_803E49B8;
extern f32 lbl_803E49BC;
extern f32 lbl_803E49C0;
extern f32 lbl_803E49C4;
extern f32 lbl_803E49C8;
extern f32 lbl_803E49CC;
extern int lbl_803E4928;
extern int lbl_803E8468;
extern u8 lbl_803DDB58;
extern f32 lbl_803DDB5C;
extern f32 lbl_803DDB60;
extern f32 lbl_803DDB64;
extern f32 lbl_803DDB68;
extern f32 lbl_803DDB6C;
extern f32 lbl_803DDB70;
extern f32 lbl_803DCDD8;
extern f32 lbl_803DCDDC;
extern f32 lbl_80325528[];
extern FbTexTbl lbl_802C2328;
extern u8 framesThisStep;
extern int *gPartfxInterface;
extern f32 lbl_803E4A00;
extern f32 lbl_803E4A04;
extern f32 lbl_803E4A08;
extern f32 lbl_803E4A0C;
extern int ObjModel_GetBaseVertexCoords(int mdl, int idx);

extern f32 expf(f32 x);
extern f32 sqrtf(f32 x);
extern f32 fn_80293E80(f32 x);
extern void Sfx_PlayFromObject(int obj, int id);
extern void Sfx_PlayFromObjectLimited(int obj, int id, int n);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXSetCurrentMtx(int id);
extern void GXLoadPosMtxImm(f32 *m, int id);
extern void GXBegin(int prim, int fmt, int n);
extern void PSMTXRotRad(f32 *m, int axis, f32 rad);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *out);
extern void PSMTXScale(f32 *m, f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32 *m, f32 x, f32 y, f32 z);
extern void PSMTXMultVecSR(f32 *m, f32 *in, f32 *out);
extern f32 *Camera_GetViewMatrix(void);
extern f32 *Camera_GetInverseViewRotationMatrix(void);
extern int fn_8000FA70(void);
extern int fn_8000FA90(void);
extern void fn_80073AAC(void *tex, u32 *a, u32 *b, int k);
extern void Obj_BuildWorldTransformMatrix(int obj, f32 *m, int p3);
extern void renderResetFn_8003fc60(void);
extern int textureLoadAsset(int id);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern int hitDetectFn_800658a4(int obj, int out, int p3, f32 x, f32 y, f32 z);
extern int objCreateLight(int a, int b);
extern void modelLightStruct_setLightKind(int h, int v);
extern void modelLightStruct_setPosition(int h, f32 x, f32 y, f32 z);
extern void modelLightStruct_setAffectsAabbLightSelection(int h, int v);
extern void modelLightStruct_setEnabled(int h, int n, f32 v);
extern void modelLightStruct_setDistanceAttenuation(int h, f32 a, f32 b);
extern void modelLightStruct_setDiffuseColor(int h, int r, int g, int b, int a);
extern void Obj_FreeObject(int obj);
extern void DCStoreRange(void *p, int n);
extern void *memcpy(void *dst, const void *src, unsigned long n);

void fn_801B3DE4(int obj, int b, f32 spd, f32 x, f32 y, f32 z);
void fn_801B40B8(u8 mode, u8 *out, f32 a, f32 b);

#pragma scheduling off
#pragma peephole off
void fn_801B3DE4(int obj, int b, f32 spd, f32 x, f32 y, f32 z)
{
    int p4c = *(int *)((char *)obj + 0x4c);
    int state = *(int *)((char *)obj + 0xb8);
    u8 idx;
    int off;
    int e;
    int p;
    idx = *(u8 *)((char *)state + 0xa58);
    *(u8 *)((char *)state + 0xa58) = idx + 1;
    off = idx * 0x30;
    *(f32 *)((char *)state + off) = x;
    e = state + off;
    *(f32 *)((char *)e + 0x4) = y;
    *(f32 *)((char *)e + 0x8) = z;
    *(f32 *)((char *)e + 0x18) = lbl_803E492C;
    *(f32 *)((char *)e + 0xc) = *(f32 *)((char *)state + 0x18);
    *(f32 *)((char *)e + 0x1c) = spd;
    *(u8 *)((char *)e + 0x2d) = b;
    *(int *)((char *)e + 0x10) = 0;
    *(int *)((char *)e + 0x14) = (int)(lbl_803E4930 * sqrtf(spd));
    {
        int v = *(int *)((char *)e + 0x14);
        if (v < 0) {
            v = 0;
        } else if (v > 0x3c) {
            v = 0x3c;
        }
        *(int *)((char *)e + 0x14) = v;
    }
    if (*(u8 *)((char *)e + 0x2d) < 1) {
        s8 c = *(s8 *)((char *)p4c + 0x19);
        if (c != 0) {
            if (c == 2) {
                Sfx_PlayFromObject(obj, 0x4bf);
            } else if (c == 3) {
                Sfx_PlayFromObject(obj, 0x4c2);
            } else {
                s8 m = *(s8 *)((char *)obj + 0xac);
                if (m < 0x3a) {
                    if (m == 0x2c) {
                        goto playLimited;
                    }
                } else if (m < 0x3f) {
                playLimited:
                    Sfx_PlayFromObjectLimited(obj, 0x4b8, 2);
                    goto done;
                }
                Sfx_PlayFromObject(obj, 0x203);
            done:;
            }
        }
    }
    *(s16 *)((char *)state + off + 0x28) = randomGetRange(0, 0xffff);
    *(s16 *)((char *)state + off + 0x2a) = randomGetRange(0xc8, 0x12c);
    if (randomGetRange(0, 1) != 0) {
        *(s16 *)((char *)state + off + 0x2a) = -*(s16 *)((char *)state + off + 0x2a);
    }
    *(u8 *)((char *)state + off + 0x2c) = randomGetRange(0, 3);
    {
        f32 sp = *(f32 *)((char *)e + 0x1c);
        f32 ev = expf((lbl_803E4934 * ((f32)(int)*(int *)((char *)e + 0x14) - (f32)(int)*(int *)((char *)e + 0x10))) / (f32)(int)*(int *)((char *)e + 0x14));
        f32 t = (sp - *(f32 *)((char *)e + 0x18)) * ev;
        *(f32 *)((char *)e + 0xc) = sp - t * lbl_803DDB70;
        ev = expf((lbl_803E493C * (f32)(int)*(int *)((char *)e + 0x10)) / (f32)(int)*(int *)((char *)e + 0x14));
        t = lbl_803E4938 * ev;
        p = state + off;
        *(s8 *)((char *)p + 0x2e) = lbl_803E4938 - t * lbl_803DDB6C;
        *(int *)((char *)p + 0x20) = (int)lbl_803E4940;
        *(int *)((char *)p + 0x24) = *(int *)((char *)p + 0x20);
        *(u8 *)((char *)p + 0x2f) = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_801B40B8(u8 mode, u8 *out, f32 a, f32 b)
{
    s16 c1;
    s16 c2;
    s16 c3;
    s16 v1;
    s16 v2;
    s16 v3;
    c1 = 0xff - (u8)(int)(lbl_803DDB64 * (lbl_803E4938 * expf((lbl_803E4950 * a) / b)));
    c2 = 0xff - (u8)(int)(lbl_803DDB60 * (lbl_803E4938 * expf((lbl_803E4954 * a) / b)));
    c3 = 0xff - (u8)(int)(lbl_803DDB5C * (lbl_803E4938 * expf(a / b)));
    if (c1 < 1) {
        v1 = 1;
    } else if (c1 > 0xff) {
        v1 = 0xff;
    } else {
        v1 = c1;
    }
    if (c2 < 1) {
        v2 = 1;
    } else if (c2 > 0xff) {
        v2 = 0xff;
    } else {
        v2 = c2;
    }
    if (c3 < 1) {
        v3 = 1;
    } else if (c3 > 0xff) {
        v3 = 0xff;
    } else {
        v3 = c3;
    }
    switch (mode) {
    case 0:
        out[0] = v1;
        out[1] = v2;
        out[2] = v3;
        break;
    case 1:
        out[0] = v1;
        out[1] = v3;
        out[2] = v3;
        break;
    case 2:
        out[0] = v3;
        out[1] = v1;
        out[2] = v3;
        break;
    case 3:
        out[0] = v3;
        out[1] = v3;
        out[2] = v1;
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void explosion_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u32 colB2;
    u32 colA2;
    u32 colB;
    u32 colA;
    f32 m1[12];
    f32 m2[12];
    f32 m3[12];
    f32 m4[12];
    f32 mE[12];
    int state;
    int model;
    int p;
    int i;
    colA = lbl_803E4928;
    colB = lbl_803E8468;
    state = *(int *)((char *)obj + 0xb8);
    model = Obj_GetActiveModel((int)obj);
    if (visible != 0) {
        GXClearVtxDesc();
        GXSetVtxDesc(9, 1);
        GXSetVtxDesc(0xd, 1);
        GXSetCurrentMtx(0);
        p = state;
        for (i = 0; i < *(u8 *)((char *)state + 0xa58); i++) {
            if (*(s8 *)((char *)p + 0x2f) != 0) {
                void **tex;
                int k;
                u32 cv;
                Obj_BuildWorldTransformMatrix(obj, mE, 0);
                PSMTXRotRad(m1, 0x7a, (f32)((lbl_803E4978 * (f64)(int)*(s16 *)((char *)p + 0x28)) / lbl_803E4980));
                PSMTXRotRad(m3, 0x78, (f32)((lbl_803E4978 * ((f64)(u32)(fn_8000FA70() & 0xffff) - 0.0)) / lbl_803E4980));
                PSMTXConcat(m3, m1, m3);
                PSMTXRotRad(m2, 0x79, (f32)((lbl_803E4978 * (f64)(int)(0x10000 - (fn_8000FA90() & 0xffff))) / lbl_803E4980));
                PSMTXConcat(m2, m3, m2);
                PSMTXScale(m4, *(f32 *)((char *)p + 0xc), *(f32 *)((char *)p + 0xc), *(f32 *)((char *)p + 0xc));
                PSMTXConcat(m4, m2, m4);
                PSMTXTrans(mE, *(f32 *)((char *)p + 0x0) - lbl_803DCDD8, *(f32 *)((char *)p + 0x4), *(f32 *)((char *)p + 0x8) - lbl_803DCDDC);
                PSMTXConcat(mE, m4, mE);
                PSMTXConcat(Camera_GetViewMatrix(), mE, mE);
                GXLoadPosMtxImm(mE, 0);
                colA = (colA & 0xffffff00) | *(u8 *)((char *)p + 0x2e);
                cv = (u32)(lbl_803DDB68 * (lbl_803E4938 * expf((lbl_803E4958 * ((f32)(int)*(int *)((char *)p + 0x14) - (f32)(int)*(int *)((char *)p + 0x10))) / (f32)(int)*(int *)((char *)p + 0x14))));
                colB = (cv & 0xff) | ((u8)cv << 8) | ((u8)cv << 16) | ((u8)cv << 24);
                fn_801B40B8(*(u8 *)((char *)state + 0xa5d), (u8 *)&colA, (f32)(int)*(int *)((char *)p + 0x10), (f32)(int)*(int *)((char *)p + 0x14));
                tex = (void **)((int *)lbl_803AC960)[*(u8 *)((char *)state + 0xa5d)];
                for (k = 0; k < *(u8 *)((char *)p + 0x2c); k++) {
                    tex = (void **)*tex;
                }
                colB2 = colB;
                colA2 = colA;
                fn_80073AAC(tex, &colA2, &colB2, k);
                GXBegin(0x80, 2, 4);
                GXWGFifo.f32 = lbl_803E4988;
                GXWGFifo.f32 = lbl_803E4988;
                GXWGFifo.f32 = lbl_803E4960;
                GXWGFifo.f32 = lbl_803E4960;
                GXWGFifo.f32 = lbl_803E4960;
                GXWGFifo.f32 = lbl_803E492C;
                GXWGFifo.f32 = lbl_803E4988;
                GXWGFifo.f32 = lbl_803E4960;
                GXWGFifo.f32 = lbl_803E492C;
                GXWGFifo.f32 = lbl_803E4960;
                GXWGFifo.f32 = lbl_803E492C;
                GXWGFifo.f32 = lbl_803E492C;
                GXWGFifo.f32 = lbl_803E4960;
                GXWGFifo.f32 = lbl_803E492C;
                GXWGFifo.f32 = lbl_803E492C;
                GXWGFifo.f32 = lbl_803E4988;
                GXWGFifo.f32 = lbl_803E492C;
                GXWGFifo.f32 = lbl_803E4960;
                GXWGFifo.f32 = lbl_803E4960;
                GXWGFifo.f32 = lbl_803E492C;
            }
            p += 0x30;
        }
        if (*(int *)((char *)state + 0xa4c) < *(int *)((char *)state + 0xa50) && *(s8 *)((char *)state + 0xa59) != 0) {
            p = state;
            for (i = 0; i < *(u8 *)((char *)state + 0xa59); i++) {
                *(s16 *)((char *)obj + 0x2) = *(s16 *)((char *)p + 0xa44);
                *(s16 *)((char *)obj + 0x0) = *(s16 *)((char *)p + 0xa46);
                objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (f32)visible);
                if (i < *(u8 *)((char *)state + 0xa59) - 1) {
                    *(u16 *)((char *)model + 0x18) &= ~8;
                }
                p += 4;
            }
        }
    }
    renderResetFn_8003fc60();
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void explosion_update(int obj)
{
    u8 fake[0x38];
    s16 ang[6];
    f32 vpos[3];
    f32 m[12];
    u8 rgb[3];
    int state = *(int *)((char *)obj + 0xb8);
    int i;
    int p;
    lbl_803DDB58 += 1;
    *(int *)((char *)state + 0xa4c) += framesThisStep;
    for (i = 0, p = state; i < *(u8 *)((char *)state + 0xa58); i++) {
        *(int *)((char *)p + 0x10) += framesThisStep;
        if (*(u8 *)((char *)p + 0x2f) != 0) {
            f32 sp = *(f32 *)((char *)p + 0x1c);
            f32 ev = expf((lbl_803E4934 * ((f32)(int)*(int *)((char *)p + 0x14) - (f32)(int)*(int *)((char *)p + 0x10))) / (f32)(int)*(int *)((char *)p + 0x14));
            f32 t = (sp - *(f32 *)((char *)p + 0x18)) * ev;
            *(f32 *)((char *)p + 0xc) = sp - t * lbl_803DDB70;
            ev = expf((lbl_803E493C * (f32)(int)*(int *)((char *)p + 0x10)) / (f32)(int)*(int *)((char *)p + 0x14));
            t = lbl_803E4938 * ev;
            *(s8 *)((char *)p + 0x2e) = lbl_803E4938 - t * lbl_803DDB6C;
            if (*(int *)((char *)p + 0x10) >= *(int *)((char *)p + 0x14)) {
                *(u8 *)((char *)p + 0x2f) = 0;
            } else {
                *(s16 *)((char *)p + 0x28) += framesThisStep * *(s16 *)((char *)p + 0x2a);
                if (*(u8 *)((char *)p + 0x2c) >= 4) {
                    *(u8 *)((char *)p + 0x2c) -= 4;
                }
                if (*(u8 *)((char *)p + 0x2d) < 5) {
                    if ((f32)(int)*(int *)((char *)p + 0x10) / (f32)(int)*(int *)((char *)p + 0x14) < lbl_803E4998 &&
                        (*(int *)((char *)p + 0x20) -= framesThisStep, *(int *)((char *)p + 0x20) <= 0)) {
                        u8 c = *(u8 *)((char *)p + 0x2d);
                        f32 sp2 = *(f32 *)((char *)p + 0x1c);
                        int st2 = *(int *)((char *)obj + 0xb8);
                        f32 sv;
                        vpos[0] = *(f32 *)((char *)p + 0xc) * (lbl_803E495C * (f32)(int)randomGetRange(-5, 3) + lbl_803E492C);
                        vpos[1] = lbl_803E4960;
                        vpos[2] = lbl_803E4960;
                        PSMTXRotRad(m, 0x7a, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0, 0xffff) / lbl_803E4970)));
                        PSMTXConcat(Camera_GetInverseViewRotationMatrix(), m, m);
                        PSMTXMultVecSR(m, vpos, vpos);
                        vpos[0] += *(f32 *)((char *)p + 0x0);
                        vpos[1] += *(f32 *)((char *)p + 0x4);
                        vpos[2] += *(f32 *)((char *)p + 0x8);
                        sv = sp2 * (f32)(int)randomGetRange(0xc0, 0x100);
                        if (*(u8 *)((char *)st2 + 0xa58) < 0x32) {
                            fn_801B3DE4(obj, (u8)(c + 1), sv * lbl_803E4974, vpos[0], vpos[1], vpos[2]);
                        }
                        *(int *)((char *)p + 0x20) = *(int *)((char *)p + 0x24);
                    }
                }
            }
        }
        p += 0x30;
    }
    memcpy(fake, (void *)obj, 0x38);
    *(f32 *)(fake + 0x8) = lbl_803E492C;
    *(f32 *)(fake + 0x24) = lbl_803E4960;
    *(f32 *)(fake + 0x28) = lbl_803E4960;
    *(f32 *)(fake + 0x2c) = lbl_803E4960;
    for (i = 0, p = state; i < *(u8 *)((char *)state + 0xa5a); i++) {
        if (*(u8 *)((char *)p + 0x984) != 0) {
            *(int *)((char *)p + 0x97c) += framesThisStep;
            if (*(int *)((char *)p + 0x97c) >= *(int *)((char *)p + 0x980)) {
                *(u8 *)((char *)p + 0x984) = 0;
            } else {
                f32 grav = *(f32 *)((char *)state + 0xa3c);
                u32 ft = framesThisStep;
                f32 n974 = -(grav * (f32)(u32)ft - *(f32 *)((char *)p + 0x974));
                *(f32 *)((char *)p + 0x968) = -(lbl_803E499C * (grav * (f32)(int)(ft * ft)) - (*(f32 *)((char *)p + 0x974) * (f32)(u32)ft + *(f32 *)((char *)p + 0x968)));
                *(f32 *)((char *)p + 0x974) = n974;
                *(f32 *)((char *)p + 0x964) += *(f32 *)((char *)p + 0x970) * (f32)(u32)framesThisStep;
                *(f32 *)((char *)p + 0x96c) += *(f32 *)((char *)p + 0x978) * (f32)(u32)framesThisStep;
                if (*(s8 *)((char *)state + 0xa5c) != 0 && *(f32 *)((char *)p + 0x968) < *(f32 *)((char *)state + 0x960) &&
                    *(f32 *)((char *)p + 0x974) < lbl_803E4960) {
                    *(f32 *)((char *)p + 0x974) = lbl_803E49A0 * -*(f32 *)((char *)p + 0x974);
                }
                *(f32 *)(fake + 0xc) = *(f32 *)((char *)p + 0x964);
                *(f32 *)(fake + 0x10) = *(f32 *)((char *)p + 0x968);
                *(f32 *)(fake + 0x14) = *(f32 *)((char *)p + 0x96c);
                *(f32 *)(fake + 0x18) = *(f32 *)(fake + 0xc);
                *(f32 *)(fake + 0x1c) = *(f32 *)(fake + 0x10);
                *(f32 *)(fake + 0x20) = *(f32 *)(fake + 0x14);
                if (lbl_803DDB58 & 1) {
                    int t = *(int *)((char *)p + 0x97c);
                    if (t < 0x40) {
                        ang[4] = t << 6;
                        ang[0] = -1 - ang[4];
                        ang[2] = -0x8000;
                        ang[3] = -0x4000 - ang[4];
                        ang[4] = -0x6000 - ang[4];
                        ang[1] = ang[0];
                    } else if (t < 0x80) {
                        ang[1] = t << 6;
                        ang[0] = -0x4000 - ang[1];
                        ang[1] = -0x6000 - ang[1];
                        ang[2] = 0;
                        ang[3] = -0x8000;
                        ang[4] = 0;
                    } else {
                        ang[0] = -0x6000;
                        ang[1] = 0;
                        ang[2] = 0;
                        ang[3] = 0;
                        ang[4] = 0;
                    }
                    {
                        s16 sv = ang[2];
                        u8 md;
                        ang[5] = 0;
                        md = *(u8 *)((char *)state + 0xa5d);
                        if (md == 2) {
                            ang[1] = ang[0];
                            ang[4] = ang[3];
                            ang[0] = ang[2];
                            ang[3] = 0;
                        } else if (md < 2) {
                            if (md != 0) {
                                ang[1] = ang[2];
                                ang[4] = 0;
                            }
                        } else if (md < 4) {
                            ang[1] = ang[2];
                            ang[4] = 0;
                            ang[2] = ang[0];
                            ang[5] = ang[3];
                            ang[0] = sv;
                            ang[3] = 0;
                        }
                    }
                    (*(void (*)(int, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x5e, fake, 0x200001, -1, ang);
                }
            }
        }
        p += 0x24;
    }
    {
        int e = *(int *)((char *)state + 0xa4c);
        int d = *(int *)((char *)state + 0xa50);
        if (d << 1 < e) {
            Obj_FreeObject(obj);
        } else {
            if (d < e) {
                if (*(int *)((char *)state + 0xa40) != 0) {
                    modelLightStruct_setEnabled(*(int *)((char *)state + 0xa40), 0, lbl_803E4960);
                }
            } else {
                fn_801B40B8(*(u8 *)((char *)state + 0xa5d), rgb, (f32)(int)e, (f32)(int)d);
                if (*(int *)((char *)state + 0xa40) != 0) {
                    modelLightStruct_setDiffuseColor(*(int *)((char *)state + 0xa40), rgb[0], rgb[1], rgb[2], 0xff);
                }
            }
            {
                f32 frac = (f32)(int)*(int *)((char *)state + 0xa4c) / (f32)(int)*(int *)((char *)state + 0xa50);
                *(f32 *)((char *)obj + 0x8) = lbl_803E49A4 * frac * *(f32 *)((char *)state + 0xa54);
                *(s8 *)((char *)obj + 0x36) = (s8)(int)-(lbl_803E4938 * frac - lbl_803E4938);
            }
            if (*(s8 *)((char *)state + 0xa5b) == 0 && (*(int *)((char *)state + 0xa50) >> 1) <= *(int *)((char *)state + 0xa4c)) {
                u32 k;
                ang[0] = randomGetRange(0x1000, 0x6000);
                ang[3] = *(s16 *)((char *)state + 0x14);
                k = 0;
                while ((f32)(int)k < *(f32 *)((char *)state + 0xa54)) {
                    k++;
                }
                *(u8 *)((char *)state + 0xa5b) = 1;
                ang[1] = ang[0];
                ang[2] = ang[0];
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void explosion_init(int obj, int p2)
{
    f32 vsp[3];
    f32 mA[12];
    f32 mB[12];
    int state = *(int *)((char *)obj + 0xb8);
    f32 scale;
    int p;
    int i;
    int n;
    *(u8 *)((char *)state + 0xa58) = 0;
    if (*(s16 *)((char *)p2 + 0x1a) == 0) {
        scale = lbl_803E49A8;
    } else {
        scale = (f32)(int)*(s16 *)((char *)p2 + 0x1a) * lbl_803E4974;
        if (scale > lbl_803E49A8) {
            scale = lbl_803E49A8;
        }
    }
    fn_801B3DE4(obj, 0, lbl_803E49AC * scale, *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10), *(f32 *)((char *)obj + 0x14));
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
    *(u8 *)((char *)state + 0xa5d) = *(s16 *)((char *)p2 + 0x1c) & 3;
    Obj_SetActiveModelIndex(obj, *(u8 *)((char *)state + 0xa5d));
    if (*(s16 *)((char *)p2 + 0x1c) & 4) {
        *(f32 *)((char *)state + 0xa3c) = lbl_803E49A4;
    } else {
        *(f32 *)((char *)state + 0xa3c) = lbl_803E4960;
    }
    *(u8 *)((char *)state + 0xa5c) = 0;
    if (hitDetectFn_800658a4(obj, state + 0x960, 0, *(f32 *)((char *)obj + 0xc), lbl_803E49B0 + *(f32 *)((char *)obj + 0x10), *(f32 *)((char *)obj + 0x14)) == 0) {
        if (*(f32 *)((char *)state + 0x960) < lbl_803E49B4) {
            *(u8 *)((char *)state + 0xa5c) = 1;
        }
        *(f32 *)((char *)state + 0x960) = *(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)state + 0x960);
    } else {
        *(f32 *)((char *)state + 0x960) = *(f32 *)((char *)obj + 0x10);
    }
    if (*(s16 *)((char *)p2 + 0x1c) & 0x10) {
        n = (int)((f32)(lbl_803E49B8 * scale) / lbl_803E49A8);
        p = state;
        for (i = 0; i < n; i++) {
            if (*(u8 *)((char *)state + 0xa5c) != 0) {
                vsp[0] = lbl_803E49BC * ((f32)(int)randomGetRange(0x14, 0x28) * lbl_803E49C0) + lbl_803E49BC;
                vsp[1] = lbl_803E4960;
                vsp[2] = lbl_803E4960;
                PSMTXRotRad(mB, 0x7a, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0x2000, 0x6000) / lbl_803E49C4)));
                PSMTXRotRad(mA, 0x79, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0, 0xffff) / lbl_803E4970)));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, vsp, vsp);
            } else {
                f32 mag = lbl_803E49BC * ((f32)(int)randomGetRange(0x14, 0x28) * lbl_803E49C0) + lbl_803E49BC;
                u8 idx = i % 4;
                vsp[0] = mag * lbl_80325528[idx * 3];
                vsp[1] = mag * lbl_80325528[idx * 3 + 1];
                vsp[2] = mag * lbl_80325528[idx * 3 + 2];
                PSMTXRotRad(mB, 0x7a, (f32)(lbl_803E4968 * (f64)(((f32)(int)randomGetRange(0, 0x8000) - lbl_803E49C8) / lbl_803E49C4)));
                PSMTXRotRad(mA, 0x78, (f32)(lbl_803E4968 * (f64)(((f32)(int)randomGetRange(0, 0x8000) - lbl_803E49C8) / lbl_803E49C4)));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, vsp, vsp);
            }
            *(int *)((char *)p + 0x964) = *(int *)((char *)obj + 0xc);
            *(int *)((char *)p + 0x968) = *(int *)((char *)obj + 0x10);
            *(int *)((char *)p + 0x96c) = *(int *)((char *)obj + 0x14);
            *(f32 *)((char *)p + 0x970) = vsp[0];
            *(f32 *)((char *)p + 0x974) = vsp[1];
            *(f32 *)((char *)p + 0x978) = vsp[2];
            *(int *)((char *)p + 0x97c) = 0;
            *(int *)((char *)p + 0x980) = randomGetRange(0x28, 0x32);
            *(u8 *)((char *)p + 0x984) = 1;
            p += 0x24;
        }
        *(u8 *)((char *)state + 0xa5a) = i;
    } else {
        *(u8 *)((char *)state + 0xa5a) = 0;
    }
    *(int *)((char *)state + 0xa40) = 0;
    if (*(s16 *)((char *)p2 + 0x1c) & 0x20) {
        *(int *)((char *)state + 0xa40) = objCreateLight(0, 1);
        if (*(int *)((char *)state + 0xa40) != 0) {
            modelLightStruct_setLightKind(*(int *)((char *)state + 0xa40), 2);
            modelLightStruct_setPosition(*(int *)((char *)state + 0xa40), *(f32 *)((char *)obj + 0x18), *(f32 *)((char *)obj + 0x1c), *(f32 *)((char *)obj + 0x20));
            modelLightStruct_setAffectsAabbLightSelection(*(int *)((char *)state + 0xa40), 1);
            modelLightStruct_setEnabled(*(int *)((char *)state + 0xa40), 1, lbl_803E4960);
            modelLightStruct_setDistanceAttenuation(*(int *)((char *)state + 0xa40), (f32)(lbl_803E49CC * scale), (f32)(lbl_803E4958 * scale));
            modelLightStruct_setDiffuseColor(*(int *)((char *)state + 0xa40), 0xff, 0xeb, 0xa0, 0xff);
        }
    }
    *(u8 *)((char *)obj + 0x36) = 0xff;
    if (*(s16 *)((char *)p2 + 0x1c) & 8) {
        if (*(u8 *)((char *)state + 0xa5c) == 0) {
        *(u8 *)((char *)state + 0xa59) = 2;
        *(s16 *)((char *)state + 0xa44) = randomGetRange(0, 0x4000);
        *(s16 *)((char *)state + 0xa46) = randomGetRange(0, 0x8000);
        *(s16 *)((char *)state + 0xa48) = *(s16 *)((char *)state + 0xa44) + 0x4000;
        *(s16 *)((char *)state + 0xa4a) = *(s16 *)((char *)state + 0xa46);
        } else {
            *(u8 *)((char *)state + 0xa59) = 1;
            *(s16 *)((char *)state + 0xa44) = 0;
            *(s16 *)((char *)state + 0xa46) = 0;
        }
    } else {
        *(u8 *)((char *)state + 0xa59) = 0;
    }
    *(u8 *)((char *)state + 0xa5b) = 0;
    *(int *)((char *)state + 0xa4c) = 0;
    *(int *)((char *)state + 0xa50) = (int)(lbl_803E4930 * sqrtf(scale));
    {
        int v = *(int *)((char *)state + 0xa50);
        if (v < 0) {
            v = 0;
        } else if (v > 0x3c) {
            v = 0x3c;
        }
        *(int *)((char *)state + 0xa50) = v;
    }
    *(f32 *)((char *)state + 0xa54) = scale;
    *(f32 *)((char *)obj + 0x8) = lbl_803E4960;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void explosion_initialise(void)
{
    FbTexTbl t;
    int i;
    int *src;
    int *dst;
    t = lbl_802C2328;
    lbl_803DDB70 = lbl_803E492C / expf(lbl_803E4934);
    lbl_803DDB6C = lbl_803E492C / expf(lbl_803E493C);
    lbl_803DDB68 = lbl_803E492C / expf(lbl_803E4958);
    lbl_803DDB64 = lbl_803E492C / expf(lbl_803E4950);
    lbl_803DDB60 = lbl_803E492C / expf(lbl_803E4954);
    lbl_803DDB5C = lbl_803E492C / expf(lbl_803E492C);
    for (i = 0, src = t.v, dst = lbl_803AC960; i < 4; i++) {
        *dst = textureLoadAsset(*src);
        src++;
        dst++;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dimmagicbridge_updateVertexWave(int obj, u8 *sub)
{
    int model = (int)Obj_GetActiveModel((int)obj);
    int mdl = *(int *)model;
    int i;
    int cnt;
    for (i = 0; cnt = *(u16 *)((char *)mdl + 0xe4), i < cnt; i++) {
        s16 *vc = (s16 *)ObjModel_GetCurrentVertexCoords(model, i);
        s16 *vb = (s16 *)ObjModel_GetBaseVertexCoords(mdl, i);
        int u = (u16)(int)(lbl_803E4A00 * ((f32)(int)vc[2] / *(f32 *)sub)) + *(u16 *)(sub + 0x60);
        if (*vb > 0) {
            *vc = lbl_803E4A04 * fn_80293E80((lbl_803E4A08 * (f32)(int)u) / lbl_803E4A0C) + (f32)(int)*vb;
        } else {
            *vc = -(lbl_803E4A04 * fn_80293E80((lbl_803E4A08 * (f32)(int)u) / lbl_803E4A0C) - (f32)(int)*vb);
        }
    }
    DCStoreRange((void *)ObjModel_GetCurrentVertexCoords(model, 0), cnt * 6);
    *(u8 *)((char *)obj + 0x36) = *(u8 *)(sub + 0x51);
}
#pragma peephole reset
#pragma scheduling reset
