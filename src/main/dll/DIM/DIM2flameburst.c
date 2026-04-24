#include "ghidra_import.h"
#include "main/dll/DIM/DIM2flameburst.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_8000b4f0();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000f560();
extern undefined4 FUN_8000f56c();
extern ushort FUN_8000fa90();
extern ushort FUN_8000fab0();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_8001dbb4();
extern undefined4 FUN_8001dbf0();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_8001dcfc();
extern undefined4 FUN_8001de04();
extern undefined4 FUN_8001de4c();
extern undefined4 FUN_8001f448();
extern void* FUN_8001f58c();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80022264();
extern undefined4 FUN_800284d8();
extern uint FUN_80028568();
extern undefined4 FUN_8002b554();
extern int FUN_8002b660();
extern undefined4 FUN_8002b95c();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8002fb40();
extern int FUN_80036f50();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_800395a4();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_8003fd58();
extern undefined4 FUN_80041110();
extern undefined4 FUN_80054484();
extern undefined4 FUN_80054ed0();
extern undefined4 FUN_800656f0();
extern int FUN_80065a20();
extern undefined4 FUN_80073c28();
extern undefined4 FUN_80242114();
extern undefined4 FUN_80247618();
extern undefined4 FUN_8024782c();
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
extern undefined4 FUN_80292538();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern int FUN_80296bb8();
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
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803de7dc;
extern f32 FLOAT_803de7e0;
extern f32 FLOAT_803de7e4;
extern f32 FLOAT_803de7e8;
extern f32 FLOAT_803de7ec;
extern f32 FLOAT_803de7f0;
extern f32 FLOAT_803e55a0;
extern f32 FLOAT_803e55a8;
extern f32 FLOAT_803e55c4;
extern f32 FLOAT_803e55c8;
extern f32 FLOAT_803e55cc;
extern f32 FLOAT_803e55d0;
extern f32 FLOAT_803e55d8;
extern f32 FLOAT_803e55f0;
extern f32 FLOAT_803e55f4;
extern f32 FLOAT_803e55f8;
extern f32 FLOAT_803e5608;
extern f32 FLOAT_803e560c;
extern f32 FLOAT_803e5620;
extern f32 FLOAT_803e5630;
extern f32 FLOAT_803e5634;
extern f32 FLOAT_803e5638;
extern f32 FLOAT_803e563c;
extern f32 FLOAT_803e5640;
extern f32 FLOAT_803e5644;
extern f32 FLOAT_803e5648;
extern f32 FLOAT_803e564c;
extern f32 FLOAT_803e5650;
extern f32 FLOAT_803e5654;
extern f32 FLOAT_803e5658;
extern f32 FLOAT_803e565c;
extern f32 FLOAT_803e5660;
extern f32 FLOAT_803e5664;
extern f32 FLOAT_803e566c;
extern f32 FLOAT_803e5670;
extern f32 FLOAT_803e5674;
extern f32 FLOAT_803e5678;
extern f32 FLOAT_803e567c;
extern f32 FLOAT_803e5684;
extern f32 FLOAT_803e5688;
extern f32 FLOAT_803e568c;
extern f32 FLOAT_803e5690;
extern f32 FLOAT_803e5694;
extern f32 FLOAT_803e569c;

/*
 * --INFO--
 *
 * Function: FUN_801b401c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B401C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b401c(undefined4 param_1,uint param_2)
{
  (**(code **)(*DAT_803dd6d4 + 0x48))((param_2 ^ 1) + 2,param_1,0xffffffff);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b4060
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B4060
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_801b4060(int param_1)
{
  bool bVar1;
  int iVar2;
  float *pfVar3;
  
  iVar2 = FUN_8002bac4();
  pfVar3 = *(float **)(param_1 + 0xb8);
  bVar1 = pfVar3[3] +
          pfVar3[2] * *(float *)(iVar2 + 0x14) +
          *pfVar3 * *(float *)(iVar2 + 0xc) + pfVar3[1] * *(float *)(iVar2 + 0x10) < FLOAT_803e55a0;
  (**(code **)(*DAT_803dd6d4 + 0x48))(bVar1,param_1,0xffffffff);
  return bVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_801b4114
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B4114
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b4114(int param_1)
{
  FUN_8003709c(param_1,0x13);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b4138
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B4138
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b4138(int param_1)
{
  char in_r8;
  
  if ((in_r8 == '\0') || (*(int *)(param_1 + 0xf8) != 0)) {
    if (*(int *)(param_1 + 0xf8) != 0) {
      FUN_80041110();
    }
  }
  else {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b418c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B418C
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b418c(int param_1)
{
  int iVar1;
  uint uVar2;
  float local_18 [4];
  
  local_18[0] = FLOAT_803e55a8;
  iVar1 = FUN_80036f50(10,param_1,local_18);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  uVar2 = FUN_80020078(0x3e3);
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
    FUN_80041110();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b4294
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B4294
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b4294(undefined2 *param_1,int param_2)
{
  float *pfVar1;
  double dVar2;
  
  FUN_800372f8((int)param_1,0x13);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar1 = *(float **)(param_1 + 0x5c);
  dVar2 = (double)FUN_802945e0();
  *pfVar1 = (float)dVar2;
  pfVar1[1] = FLOAT_803e55a0;
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
 * Function: FUN_801b4398
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B4398
 * EN v1.1 Size: 724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b4398(undefined8 param_1,double param_2,double param_3,double param_4)
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
  *(float *)(iVar8 + 0x18) = FLOAT_803e55c4;
  *(undefined4 *)(iVar8 + 0xc) = *(undefined4 *)(iVar6 + 0x18);
  *(float *)(iVar8 + 0x1c) = (float)extraout_f1;
  *(undefined *)(iVar8 + 0x2d) = extraout_r4;
  *(undefined4 *)(iVar8 + 0x10) = 0;
  dVar9 = FUN_80293900(extraout_f1);
  *(int *)(iVar8 + 0x14) = (int)((double)FLOAT_803e55c8 * dVar9);
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
    FUN_8000bb38(uVar4,0x4bf);
    goto LAB_801b44d4;
  }
  if (cVar2 == '\x03') {
    FUN_8000bb38(uVar4,0x4c2);
    goto LAB_801b44d4;
  }
  cVar2 = *(char *)(uVar4 + 0xac);
  if (cVar2 < ':') {
    if (cVar2 == ',') {
LAB_801b44b4:
      FUN_8000b4f0(uVar4,0x4b8,2);
      goto LAB_801b44d4;
    }
  }
  else if (cVar2 < '?') goto LAB_801b44b4;
  FUN_8000bb38(uVar4,0x203);
LAB_801b44d4:
  uVar4 = FUN_80022264(0,0xffff);
  *(short *)(iVar6 + iVar7 + 0x28) = (short)uVar4;
  uVar4 = FUN_80022264(200,300);
  iVar3 = iVar6 + iVar7;
  *(short *)(iVar3 + 0x2a) = (short)uVar4;
  uVar4 = FUN_80022264(0,1);
  if (uVar4 != 0) {
    *(short *)(iVar3 + 0x2a) = -*(short *)(iVar3 + 0x2a);
  }
  uVar4 = FUN_80022264(0,3);
  *(char *)(iVar6 + iVar7 + 0x2c) = (char)uVar4;
  dVar10 = (double)*(float *)(iVar8 + 0x1c);
  dVar9 = (double)FUN_80292538();
  *(float *)(iVar8 + 0xc) =
       -(float)((double)FLOAT_803de7f0 *
                (double)(float)((double)(float)(dVar10 - (double)*(float *)(iVar8 + 0x18)) * dVar9)
               - dVar10);
  dVar9 = (double)FUN_80292538();
  iVar6 = iVar6 + iVar7;
  *(char *)(iVar6 + 0x2e) =
       (char)(int)-(float)((double)FLOAT_803de7ec * (double)(float)((double)FLOAT_803e55d0 * dVar9)
                          - (double)FLOAT_803e55d0);
  *(int *)(iVar6 + 0x20) = (int)FLOAT_803e55d8;
  *(undefined4 *)(iVar6 + 0x24) = *(undefined4 *)(iVar6 + 0x20);
  *(undefined *)(iVar6 + 0x2f) = 1;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b466c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B466C
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b466c(byte param_1,undefined *param_2)
{
  undefined uVar1;
  undefined uVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  double dVar6;
  
  dVar6 = (double)FUN_80292538();
  sVar3 = 0xff - ((ushort)(int)(FLOAT_803de7e4 * (float)((double)FLOAT_803e55d0 * dVar6)) & 0xff);
  dVar6 = (double)FUN_80292538();
  sVar4 = 0xff - ((ushort)(int)(FLOAT_803de7e0 * (float)((double)FLOAT_803e55d0 * dVar6)) & 0xff);
  dVar6 = (double)FUN_80292538();
  sVar5 = 0xff - ((ushort)(int)(FLOAT_803de7dc * (float)((double)FLOAT_803e55d0 * dVar6)) & 0xff);
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
 * Function: FUN_801b48b4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B48B4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b48b4(int param_1)
{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 0xa40);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b48e4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B48E4
 * EN v1.1 Size: 1240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b48e4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b4dbc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B4DBC
 * EN v1.1 Size: 2124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b4dbc(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
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
      param_3 = (double)FLOAT_803e55cc;
      fStack_5c = -pfVar11[5];
      local_60 = 0x43300000;
      fStack_54 = -pfVar11[4];
      local_58 = 0x43300000;
      local_50 = 0x43300000;
      fStack_4c = fStack_5c;
      dVar12 = (double)FUN_80292538();
      pfVar11[3] = -(float)((double)FLOAT_803de7f0 *
                            (double)(float)((double)(float)(dVar13 - (double)pfVar11[6]) * dVar12) -
                           dVar13);
      local_48 = (double)CONCAT44(0x43300000,-pfVar11[4]);
      fStack_3c = -pfVar11[5];
      local_40 = 0x43300000;
      dVar12 = (double)FUN_80292538();
      param_2 = (double)FLOAT_803e55d0;
      iVar8 = (int)-(float)((double)FLOAT_803de7ec * (double)(float)(param_2 * dVar12) - param_2);
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
               (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e55e0) < FLOAT_803e5630)
             && (pfVar11[8] = (float)((int)pfVar11[8] - (uint)DAT_803dc070), (int)pfVar11[8] < 1)) {
            dVar12 = (double)pfVar11[7];
            iVar8 = *(int *)(uVar3 + 0xb8);
            uVar6 = FUN_80022264(0xfffffffb,3);
            local_38 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
            param_2 = (double)(float)(local_38 - DOUBLE_803e55e0);
            local_e4 = pfVar11[3] *
                       (float)((double)FLOAT_803e55f4 * param_2 + (double)FLOAT_803e55c4);
            local_e0 = FLOAT_803e55f8;
            local_dc = FLOAT_803e55f8;
            fStack_3c = (float)FUN_80022264(0,0xffff);
            fStack_3c = -fStack_3c;
            local_40 = 0x43300000;
            FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                        (double)((float)((double)CONCAT44(0x43300000,fStack_3c) -
                                                        DOUBLE_803e55e0) / FLOAT_803e5608)),
                         afStack_cc,0x7a);
            pfVar4 = (float *)FUN_8000f560();
            FUN_80247618(pfVar4,afStack_cc,afStack_cc);
            FUN_80247cd8(afStack_cc,&local_e4,&local_e4);
            local_e4 = local_e4 + *pfVar11;
            local_e0 = local_e0 + pfVar11[1];
            local_dc = local_dc + pfVar11[2];
            uVar6 = FUN_80022264(0xc0,0x100);
            local_48 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
            if (*(byte *)(iVar8 + 0xa58) < 0x32) {
              param_2 = (double)local_e4;
              param_3 = (double)local_e0;
              param_4 = (double)local_dc;
              FUN_801b4398((double)((float)(dVar12 * (double)(float)(local_48 - DOUBLE_803e55e0)) *
                                   FLOAT_803e560c),param_2,param_3,param_4);
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
  local_94 = FLOAT_803e55c4;
  local_78 = FLOAT_803e55f8;
  local_74 = FLOAT_803e55f8;
  local_70 = FLOAT_803e55f8;
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
        param_3 = (double)FLOAT_803e5634;
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
           (pfVar11[0x25d] < FLOAT_803e55f8)) {
          pfVar11[0x25d] = FLOAT_803e5638 * -pfVar11[0x25d];
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
    FUN_8002cc9c(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3);
  }
  else {
    if ((int)fVar7 < (int)fVar5) {
      if (pfVar9[0x290] != 0.0) {
        FUN_8001dc30((double)FLOAT_803e55f8,(int)pfVar9[0x290],'\0');
      }
    }
    else {
      local_38 = (double)CONCAT44(0x43300000,-fVar5);
      fStack_3c = -fVar7;
      local_40 = 0x43300000;
      FUN_801b466c(*(byte *)((int)pfVar9 + 0xa5d),&local_e8);
      if (pfVar9[0x290] != 0.0) {
        FUN_8001dbb4((int)pfVar9[0x290],local_e8,local_e7,local_e6,0xff);
      }
    }
    local_38 = (double)CONCAT44(0x43300000,-pfVar9[0x293]);
    fStack_3c = -pfVar9[0x294];
    local_40 = 0x43300000;
    fVar5 = (float)(local_38 - DOUBLE_803e55e0) /
            (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e55e0);
    *(float *)(uVar3 + 8) = FLOAT_803e563c * fVar5 * pfVar9[0x295];
    iVar10 = (int)-(FLOAT_803e55d0 * fVar5 - FLOAT_803e55d0);
    local_48 = (double)(longlong)iVar10;
    *(char *)(uVar3 + 0x36) = (char)iVar10;
    if ((*(char *)((int)pfVar9 + 0xa5b) == '\0') && ((int)pfVar9[0x294] >> 1 <= (int)pfVar9[0x293]))
    {
      uVar3 = FUN_80022264(0x1000,0x6000);
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
 * Function: FUN_801b5608
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B5608
 * EN v1.1 Size: 1532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5608(void)
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
    dVar11 = (double)FLOAT_803e5640;
  }
  else {
    local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 0x1a) ^ 0x80000000);
    dVar11 = (double)((float)(local_48 - DOUBLE_803e55e0) * FLOAT_803e560c);
    if ((double)FLOAT_803e5640 < dVar11) {
      dVar11 = (double)FLOAT_803e5640;
    }
  }
  FUN_801b4398((double)(float)((double)FLOAT_803e5644 * dVar11),(double)*(float *)(iVar3 + 0xc),
               (double)*(float *)(iVar3 + 0x10),(double)*(float *)(iVar3 + 0x14));
  *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x2000;
  *(byte *)(iVar8 + 0xa5d) = (byte)*(undefined2 *)(iVar2 + 0x1c) & 3;
  FUN_8002b95c(iVar3,(uint)*(byte *)(iVar8 + 0xa5d));
  if ((*(ushort *)(iVar2 + 0x1c) & 4) == 0) {
    *(float *)(iVar8 + 0xa3c) = FLOAT_803e55f8;
  }
  else {
    *(float *)(iVar8 + 0xa3c) = FLOAT_803e563c;
  }
  *(undefined *)(iVar8 + 0xa5c) = 0;
  iVar4 = FUN_80065a20((double)*(float *)(iVar3 + 0xc),
                       (double)(FLOAT_803e5648 + *(float *)(iVar3 + 0x10)),
                       (double)*(float *)(iVar3 + 0x14),iVar3,(float *)(iVar8 + 0x960),0);
  if (iVar4 == 0) {
    if (*(float *)(iVar8 + 0x960) < FLOAT_803e564c) {
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
    iVar4 = (int)((float)((double)FLOAT_803e5650 * dVar11) / FLOAT_803e5640);
    local_48 = (double)(longlong)iVar4;
    iVar9 = iVar8;
    for (iVar7 = 0; iVar7 < iVar4; iVar7 = iVar7 + 1) {
      if (*(char *)(iVar8 + 0xa5c) == '\0') {
        uVar6 = FUN_80022264(0x14,0x28);
        local_38 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_b0 = FLOAT_803e5654 * FLOAT_803e5658 * (float)(local_38 - DOUBLE_803e55e0) +
                   FLOAT_803e5654;
        iVar1 = iVar7 >> 0x1f;
        uVar6 = (iVar1 * 4 | (uint)(iVar7 * 0x40000000 + iVar1) >> 0x1e) - iVar1 & 0xff;
        local_b8 = local_b0 * (float)(&DAT_80326168)[uVar6 * 3];
        local_b4 = local_b0 * (float)(&DAT_8032616c)[uVar6 * 3];
        local_b0 = local_b0 * (float)(&DAT_80326170)[uVar6 * 3];
        uStack_3c = FUN_80022264(0,0x8000);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                    (double)(((float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                     DOUBLE_803e55e0) - FLOAT_803e5660) /
                                            FLOAT_803e565c)),afStack_7c,0x7a);
        uVar6 = FUN_80022264(0,0x8000);
        local_48 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                    (double)(((float)(local_48 - DOUBLE_803e55e0) - FLOAT_803e5660)
                                            / FLOAT_803e565c)),afStack_ac,0x78);
        FUN_80247618(afStack_ac,afStack_7c,afStack_7c);
        FUN_80247cd8(afStack_7c,&local_b8,&local_b8);
      }
      else {
        uVar6 = FUN_80022264(0x14,0x28);
        local_48 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_b8 = FLOAT_803e5654 * FLOAT_803e5658 * (float)(local_48 - DOUBLE_803e55e0) +
                   FLOAT_803e5654;
        local_b4 = FLOAT_803e55f8;
        local_b0 = FLOAT_803e55f8;
        uStack_3c = FUN_80022264(0x2000,0x6000);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                    (double)((float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                    DOUBLE_803e55e0) / FLOAT_803e565c)),afStack_7c,
                     0x7a);
        uVar6 = FUN_80022264(0,0xffff);
        local_38 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                    (double)((float)(local_38 - DOUBLE_803e55e0) / FLOAT_803e5608)),
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
      uVar6 = FUN_80022264(0x28,0x32);
      *(uint *)(iVar9 + 0x980) = uVar6;
      *(undefined *)(iVar9 + 0x984) = 1;
      iVar9 = iVar9 + 0x24;
    }
    *(char *)(iVar8 + 0xa5a) = (char)iVar7;
  }
  *(undefined4 *)(iVar8 + 0xa40) = 0;
  if ((*(ushort *)(iVar2 + 0x1c) & 0x20) != 0) {
    piVar5 = FUN_8001f58c(0,'\x01');
    *(int **)(iVar8 + 0xa40) = piVar5;
    if (*(int *)(iVar8 + 0xa40) != 0) {
      FUN_8001dbf0(*(int *)(iVar8 + 0xa40),2);
      FUN_8001de4c((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                   (double)*(float *)(iVar3 + 0x20),*(int **)(iVar8 + 0xa40));
      FUN_8001de04(*(int *)(iVar8 + 0xa40),1);
      FUN_8001dc30((double)FLOAT_803e55f8,*(int *)(iVar8 + 0xa40),'\x01');
      FUN_8001dcfc((double)(float)((double)FLOAT_803e5664 * dVar11),
                   (double)(float)((double)FLOAT_803e55f0 * dVar11),*(int *)(iVar8 + 0xa40));
      FUN_8001dbb4(*(int *)(iVar8 + 0xa40),0xff,0xeb,0xa0,0xff);
    }
  }
  *(undefined *)(iVar3 + 0x36) = 0xff;
  if ((*(ushort *)(iVar2 + 0x1c) & 8) == 0) {
    *(undefined *)(iVar8 + 0xa59) = 0;
  }
  else if (*(char *)(iVar8 + 0xa5c) == '\0') {
    *(undefined *)(iVar8 + 0xa59) = 2;
    uVar6 = FUN_80022264(0,0x4000);
    *(short *)(iVar8 + 0xa44) = (short)uVar6;
    uVar6 = FUN_80022264(0,0x8000);
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
  local_38 = (double)(longlong)(int)((double)FLOAT_803e55c8 * dVar10);
  *(int *)(iVar8 + 0xa50) = (int)((double)FLOAT_803e55c8 * dVar10);
  iVar2 = *(int *)(iVar8 + 0xa50);
  if (iVar2 < 0) {
    iVar2 = 0;
  }
  else if (0x3c < iVar2) {
    iVar2 = 0x3c;
  }
  *(int *)(iVar8 + 0xa50) = iVar2;
  *(float *)(iVar8 + 0xa54) = (float)dVar11;
  *(float *)(iVar3 + 8) = FLOAT_803e55f8;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5c04
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B5C04
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5c04(void)
{
  int iVar1;
  int *piVar2;
  
  iVar1 = 0;
  piVar2 = &DAT_803ad5c0;
  do {
    if (*piVar2 != 0) {
      FUN_80054484();
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
 * Function: FUN_801b5c6c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B5C6C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5c6c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b5d84
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B5D84
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5d84(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5db8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B5DB8
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5db8(uint param_1)
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
  FUN_8002fb40((double)*(float *)(pcVar6 + 4),(double)FLOAT_803dc074);
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + *(float *)(pcVar6 + 8);
  fVar2 = FLOAT_803e566c;
  if (*(float *)(pcVar6 + 8) != FLOAT_803e566c) {
    *(float *)(pcVar6 + 8) = *(float *)(pcVar6 + 8) * FLOAT_803e5670;
    if (*(float *)(pcVar6 + 8) < fVar2) {
      fVar2 = *(float *)(pcVar6 + 8);
    }
    *(float *)(pcVar6 + 8) = fVar2;
  }
  if ((('\0' < *pcVar6) || (*psVar7 != 0x338)) || (*(float *)(param_1 + 0x98) <= FLOAT_803e5674)) {
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
      *(float *)(pcVar6 + 4) = FLOAT_803e5678;
      *(float *)(pcVar6 + 8) = FLOAT_803e567c;
      *pcVar6 = '\0';
      FUN_800201ac((int)psVar7[0xf],1);
      FUN_8000bb38(param_1,0x3e1);
    }
  }
  else {
    iVar4 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -0x10;
    if (iVar4 < 0) {
      iVar4 = 0;
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(char *)(param_1 + 0x36) = (char)iVar4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5f38
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B5F38
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5f38(undefined2 *param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  undefined *puVar3;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  puVar3 = *(undefined **)(param_1 + 0x5c);
  *puVar3 = 3;
  fVar1 = FLOAT_803e566c;
  *(float *)(puVar3 + 4) = FLOAT_803e566c;
  *(float *)(puVar3 + 8) = fVar1;
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar2 != 0) {
    *puVar3 = 0;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5fec
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B5FEC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5fec(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b6020
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B6020
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b6020(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b6054
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B6054
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b6054(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe, *(char *)(pfVar8 + 2) == '\x01')
       ) {
      param_2 = (double)pfVar8[1];
      *pfVar8 = (float)(param_2 * (double)FLOAT_803dc074 + (double)*pfVar8);
      if (*pfVar8 <= FLOAT_803e5684) {
        if (*pfVar8 < FLOAT_803e568c) {
          *pfVar8 = FLOAT_803e568c;
          pfVar8[1] = FLOAT_803e5690;
        }
      }
      else {
        *pfVar8 = FLOAT_803e5684;
        pfVar8[1] = FLOAT_803e5688;
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
        FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
        *(undefined *)(pfVar8 + 2) = 1;
        uVar5 = FUN_80020078(0x46d);
        if (((int)*(short *)(iVar9 + 0x1a) == uVar5) &&
           (uVar5 = FUN_8002e144(), (uVar5 & 0xff) != 0)) {
          puVar6 = FUN_8002becc(0x30,0x246);
          *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(iVar9 + 8);
          dVar10 = (double)FLOAT_803e5694;
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
          FUN_8002e088(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,
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
 * Function: FUN_801b625c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B625C
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b625c(undefined2 *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x2000;
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 9) = 1;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    *(undefined *)(iVar2 + 9) = 0;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  *(float *)(iVar2 + 4) = FLOAT_803e5688;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b62fc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B62FC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b62fc(void)
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
  piVar2 = (int *)FUN_8002b660(iVar1);
  iVar6 = *piVar2;
  for (iVar7 = 0; uVar8 = (uint)*(ushort *)(iVar6 + 0xe4), iVar7 < (int)uVar8; iVar7 = iVar7 + 1) {
    puVar3 = (undefined2 *)FUN_80028568((int)piVar2,iVar7);
    psVar4 = (short *)FUN_800284d8(iVar6,iVar7);
    if (*psVar4 < 1) {
      dVar9 = (double)FUN_802945e0();
      local_50 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)-(float)((double)FLOAT_803e569c * dVar9 -
                                    (double)(float)(local_50 - DOUBLE_803e56a8));
    }
    else {
      dVar9 = (double)FUN_802945e0();
      local_58 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)((double)FLOAT_803e569c * dVar9 +
                            (double)(float)(local_58 - DOUBLE_803e56a8));
    }
  }
  uVar5 = FUN_80028568((int)piVar2,0);
  FUN_80242114(uVar5,uVar8 * 6);
  *(undefined *)(iVar1 + 0x36) = *(undefined *)((int)uVar10 + 0x51);
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b64d0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B64D0
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b64d0(int param_1,int param_2)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_800395a4(param_1,0);
  *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + 0x14;
  if (10000 < *(short *)(iVar1 + 10)) {
    *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + -10000;
  }
  *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + 10;
  if (10000 < *(short *)(iVar1 + 8)) {
    *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + -10000;
  }
  iVar1 = FUN_800395a4(param_1,1);
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
 * Function: FUN_801b65e0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B65E0
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801b65e0(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
  FUN_801b64d0(param_1,iVar4);
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
  FUN_801b62fc();
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801b672c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B672C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b672c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b6760
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B6760
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b6760(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar1 = FUN_8002bac4();
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_801b64d0(param_1,iVar3);
  FUN_801b62fc();
  if (*(char *)(iVar3 + 0x5f) == '\0') {
    uVar2 = FUN_80020078(0x1ef);
    if ((uVar2 != 0) && (iVar1 = FUN_80296bb8(iVar1), iVar1 != 0)) {
      FUN_800201ac(0x1e8,1);
    }
  }
  else {
    FUN_800656f0(0x11,0,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b6808
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801B6808
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b6808(void)
{
}
