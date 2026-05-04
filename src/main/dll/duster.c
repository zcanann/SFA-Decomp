#include "ghidra_import.h"
#include "main/dll/duster.h"

extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern int FUN_80017730();
extern uint FUN_80017760();
extern undefined4 FUN_80017a88();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern char FUN_800620e8();
extern double FUN_8014d2a4();
extern undefined4 FUN_8014d164();
extern undefined4 FUN_8014d4c8();
extern undefined4 FUN_8015506c();
extern int FUN_8016a534();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f90();
extern undefined4 FUN_80247fb0();
extern undefined4 FUN_80293474();
extern double FUN_80293900();
extern uint FUN_80294c18();

extern undefined4 DAT_8031ff48;
extern undefined4 DAT_8031ff68;
extern undefined4 DAT_8031ff70;
extern undefined4 DAT_803dc940;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e36a8;
extern f64 DOUBLE_803e36b0;
extern f64 DOUBLE_803e3700;
extern f64 DOUBLE_803e3738;
extern f32 lbl_803DC074;
extern f32 lbl_803E3698;
extern f32 lbl_803E369C;
extern f32 lbl_803E36A0;
extern f32 lbl_803E36B8;
extern f32 lbl_803E36BC;
extern f32 lbl_803E36C0;
extern f32 lbl_803E36C4;
extern f32 lbl_803E36C8;
extern f32 lbl_803E36CC;
extern f32 lbl_803E36D0;
extern f32 lbl_803E36D4;
extern f32 lbl_803E36D8;
extern f32 lbl_803E36E0;
extern f32 lbl_803E36E4;
extern f32 lbl_803E36E8;
extern f32 lbl_803E36EC;
extern f32 lbl_803E36F0;
extern f32 lbl_803E36F4;
extern f32 lbl_803E36F8;
extern f32 lbl_803E3708;
extern f32 lbl_803E370C;
extern f32 lbl_803E3710;
extern f32 lbl_803E3714;
extern f32 lbl_803E3718;
extern f32 lbl_803E371C;
extern f32 lbl_803E3720;
extern f32 lbl_803E3724;
extern f32 lbl_803E3728;
extern f32 lbl_803E3730;
extern f32 lbl_803E3740;
extern f32 lbl_803E3744;
extern f32 lbl_803E3748;
extern f32 lbl_803E374C;
extern f32 lbl_803E3750;
extern f32 lbl_803E3754;
extern f32 lbl_803E3758;
extern f32 lbl_803E375C;
extern f32 lbl_803E3760;
extern f32 lbl_803E3764;
extern f32 lbl_803E3768;
extern f32 lbl_803E376C;
extern f32 lbl_803E3770;
extern f32 lbl_803E3774;
extern f32 lbl_803E3778;
extern f32 lbl_803E377C;
extern f32 lbl_803E3780;
extern f32 lbl_803E3784;
extern f32 lbl_803E3788;
extern f32 lbl_803E378C;
extern f32 lbl_803E3790;
extern f32 lbl_803E3794;
extern f32 lbl_803E3798;
extern f32 lbl_803E379C;

/*
 * --INFO--
 *
 * Function: FUN_8015536c
 * EN v1.0 Address: 0x8015536C
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x80155460
 * EN v1.1 Size: 952b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8015536c(double param_1,short *param_2,int param_3,uint param_4)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  float local_108;
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0 [2];
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float afStack_d8 [3];
  float local_cc [2];
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float afStack_b4 [3];
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float afStack_90 [4];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  
  local_c0 = *(float *)(param_3 + 0x360);
  local_bc = *(float *)(param_3 + 0x358);
  local_b8 = *(float *)(param_3 + 0x364);
  FUN_80247eb8(&local_c0,(float *)(param_2 + 6),afStack_b4);
  dVar4 = FUN_80247f90(afStack_b4,(float *)(param_3 + 0x344));
  local_c0 = (float)((double)*(float *)(param_3 + 0x344) * dVar4 + (double)*(float *)(param_2 + 6));
  dVar8 = (double)*(float *)(param_2 + 8);
  local_bc = (float)((double)*(float *)(param_3 + 0x348) * dVar4 + dVar8);
  local_b8 = (float)((double)*(float *)(param_3 + 0x34c) * dVar4 + (double)*(float *)(param_2 + 10))
  ;
  local_fc = lbl_803E3698;
  local_f8 = lbl_803E369C;
  local_f4 = lbl_803E3698;
  FUN_80247fb0(&local_fc,(float *)(param_3 + 0x344),local_cc);
  FUN_80247ef8(local_cc,local_cc);
  if (lbl_803E3698 == local_cc[0]) {
    local_cc[0] = (*(float *)(param_2 + 10) - *(float *)(param_3 + 0x364)) / local_c4;
  }
  else {
    local_cc[0] = (*(float *)(param_2 + 6) - *(float *)(param_3 + 0x360)) / local_cc[0];
  }
  dVar6 = (double)local_cc[0];
  iVar2 = *(int *)(param_3 + 0x29c);
  local_a8 = *(float *)(iVar2 + 0xc);
  local_a4 = lbl_803E36A0 + *(float *)(iVar2 + 0x10);
  local_a0 = *(float *)(iVar2 + 0x14);
  local_e4 = *(float *)(param_3 + 0x360);
  local_e0 = *(float *)(param_3 + 0x358);
  local_dc = *(float *)(param_3 + 0x364);
  FUN_80247eb8(&local_e4,&local_a8,afStack_d8);
  dVar4 = FUN_80247f90(afStack_d8,(float *)(param_3 + 0x344));
  local_e4 = (float)((double)*(float *)(param_3 + 0x344) * dVar4 + (double)local_a8);
  dVar7 = (double)local_a4;
  local_e0 = (float)((double)*(float *)(param_3 + 0x348) * dVar4 + dVar7);
  local_dc = (float)((double)*(float *)(param_3 + 0x34c) * dVar4 + (double)local_a0);
  local_108 = lbl_803E3698;
  local_104 = lbl_803E369C;
  local_100 = lbl_803E3698;
  FUN_80247fb0(&local_108,(float *)(param_3 + 0x344),local_f0);
  FUN_80247ef8(local_f0,local_f0);
  if (lbl_803E3698 == local_f0[0]) {
    local_f0[0] = (local_a0 - *(float *)(param_3 + 0x364)) / local_e8;
  }
  else {
    local_f0[0] = (local_a8 - *(float *)(param_3 + 0x360)) / local_f0[0];
  }
  dVar4 = (double)(float)(dVar6 - (double)local_f0[0]);
  dVar7 = (double)(float)(dVar8 - dVar7);
  uVar3 = FUN_80017730();
  uStack_74 = (uVar3 & 0xffff) - (uint)(ushort)param_2[1];
  if (0x8000 < (int)uStack_74) {
    uStack_74 = uStack_74 - 0xffff;
  }
  if ((int)uStack_74 < -0x8000) {
    uStack_74 = uStack_74 + 0xffff;
  }
  uStack_7c = param_4 & 0xffff;
  local_80 = 0x43300000;
  fVar1 = lbl_803DC074 / (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e36a8);
  if (lbl_803E369C < fVar1) {
    fVar1 = lbl_803E369C;
  }
  uStack_74 = uStack_74 ^ 0x80000000;
  local_78 = 0x43300000;
  uVar3 = (uint)((float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e36b0) * fVar1);
  local_70 = (longlong)(int)uVar3;
  *param_2 = param_2[1] + (short)uVar3;
  param_2[2] = 0x4000;
  param_2[1] = *param_2;
  iVar2 = FUN_80017730();
  *param_2 = (short)iVar2;
  dVar5 = FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar7 * dVar7)));
  if (param_1 < dVar5) {
    dVar4 = (double)(float)(param_1 *
                           (double)(float)(dVar4 * (double)(float)((double)lbl_803E369C / dVar5)))
    ;
    dVar7 = (double)(float)(param_1 *
                           (double)(float)(dVar7 * (double)(float)((double)lbl_803E369C / dVar5)))
    ;
  }
  FUN_801556d4((double)(float)(dVar6 - dVar4),(double)(float)(dVar8 - dVar7),afStack_90,
               (float *)(param_3 + 0x344));
  FUN_80247eb8(afStack_90,(float *)(param_2 + 6),&local_9c);
  FUN_80017a88((double)local_9c,(double)local_98,(double)local_94,(int)param_2);
  fVar1 = lbl_803E3698;
  *(float *)(param_2 + 0x12) = lbl_803E3698;
  *(float *)(param_2 + 0x14) = fVar1;
  *(float *)(param_2 + 0x16) = fVar1;
  if ((int)uVar3 < 0) {
    uVar3 = -uVar3;
  }
  return uVar3 & 0xffff;
}

/*
 * --INFO--
 *
 * Function: FUN_801556d4
 * EN v1.0 Address: 0x801556D4
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80155818
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801556d4(double param_1,double param_2,float *param_3,float *param_4)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  float local_24;
  
  dVar2 = (double)(param_4[6] - lbl_803E36B8);
  if ((param_2 <= dVar2) && (dVar2 = param_2, param_2 < (double)(lbl_803E36BC + param_4[5]))) {
    dVar2 = (double)(lbl_803E36BC + param_4[5]);
  }
  dVar4 = (double)param_4[4];
  if (dVar4 <= (double)lbl_803E3698) {
    dVar3 = (double)(float)((double)lbl_803E36B8 + dVar4);
    fVar1 = lbl_803E36C0;
  }
  else {
    dVar3 = (double)lbl_803E36B8;
    fVar1 = (float)(dVar4 - dVar3);
  }
  dVar4 = (double)fVar1;
  if ((param_1 <= dVar4) && (dVar4 = param_1, param_1 < dVar3)) {
    dVar4 = dVar3;
  }
  param_3[1] = (float)dVar2;
  local_38 = lbl_803E3698;
  local_34 = lbl_803E369C;
  local_30 = lbl_803E3698;
  FUN_80247fb0(&local_38,param_4,local_2c);
  FUN_80247ef8(local_2c,local_2c);
  *param_3 = (float)(dVar4 * (double)local_2c[0] + (double)param_4[7]);
  param_3[2] = (float)(dVar4 * (double)local_24 + (double)param_4[8]);
  fVar1 = lbl_803E36C4;
  *param_3 = lbl_803E36C4 * *param_4 + *param_3;
  param_3[1] = fVar1 * param_4[1] + param_3[1];
  param_3[2] = fVar1 * param_4[2] + param_3[2];
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80155830
 * EN v1.0 Address: 0x80155830
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x80155960
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80155830(int *param_1,int param_2)
{
  float fVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4 [2];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float afStack_ac [3];
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float afStack_88 [3];
  float local_7c;
  int local_78;
  float local_74;
  float local_70;
  int local_6c;
  float local_68;
  int iStack_64;
  undefined4 local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  float local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  float local_28;
  float local_24;
  float local_20;
  
  cVar3 = '\0';
  pfVar5 = (float *)&DAT_8031ff48;
  for (iVar4 = 0; (fVar2 = lbl_803E36BC, fVar1 = lbl_803E36B8, cVar3 == '\0' && (iVar4 < 4));
      iVar4 = iVar4 + 1) {
    local_70 = (float)param_1[3] + *pfVar5;
    local_78 = param_1[4];
    local_68 = (float)param_1[5] + pfVar5[1];
    local_7c = (float)param_1[3] - *pfVar5;
    local_74 = (float)param_1[5] - pfVar5[1];
    local_6c = local_78;
    cVar3 = FUN_800620e8(&local_70,&local_7c,(float *)0x3,&iStack_64,param_1,5,3,0xff,0);
    pfVar5 = pfVar5 + 2;
  }
  if (cVar3 != '\0') {
    param_1[3] = (int)((local_20 - lbl_803E36B8) * ((local_7c - local_70) / lbl_803E36BC) +
                      local_70);
    param_1[5] = (int)((local_20 - fVar1) * ((local_74 - local_68) / fVar2) + local_68);
    *(undefined4 *)(param_2 + 0x344) = local_48;
    *(undefined4 *)(param_2 + 0x348) = local_44;
    *(undefined4 *)(param_2 + 0x34c) = local_40;
    *(undefined4 *)(param_2 + 0x350) = local_3c;
    if (local_54 < local_58) {
      local_54 = local_58;
    }
    *(float *)(param_2 + 0x358) = local_54;
    if (local_28 < local_24) {
      local_24 = local_28;
    }
    *(float *)(param_2 + 0x35c) = local_24;
    local_a0 = lbl_803E3698;
    local_9c = lbl_803E369C;
    local_98 = lbl_803E3698;
    FUN_80247fb0(&local_a0,(float *)(param_2 + 0x344),afStack_88);
    FUN_80247ef8(afStack_88,afStack_88);
    *(undefined4 *)(param_2 + 0x360) = local_60;
    *(undefined4 *)(param_2 + 0x364) = local_50;
    local_94 = local_5c;
    local_8c = local_4c;
    local_b8 = *(float *)(param_2 + 0x360);
    local_b4 = *(float *)(param_2 + 0x358);
    local_b0 = *(float *)(param_2 + 0x364);
    FUN_80247eb8(&local_b8,&local_94,afStack_ac);
    dVar6 = FUN_80247f90(afStack_ac,(float *)(param_2 + 0x344));
    local_b8 = (float)((double)*(float *)(param_2 + 0x344) * dVar6 + (double)local_94);
    local_b4 = (float)((double)*(float *)(param_2 + 0x348) * dVar6 + (double)local_90);
    local_b0 = (float)((double)*(float *)(param_2 + 0x34c) * dVar6 + (double)local_8c);
    local_d0 = lbl_803E3698;
    local_cc = lbl_803E369C;
    local_c8 = lbl_803E3698;
    FUN_80247fb0(&local_d0,(float *)(param_2 + 0x344),local_c4);
    FUN_80247ef8(local_c4,local_c4);
    if (lbl_803E3698 == local_c4[0]) {
      *(float *)(param_2 + 0x354) = (local_8c - *(float *)(param_2 + 0x364)) / local_bc;
    }
    else {
      *(float *)(param_2 + 0x354) = (local_94 - *(float *)(param_2 + 0x360)) / local_c4[0];
    }
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80155b08
 * EN v1.0 Address: 0x80155B08
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80155C1C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80155b08(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
  }
  else if (param_4 != 0x11) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    FUN_80006824(param_1,0x254);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80155b6c
 * EN v1.0 Address: 0x80155B6C
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80155C80
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80155b6c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9,int param_10)
{
  uint uVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (*(char *)(param_10 + 0x33a) == '\0') {
    FUN_80155830(param_9,param_10);
  }
  else {
    if ((*(short *)(*(int *)(param_10 + 0x29c) + 0x44) == 1) &&
       (uVar1 = FUN_80294c18(*(int *)(param_10 + 0x29c)), uVar1 != 0)) {
      *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & 0xfffeffff;
    }
    if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
      FUN_80006824((uint)param_9,0x253);
      FUN_8014d4c8((double)lbl_803E369C,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80155cac
 * EN v1.0 Address: 0x80155CAC
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x80155D30
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80155cac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9,int param_10)
{
  uint uVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (*(char *)(param_10 + 0x33a) == '\0') {
    FUN_80155830(param_9,param_10);
  }
  else if ((*(short *)(*(int *)(param_10 + 0x29c) + 0x44) == 1) &&
          (uVar1 = FUN_80294c18(*(int *)(param_10 + 0x29c)), uVar1 != 0)) {
    FUN_8015536c((double)lbl_803E36C8,(short *)param_9,param_10,0x19);
    if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
      FUN_8014d4c8((double)lbl_803E36C8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,0,0,0,in_r8,in_r9,in_r10);
      FUN_80006824((uint)param_9,0x252);
    }
  }
  else {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80155e00
 * EN v1.0 Address: 0x80155E00
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x80155DF4
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80155e00(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9,int param_10)
{
  short sVar1;
  uint uVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  ushort local_18 [2];
  float afStack_14 [3];
  
  if (*(char *)(param_10 + 0x33a) == '\0') {
    FUN_80155830(param_9,param_10);
  }
  else if ((*(short *)(*(int *)(param_10 + 0x29c) + 0x44) == 1) &&
          (uVar2 = FUN_80294c18(*(int *)(param_10 + 0x29c)), uVar2 != 0)) {
    ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
    sVar1 = *(short *)(param_9 + 0x28);
    if (sVar1 == 3) {
      FUN_8015536c((double)lbl_803E3698,(short *)param_9,param_10,0x19);
    }
    else if ((sVar1 == 0) || (sVar1 == 1)) {
      FUN_8015536c((double)lbl_803E36C8,(short *)param_9,param_10,0x19);
    }
    FUN_8015506c((int)param_9,param_10,local_18,afStack_14);
    if (((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) ||
       ((local_18[0] < 0x5dc && (*(short *)(param_9 + 0x28) != 1)))) {
      if (local_18[0] < 0x5dc) {
        FUN_80006824((uint)param_9,0x251);
        FUN_8014d4c8((double)lbl_803E36C8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
      }
      else {
        FUN_8014d4c8((double)lbl_803E36C8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,param_10,3,0,0,in_r8,in_r9,in_r10);
      }
    }
  }
  else {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015603c
 * EN v1.0 Address: 0x8015603C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80155F58
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015603c(undefined4 param_1,int param_2)
{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E36CC;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  fVar1 = lbl_803E36D0;
  *(float *)(param_2 + 0x308) = lbl_803E36D0;
  *(float *)(param_2 + 0x300) = fVar1;
  *(float *)(param_2 + 0x304) = lbl_803E36D4;
  *(undefined *)(param_2 + 800) = 0;
  fVar2 = lbl_803E36D8;
  *(float *)(param_2 + 0x314) = lbl_803E36D8;
  *(undefined *)(param_2 + 0x321) = 4;
  fVar1 = lbl_803E369C;
  *(float *)(param_2 + 0x318) = lbl_803E369C;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(float *)(param_2 + 0x324) = lbl_803E3698;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x2fc) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801560a0
 * EN v1.0 Address: 0x801560A0
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x80155FBC
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801560a0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  double dVar5;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    local_2c = *(float *)(param_9 + 0xc);
    local_28 = lbl_803E36E0 + *(float *)(param_9 + 0x10);
    local_24 = *(undefined4 *)(param_9 + 0x14);
    iVar2 = *(int *)(param_10 + 0x29c);
    local_38 = *(float *)(iVar2 + 0xc);
    local_34 = lbl_803E36E4 + *(float *)(iVar2 + 0x10);
    local_30 = *(float *)(iVar2 + 0x14);
    uStack_1c = FUN_80017760(0xfffffff6,10);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    dVar5 = (double)(lbl_803E36E8 *
                    (lbl_803E36F0 *
                     (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3700) +
                    lbl_803E36EC));
    iVar2 = FUN_8016a534(dVar5,(double)lbl_803E36F4,&local_2c,&local_38,'\x01');
    FUN_80293474(iVar2,&local_40,&local_3c);
    local_3c = (float)((double)local_3c * dVar5);
    local_40 = (float)((double)local_40 * dVar5);
    dVar5 = (double)(local_38 - *(float *)(param_9 + 0xc));
    dVar4 = (double)(local_30 - *(float *)(param_9 + 0x14));
    if ((double)lbl_803E36F8 == dVar4) {
      local_44 = lbl_803E36F8;
    }
    else {
      iVar2 = FUN_80017730();
      FUN_80293474(iVar2,&local_48,&local_44);
      dVar5 = (double)local_3c;
      local_44 = (float)((double)local_44 * dVar5);
      local_3c = (float)(dVar5 * (double)local_48);
    }
    puVar3 = FUN_80017aa4(0x24,0x47b);
    *(float *)(puVar3 + 4) = local_2c;
    *(float *)(puVar3 + 6) = local_28;
    *(undefined4 *)(puVar3 + 8) = local_24;
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar2 = FUN_80017ae4(dVar5,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff,
                         0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar2 != 0) {
      *(float *)(iVar2 + 0x24) = local_3c;
      *(float *)(iVar2 + 0x28) = local_40;
      *(float *)(iVar2 + 0x2c) = local_44;
      *(uint *)(iVar2 + 0xc4) = param_9;
      FUN_80006824(param_9,0x259);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80156314
 * EN v1.0 Address: 0x80156314
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x801561A4
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80156314(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  bool bVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float local_18 [4];
  
  (**(code **)(*DAT_803dd6d8 + 0x14))(local_18);
  if ((local_18[0] < lbl_803E3708) || (lbl_803E370C < local_18[0])) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if ((bVar1) && (*(char *)(param_10 + 0x33a) == '\0')) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    FUN_8014d4c8((double)lbl_803E3710,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
  }
  else if ((!bVar1) && (*(char *)(param_10 + 0x33a) == '\x02')) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    FUN_8014d4c8((double)lbl_803E3710,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,3,0,0,in_r8,in_r9,in_r10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801564ec
 * EN v1.0 Address: 0x801564EC
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x801562BC
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801564ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)
{
  if (param_12 == 0x10) {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
  }
  else if (param_12 == 0x11) {
    if ((*(char *)(param_10 + 0x33a) == '\x02') && (*(short *)(param_9 + 0xa0) != 5)) {
      FUN_8014d4c8((double)lbl_803E3714,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,param_10,5,0,0,param_14,param_15,param_16);
    }
  }
  else if ((*(short *)(param_9 + 0xa0) == 5) || (*(short *)(param_9 + 0xa0) == 4)) {
    if ((int)(uint)*(ushort *)(param_10 + 0x2b0) < param_14) {
      *(undefined2 *)(param_10 + 0x2b0) = 0;
      FUN_80006824(param_9,600);
      FUN_80006824(param_9,0x22);
    }
    else {
      *(ushort *)(param_10 + 0x2b0) = *(ushort *)(param_10 + 0x2b0) - (short)param_14;
      FUN_80006824(param_9,0x24f);
      FUN_80006824(param_9,0x22);
    }
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
  }
  else {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
    FUN_80006824(param_9,0x250);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015666c
 * EN v1.0 Address: 0x8015666C
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x801563CC
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015666c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  *(float *)(param_10 + 0x324) = lbl_803E36F8;
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (*(char *)(param_10 + 0x33a) == '\x01') {
      if (*(short *)(param_9 + 0xa0) == 1) {
        *(undefined *)(param_10 + 0x33a) = 2;
        *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & 0xfffeffff;
      }
      else if (*(short *)(param_9 + 0xa0) == 3) {
        *(undefined *)(param_10 + 0x33a) = 0;
        *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
        param_1 = FUN_8014d4c8((double)lbl_803E36EC,param_2,param_3,param_4,param_5,param_6,
                               param_7,param_8,param_9,param_10,0,0,0,in_r8,in_r9,in_r10);
      }
    }
    else if ((*(char *)(param_10 + 0x33a) == '\x02') && (*(short *)(param_9 + 0xa0) != 2)) {
      param_1 = FUN_8014d4c8((double)lbl_803E36EC,param_2,param_3,param_4,param_5,param_6,param_7,
                             param_8,param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
    }
  }
  FUN_80156314(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80156978
 * EN v1.0 Address: 0x80156978
 * EN v1.0 Size: 1132b
 * EN v1.1 Address: 0x801564BC
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80156978(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  bool bVar1;
  short sVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar3;
  
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - lbl_803DC074;
  dVar3 = (double)*(float *)(param_10 + 0x324);
  bVar1 = dVar3 <= (double)lbl_803E36F8;
  if (bVar1) {
    *(float *)(param_10 + 0x324) = lbl_803E36F8;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    sVar2 = *(short *)(param_9 + 0xa0);
    if (sVar2 == 4) {
      FUN_801560a0(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
      *(float *)(param_10 + 0x324) = lbl_803E3718;
      dVar3 = (double)FUN_8014d4c8((double)lbl_803E36EC,param_2,param_3,param_4,param_5,param_6,
                                   param_7,param_8,param_9,param_10,5,0,0,in_r8,in_r9,in_r10);
    }
    else if ((sVar2 == 5) && (bVar1)) {
      FUN_8014d4c8((double)lbl_803E36EC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,param_10,6,0,0,in_r8,in_r9,in_r10);
      dVar3 = (double)FUN_80006824(param_9,0x24c);
    }
    else if (sVar2 == 6) {
      dVar3 = (double)FUN_8014d4c8((double)lbl_803E36EC,param_2,param_3,param_4,param_5,param_6,
                                   param_7,param_8,param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
      *(float *)(param_10 + 0x324) = lbl_803E3718;
    }
    else if (((sVar2 == 2) && (bVar1)) && ((*(uint *)(param_10 + 0x2dc) & 0x4000000) != 0)) {
      FUN_8014d4c8((double)lbl_803E36EC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,param_10,4,0,0,in_r8,in_r9,in_r10);
      dVar3 = (double)FUN_80006824(param_9,0x24b);
    }
  }
  FUN_80156314(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80156de4
 * EN v1.0 Address: 0x80156DE4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80156634
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80156de4(undefined4 param_1,int param_2)
{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E371C;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(float *)(param_2 + 0x308) = lbl_803E36F0;
  *(float *)(param_2 + 0x300) = lbl_803E3720;
  *(float *)(param_2 + 0x304) = lbl_803E3724;
  *(undefined *)(param_2 + 800) = 0;
  fVar2 = lbl_803E3728;
  *(float *)(param_2 + 0x314) = lbl_803E3728;
  *(undefined *)(param_2 + 0x321) = 7;
  fVar1 = lbl_803E36EC;
  *(float *)(param_2 + 0x318) = lbl_803E36EC;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(float *)(param_2 + 0x324) = lbl_803E36F8;
  *(float *)(param_2 + 0x2fc) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80156e48
 * EN v1.0 Address: 0x80156E48
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80156698
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80156e48(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 != 0x11) {
    if (param_4 == 0x10) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
    else {
      FUN_80006824(param_1,0x260);
      *(undefined2 *)(param_2 + 0x2b0) = 0;
      *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80156eb8
 * EN v1.0 Address: 0x80156EB8
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x80156708
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80156eb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  
  if (lbl_803E3740 < *(float *)(param_10 + 0x328)) {
    *(float *)(param_10 + 0x328) = lbl_803E3744;
  }
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
  uVar4 = 0;
  ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    FUN_80006824((uint)param_9,0x261);
  }
  *(float *)(param_10 + 0x328) = *(float *)(param_10 + 0x328) - lbl_803DC074;
  if (*(float *)(param_10 + 0x328) <= lbl_803E3730) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x600) == 0) {
      uVar2 = FUN_80017760(600,0x352);
      *(float *)(param_10 + 0x328) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
    }
    else {
      uVar2 = FUN_80017760(0x96,0xfa);
      *(float *)(param_10 + 0x328) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
    }
    FUN_80006824((uint)param_9,0x262);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    FUN_800305f8((double)lbl_803E3730,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,3,(uint)*(byte *)(param_10 + 0x323),uVar4,param_13,param_14,param_15,
                 param_16);
  }
  fVar1 = lbl_803E3730;
  if (*(float *)(param_10 + 0x324) <= lbl_803E3730) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x400) != 0) {
      *(float *)(param_10 + 0x324) = lbl_803E3748;
    }
  }
  else {
    *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - lbl_803DC074;
    if (*(float *)(param_10 + 0x324) <= fVar1) {
      *(float *)(param_10 + 0x324) = lbl_803E3748;
      *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    }
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x8000000) == 0) {
    iVar3 = *(int *)(param_10 + 0x29c);
    dVar5 = FUN_8014d2a4((double)*(float *)(iVar3 + 0x18),
                         (double)(lbl_803E3750 + *(float *)(iVar3 + 0x1c)),
                         (double)*(float *)(iVar3 + 0x20),(double)lbl_803E3754,
                         (double)lbl_803E3758,(double)lbl_803E375C,
                         (double)*(float *)(param_10 + 0x304),(int)param_9);
  }
  else {
    dVar5 = (double)lbl_803E374C;
  }
  if ((((double)lbl_803E3730 < dVar5) && (*(float *)(param_9 + 0x14) < lbl_803E3760)) ||
     ((*(uint *)(param_10 + 0x2dc) & 0x8000000) != 0)) {
    *(undefined *)(param_10 + 0x33a) = 1;
  }
  if ((*(char *)(param_10 + 0x33a) == '\0') || (dVar5 <= (double)lbl_803E3730)) {
    *(undefined *)(param_10 + 0x33a) = 0;
    if (lbl_803E3774 < *(float *)(param_10 + 0x308)) {
      *(float *)(param_10 + 0x308) =
           -(lbl_803E3778 * lbl_803DC074 - *(float *)(param_10 + 0x308));
    }
  }
  else {
    *(float *)(param_10 + 0x308) = lbl_803E3764;
    if (*(short *)(param_10 + 0x2b0) != 0) {
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + lbl_803E3768;
    }
    if (lbl_803E376C <= *(float *)(param_9 + 0x14)) {
      if (lbl_803E3770 < *(float *)(param_9 + 0x14)) {
        *(float *)(param_9 + 0x14) = lbl_803E3770;
      }
    }
    else {
      *(float *)(param_9 + 0x14) = lbl_803E376C;
    }
  }
  FUN_8014d164((double)lbl_803E3730,(double)lbl_803E3730,param_9,param_10,0x2d,'\0');
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80157220
 * EN v1.0 Address: 0x80157220
 * EN v1.0 Size: 1284b
 * EN v1.1 Address: 0x801569D8
 * EN v1.1 Size: 892b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80157220(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 *param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  char cVar3;
  undefined4 uVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  
  pfVar6 = (float *)*param_10;
  iVar5 = *(int *)(param_9 + 0x26);
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
  uVar4 = 0;
  ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
  if ((param_10[0xb7] & 0x40000000) != 0) {
    FUN_80006824((uint)param_9,0x261);
  }
  param_10[0xca] = (float)param_10[0xca] - lbl_803DC074;
  if ((float)param_10[0xca] <= lbl_803E3730) {
    if ((param_10[0xb7] & 0x600) == 0) {
      uVar2 = FUN_80017760(600,0x352);
      param_10[0xca] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
    }
    else {
      uVar2 = FUN_80017760(0x96,0xfa);
      param_10[0xca] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
    }
    FUN_80006824((uint)param_9,0x262);
  }
  if ((param_10[0xb7] & 0x40000000) != 0) {
    FUN_800305f8((double)lbl_803E3730,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,(uint)*(byte *)((int)param_10 + 0x323),uVar4,param_13,param_14,param_15,
                 param_16);
  }
  fVar1 = lbl_803E3730;
  if ((float)param_10[0xc9] <= lbl_803E3730) {
    param_10[0xb9] = param_10[0xb9] & 0xfffeffff;
  }
  else {
    param_10[0xc9] = (float)param_10[0xc9] - lbl_803DC074;
    if ((float)param_10[0xc9] <= fVar1) {
      param_10[0xc9] = fVar1;
    }
  }
  if ((param_10[0xb7] & 0x2000) == 0) {
    if ((param_10[0xb7] & 0x8000000) == 0) {
      dVar7 = FUN_8014d2a4((double)*(float *)(iVar5 + 8),(double)*(float *)(iVar5 + 0xc),
                           (double)*(float *)(iVar5 + 0x10),(double)lbl_803E3754,
                           (double)lbl_803E3758,(double)lbl_803E375C,
                           (double)(float)param_10[0xc1],(int)param_9);
    }
    else {
      dVar7 = (double)lbl_803E3754;
    }
  }
  else {
    iVar5 = FUN_80006a10((double)(float)param_10[0xbf],pfVar6);
    if ((((iVar5 != 0) || (pfVar6[4] != 0.0)) &&
        (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar6), cVar3 != '\0')) &&
       (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)lbl_803E377C,*param_10,param_9,&DAT_803dc940,0xffffffff),
       cVar3 != '\0')) {
      param_10[0xb7] = param_10[0xb7] & 0xffffdfff;
    }
    if ((param_10[0xb7] & 0x8000000) == 0) {
      dVar7 = FUN_8014d2a4((double)pfVar6[0x1a],(double)pfVar6[0x1b],(double)pfVar6[0x1c],
                           (double)lbl_803E3754,(double)lbl_803E3758,(double)lbl_803E375C,
                           (double)(float)param_10[0xc1],(int)param_9);
    }
    else {
      dVar7 = (double)lbl_803E3754;
    }
  }
  if ((((double)lbl_803E3730 < dVar7) && (*(float *)(param_9 + 0x14) < lbl_803E3760)) ||
     ((param_10[0xb7] & 0x8000000) != 0)) {
    *(undefined *)((int)param_10 + 0x33a) = 1;
  }
  if ((*(char *)((int)param_10 + 0x33a) == '\0') || (dVar7 <= (double)lbl_803E3730)) {
    *(undefined *)((int)param_10 + 0x33a) = 0;
    if (lbl_803E3774 < (float)param_10[0xc2]) {
      param_10[0xc2] = -(lbl_803E3778 * lbl_803DC074 - (float)param_10[0xc2]);
    }
  }
  else {
    param_10[0xc2] = lbl_803E3764;
    if (*(short *)(param_10 + 0xac) != 0) {
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + lbl_803E3768;
    }
    if (lbl_803E376C <= *(float *)(param_9 + 0x14)) {
      if (lbl_803E3770 < *(float *)(param_9 + 0x14)) {
        *(float *)(param_9 + 0x14) = lbl_803E3770;
      }
    }
    else {
      *(float *)(param_9 + 0x14) = lbl_803E376C;
    }
  }
  FUN_8014d164((double)lbl_803E3730,(double)lbl_803E3730,param_9,(int)param_10,0x2d,'\0');
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80157724
 * EN v1.0 Address: 0x80157724
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x80156D54
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80157724(undefined4 param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E3780;
  *(undefined4 *)(param_2 + 0x2e4) = 0x2002b029;
  *(float *)(param_2 + 0x308) = lbl_803E3764;
  *(float *)(param_2 + 0x300) = lbl_803E3784;
  *(float *)(param_2 + 0x304) = lbl_803E3788;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E378C;
  *(float *)(param_2 + 0x314) = lbl_803E378C;
  *(undefined *)(param_2 + 0x321) = 1;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 2;
  *(float *)(param_2 + 0x31c) = fVar1;
  uVar2 = FUN_80017760(0x78,0x1e0);
  *(float *)(param_2 + 0x328) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3738);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801577c8
 * EN v1.0 Address: 0x801577C8
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x80156DFC
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801577c8(uint param_1,int param_2)
{
  short sVar1;
  
  sVar1 = *(short *)(param_1 + 0xa0);
  if (sVar1 == 7) {
    if (*(short *)(param_2 + 0x2f8) != 0) {
      if (lbl_803E3790 <= *(float *)(param_1 + 0x98)) {
        FUN_80006824(param_1,0x24c);
      }
      else {
        FUN_80006824(param_1,0x24d);
      }
    }
  }
  else if (sVar1 < 7) {
    if (sVar1 == 5) {
      if (*(short *)(param_2 + 0x2f8) != 0) {
        FUN_80006824(param_1,0x24d);
      }
    }
    else if ((4 < sVar1) && (*(short *)(param_2 + 0x2f8) != 0)) {
      FUN_80006824(param_1,0x24d);
    }
  }
  else if ((sVar1 < 9) && (*(short *)(param_2 + 0x2f8) != 0)) {
    if (lbl_803E3794 <= *(float *)(param_1 + 0x98)) {
      if (lbl_803E3798 <= *(float *)(param_1 + 0x98)) {
        FUN_80006824(param_1,0x24c);
      }
      else {
        FUN_80006824(param_1,0x24e);
      }
    }
    else {
      FUN_80006824(param_1,0x24b);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801578c4
 * EN v1.0 Address: 0x801578C4
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x80156EF0
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801578c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  
  if (param_12 != 0x11) {
    if (param_12 == 0x10) {
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
    }
    else {
      sVar1 = *(short *)(param_9 + 0xa0);
      if ((((sVar1 == 0) || (sVar1 == 1)) || (sVar1 == 3)) || (sVar1 == 4)) {
        FUN_80006824(param_9,0x250);
        *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
      }
      else {
        FUN_8014d4c8((double)lbl_803E379C,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,param_10,4,0,0,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x33a) = 0;
        FUN_80006824(param_9,0x24f);
        *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801579f4
 * EN v1.0 Address: 0x801579F4
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x80156FB8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801579f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  int iVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  if (((*(uint *)(param_10 + 0x2dc) & 0x80000000) != 0) && (*(byte *)(param_10 + 0x33a) < 2)) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
    if (10 < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = 3;
    }
    if (*(ushort *)(param_10 + 0x2a0) < 4) {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      FUN_8014d4c8((double)*(float *)(&DAT_8031ff68 + iVar1),param_2,param_3,param_4,param_5,param_6
                   ,param_7,param_8,param_9,param_10,(uint)(byte)(&DAT_8031ff70)[iVar1],0,0,in_r8,
                   in_r9,in_r10);
    }
    else {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      FUN_8014d4c8((double)*(float *)(&DAT_8031ff68 + iVar1),param_2,param_3,param_4,param_5,param_6
                   ,param_7,param_8,param_9,param_10,(uint)*(byte *)(iVar1 + -0x7fce008f),0,0,in_r8,
                   in_r9,in_r10);
    }
  }
  FUN_801577c8(param_9,param_10);
  return;
}
