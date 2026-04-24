#include "ghidra_import.h"
#include "main/dll/baddie/skeetla.h"

extern bool FUN_800067f0();
extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern double FUN_80017708();
extern double FUN_80017714();
extern int FUN_80017730();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern int FUN_80017b00();
extern int FUN_80037008();
extern void* FUN_80037134();
extern int fn_80037B60();
extern undefined4 FUN_80039468();
extern undefined4 FUN_800469d0();
extern undefined4 FUN_80046a00();
extern int fn_8004B394();
extern undefined4 FUN_80046cd0();
extern int FUN_8005b024();
extern int FUN_8005b398();
extern undefined4 FUN_800632e8();
extern undefined4 FUN_800810e8();
extern undefined4 FUN_80081120();
extern undefined4 FUN_800da594();
extern undefined4 FUN_80146fa0();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e3064;
extern undefined4 DAT_803e3068;
extern f64 DOUBLE_803e3090;
extern f64 DOUBLE_803e30f0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3070;
extern f32 FLOAT_803e3078;
extern f32 FLOAT_803e307c;
extern f32 FLOAT_803e3088;
extern f32 FLOAT_803e30a0;
extern f32 FLOAT_803e30a4;
extern f32 FLOAT_803e30a8;
extern f32 FLOAT_803e30b0;
extern f32 FLOAT_803e30b4;
extern f32 FLOAT_803e30b8;
extern f32 FLOAT_803e30bc;
extern f32 FLOAT_803e30c0;
extern f32 FLOAT_803e30c8;
extern f32 FLOAT_803e30cc;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d8;
extern f32 FLOAT_803e30dc;
extern f32 FLOAT_803e30e0;
extern f32 FLOAT_803e30f8;
extern f32 FLOAT_803e30fc;
extern f32 FLOAT_803e3100;
extern f32 FLOAT_803e3104;
extern f32 FLOAT_803e3108;
extern f32 FLOAT_803e310c;
extern f32 FLOAT_803e3110;
extern f32 FLOAT_803e3114;

/*
 * --INFO--
 *
 * Function: FUN_8013939c
 * EN v1.0 Address: 0x8013939C
 * EN v1.0 Size: 1124b
 * EN v1.1 Address: 0x80139724
 * EN v1.1 Size: 1176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013939c(uint param_1)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  float local_38;
  int local_34;
  float local_30;
  undefined auStack_2c [12];
  float afStack_20 [5];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  bVar1 = false;
  local_38 = FLOAT_803e30b4;
  iVar2 = FUN_8005b398((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c));
  if ((iVar2 == -1) && ((*(uint *)(iVar3 + 0x54) & 0x80000) == 0)) {
    *(undefined *)(iVar3 + 0x353) = 0;
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 0x80);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 0x84);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x88);
  }
  *(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) & 0xfff7ffff;
  if (*(char *)(iVar3 + 0x374) == '\0') {
    if ((*(uint *)(iVar3 + 0x54) & 0x2000) != 0) {
      bVar1 = true;
    }
  }
  else {
    *(char *)(iVar3 + 0x374) = *(char *)(iVar3 + 0x374) + -1;
    bVar1 = true;
  }
  if (bVar1) {
    FUN_800632e8((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),param_1,&local_30,0);
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - local_30;
    *(undefined *)(iVar3 + 0x353) = 0;
  }
  if ((*(char *)(iVar3 + 0x353) == '\0') || ((*(byte *)(iVar3 + 0x58) >> 5 & 1) != 0)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e306c;
  }
  else {
    if (FLOAT_803e306c == *(float *)(iVar3 + 0x2ac)) {
      bVar1 = false;
    }
    else if (FLOAT_803e30a0 == *(float *)(iVar3 + 0x2b0)) {
      bVar1 = true;
    }
    else if (*(float *)(iVar3 + 0x2b4) - *(float *)(iVar3 + 0x2b0) <= FLOAT_803e30a4) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      *(float *)(param_1 + 0x28) = FLOAT_803e306c;
      *(float *)(param_1 + 0x10) = *(float *)(iVar3 + 0x2b4) - FLOAT_803e307c;
    }
    else {
      *(float *)(param_1 + 0x28) = FLOAT_803e30b8 * FLOAT_803dc074 + *(float *)(param_1 + 0x28);
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
    }
  }
  local_34 = **(int **)(param_1 + 0x54);
  if (((*(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 8) == 0) ||
     (*(short *)(local_34 + 0x46) == 0x1f)) {
    local_34 = 0;
  }
  if ((*(uint *)(iVar3 + 0x54) & 8) == 0) {
    if ((*(int *)(iVar3 + 0x360) == 0) || (local_34 != *(int *)(iVar3 + 0x360))) {
      *(float *)(iVar3 + 0x364) = FLOAT_803e306c;
    }
    else {
      *(float *)(iVar3 + 0x364) = *(float *)(iVar3 + 0x364) + FLOAT_803dc074;
      if (FLOAT_803e3070 <= *(float *)(iVar3 + 0x364)) {
        *(float *)(iVar3 + 0x364) = *(float *)(iVar3 + 0x364) - FLOAT_803e3070;
        *(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) | 8;
        *(undefined *)(*(int *)(param_1 + 0x50) + 0x71) = 0x7e;
      }
    }
  }
  else {
    *(float *)(iVar3 + 0x364) = *(float *)(iVar3 + 0x364) + FLOAT_803dc074;
    if (FLOAT_803e30bc <= *(float *)(iVar3 + 0x364)) {
      iVar2 = FUN_80017a98();
      dVar4 = FUN_80017714((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if ((double)FLOAT_803e30c0 < dVar4) {
        *(float *)(iVar3 + 0x364) = *(float *)(iVar3 + 0x364) - FLOAT_803e30bc;
        *(undefined *)(*(int *)(param_1 + 0x50) + 0x71) = 0x7f;
        *(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) & 0xfffffff7;
      }
    }
  }
  *(int *)(iVar3 + 0x360) = local_34;
  iVar2 = fn_80037B60(param_1,(float *)(iVar3 + 0x370),&local_34,afStack_20);
  *(int *)(iVar3 + 0x368) = iVar2;
  switch(*(undefined4 *)(iVar3 + 0x368)) {
  case 1:
  case 2:
  case 4:
  case 5:
  case 0xe:
  case 0xf:
  case 0x11:
  case 0x13:
    FUN_80081120(param_1,auStack_2c,1,(int *)0x0);
    break;
  case 7:
  case 8:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
    FUN_800810e8(afStack_20,8,0xff,0x20,0x20);
    FUN_80081120(param_1,auStack_2c,4,(int *)0x0);
    if (*(short *)(local_34 + 0x46) == 0x69) {
      FUN_80006824(param_1,0x23f);
    }
    break;
  case 0x1f:
    *(float *)(iVar3 + 0x838) = FLOAT_803e30c8;
  }
  if (*(char *)(iVar3 + 0x353) == '\0') {
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar3 + 0xf8);
  }
  iVar2 = FUN_8005b024();
  if ((iVar2 == 0xe) || (iVar2 = FUN_80037008(5,param_1,&local_38), iVar2 != 0)) {
    *(uint *)(iVar3 + 0xf8) = *(uint *)(iVar3 + 0xf8) & 0xfffffffb;
  }
  else {
    *(uint *)(iVar3 + 0xf8) = *(uint *)(iVar3 + 0xf8) | 4;
  }
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,iVar3 + 0xf8);
  (**(code **)(*DAT_803dd728 + 0x14))(param_1,iVar3 + 0xf8);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,iVar3 + 0xf8);
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(iVar3 + 0x290);
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)(iVar3 + 0x292);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80139800
 * EN v1.0 Address: 0x80139800
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x80139BBC
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80139800(double param_1,int param_2,float *param_3)
{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  uVar2 = 0;
  fVar1 = FLOAT_803e30dc * (float)(param_1 * (double)FLOAT_803dc074);
  dVar6 = (double)(fVar1 * fVar1);
  dVar4 = FUN_80017708(param_3 + 0x1a,(float *)(param_2 + 0x18));
  fVar1 = FLOAT_803e3088;
  if (param_3[0x20] != 0.0) {
    fVar1 = FLOAT_803e30d8;
  }
  dVar5 = (double)fVar1;
  iVar3 = 0;
  dVar7 = (double)FLOAT_803e30b4;
  while ((dVar4 <= dVar7 || (dVar4 <= dVar6))) {
    uVar2 = 1;
    FUN_800da594(dVar5,param_3);
    dVar4 = FUN_80017708(param_3 + 0x1a,(float *)(param_2 + 0x18));
    iVar3 = iVar3 + 1;
    if (4 < iVar3) {
      return 1;
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80139910
 * EN v1.0 Address: 0x80139910
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x80139CB8
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80139910(ushort *param_1,ushort param_2)
{
  ushort uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(ushort *)(iVar2 + 0x5a) = param_2;
  uVar1 = *param_1;
  iVar3 = (int)(short)uVar1 - (uint)param_2;
  if (0x8000 < iVar3) {
    iVar3 = iVar3 + -0xffff;
  }
  if (iVar3 < -0x8000) {
    iVar3 = iVar3 + 0xffff;
  }
  uVar4 = *(uint *)(iVar2 + 0x54);
  if ((uVar4 & 0x100000) == 0) {
    *(uint *)(iVar2 + 0x54) = uVar4 & 0xffdfffff;
  }
  else {
    *(uint *)(iVar2 + 0x54) = uVar4 | 0x200000;
  }
  *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xef2fffff;
  if (iVar3 < 0x11) {
    if (-0x11 < iVar3) {
      *param_1 = param_2;
      return iVar3;
    }
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x500000;
  }
  else {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x900000;
  }
  if (iVar3 < 0x201) {
    if (iVar3 < -0x200) {
      *param_1 = uVar1 + (short)(int)(FLOAT_803e30e0 * FLOAT_803dc074);
      *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000000;
    }
    else {
      *param_1 = param_2;
    }
  }
  else {
    *param_1 = uVar1 - (short)(int)(FLOAT_803e30e0 * FLOAT_803dc074);
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000000;
  }
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_80139a48
 * EN v1.0 Address: 0x80139A48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80139E14
 * EN v1.1 Size: 2404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80139a48(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80139a4c
 * EN v1.0 Address: 0x80139A4C
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x8013A778
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80139a4c(double param_1,int param_2,int param_3,uint param_4)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0xb8);
  if (*(int *)(iVar2 + 0x20) == param_3) {
    if (*(short *)(param_2 + 0xa0) == param_3) {
      *(float *)(iVar2 + 0x34) = (float)param_1;
      *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | param_4;
    }
    return 1;
  }
  if ((param_4 & 0x4000000) != 0) {
    *(float *)(iVar2 + 0x18) = FLOAT_803e310c;
  }
  *(int *)(iVar2 + 0x20) = param_3;
  *(float *)(iVar2 + 0x38) = (float)param_1;
  *(uint *)(iVar2 + 0x50) = param_4;
  if ((param_4 & 0x20) == 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xffffffdf;
  }
  if ((param_4 & 0x40) == 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xffffffbf;
  }
  if ((param_4 & 0x80) == 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xffffff7f;
  }
  if ((param_4 & 0x100) == 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xfffffeff;
  }
  fVar1 = FLOAT_803e3078;
  *(float *)(iVar2 + 0x40) = FLOAT_803e3078;
  *(float *)(iVar2 + 0x44) = fVar1;
  *(float *)(iVar2 + 0x48) = fVar1;
  *(float *)(iVar2 + 0x4c) = fVar1;
  if (FLOAT_803e310c <= *(float *)(iVar2 + 0x18)) {
    return 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: fn_8013A874
 * EN v1.0 Address: 0x80139B2C
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x8013A874
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_8013A874(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4_00;
  int iVar4;
  ushort uVar5;
  ushort uVar6;
  uint uVar7;
  double dVar8;
  double dVar9;
  undefined8 uVar10;
  int local_38 [14];
  
  iVar4_00 = 0;
  uVar10 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar4 = (int)uVar10;
  uVar5 = 0;
  uVar7 = 1;
  for (uVar6 = 0; uVar6 < 4; uVar6 = uVar6 + 1) {
    if ((-1 < *(int *)(iVar4 + (uint)uVar6 * 4 + 0x1c)) &&
       (param_4 == ((int)*(char *)(iVar4 + 0x1b) & uVar7))) {
      iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))();
      uVar3 = (uint)uVar5;
      local_38[uVar3] = iVar2;
      iVar2 = local_38[uVar3];
      if ((((iVar2 != 0) && ((param_3 == 0 || (*(byte *)(iVar4 + uVar3 + 4) == param_3)))) &&
          (((int)*(short *)(iVar2 + 0x30) == 0xffffffff ||
           (uVar3 = FUN_80017690((int)*(short *)(iVar2 + 0x30)), uVar3 != 0)))) &&
         ((((int)*(short *)(iVar2 + 0x32) == 0xffffffff ||
           (uVar3 = FUN_80017690((int)*(short *)(iVar2 + 0x32)), uVar3 == 0)) &&
          ((*(char *)(iVar4 + 0x1a) != '\t' || (*(char *)(iVar2 + 0x1a) != '\b')))))) {
        uVar5 = uVar5 + 1;
      }
    }
    uVar7 = (uVar7 & 0x7fff) << 1;
    param_4 = param_4 << 1;
  }
  if (uVar5 != 0) {
    iVar4_00 = local_38[0];
    dVar8 = FUN_80017708((float *)(*(int *)(iVar1 + 4) + 0x18),(float *)(local_38[0] + 8));
    for (uVar6 = 1; uVar6 < uVar5; uVar6 = uVar6 + 1) {
      dVar9 = FUN_80017708((float *)(*(int *)(iVar1 + 4) + 0x18),(float *)(local_38[uVar6] + 8));
      if (dVar9 < dVar8) {
        dVar8 = dVar9;
        iVar4_00 = local_38[uVar6];
      }
    }
  }
  FUN_80286880();
  return iVar4_00;
}

/*
 * --INFO--
 *
 * Function: FUN_80139ce8
 * EN v1.0 Address: 0x80139CE8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x8013AA44
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80139ce8(int param_1,int param_2,int param_3)
{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  if (param_3 == 0) {
    return 0;
  }
  if ((*(int *)(param_1 + 0x6ec) == param_3) && (*(int *)(param_1 + 0x6e8) == param_2)) {
    uVar1 = FUN_800469d0(param_1 + 0x6b8);
    *(undefined4 *)(param_1 + 0x6e8) = uVar1;
    iVar3 = *(int *)(param_1 + 0x6e8);
    if (iVar3 == 0) {
      return 0;
    }
    if (iVar3 != 0) {
      if ((((int)*(short *)(iVar3 + 0x30) != 0xffffffff) &&
          (uVar2 = FUN_80017690((int)*(short *)(iVar3 + 0x30)), uVar2 == 0)) ||
         (((int)*(short *)(iVar3 + 0x32) != 0xffffffff &&
          (uVar2 = FUN_80017690((int)*(short *)(iVar3 + 0x32)), uVar2 != 0)))) {
        iVar3 = 0;
      }
    }
    else {
      iVar3 = 0;
    }
    *(int *)(param_1 + 0x6e8) = iVar3;
    if (*(int *)(param_1 + 0x6e8) != 0) {
      return *(int *)(param_1 + 0x6e8);
    }
  }
  FUN_80046cd0((int *)(param_1 + 0x6b8),param_2,*(int *)(param_1 + 0x28),param_3,
               (byte)*(undefined4 *)(param_1 + 0x4a0));
  iVar3 = fn_8004B394();
  if (iVar3 == 1) {
    FUN_80046a00((int *)(param_1 + 0x6b8));
    uVar1 = FUN_800469d0(param_1 + 0x6b8);
    *(undefined4 *)(param_1 + 0x6e8) = uVar1;
    *(int *)(param_1 + 0x6ec) = param_3;
    iVar3 = *(int *)(param_1 + 0x6e8);
  }
  else {
    iVar3 = 0;
  }
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_80139e1c
 * EN v1.0 Address: 0x80139E1C
 * EN v1.0 Size: 416b
 * EN v1.1 Address: 0x8013AB7C
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80139e1c(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
  ulonglong uVar1;
  char cVar3;
  char cVar4;
  int *piVar2;
  int iVar5;
  char cVar6;
  char cVar7;
  char *pcVar8;
  int iVar9;
  int *piVar10;
  undefined8 uVar11;
  char local_28 [40];
  
  uVar11 = FUN_80286834();
  uVar1 = (ulonglong)uVar11 >> 0x20;
  piVar2 = (int *)uVar11;
  cVar7 = '\0';
  while( true ) {
    iVar9 = (int)((ulonglong)uVar11 >> 0x20);
    if ('\a' < cVar7) break;
    iVar5 = *(int *)uVar11;
    if (iVar5 != 0) {
      FUN_80046cd0((int *)(iVar9 + 0x538),iVar5,*(int *)((int)uVar1 + 0x28),param_4,
                   *(byte *)(param_3 + cVar7));
    }
    uVar11 = CONCAT44(iVar9 + 0x30,(int *)uVar11 + 1);
    cVar7 = cVar7 + '\x01';
  }
  for (cVar7 = '\0'; cVar7 < 'd'; cVar7 = cVar7 + '\x01') {
    cVar4 = '\0';
    pcVar8 = local_28;
    piVar10 = piVar2;
    for (cVar6 = '\0'; cVar6 < '\b'; cVar6 = cVar6 + '\x01') {
      if (*piVar10 == 0) {
        *pcVar8 = -1;
      }
      else {
        cVar3 = fn_8004B394();
        *pcVar8 = cVar3;
      }
      cVar3 = *pcVar8;
      if (cVar3 != '\0') {
        if (cVar3 < '\0') {
          if (-2 < cVar3) {
            *piVar10 = 0;
            cVar4 = cVar4 + '\x01';
          }
        }
        else if (cVar3 < '\x02') goto LAB_8013ad38;
      }
      piVar10 = piVar10 + 1;
      pcVar8 = pcVar8 + 1;
    }
    if (cVar4 == '\b') break;
    if ((cVar4 < '\b') && ('\x06' < cVar4)) {
      cVar7 = '\0';
      goto LAB_8013ad10;
    }
  }
LAB_8013ad38:
  FUN_80286880();
  return;
LAB_8013ad10:
  if ('\a' < cVar7) goto LAB_8013ad38;
  if (*piVar2 != 0) {
    cVar4 = fn_8004B394();
    local_28[cVar7] = cVar4;
    goto LAB_8013ad38;
  }
  piVar2 = piVar2 + 1;
  cVar7 = cVar7 + '\x01';
  goto LAB_8013ad10;
}

/*
 * --INFO--
 *
 * Function: fn_8013AD50
 * EN v1.0 Address: 0x80139FBC
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8013AD50
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8013AD50(int param_1,int param_2,byte param_3)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = 0;
  if (((*(int *)(param_1 + 0x528) == param_2) &&
      (*(short *)(param_1 + 0x530) == *(short *)(param_1 + 0x532))) &&
     (*(byte *)(param_1 + 0x536) == param_3)) {
    iVar1 = *(int *)(param_1 + 0x52c);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      if (((int)*(short *)(iVar1 + 0x30) != 0xffffffff) &&
         (uVar2 = FUN_80017690((int)*(short *)(iVar1 + 0x30)), uVar2 == 0)) {
        iVar1 = 0;
      }
      else if (((int)*(short *)(iVar1 + 0x32) != 0xffffffff) &&
              (uVar2 = FUN_80017690((int)*(short *)(iVar1 + 0x32)), uVar2 != 0)) {
        iVar1 = 0;
      }
    }
  }
  if (iVar1 == 0) {
    uVar2 = (uint)param_3;
    iVar1 = fn_8013A874(param_1,param_2,(uint)*(ushort *)(param_1 + 0x532),uVar2);
    if (iVar1 == 0) {
      iVar1 = FUN_80139ce8(param_1,param_2,(uint)*(ushort *)(param_1 + 0x532));
    }
    if (iVar1 == 0) {
      if (*(ushort *)(param_1 + 0x534) != 0) {
        iVar1 = fn_8013A874(param_1,param_2,(uint)*(ushort *)(param_1 + 0x534),uVar2);
        if (iVar1 == 0) {
          iVar1 = FUN_80139ce8(param_1,param_2,(uint)*(ushort *)(param_1 + 0x534));
        }
        if (iVar1 != 0) {
          *(undefined2 *)(param_1 + 0x532) = *(undefined2 *)(param_1 + 0x534);
        }
      }
      if (iVar1 == 0) {
        iVar1 = fn_8013A874(param_1,param_2,0,uVar2);
        *(undefined2 *)(param_1 + 0x532) = 0;
      }
    }
  }
  *(int *)(param_1 + 0x528) = param_2;
  *(int *)(param_1 + 0x52c) = iVar1;
  *(undefined2 *)(param_1 + 0x530) = *(undefined2 *)(param_1 + 0x532);
  *(byte *)(param_1 + 0x536) = param_3;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013a144
 * EN v1.0 Address: 0x8013A144
 * EN v1.0 Size: 708b
 * EN v1.1 Address: 0x8013AED4
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013a144(undefined4 param_1,undefined4 param_2,ushort param_3,undefined4 *param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  uint uVar8;
  float *pfVar9;
  int iVar10;
  byte bVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  uint unaff_r26;
  int iVar15;
  int iVar16;
  double in_f31;
  double dVar17;
  double in_ps31_1;
  undefined8 uVar18;
  float local_68 [4];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar18 = FUN_8028682c();
  iVar6 = (int)((ulonglong)uVar18 >> 0x20);
  iVar12 = (int)uVar18;
  iVar14 = *(int *)(iVar6 + 0xb8);
  piVar7 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_68);
  local_68[2] = FLOAT_803e30a8;
  local_68[1] = FLOAT_803e30a8;
  *param_4 = 0;
  param_4[1] = 0;
  local_68[3] = local_68[2];
  param_4[2] = 0;
  local_58 = local_68[2];
  param_4[3] = 0;
  local_54 = local_68[2];
  param_4[4] = 0;
  local_50 = local_68[2];
  param_4[5] = 0;
  local_4c = local_68[2];
  param_4[6] = 0;
  local_48 = local_68[2];
  param_4[7] = 0;
  if (param_3 != 0) {
    for (iVar16 = 0; iVar16 < (int)local_68[0]; iVar16 = iVar16 + 1) {
      iVar15 = *piVar7;
      if ((((*(char *)(iVar15 + 0x19) == '$') && (*(char *)(iVar15 + 3) == '\0')) &&
          (((int)*(short *)(iVar15 + 0x30) == 0xffffffff ||
           (uVar8 = FUN_80017690((int)*(short *)(iVar15 + 0x30)), uVar8 != 0)))) &&
         ((((int)*(short *)(iVar15 + 0x32) == 0xffffffff ||
           (uVar8 = FUN_80017690((int)*(short *)(iVar15 + 0x32)), uVar8 == 0)) &&
          (pfVar9 = *(float **)(iVar14 + 0x28), fVar1 = pfVar9[2] - *(float *)(iVar15 + 0x10),
          fVar3 = *pfVar9 - *(float *)(iVar15 + 8),
          fVar4 = *(float *)(iVar6 + 0x18) - *(float *)(iVar15 + 8),
          fVar2 = *(float *)(iVar6 + 0x20) - *(float *)(iVar15 + 0x10),
          dVar17 = (double)(fVar1 * fVar1 + fVar3 * fVar3 + fVar4 * fVar4 + fVar2 * fVar2),
          dVar17 < (double)local_48)))) {
        for (uVar8 = 0; (uVar8 & 0xff) < 4; uVar8 = uVar8 + 1) {
          if (((-1 < *(int *)(iVar15 + (uVar8 & 0xff) * 4 + 0x1c)) &&
              (*(byte *)(iVar15 + (uVar8 & 0xff) + 4) == param_3)) &&
             ((*(char *)(iVar15 + 0x1a) != '\b' ||
              ((iVar10 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar10 == 0 ||
               (*(char *)(iVar10 + 0x1a) != '\t')))))) {
            unaff_r26 = (int)*(char *)(iVar15 + 0x1b) >> (uVar8 & 0x3f) & 0xff;
            break;
          }
        }
        if ((uVar8 & 0xff) != 4) {
          bVar11 = 0;
LAB_8013b144:
          if (bVar11 < 8) {
            uVar8 = (uint)bVar11;
            if ((double)local_68[uVar8 + 1] <= dVar17) goto LAB_8013b140;
            for (uVar13 = 7; uVar8 < (uVar13 & 0xff); uVar13 = uVar13 - 1) {
              uVar5 = uVar13 & 0xff;
              *(undefined *)(iVar12 + uVar5) = *(undefined *)(iVar12 + (uVar5 - 1));
              param_4[uVar5] = param_4[uVar5 - 1];
              local_68[uVar5 + 1] = local_68[uVar5];
            }
            *(byte *)(iVar12 + uVar8) = (byte)unaff_r26 & 1 ^ 1;
            param_4[uVar8] = iVar15;
            local_68[uVar8 + 1] = (float)dVar17;
          }
        }
      }
      piVar7 = piVar7 + 1;
    }
  }
  FUN_80286878();
  return;
LAB_8013b140:
  bVar11 = bVar11 + 1;
  goto LAB_8013b144;
}

/*
 * --INFO--
 *
 * Function: FUN_8013a408
 * EN v1.0 Address: 0x8013A408
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8013B184
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013a408(undefined2 *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined2 local_28 [2];
  ushort local_24;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = *(int *)(iVar3 + 0x24);
  local_1c = *(undefined4 *)(iVar3 + 0x3d8);
  local_18 = *(undefined4 *)(iVar3 + 0x3dc);
  local_14 = *(undefined4 *)(iVar3 + 0x3e0);
  local_28[0] = *param_1;
  if (*(short *)(iVar1 + 0x46) == 0x1ca) {
    local_24 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))();
    local_24 = local_24 & 0xff;
  }
  else if (*(short *)(iVar1 + 0x46) == 0x160) {
    local_24 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))();
    local_24 = local_24 & 0xff;
  }
  else {
    local_24 = 0;
  }
  uVar2 = FUN_80017760(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xca,local_28,0x200001,0xffffffff,0);
  }
  uVar2 = FUN_80017760(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xcb,local_28,0x200001,0xffffffff,0);
  }
  local_1c = *(undefined4 *)(iVar3 + 0x3e4);
  local_18 = *(undefined4 *)(iVar3 + 1000);
  local_14 = *(undefined4 *)(iVar3 + 0x3ec);
  local_28[0] = *param_1;
  uVar2 = FUN_80017760(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xca,local_28,0x200001,0xffffffff,0);
  }
  uVar2 = FUN_80017760(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xcb,local_28,0x200001,0xffffffff,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013a5b0
 * EN v1.0 Address: 0x8013A5B0
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x8013B368
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013a5b0(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,float *param_6)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  float *pfVar5;
  double extraout_f1;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double dVar12;
  double in_f31;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  float local_88 [2];
  float local_80;
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
  uVar13 = FUN_80286840();
  pfVar4 = (float *)((ulonglong)uVar13 >> 0x20);
  pfVar5 = (float *)uVar13;
  dVar10 = extraout_f1;
  dVar6 = FUN_80017708(param_6,pfVar4);
  dVar7 = FUN_80017708(param_6,pfVar5);
  dVar11 = (double)(float)(dVar10 * dVar10);
  dVar10 = (double)(float)(param_2 * param_2);
  if ((dVar7 <= dVar6) && (dVar8 = FUN_80017708(param_5,param_6), dVar11 <= dVar8)) {
    dVar8 = FUN_80017708(pfVar4,param_5);
    dVar9 = FUN_80017708(pfVar4,param_6);
    if (dVar9 <= dVar8) {
      dVar8 = dVar10;
      if (dVar6 < dVar10) {
        dVar8 = dVar6;
      }
      if (dVar7 < dVar8) {
        fVar2 = pfVar5[2] - pfVar4[2];
        fVar1 = *pfVar4;
        fVar3 = fVar2 / (*pfVar5 - fVar1);
        local_80 = -(fVar3 * fVar1 - pfVar4[2]);
        fVar2 = (fVar1 - *pfVar5) / fVar2;
        local_88[0] = (-(fVar2 * *param_6 - param_6[2]) - local_80) / (fVar3 - fVar2);
        local_80 = fVar3 * local_88[0] + local_80;
        dVar9 = FUN_80017708(param_6,local_88);
        if (dVar9 < dVar11) {
          dVar9 = (double)(*pfVar5 - *param_6);
          dVar12 = (double)(pfVar5[2] - param_6[2]);
          dVar11 = FUN_80293900((double)(float)(dVar9 * dVar9 + (double)(float)(dVar12 * dVar12)));
          if ((double)FLOAT_803e306c != dVar11) {
            dVar9 = (double)(float)(dVar9 / dVar11);
            dVar12 = (double)(float)(dVar12 / dVar11);
          }
          if (dVar6 < dVar10) {
            dVar10 = FUN_80293900(dVar8);
            dVar6 = FUN_80293900(dVar7);
            param_2 = -(double)(float)((double)(float)(dVar10 - dVar6) * (double)FLOAT_803e3110 -
                                      dVar10);
          }
          *pfVar5 = (float)(dVar9 * param_2 + (double)*param_6);
          pfVar5[2] = (float)(dVar12 * param_2 + (double)param_6[2]);
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013a804
 * EN v1.0 Address: 0x8013A804
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x8013B568
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013a804(undefined4 param_1,undefined4 param_2,float *param_3)
{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double in_f30;
  double dVar6;
  double in_f31;
  double dVar7;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar8;
  int local_58;
  int local_54;
  int local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar8 = FUN_8028683c();
  uVar1 = (undefined4)((ulonglong)uVar8 >> 0x20);
  piVar2 = FUN_80037134(0x40,local_50);
  dVar6 = (double)FLOAT_803e3114;
  dVar7 = DOUBLE_803e3090;
  for (iVar5 = 0; iVar5 < local_50[0]; iVar5 = iVar5 + 1) {
    iVar3 = *(int *)(*piVar2 + 0x4c);
    uStack_44 = (uint)*(ushort *)(iVar3 + 0x18);
    local_48 = 0x43300000;
    uStack_3c = (uint)*(ushort *)(iVar3 + 0x1a);
    local_40 = 0x43300000;
    FUN_8013a5b0((double)(float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) -
                                                        dVar7)),
                 (double)(float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                        dVar7)),uVar1,(int)uVar8,param_3,
                 (float *)(*piVar2 + 0x18));
    piVar2 = piVar2 + 1;
  }
  iVar5 = FUN_80017b00(&local_54,&local_58);
  piVar2 = (int *)(iVar5 + local_54 * 4);
  for (; local_54 < local_58; local_54 = local_54 + 1) {
    iVar5 = *piVar2;
    uVar4 = (uint)*(ushort *)(*(int *)(iVar5 + 0x50) + 0x84);
    if (((uVar4 != 0) && (*(int *)(iVar5 + 0x54) != 0)) &&
       ((*(ushort *)(*(int *)(iVar5 + 0x54) + 0x60) & 1) != 0)) {
      local_40 = 0x43300000;
      uStack_44 = (uint)*(ushort *)(*(int *)(iVar5 + 0x50) + 0x86);
      local_48 = 0x43300000;
      uStack_3c = uVar4;
      FUN_8013a5b0((double)(FLOAT_803e3114 *
                           (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e3090)),
                   (double)(FLOAT_803e3114 *
                           (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e3090)),uVar1,
                   (int)uVar8,param_3,(float *)(iVar5 + 0x18));
    }
    piVar2 = piVar2 + 1;
  }
  FUN_80286888();
  return;
}
