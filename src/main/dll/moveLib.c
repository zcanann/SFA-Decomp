#include "ghidra_import.h"
#include "main/dll/moveLib.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_800068f4();
extern int FUN_80006a10();
extern double FUN_80006a30();
extern char FUN_80006a64();
extern undefined8 FUN_80006a68();
extern undefined4 GameBit_Set(int eventId, int value);
extern uint FUN_80017730();
extern int FUN_80017738();
extern undefined4 FUN_80017744();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern int ObjGroup_FindNearestObjectToPoint();
extern undefined4 ObjPath_GetPointWorldPosition();
extern void* FUN_80039518();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003a9c8();
extern undefined4 FUN_8003ac24();
extern undefined8 FUN_8003ad08();
extern undefined4 FUN_800620e8();
extern int FUN_800632e8();
extern undefined4 FUN_8006f7a0();
extern int objAnimFn_80115650();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de254;
extern f64 DOUBLE_803e28b0;
extern f64 DOUBLE_803e2918;
extern f64 DOUBLE_803e2928;
extern f32 lbl_803DC074;
extern f32 lbl_803DE250;
extern f32 lbl_803E28AC;
extern f32 lbl_803E28C0;
extern f32 lbl_803E28C8;
extern f32 lbl_803E28DC;
extern f32 lbl_803E28E8;
extern f32 lbl_803E28EC;
extern f32 lbl_803E28F0;
extern f32 lbl_803E28F4;
extern f32 lbl_803E28F8;
extern f32 lbl_803E28FC;
extern f32 lbl_803E2908;
extern f32 lbl_803E290C;
extern f32 lbl_803E2910;
extern f32 lbl_803E2920;
extern f32 lbl_803E2924;
extern f32 lbl_803E2930;
extern f32 lbl_803E2934;
extern f32 lbl_803E2938;
extern f32 lbl_803E2944;
extern f32 lbl_803E2948;
extern f32 lbl_803E294C;

/*
 * --INFO--
 *
 * Function: dll_19_func0F
 * EN v1.0 Address: 0x80113504
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x80113590
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_19_func0F(double param_1,int param_2,uint *param_3,char param_4)
{
  float fVar1;
  
  *param_3 = *param_3 | 0x8000;
  *(undefined2 *)(param_3 + 0xcc) = 0;
  if (*(int *)(param_2 + 0x54) != 0) {
    ObjHits_SetHitVolumeSlot(param_2,0,0,-1);
  }
  if (param_4 != -1) {
    *(char *)((int)param_3 + 0x25f) = param_4;
  }
  param_3[0xa9] = (uint)(float)param_1;
  fVar1 = lbl_803E28AC;
  param_3[0xa4] = (uint)lbl_803E28AC;
  param_3[0xa3] = (uint)fVar1;
  param_3[199] = 0;
  param_3[0xc6] = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801135c0
 * EN v1.0 Address: 0x801135C0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x80113634
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801135c0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined2 param_5,float *param_6,float *param_7,int *param_8)
{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  if (*(char *)(iVar3 + 0x381) != '\0') {
    *(undefined4 *)(iVar3 + 0x318) = 0;
    *(undefined4 *)(iVar3 + 0x31c) = 0;
    *(undefined2 *)(iVar3 + 0x330) = 0;
    fVar1 = lbl_803E28AC;
    *(float *)(iVar3 + 0x290) = lbl_803E28AC;
    *(float *)(iVar3 + 0x28c) = fVar1;
    *param_8 = 1;
    dVar7 = (double)(*param_6 - *(float *)(iVar2 + 0xc));
    dVar6 = (double)(*param_7 - *(float *)(iVar2 + 0x14));
    dVar4 = FUN_80293900((double)(float)(dVar7 * dVar7 + (double)(float)(dVar6 * dVar6)));
    if ((double)lbl_803E28E8 <= dVar4) {
      dVar5 = (double)lbl_803E28EC;
      *(float *)(iVar3 + 0x290) = (float)(dVar5 * -(double)(float)(dVar7 / dVar4));
      *(float *)(iVar3 + 0x28c) = (float)(dVar5 * (double)(float)(dVar6 / dVar4));
      *(float *)(iVar2 + 0xc) =
           (float)(dVar4 * (double)(float)(dVar7 / dVar4) + (double)*(float *)(iVar2 + 0xc));
      *(float *)(iVar2 + 0x14) =
           (float)(dVar4 * (double)(float)(dVar6 / dVar4) + (double)*(float *)(iVar2 + 0x14));
      (**(code **)(*DAT_803dd70c + 8))
                ((double)lbl_803DC074,(double)lbl_803DC074,iVar2,iVar3,param_3,param_4);
    }
    else {
      *param_8 = 0;
    }
    if (*param_8 == 0) {
      *(undefined *)(iVar3 + 0x405) = 0;
      *(undefined2 *)(iVar3 + 0x274) = param_5;
      *(undefined4 *)(iVar3 + 0x2d0) = 0;
      *(undefined *)(iVar3 + 0x25f) = 0;
      GameBit_Set((int)*(short *)(iVar3 + 0x3f4),0);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80113758
 * EN v1.0 Address: 0x80113758
 * EN v1.0 Size: 836b
 * EN v1.1 Address: 0x801137A0
 * EN v1.1 Size: 864b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80113758(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined2 param_6)
{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar5 = (int)uVar12;
  *(undefined4 *)(param_3 + 0x318) = 0;
  *(undefined4 *)(param_3 + 0x31c) = 0;
  *(undefined2 *)(param_3 + 0x330) = 0;
  fVar1 = lbl_803E28AC;
  *(float *)(param_3 + 0x290) = lbl_803E28AC;
  *(float *)(param_3 + 0x28c) = fVar1;
  if (*(char *)(iVar5 + 0x56) != '\x01') {
    *(undefined4 *)(iVar5 + 0x40) = *(undefined4 *)(psVar3 + 6);
    *(undefined4 *)(iVar5 + 0x44) = *(undefined4 *)(psVar3 + 8);
    *(undefined4 *)(iVar5 + 0x48) = *(undefined4 *)(psVar3 + 10);
    lbl_803DE250 = lbl_803E28F0;
    DAT_803de254 = '\0';
  }
  *(undefined2 *)(iVar5 + 0x6e) = 0;
  *(undefined *)(iVar5 + 0x56) = 1;
  fVar1 = *(float *)(iVar5 + 0x40) - *(float *)(psVar3 + 6);
  fVar2 = *(float *)(iVar5 + 0x48) - *(float *)(psVar3 + 10);
  dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  iVar4 = *(int *)(param_3 + 0x2d0);
  if (iVar4 != 0) {
    dVar11 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(iVar5 + 0x40));
    dVar10 = (double)(*(float *)(iVar4 + 0x14) - *(float *)(iVar5 + 0x48));
    dVar8 = FUN_80293900((double)(float)(dVar11 * dVar11 + (double)(float)(dVar10 * dVar10)));
    dVar9 = (double)(lbl_803DC074 * (float)(dVar8 - dVar7) * lbl_803E28F4);
    dVar6 = (double)lbl_803E28EC;
    if ((dVar9 <= dVar6) && (dVar6 = dVar9, dVar9 < (double)lbl_803E28DC)) {
      dVar6 = (double)lbl_803E28DC;
    }
    if (dVar7 <= (double)lbl_803DE250) {
      DAT_803de254 = DAT_803de254 + '\x01';
    }
    if ((dVar8 <= dVar7) || ('\t' < DAT_803de254)) {
      iVar4 = (int)*psVar3 - (uint)**(ushort **)(param_3 + 0x2d0);
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      if (0x2000 < iVar4) {
        iVar4 = 0x2000;
      }
      if (iVar4 < -0x2000) {
        iVar4 = -0x2000;
      }
      *psVar3 = *psVar3 - (short)((int)(iVar4 * (uint)DAT_803dc070) >> 3);
      if ('\n' < DAT_803de254) {
        iVar4 = 0;
      }
      if ((iVar4 < 0x100) && (-0x100 < iVar4)) {
        *(undefined *)(iVar5 + 0x56) = 0;
        *(short *)(iVar5 + 0x5a) = *(short *)(iVar5 + 0x58) + -1;
      }
      else {
        (**(code **)(*DAT_803dd70c + 8))
                  ((double)lbl_803DC074,(double)lbl_803DC074,psVar3,param_3,param_4,param_5);
      }
    }
    else {
      *(float *)(param_3 + 0x290) = (float)(-(double)(float)(dVar11 / dVar8) * dVar6);
      *(float *)(param_3 + 0x28c) = (float)((double)(float)(dVar10 / dVar8) * dVar6);
      *(float *)(psVar3 + 6) =
           (float)(dVar7 * (double)(float)(dVar11 / dVar8) + (double)*(float *)(iVar5 + 0x40));
      *(float *)(psVar3 + 10) =
           (float)(dVar7 * (double)(float)(dVar10 / dVar8) + (double)*(float *)(iVar5 + 0x48));
      (**(code **)(*DAT_803dd70c + 8))
                ((double)lbl_803DC074,(double)lbl_803DC074,psVar3,param_3,param_4,param_5);
    }
    lbl_803DE250 = (float)dVar7;
    if (*(char *)(iVar5 + 0x56) == '\0') {
      *(undefined *)(param_3 + 0x405) = 0;
      *(undefined2 *)(param_3 + 0x274) = param_6;
      *(undefined4 *)(param_3 + 0x2d0) = 0;
      *(undefined2 *)(iVar5 + 0x6e) = 0xffff;
      *(ushort *)(iVar5 + 0x6e) = *(ushort *)(iVar5 + 0x6e) & ~0x40;
      *(undefined *)(param_3 + 0x25f) = 0;
      GameBit_Set((int)*(short *)(param_3 + 0x3f4),0);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80113a9c
 * EN v1.0 Address: 0x80113A9C
 * EN v1.0 Size: 368b
 * EN v1.1 Address: 0x80113B00
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80113a9c(double param_1,double param_2,short *param_3,int param_4)
{
  float fVar1;
  
  if (*(float *)(param_4 + 0x298) < lbl_803E28F8) {
    *(undefined2 *)(param_4 + 0x334) = 0;
    *(undefined2 *)(param_4 + 0x336) = 0;
    fVar1 = lbl_803E28AC;
    *(float *)(param_4 + 0x298) = lbl_803E28AC;
    *(float *)(param_4 + 0x280) = fVar1;
  }
  *(float *)(param_4 + 0x284) = lbl_803E28AC;
  *param_3 = (short)(int)(lbl_803E28FC *
                          (float)((double)((float)((double)CONCAT44(0x43300000,
                                                                    (int)*(short *)(param_4 + 0x336)
                                                                    ^ 0x80000000) - DOUBLE_803e28b0)
                                          * lbl_803DC074) / param_2) +
                         (float)((double)CONCAT44(0x43300000,(int)*param_3 ^ 0x80000000) -
                                DOUBLE_803e28b0));
  *(float *)(param_4 + 0x294) =
       lbl_803DC074 *
       ((*(float *)(param_4 + 0x298) - *(float *)(param_4 + 0x294)) / *(float *)(param_4 + 0x2b8)) +
       *(float *)(param_4 + 0x294);
  *(float *)(param_4 + 0x280) =
       lbl_803DC074 *
       ((*(float *)(param_4 + 0x298) - *(float *)(param_4 + 0x280)) / *(float *)(param_4 + 0x2b8)) +
       *(float *)(param_4 + 0x280);
  if (param_1 < (double)*(float *)(param_4 + 0x294)) {
    *(float *)(param_4 + 0x294) = (float)param_1;
  }
  if (param_1 < (double)*(float *)(param_4 + 0x280)) {
    *(float *)(param_4 + 0x280) = (float)param_1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80113c0c
 * EN v1.0 Address: 0x80113C0C
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x80113BF8
 * EN v1.1 Size: 628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80113c0c(double param_1,double param_2,double param_3,int param_4,int param_5)
{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  fVar1 = (float)((double)*(float *)(param_5 + 0x18) - param_1);
  fVar2 = (float)((double)*(float *)(param_5 + 0x20) - param_2);
  dVar3 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  if (dVar3 < param_3) {
    dVar4 = (double)FUN_80293f90();
    dVar5 = (double)FUN_80294964();
    fVar1 = -(float)(dVar4 * (double)(float)(param_1 - dVar4) +
                    (double)(float)(dVar5 * (double)(float)(param_2 - dVar5)));
    dVar6 = (double)(fVar1 + (float)(dVar4 * (double)*(float *)(param_5 + 0x18) +
                                    (double)(float)(dVar5 * (double)*(float *)(param_5 + 0x20))));
    fVar1 = fVar1 + (float)(dVar4 * (double)*(float *)(param_5 + 0x8c) +
                           (double)(float)(dVar5 * (double)*(float *)(param_5 + 0x94)));
    if ((dVar6 <= (double)lbl_803E28AC) || (lbl_803E28C8 < fVar1)) {
      if (lbl_803E28C8 < fVar1) {
        dVar3 = (double)(float)((double)lbl_803E28C0 * param_3);
      }
    }
    else {
      *(float *)(param_5 + 0x18) = -(float)(dVar4 * dVar6 - (double)*(float *)(param_5 + 0x18));
      *(float *)(param_5 + 0x20) = -(float)(dVar5 * dVar6 - (double)*(float *)(param_5 + 0x20));
      FUN_800068f4((double)*(float *)(param_5 + 0x18),(double)*(float *)(param_5 + 0x1c),
                   (double)*(float *)(param_5 + 0x20),(float *)(param_5 + 0xc),
                   (float *)(param_5 + 0x10),(float *)(param_5 + 0x14),*(int *)(param_5 + 0x30));
    }
  }
  if (dVar3 < param_3) {
    param_1 = (double)*(float *)(param_5 + 0x18);
    param_2 = (double)*(float *)(param_5 + 0x20);
  }
  dVar3 = (double)FUN_80293f90();
  dVar4 = (double)FUN_80294964();
  return -(double)(-(float)((double)*(float *)(param_4 + 0xc) * dVar3 +
                           (double)(float)((double)*(float *)(param_4 + 0x14) * dVar4)) +
                  (float)(dVar3 * param_1 + (double)(float)(dVar4 * param_2)));
}

/*
 * --INFO--
 *
 * Function: FUN_80113e58
 * EN v1.0 Address: 0x80113E58
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x80113E6C
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80113e58(undefined4 param_1,undefined4 param_2,uint param_3,undefined2 *param_4,
                 undefined2 *param_5,undefined2 *param_6)
{
  float fVar1;
  float fVar2;
  float fVar3;
  ushort uVar4;
  ushort *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_8028683c();
  puVar5 = (ushort *)((ulonglong)uVar10 >> 0x20);
  iVar7 = (int)uVar10;
  iVar8 = *(int *)(puVar5 + 0x5c);
  if ((puVar5 == (ushort *)0x0) || (iVar7 == 0)) {
    *param_4 = 0;
    *param_5 = 0;
    *param_6 = 0;
  }
  else {
    fVar1 = *(float *)(iVar7 + 0x18) - *(float *)(puVar5 + 0xc);
    fVar2 = *(float *)(iVar7 + 0x1c) - *(float *)(puVar5 + 0xe);
    fVar3 = *(float *)(iVar7 + 0x20) - *(float *)(puVar5 + 0x10);
    uVar6 = FUN_80017730();
    if (*(short **)(puVar5 + 0x18) == (short *)0x0) {
      uVar4 = *puVar5;
    }
    else {
      uVar4 = *puVar5 + **(short **)(puVar5 + 0x18);
    }
    uVar6 = (uVar6 & 0xffff) - (uint)uVar4;
    if (0x8000 < (int)uVar6) {
      uVar6 = uVar6 - 0xffff;
    }
    if ((int)uVar6 < -0x8000) {
      uVar6 = uVar6 + 0xffff;
    }
    *param_5 = (short)uVar6;
    if (((uVar6 & 0xffff) < 0x31c4) || (0xce3b < (uVar6 & 0xffff))) {
      *(ushort *)(iVar8 + 0x400) = *(ushort *)(iVar8 + 0x400) & ~0x10;
    }
    else {
      *(ushort *)(iVar8 + 0x400) = *(ushort *)(iVar8 + 0x400) | 0x10;
    }
    *param_4 = (short)((uVar6 & 0xffff) / (0x10000 / (param_3 & 0xff)));
    dVar9 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *param_6 = (short)(int)dVar9;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80113fdc
 * EN v1.0 Address: 0x80113FDC
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80114000
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80113fdc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  int *piVar2;
  char cVar3;
  ushort uVar4;
  double extraout_f1;
  double dVar5;
  undefined8 uVar6;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  char local_100 [4];
  short asStack_fc [4];
  short asStack_f4 [4];
  float local_ec;
  float local_e8;
  float local_e4;
  int aiStack_e0 [22];
  undefined4 local_88;
  uint uStack_84;
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
  uVar9 = FUN_80286834();
  piVar2 = (int *)((ulonglong)uVar9 >> 0x20);
  local_ec = (float)piVar2[3];
  local_e8 = lbl_803E28E8 + (float)piVar2[4];
  local_e4 = (float)piVar2[5];
  dVar8 = extraout_f1;
  FUN_80006a68(&local_ec,asStack_fc);
  if ((short *)piVar2[0xc] == (short *)0x0) {
    sVar1 = *(short *)piVar2;
  }
  else {
    sVar1 = *(short *)piVar2 + *(short *)piVar2[0xc];
  }
  dVar7 = (double)lbl_803E28E8;
  for (uVar4 = 0; uVar4 < 4; uVar4 = uVar4 + 1) {
    uStack_84 = (int)sVar1 + (uint)uVar4 * 0x4000 ^ 0x80000000;
    local_88 = 0x43300000;
    dVar5 = (double)FUN_80293f90();
    local_ec = -(float)(dVar8 * dVar5 - (double)(float)piVar2[3]);
    local_e8 = (float)(dVar7 + (double)(float)piVar2[4]);
    dVar5 = (double)FUN_80294964();
    local_e4 = -(float)(dVar8 * dVar5 - (double)(float)piVar2[5]);
    uVar6 = FUN_80006a68(&local_ec,asStack_f4);
    if (piVar2[0xc] == 0) {
      cVar3 = FUN_80006a64(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_f4,
                           asStack_fc,(undefined4 *)0x0,local_100,0);
      if (local_100[0] == '\x01') {
        cVar3 = '\x01';
      }
    }
    else {
      cVar3 = '\x01';
    }
    if (cVar3 != '\0') {
      FUN_800620e8(piVar2 + 3,&local_ec,(float *)0x0,aiStack_e0,piVar2,
                   (uint)*(byte *)((int)uVar9 + 0x261),0xffffffff,0,0);
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801141dc
 * EN v1.0 Address: 0x801141DC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80114230
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801141dc(double param_1,int param_2)
{
  *(float *)(param_2 + 0x614) = (float)param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801141e8
 * EN v1.0 Address: 0x801141E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80114238
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801141e8(int param_1,wchar_t *param_2,wchar_t *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801141ec
 * EN v1.0 Address: 0x801141EC
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801142B4
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801141ec(undefined4 param_1,undefined4 param_2)
{
  int iVar1;
  double dVar2;
  
  iVar1 = (**(code **)(*DAT_803dd71c + 0x40))(param_2);
  if (iVar1 < 0) {
    dVar2 = (double)lbl_803E2908;
  }
  else {
    dVar2 = (double)(**(code **)(*DAT_803dd71c + 0x24))(param_1);
  }
  return dVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80114274
 * EN v1.0 Address: 0x80114274
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x80114320
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80114274(undefined4 param_1,undefined2 *param_2)
{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  float local_28 [2];
  longlong local_20;
  longlong local_18;
  
  local_28[0] = lbl_803E290C;
  iVar1 = (**(code **)(*DAT_803dd71c + 0x40))();
  if (iVar1 < 0) {
    uVar3 = 0;
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd71c + 0x1c))();
    *(undefined4 *)(param_2 + 6) = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(param_2 + 10) = *(undefined4 *)(iVar1 + 0x10);
    iVar2 = ObjGroup_FindNearestObjectToPoint(8,param_2 + 6,local_28);
    if (iVar2 == 0) {
      *param_2 = (short)((int)*(char *)(iVar1 + 0x2c) << 8);
    }
    else {
      local_20 = (longlong)(int)(*(float *)(iVar2 + 0xc) - *(float *)(param_2 + 6));
      local_18 = (longlong)(int)(*(float *)(iVar2 + 0x14) - *(float *)(param_2 + 10));
      iVar1 = FUN_80017738();
      *param_2 = (short)iVar1;
    }
    uVar3 = 1;
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_80114340
 * EN v1.0 Address: 0x80114340
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80114420
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80114340(int param_1,undefined2 *param_2)
{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 < 0x1c) {
    iVar2 = (**(code **)(*DAT_803dd71c + 0x40))();
    if (iVar2 < 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))();
      *(undefined4 *)(param_2 + 6) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_2 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_2 + 10) = *(undefined4 *)(iVar2 + 0x10);
      *param_2 = (short)((int)*(char *)(iVar2 + 0x2c) << 8);
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

extern f32 curveFn_80010dc0(f32* points, int unused, f32 t);
extern f32 sqrtf(f32 x);
extern f64 lbl_803E1C98;

#pragma scheduling off
#pragma peephole off
f32 fn_80114224(int p1, int p2, int p3, int p4, int n)
{
    extern f32 lbl_803E1C90;
    f32 prev_x, prev_y, prev_z;
    f32 cur_x, cur_y, cur_z;
    f32 dx, dy, dz;
    f32 total;
    f32 t;
    f32 buf[4];
    int i;

    prev_x = *(f32*)(p1 + 0);
    prev_y = *(f32*)(p1 + 4);
    prev_z = *(f32*)(p1 + 8);
    total = lbl_803E1C90;

    for (i = 1; i <= n; i++) {
        t = (f32)((f64)CONCAT44(0x43300000, i ^ 0x80000000) - lbl_803E1C98) /
            (f32)((f64)CONCAT44(0x43300000, n ^ 0x80000000) - lbl_803E1C98);

        buf[0] = *(f32*)(p1 + 0);
        buf[1] = *(f32*)(p3 + 0);
        buf[2] = *(f32*)(p2 + 0);
        buf[3] = *(f32*)(p4 + 0);
        cur_x = curveFn_80010dc0(buf, 0, t);
        dx = cur_x - prev_x;

        buf[0] = *(f32*)(p1 + 4);
        buf[1] = *(f32*)(p3 + 4);
        buf[2] = *(f32*)(p2 + 4);
        buf[3] = *(f32*)(p4 + 4);
        cur_y = curveFn_80010dc0(buf, 0, t);
        dy = cur_y - prev_y;

        buf[0] = *(f32*)(p1 + 8);
        buf[1] = *(f32*)(p3 + 8);
        buf[2] = *(f32*)(p2 + 8);
        buf[3] = *(f32*)(p4 + 8);
        cur_z = curveFn_80010dc0(buf, 0, t);
        dz = cur_z - prev_z;

        total += sqrtf(dx * dx + dy * dy + dz * dz);
        prev_x = cur_x;
        prev_y = cur_y;
        prev_z = cur_z;
    }

    return total;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80114408(int p1, int p2, int p3, int p4, f32 p5)
{
  extern void fn_800218AC(int, int);
  extern f32 fn_80114224(int, int, int, int, int);
  extern f32 curveFn_80010dc0(int, int, f32);
  extern u8 framesThisStep;
  extern f32 lbl_803E1C90;
  extern f32 lbl_803E1CA0;
  extern f32 lbl_803E1CA4;
  int ret = 0;

  if ((void *)p2 != NULL) {
    s16 tmp[3];
    f32 va = lbl_803E1CA0;
    f32 vb = lbl_803E1C90;
    *(f32 *)(p3 + 0x18) = va;
    *(f32 *)(p3 + 0x1c) = vb;
    *(f32 *)(p3 + 0x20) = vb;
    *(f32 *)(p3 + 0x24) = va;
    *(f32 *)(p3 + 0x28) = vb;
    *(f32 *)(p3 + 0x2c) = vb;
    fn_800218AC(p1, p3 + 0x18);
    tmp[2] = 0;
    tmp[1] = (s16)(s8)*(u8 *)(p2 + 0x2d);
    tmp[0] = (s16)(s8)*(u8 *)(p2 + 0x2c);
    fn_800218AC((int)tmp, p3 + 0x24);
    *(f32 *)p4 = lbl_803E1C90;
    *(f32 *)(p3 + 0x34) = fn_80114224(p3, p3 + 0x18, p3 + 0xc, p3 + 0x24, 10);
  } else {
    *(f32 *)p4 = *(f32 *)p4 + p5 * (f32)(u32)framesThisStep / *(f32 *)(p3 + 0x34);
    if (*(f32 *)p4 > lbl_803E1CA4) {
      ret = 1;
      *(f32 *)p4 = lbl_803E1CA4;
    }
  }

  {
    f32 buf[4];
    buf[0] = *(f32 *)(p3 + 0x00);
    buf[1] = *(f32 *)(p3 + 0x0c);
    buf[2] = *(f32 *)(p3 + 0x18);
    buf[3] = *(f32 *)(p3 + 0x24);
    *(f32 *)(p1 + 0x0c) = curveFn_80010dc0((int)buf, 0, *(f32 *)p4);
    buf[0] = *(f32 *)(p3 + 0x04);
    buf[1] = *(f32 *)(p3 + 0x10);
    buf[2] = *(f32 *)(p3 + 0x1c);
    buf[3] = *(f32 *)(p3 + 0x28);
    *(f32 *)(p1 + 0x10) = curveFn_80010dc0((int)buf, 0, *(f32 *)p4);
    buf[0] = *(f32 *)(p3 + 0x08);
    buf[1] = *(f32 *)(p3 + 0x14);
    buf[2] = *(f32 *)(p3 + 0x20);
    buf[3] = *(f32 *)(p3 + 0x2c);
    *(f32 *)(p1 + 0x14) = curveFn_80010dc0((int)buf, 0, *(f32 *)p4);
  }
  return ret;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801143e8
 * EN v1.0 Address: 0x801143E8
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801144C0
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801143e8(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 uint param_5)
{
  float *pfVar1;
  undefined4 *puVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double in_f24;
  double in_f25;
  double dVar7;
  double dVar8;
  double in_f26;
  double in_f27;
  double dVar9;
  double in_f28;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  float local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  float local_78;
  float fStack_74;
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
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  uVar13 = FUN_80286834();
  pfVar1 = (float *)((ulonglong)uVar13 >> 0x20);
  puVar2 = (undefined4 *)uVar13;
  dVar7 = (double)*pfVar1;
  dVar10 = (double)pfVar1[2];
  dVar6 = (double)pfVar1[1];
  dVar12 = DOUBLE_803e2918;
  for (uVar3 = 1; (int)uVar3 < (int)(param_5 + 1); uVar3 = uVar3 + 1) {
    uStack_b4 = uVar3 ^ 0x80000000;
    local_b8 = 0x43300000;
    local_b0 = 0x43300000;
    dVar9 = (double)((float)((double)CONCAT44(0x43300000,uStack_b4) - dVar12) /
                    (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - dVar12));
    local_c8 = *pfVar1;
    local_c4 = *param_3;
    local_c0 = *puVar2;
    local_bc = *param_4;
    uStack_ac = param_5 ^ 0x80000000;
    dVar4 = FUN_80006a30(dVar9,&local_c8,(float *)0x0);
    dVar8 = (double)(float)(dVar4 - dVar7);
    local_c8 = pfVar1[1];
    local_c4 = param_3[1];
    local_c0 = puVar2[1];
    local_bc = param_4[1];
    dVar5 = FUN_80006a30(dVar9,&local_c8,(float *)0x0);
    dVar11 = (double)(float)(dVar5 - dVar6);
    local_c8 = pfVar1[2];
    local_c4 = param_3[2];
    local_c0 = puVar2[2];
    local_bc = param_4[2];
    dVar6 = FUN_80006a30(dVar9,&local_c8,(float *)0x0);
    dVar7 = dVar4;
    FUN_80293900((double)((float)(dVar6 - dVar10) * (float)(dVar6 - dVar10) +
                         (float)(dVar8 * dVar8 + (double)(float)(dVar11 * dVar11))));
    dVar10 = dVar6;
    dVar6 = dVar5;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801145a8
 * EN v1.0 Address: 0x801145A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801146A4
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801145a8(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801145ac
 * EN v1.0 Address: 0x801145AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80114858
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801145ac(undefined4 param_1,undefined4 param_2,float *param_3,uint param_4,float *param_5,
                 uint *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801145b0
 * EN v1.0 Address: 0x801145B0
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x80114A58
 * EN v1.1 Size: 864b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801145b0(undefined4 param_1,undefined4 param_2,int param_3,float *param_4,byte *param_5,
                 undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  short sVar1;
  short *psVar2;
  int iVar3;
  short *psVar4;
  float *pfVar5;
  byte *pbVar6;
  double extraout_f1;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f30;
  double dVar10;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_68;
  float local_64;
  float local_60;
  float local_5c [2];
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar11 = FUN_80286840();
  psVar2 = (short *)((ulonglong)uVar11 >> 0x20);
  psVar4 = (short *)uVar11;
  if (psVar4 != (short *)0x0) {
    local_64 = *(float *)(psVar4 + 6) - *(float *)(psVar2 + 6);
    dVar9 = (double)local_64;
    local_60 = *(float *)(psVar4 + 8) - *(float *)(psVar2 + 8);
    local_5c[0] = *(float *)(psVar4 + 10) - *(float *)(psVar2 + 10);
    pfVar5 = param_4;
    pbVar6 = param_5;
    dVar10 = extraout_f1;
    dVar7 = FUN_80293900((double)(local_5c[0] * local_5c[0] +
                                 (float)(dVar9 * dVar9) + local_60 * local_60));
    if ((double)(float)((double)lbl_803E2934 * dVar10) <= dVar7) {
      FUN_8006f7a0(&local_64,&local_60,local_5c);
      *(float *)(psVar2 + 0x12) = local_64 * (float)(dVar10 * (double)lbl_803DC074);
      *(float *)(psVar2 + 0x14) = local_60 * (float)(dVar10 * (double)lbl_803DC074);
      *(float *)(psVar2 + 0x16) = local_5c[0] * (float)(dVar10 * (double)lbl_803DC074);
      if (((*param_5 & 1) != 0) &&
         (iVar3 = FUN_800632e8((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                               (double)*(float *)(psVar2 + 10),psVar2,&local_68,0), iVar3 == 0)) {
        *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_68;
      }
      if ((*param_5 & 2) != 0) {
        sVar1 = *psVar4 - *psVar2;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        uStack_54 = (int)*psVar2 ^ 0x80000000;
        local_5c[1] = 176.0;
        uStack_4c = (int)sVar1 ^ 0x80000000;
        local_50 = 0x43300000;
        iVar3 = (int)((f32)(s32)uStack_54 +
                     (float)((double)((lbl_803E2938 +
                                      (float)((double)CONCAT44(0x43300000,uStack_4c) -
                                             DOUBLE_803e2918)) *
                                     (float)(dVar10 * (double)lbl_803DC074)) / dVar7));
        local_48 = (longlong)iVar3;
        *psVar2 = (short)iVar3;
      }
      dVar7 = (double)*(float *)(psVar2 + 0x14);
      dVar8 = (double)*(float *)(psVar2 + 0x16);
      FUN_80017a88((double)*(float *)(psVar2 + 0x12),dVar7,dVar8,(int)psVar2);
      if (param_3 != -1) {
        if (psVar2[0x50] != param_3) {
          FUN_800305f8((double)lbl_803E2910,dVar7,dVar8,dVar9,in_f5,in_f6,in_f7,in_f8,psVar2,
                       param_3,0,pfVar5,pbVar6,param_6,param_7,param_8);
        }
        iVar3 = FUN_80017730();
        sVar1 = *psVar2 - (short)iVar3;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        local_48 = CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000);
        dVar7 = (double)FUN_80294964();
        FUN_8002f6ac((double)(float)(dVar10 * -dVar7),(int)psVar2,param_4);
      }
    }
    else {
      *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(psVar4 + 6);
      *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(psVar4 + 8);
      *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(psVar4 + 10);
      if (((*param_5 & 1) != 0) &&
         (iVar3 = FUN_800632e8((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                               (double)*(float *)(psVar2 + 10),psVar2,&local_68,0), iVar3 == 0)) {
        *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_68;
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80114920
 * EN v1.0 Address: 0x80114920
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x80114DB8
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80114920(int param_1)
{
  uint *puVar1;
  int iVar2;
  
  puVar1 = FUN_80039518();
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6d0 + 0x48))(0);
  *(undefined *)(iVar2 + 0x600) = 0;
  FUN_8003ad08(param_1,puVar1,(uint)*(byte *)(iVar2 + 0x610),iVar2 + 0x1c);
  *(undefined4 *)(iVar2 + 0x5f8) = 0x50;
  FUN_8003a9c8(iVar2 + 0x1c,(uint)*(byte *)(iVar2 + 0x610),0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801149b8
 * EN v1.0 Address: 0x801149B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80114E4C
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801149b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,short param_12,
                 undefined2 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801149bc
 * EN v1.0 Address: 0x801149BC
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x80115088
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801149bc(short *param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  uint *puVar3;
  ushort local_38;
  short local_36;
  short local_34;
  float local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  undefined4 uStack_20;
  float local_1c [4];
  
  if (*(char *)(param_2 + 0x601) != '\0') {
    puVar3 = FUN_80039518();
    FUN_8003ac24((int)param_1,puVar3,(uint)*(byte *)(param_2 + 0x610));
    ObjPath_GetPointWorldPosition(param_1,param_3,&local_30,&local_2c,&local_28,0);
    ObjPath_GetPointWorldPosition(param_1,param_3 + 1,&local_24,&uStack_20,local_1c,0);
    fVar2 = lbl_803E294C;
    fVar1 = lbl_803E2948;
    *(float *)(param_2 + 4) = (lbl_803E2948 * local_30 + local_24) * lbl_803E294C;
    *(undefined4 *)(param_2 + 8) = local_2c;
    *(float *)(param_2 + 0xc) = (fVar1 * local_28 + local_1c[0]) * fVar2;
    *(float *)(param_2 + 4) = *(float *)(param_2 + 4) - *(float *)(param_1 + 6);
    *(float *)(param_2 + 8) = *(float *)(param_2 + 8) - *(float *)(param_1 + 8);
    *(float *)(param_2 + 0xc) = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 10);
    local_38 = -param_1[2];
    local_36 = -param_1[1];
    local_34 = -*param_1;
    FUN_80017748(&local_38,(float *)(param_2 + 4));
    *(undefined *)(param_2 + 0x601) = 0;
  }
  ObjPath_GetPointWorldPosition(param_1,param_3,&local_30,&local_2c,&local_28,0);
  *(float *)(param_2 + 0x10) = local_30;
  *(undefined4 *)(param_2 + 0x14) = local_2c;
  *(float *)(param_2 + 0x18) = local_28;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80114b10
 * EN v1.0 Address: 0x80114B10
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80115200
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80114b10(int param_1,undefined4 *param_2,undefined2 param_3,undefined2 param_4,int param_5)
{
  float fVar1;
  uint *puVar2;
  
  *(undefined2 *)(param_2 + 0x183) = param_3;
  *(undefined2 *)((int)param_2 + 0x60e) = param_4;
  *(char *)(param_2 + 0x184) = (char)param_5;
  param_2[0x17f] = 0;
  fVar1 = lbl_803E2910;
  *param_2 = lbl_803E2910;
  param_2[0x17e] = 0;
  param_2[0x181] = 0;
  param_2[0x182] = 0;
  param_2[0x185] = lbl_803E290C;
  *(undefined *)(param_2 + 0x180) = 0;
  *(undefined *)((int)param_2 + 0x601) = 1;
  param_2[1] = fVar1;
  param_2[2] = fVar1;
  param_2[3] = fVar1;
  param_2[0x186] = 0xffffffff;
  puVar2 = FUN_80039518();
  FUN_8003ac24(param_1,puVar2,param_5);
  puVar2 = FUN_80039518();
  FUN_8003ad08(param_1,puVar2,param_5,(int)(param_2 + 7));
  FUN_8003a9c8((int)(param_2 + 7),(uint)*(byte *)(param_2 + 0x184),0,0);
  FUN_80003494((uint)(param_2 + 0x16f),0x8031ad30,(uint)*(byte *)(param_2 + 0x184) << 1);
  FUN_80003494((int)param_2 + 0x5da,0x8031ad30,(uint)*(byte *)(param_2 + 0x184) << 1);
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_19_func04_nop(void) {}
void dll_19_func03_nop(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_19_func09_ret_0(void) { return 0x0; }
int dll_2E_func0F_ret_0(void) { return 0x0; }

/* 12b chained getters. */
f32 dll_19_func0B(int *obj) { return *(f32*)((char*)((int**)obj)[0xb8/4] + 0x3e4); }

/* misc 8b leaves */
void fn_80113F94(int *p, f32 v) { *(f32*)((char*)p + 0x614) = v; }
void dll_2E_func04(int *p, int v) { *(int*)((char*)p + 0x608) = v; }

void dll_2E_func08(int obj, int v1, int v2) {
    *(int *)(obj + 0x618) = v1;
    *(int *)(obj + 0x61c) = v2;
    *(int *)(obj + 0x620) = v1;
}

u16 dll_19_func0A(int obj) {
    void *p = *(void **)(obj + 0x4c);
    if (p != NULL) return *(u16 *)((char *)p + 0x34);
    return 0xd2;
}

extern void *memcpy(void *dst, const void *src, u32 n);
extern u8 lbl_8031A0E0[];
#pragma scheduling off
#pragma peephole off
void dll_2E_func09(int obj, void *src1, void *src2) {
    if (src1 == NULL) src1 = lbl_8031A0E0;
    if (src2 == NULL) src2 = lbl_8031A0E0;
    memcpy((char *)obj + 0x5bc, src1, (u32)*(u8 *)(obj + 0x610) * 2);
    memcpy((char *)obj + 0x5da, src2, (u32)*(u8 *)(obj + 0x610) * 2);
}
#pragma peephole reset
#pragma scheduling reset

extern int *gRomCurveInterface;
extern f32 lbl_803E1C88;
#pragma scheduling off
#pragma peephole off
f32 dll_2E_func0B(int obj, int arg) {
    int r = (*(int (*)(int))(*(int *)(*gRomCurveInterface + 0x40)))(arg);
    if (r > -1) {
        return (*(f32 (*)(int, int))(*(int *)(*gRomCurveInterface + 0x24)))(obj, r);
    }
    return lbl_803E1C88;
}
#pragma peephole reset
#pragma scheduling reset

extern undefined4 *gCameraInterface;
extern void *seqFn_800394a0(void);
extern void objFn_8003acfc(int *obj, int *types, int count, char *out);
extern void fn_8003A9C0(char *p, int count, s16 a, s16 b);
#pragma scheduling off
#pragma peephole off
void fn_80114B1C(int *obj) {
    int *state;
    int *types;

    types = (int *)seqFn_800394a0();
    state = *(int **)((char *)obj + 0xb8);

    (*((void (***)(int))gCameraInterface))[18](0);

    *(u8 *)((char *)state + 0x600) = 0;
    objFn_8003acfc(obj, types, *(u8 *)((char *)state + 0x610), (char *)state + 0x1c);
    *(int *)((char *)state + 0x5f8) = 0x50;
    fn_8003A9C0((char *)state + 0x1c, *(u8 *)((char *)state + 0x610), 0, 0);
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */
#pragma scheduling off
#pragma peephole off
int dll_2E_func0A(int idx, char *out)
{
    int r;

    if (idx >= 0x1c) {
        return 0;
    }
    r = (*(int (*)(int))(*(int *)(*gRomCurveInterface + 0x40)))(idx);
    if (r > -1) {
        char *p = (char *)(*(int (*)(int))(*(int *)(*gRomCurveInterface + 0x1c)))(r);
        *(f32 *)(out + 0xc) = *(f32 *)(p + 0x8);
        *(f32 *)(out + 0x10) = *(f32 *)(p + 0xc);
        *(f32 *)(out + 0x14) = *(f32 *)(p + 0x10);
        *(s16 *)(out + 0x0) = (s16)(*(s8 *)(p + 0x2c) << 8);
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern s16 atan2i(int x, int z);
extern f32 lbl_803E1C8C;

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */
#pragma scheduling off
#pragma peephole off
int dll_2E_func0C(int idx, char *out)
{
    f32 range;
    int r;

    range = lbl_803E1C8C;
    r = (*(int (*)(int))(*(int *)(*gRomCurveInterface + 0x40)))(idx);
    if (r > -1) {
        char *p = (char *)(*(int (*)(int))(*(int *)(*gRomCurveInterface + 0x1c)))(r);
        char *q;
        *(f32 *)(out + 0xc) = *(f32 *)(p + 0x8);
        *(f32 *)(out + 0x10) = *(f32 *)(p + 0xc);
        *(f32 *)(out + 0x14) = *(f32 *)(p + 0x10);
        q = (char *)ObjGroup_FindNearestObjectToPoint(8, out + 0xc, &range);
        if (q != NULL) {
            *(s16 *)(out + 0x0) = (s16)atan2i((int)(*(f32 *)(q + 0xc) - *(f32 *)(out + 0xc)),
                                         (int)(*(f32 *)(q + 0x14) - *(f32 *)(out + 0x14)));
        } else {
            *(s16 *)(out + 0x0) = (s16)(*(s8 *)(p + 0x2c) << 8);
        }
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 timeDelta;
extern f32 lbl_803E1C78;
extern f32 lbl_803E1C2C;
extern f32 lbl_803E1C7C;

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */
#pragma scheduling off
#pragma peephole off
void dll_19_func06(s16 *yaw, char *st, f32 cap, f32 speed)
{
    if (*(f32 *)(st + 0x298) < lbl_803E1C78) {
        f32 rest;
        *(s16 *)(st + 0x334) = 0;
        *(s16 *)(st + 0x336) = 0;
        rest = lbl_803E1C2C;
        *(f32 *)(st + 0x298) = rest;
        *(f32 *)(st + 0x280) = rest;
    }
    *(f32 *)(st + 0x284) = lbl_803E1C2C;
    *yaw = lbl_803E1C7C * ((f32)*(s16 *)(st + 0x336) * timeDelta / speed) + (f32)*yaw;
    *(f32 *)(st + 0x294) +=
        timeDelta * ((*(f32 *)(st + 0x298) - *(f32 *)(st + 0x294)) / *(f32 *)(st + 0x2b8));
    *(f32 *)(st + 0x280) +=
        timeDelta * ((*(f32 *)(st + 0x298) - *(f32 *)(st + 0x280)) / *(f32 *)(st + 0x2b8));
    if (*(f32 *)(st + 0x294) > cap) {
        *(f32 *)(st + 0x294) = cap;
    }
    if (*(f32 *)(st + 0x280) > cap) {
        *(f32 *)(st + 0x280) = cap;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8003AC14(int obj, void *types, int count);
extern f32 lbl_803E1C90;

/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */
#pragma scheduling off
#pragma peephole off
void dll_2E_func05(int obj, char *st, s16 a, s16 b, int count)
{
    f32 z;

    *(s16 *)(st + 0x60c) = a;
    *(s16 *)(st + 0x60e) = b;
    *(u8 *)(st + 0x610) = (u8)count;
    *(int *)(st + 0x5fc) = 0;
    z = lbl_803E1C90;
    *(f32 *)(st + 0x0) = z;
    *(int *)(st + 0x5f8) = 0;
    *(int *)(st + 0x604) = 0;
    *(int *)(st + 0x608) = 0;
    *(f32 *)(st + 0x614) = lbl_803E1C8C;
    *(u8 *)(st + 0x600) = 0;
    *(u8 *)(st + 0x601) = 1;
    *(f32 *)(st + 0x4) = z;
    *(f32 *)(st + 0x8) = z;
    *(f32 *)(st + 0xc) = z;
    *(int *)(st + 0x618) = -1;
    fn_8003AC14(obj, seqFn_800394a0(), count);
    objFn_8003acfc((int *)obj, (int *)seqFn_800394a0(), count, st + 0x1c);
    fn_8003A9C0(st + 0x1c, *(u8 *)(st + 0x610), 0, 0);
    dll_2E_func09((int)st, lbl_8031A0E0, lbl_8031A0E0);
}
#pragma peephole reset
#pragma scheduling reset

extern void mathFn_80021ac8(s16 *angles, f32 *vec);
extern f32 lbl_803E1CC8;
extern f32 lbl_803E1CCC;

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */
#pragma scheduling off
#pragma peephole off
void dll_2E_func06(int obj, char *st, int point)
{
    f32 z1;
    f32 y1;
    f32 x1;
    f32 z0;
    f32 y0;
    f32 x0;
    s16 ang[3];

    if (*(u8 *)(st + 0x601) != 0) {
        f32 cA;
        f32 cB;
        fn_8003AC14(obj, seqFn_800394a0(), *(u8 *)(st + 0x610));
        ObjPath_GetPointWorldPosition(obj, point, &x0, &y0, &z0, 0);
        ObjPath_GetPointWorldPosition(obj, point + 1, &x1, &y1, &z1, 0);
        cA = lbl_803E1CC8;
        *(f32 *)(st + 0x4) = (cA * x0 + x1) * (cB = lbl_803E1CCC);
        *(f32 *)(st + 0x8) = y0;
        *(f32 *)(st + 0xc) = (cA * z0 + z1) * cB;
        *(f32 *)(st + 0x4) -= *(f32 *)(obj + 0xc);
        *(f32 *)(st + 0x8) -= *(f32 *)(obj + 0x10);
        *(f32 *)(st + 0xc) -= *(f32 *)(obj + 0x14);
        ang[0] = (s16)-*(s16 *)(obj + 0x4);
        ang[1] = (s16)-*(s16 *)(obj + 0x2);
        ang[2] = (s16)-*(s16 *)(obj + 0x0);
        mathFn_80021ac8(ang, (f32 *)(st + 0x4));
        *(u8 *)(st + 0x601) = 0;
    }
    ObjPath_GetPointWorldPosition(obj, point, &x0, &y0, &z0, 0);
    *(f32 *)(st + 0x10) = x0;
    *(f32 *)(st + 0x14) = y0;
    *(f32 *)(st + 0x18) = z0;
}
#pragma peephole reset
#pragma scheduling reset

extern s16 getAngle(f32 x, f32 z);
extern f32 sqrtf(f32 x);

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */
#pragma scheduling off
#pragma peephole off
void dll_19_func07(int obj, int target, int div, u16 *outYaw, u16 *outDelta, u16 *outDist)
{
    char *st = *(char **)(obj + 0xb8);
    f32 d[3];
    f32 *dp = d;
    s16 *ovr;
    u16 ang;
    int cur;
    int delta;

    if ((void *)obj == NULL || (void *)target == NULL) {
        *outYaw = 0;
        *outDelta = 0;
        *outDist = 0;
    } else {
        dp[0] = *(f32 *)(target + 0x18) - *(f32 *)(obj + 0x18);
        dp[1] = *(f32 *)(target + 0x1c) - *(f32 *)(obj + 0x1c);
        dp[2] = *(f32 *)(target + 0x20) - *(f32 *)(obj + 0x20);
        ang = getAngle(-dp[0], -dp[2]);
        ovr = *(s16 **)(obj + 0x30);
        if (ovr != NULL) {
            cur = (s16)(*(s16 *)(obj + 0x0) + *ovr);
        } else {
            cur = *(s16 *)(obj + 0x0);
        }
        delta = ang - (u16)(s16)cur;
        if (delta > 0x8000) {
            delta -= 0xffff;
        }
        if (delta < -0x8000) {
            delta += 0xffff;
        }
        *outDelta = (u16)delta;
        if ((u16)delta < 0x31c4 || (u16)delta > 0xce3b) {
            *(u16 *)(st + 0x400) &= ~0x10;
        } else {
            *(u16 *)(st + 0x400) |= 0x10;
        }
        *outYaw = (u16)delta / (0x10000 / (u8)div);
        *outDist = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void voxmaps_worldToGrid(f32 *world, int *grid);
extern u8 voxmaps_traceLine(int *from, int *to, int a, u8 *outFlag, int b);
extern int objBboxFn_800640cc(void *pos, f32 *world, f32 rad, int a, void *out, int obj, int b,
                              int c, int d, int e);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern const f32 lbl_803E1C68;
extern const f32 lbl_803E1C80;
extern const f32 lbl_803E1C84;
extern f32 lbl_803E1C48;

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */
#pragma scheduling off
#pragma peephole off
u8 dll_19_func08(int obj, char *st, f32 dist)
{
    u16 i;
    u8 mask;
    u8 hitFlag;
    int grid1[2];
    int grid0[2];
    f32 world[3];
    u8 bboxOut[0x80];
    int cur;
    s16 *ovr;
    u8 ok;
    f32 a;

    mask = 0;
    world[0] = *(f32 *)(obj + 0xc);
    world[1] = lbl_803E1C68 + *(f32 *)(obj + 0x10);
    world[2] = *(f32 *)(obj + 0x14);
    voxmaps_worldToGrid(world, grid0);
    ovr = *(s16 **)(obj + 0x30);
    if (ovr != NULL) {
        cur = (s16)(*(s16 *)(obj + 0x0) + *ovr);
    } else {
        cur = *(s16 *)(obj + 0x0);
    }
    for (i = 0; i < 4; i++) {
        a = lbl_803E1C80 * (f32)((s16)cur + (i << 14)) / lbl_803E1C84;
        world[0] = *(f32 *)(obj + 0xc) - dist * fn_80293E80(a);
        world[1] = lbl_803E1C68 + *(f32 *)(obj + 0x10);
        world[2] = *(f32 *)(obj + 0x14) - dist * sin(a);
        voxmaps_worldToGrid(world, grid1);
        if (*(void **)(obj + 0x30) != NULL) {
            ok = 1;
        } else {
            ok = (u8)voxmaps_traceLine(grid1, grid0, 0, &hitFlag, 0);
            if (hitFlag == 1) {
                ok = 1;
            }
        }
        if (ok != 0) {
            if (objBboxFn_800640cc((char *)(obj + 0xc), world, lbl_803E1C48, 0, bboxOut, obj,
                                   *(u8 *)(st + 0x261), -1, 0, 0) != 0) {
                ok = 0;
            }
        }
        mask |= ok << i;
    }
    return mask;
}
#pragma peephole reset
#pragma scheduling reset

extern int curveFn_80010320(int curve);
extern int ObjAnim_SampleRootCurvePhase(int objAnim, f32 distance, f32 *phaseOut);
extern int hitDetectFn_800658a4(int obj, f32 x, f32 y, f32 z, f32 *out, int flag);
extern f32 lbl_803E1CB0;

/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */
#pragma scheduling off
#pragma peephole off
int dll_2E_func0E(int obj, int curve, f32 phase, int p4, int c, f32 *d, int *flags)
{
    int moved;
    int hit;
    f32 ground;
    int fl;
    int args[2];

    moved = 1;
    hit = 0;
    ground = lbl_803E1C90;
    fl = *flags;
    if (fl & 0x10) {
        return 1;
    }
    if (fl & 0x4) {
        if (fn_80114408(obj, 0, p4, p4 + 0x30, phase) != 0) {
            args[0] = 0x19;
            args[1] = 0x15;
            (*(int (*)(int, int, f32, int *, u8))(*(int *)(*gRomCurveInterface + 0x8c)))(
                curve, obj, lbl_803E1CB0, args, (u8)c);
            *flags |= 8;
            moved = 1;
        }
    } else {
        hit = 0;
        if (curveFn_80010320(curve) != 0 || *(int *)(curve + 0x10) != 0) {
            hit = (*(u8 (*)(int))(*(int *)(*gRomCurveInterface + 0x90)))(curve);
        }
        *(f32 *)(obj + 0xc) = *(f32 *)(curve + 0x68);
        *(f32 *)(obj + 0x10) = *(f32 *)(curve + 0x6c);
        *(f32 *)(obj + 0x14) = *(f32 *)(curve + 0x70);
        if (hit != 0) {
            *flags |= 0x10;
        }
    }
    ObjAnim_SampleRootCurvePhase(obj, phase, d);
    if (*flags & 1) {
        if (hitDetectFn_800658a4(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                                 *(f32 *)(obj + 0x14), &ground, 0) == 0) {
            *(f32 *)(obj + 0x10) -= ground;
        }
    }
    if (moved != 0 && (*flags & 0x2) != 0) {
        int t = (s16)(getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80),
                               *(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88)) +
                      0x8000);
        *(s16 *)(obj + 0x0) =
            (s16)(*(s16 *)(obj + 0x0) + ((t - *(s16 *)(obj + 0x0)) >> 3));
    }
    return hit;
}
#pragma peephole reset
#pragma scheduling reset

extern int Obj_GetPlayerObject(void);
extern s16 *objModelGetVecFn_800395d8(int obj, int idx);
extern int ObjAnim_AdvanceCurrentMove(int objAnim, f32 moveStepScale, f32 deltaTime, int flags);
extern u8 framesThisStep;
extern f32 lbl_803E1CC4;

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */
#pragma scheduling off
#pragma peephole off
int dll_2E_func07(int obj, char *state, char *st, s16 a, s16 b)
{
    s16 pair[2];
    int mode;
    int player;

    player = Obj_GetPlayerObject();
    pair[0] = a;
    pair[1] = b;
    {
        char *p = *(char **)(obj + 0x54);
        *(s16 *)(p + 0x60) = *(s16 *)(p + 0x60) | 1;
    }
    mode = (s8)*(u8 *)(state + 0x56);
    if (mode == 4) {
        *(int *)(st + 0x5f8) = 0x50;
        *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) & ~8;
        *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) & ~2;
        *(u8 *)(st + 0x600) = 3;
        *(u8 *)(state + 0x56) = 5;
        if ((*(u8 *)(st + 0x611) & 2) == 0) {
            *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) & ~4;
        }
        *(void (**)(int *))(state + 0xe8) = fn_80114B1C;
        return 0;
    } else if (mode == 5) {
        if (*(u8 *)(st + 0x600) >= 2 && *(u8 *)(st + 0x600) <= 7) {
            void *types = seqFn_800394a0();
            switch (*(u8 *)(st + 0x600)) {
            case 3:
                objFn_8003acfc((int *)obj, (int *)types, *(u8 *)(st + 0x610), st + 0x1c);
                *(int *)(st + 0x5f8) = 0;
                *(u8 *)(st + 0x600) = 2;
            case 2:
                if (objAnimFn_80115650(obj, player, st + 0x5fc, st, st, pair, st + 0x10) == 0) {
                    *(u8 *)(st + 0x600) = 6;
                }
                break;
            case 6:
                *(u8 *)(st + 0x600) = 7;
            case 7:
                *(f32 *)(st + 0x0) = lbl_803E1CC4;
                break;
            }
            *(int *)(st + 0x604) = player;
            ObjAnim_AdvanceCurrentMove(obj, *(f32 *)(st + 0x0), (f32)framesThisStep, 0);
            if (*(u8 *)(st + 0x600) == 7) {
                s16 *v;
                *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) | 8;
                v = objModelGetVecFn_800395d8(obj, 0);
                if (v != NULL) {
                    *(s16 *)(state + 0x114) = v[1];
                    *(s16 *)(state + 0x116) = v[0];
                }
                *(u8 *)(st + 0x600) = 0;
                *(u8 *)(state + 0x56) = 0;
                *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) | 4;
                return 0;
            }
            return 0;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
