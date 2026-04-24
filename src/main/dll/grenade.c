#include "ghidra_import.h"
#include "main/dll/grenade.h"

extern bool FUN_800067f0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_80006ba8();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern undefined4 FUN_80017710();
extern int FUN_80017730();
extern uint FUN_80017760();
extern undefined4 FUN_80017a6c();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80036154();
extern int FUN_80037008();
extern undefined4 FUN_800381f8();
extern undefined4 FUN_80039468();
extern undefined4 FUN_80039580();
extern int FUN_800da5f0();
extern undefined4 FUN_800da700();
extern uint FUN_800db47c();
extern undefined4 FUN_8011e824();
extern int FUN_8012efc4();
extern undefined4 FUN_80139910();
extern int FUN_80139a48();
extern undefined4 FUN_80139a4c();
extern int FUN_8013b368();
extern undefined4 FUN_8013d8f0();
extern undefined4 FUN_80144e40();
extern undefined4 FUN_80145120();
extern undefined4 FUN_80146fa0();
extern undefined4 FUN_801778d0();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_802c295c;
extern undefined4 DAT_802c2960;
extern undefined4 DAT_802c2964;
extern undefined4 DAT_802c2968;
extern undefined4 DAT_802c296c;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e305c;
extern undefined4 DAT_803e3060;
extern f64 DOUBLE_803e30f0;
extern f64 DOUBLE_803e31b8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3074;
extern f32 FLOAT_803e307c;
extern f32 FLOAT_803e3080;
extern f32 FLOAT_803e3088;
extern f32 FLOAT_803e3098;
extern f32 FLOAT_803e30a0;
extern f32 FLOAT_803e30a4;
extern f32 FLOAT_803e30a8;
extern f32 FLOAT_803e30b4;
extern f32 FLOAT_803e30c8;
extern f32 FLOAT_803e30cc;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d4;
extern f32 FLOAT_803e3108;
extern f32 FLOAT_803e3114;
extern f32 FLOAT_803e3118;
extern f32 FLOAT_803e312c;
extern f32 FLOAT_803e313c;
extern f32 FLOAT_803e3158;
extern f32 FLOAT_803e3188;
extern f32 FLOAT_803e31a0;
extern f32 FLOAT_803e31a4;
extern f32 FLOAT_803e31a8;
extern f32 FLOAT_803e31ac;
extern f32 FLOAT_803e31b0;
extern f32 FLOAT_803e31b4;
extern f32 FLOAT_803e31c0;
extern void* PTR_FUN_8031dfa4;

/*
 * --INFO--
 *
 * Function: FUN_80141880
 * EN v1.0 Address: 0x80141880
 * EN v1.0 Size: 2176b
 * EN v1.1 Address: 0x80141C08
 * EN v1.1 Size: 1900b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80141880(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 *param_10,int param_11,undefined4 param_12,byte param_13
                 ,uint param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  float fVar2;
  ushort uVar3;
  bool bVar8;
  char cVar9;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar10;
  int iVar11;
  double dVar12;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  local_28[0] = DAT_803e3060;
  switch(*(undefined *)((int)param_10 + 10)) {
  case 0:
    param_11 = 2;
    iVar6 = FUN_800da5f0((float *)param_10[10],0xffffffff,2);
    uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(iVar6 + 0x1c));
    param_10[0x1c2] = uVar5;
    param_10[0x1c0] = iVar6;
    uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(iVar6 + 0x20));
    param_10[0x1c1] = uVar5;
    if (*(char *)(param_10[0x1c1] + 3) != '\0') {
      param_10[0x1c1] = param_10[0x1c1] ^ param_10[0x1c2];
      param_10[0x1c2] = param_10[0x1c2] ^ param_10[0x1c1];
      param_10[0x1c1] = param_10[0x1c1] ^ param_10[0x1c2];
    }
    if (param_10[10] != param_10[0x1c2] + 8) {
      param_10[10] = param_10[0x1c2] + 8;
      param_10[0x15] = param_10[0x15] & 0xfffffbff;
      *(undefined2 *)((int)param_10 + 0xd2) = 0;
    }
    *(undefined *)((int)param_10 + 10) = 1;
  case 1:
    FUN_80146fa0();
    FUN_8013b368((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar4 = FUN_800db47c((float *)(param_9 + 0xc),(undefined *)0x0);
    if (*(byte *)(param_10[0x1c2] + 3) == uVar4) {
      *(undefined *)((int)param_10 + 9) = 1;
      *(undefined *)((int)param_10 + 10) = 2;
    }
    break;
  case 2:
    FUN_80146fa0();
    FUN_8013d8f0((double)FLOAT_803e3118,(short *)param_9,(int)param_10,
                 (float *)(param_10[0x1c0] + 8),'\x01');
    iVar6 = FUN_80139a48();
    if (iVar6 == 0) {
      param_10[0x15] = param_10[0x15] | 0x2010;
      *(undefined *)((int)param_10 + 10) = 3;
    }
    else {
      iVar6 = FUN_800db47c((float *)(param_9 + 0xc),(undefined *)0x0);
      if (iVar6 == 0) {
        param_10[0x15] = param_10[0x15] | 0x2010;
      }
    }
    break;
  case 3:
    FUN_80139a4c((double)FLOAT_803e31a0,(int)param_9,0xe,0x4000000);
    param_10[0xb] = *(float *)(param_10[0x1c1] + 8) - *(float *)(param_10[0x1c0] + 8);
    param_10[0xc] = *(float *)(param_10[0x1c1] + 0x10) - *(float *)(param_10[0x1c0] + 0x10);
    FUN_800068d0((uint)param_9,0x13d);
    uStack_1c = FUN_80017760(0x14,0xb4);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    param_10[0x1c3] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e30f0);
    *(undefined *)((int)param_10 + 10) = 4;
  case 4:
    FUN_80146fa0();
    param_10[0x1c3] = (float)param_10[0x1c3] - FLOAT_803dc074;
    if ((float)param_10[0x1c3] <= FLOAT_803e306c) {
      uStack_1c = FUN_80017760(0x14,0xb4);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      param_10[0x1c3] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e30f0);
      param_10[0x1c3] = (float)param_10[0x1c3] * FLOAT_803e30b4;
      iVar6 = *(int *)(param_9 + 0x5c);
      if (((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < (short)param_9[0x50] || ((short)param_9[0x50] < 0x29)) &&
          (bVar8 = FUN_800067f0((int)param_9,0x10), !bVar8)))) {
        FUN_80039468(param_9,iVar6 + 0x3a8,0x360,0x500,0xffffffff,0);
      }
    }
    dVar12 = (double)(**(code **)(**(int **)(param_10[9] + 0x68) + 0x20))(param_10[9],param_9);
    *(float *)(param_9 + 6) =
         (float)((double)(float)param_10[0xb] * dVar12 + (double)*(float *)(param_10[0x1c0] + 8));
    *(float *)(param_9 + 10) =
         (float)((double)(float)param_10[0xc] * dVar12 + (double)*(float *)(param_10[0x1c0] + 0x10))
    ;
    fVar1 = *(float *)(*(int *)(param_9 + 0x5c) + 0x2c);
    fVar2 = *(float *)(*(int *)(param_9 + 0x5c) + 0x30);
    if (FLOAT_803e307c < fVar1 * fVar1 + fVar2 * fVar2) {
      iVar6 = FUN_80017730();
      FUN_80139910(param_9,(ushort)iVar6);
    }
    cVar9 = (**(code **)(**(int **)(param_10[9] + 0x68) + 0x24))();
    if (cVar9 != '\0') {
      iVar7 = 0;
      iVar6 = 0;
      iVar11 = 4;
      do {
        iVar10 = *(int *)(param_10[0x1c1] + iVar6 + 0x1c);
        if ((-1 < iVar10) && (iVar10 != *(int *)(param_10[0x1c0] + 0x14))) {
          param_10[0x1c0] = param_10[0x1c1];
          uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))
                            (*(undefined4 *)(param_10[0x1c1] + iVar7 * 4 + 0x1c));
          param_10[0x1c1] = uVar5;
          break;
        }
        iVar6 = iVar6 + 4;
        iVar7 = iVar7 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      *(char *)*param_10 = *(char *)*param_10 + -4;
      FUN_800068cc();
      *(undefined *)((int)param_10 + 10) = 5;
      uVar4 = FUN_80017760(0,1);
      uVar3 = *(ushort *)((int)local_28 + uVar4 * 2);
      iVar6 = *(int *)(param_9 + 0x5c);
      if ((((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < (short)param_9[0x50] || ((short)param_9[0x50] < 0x29)))) &&
         (bVar8 = FUN_800067f0((int)param_9,0x10), !bVar8)) {
        FUN_80039468(param_9,iVar6 + 0x3a8,uVar3,0x500,0xffffffff,0);
      }
    }
    break;
  case 5:
    FUN_80017710((float *)(param_9 + 0xc),(float *)(param_10[0x1c1] + 8));
    FUN_80146fa0();
    FUN_8013d8f0((double)FLOAT_803e3118,(short *)param_9,(int)param_10,
                 (float *)(param_10[0x1c1] + 8),'\x01');
    iVar6 = FUN_80139a48();
    if (iVar6 == 0) {
      iVar7 = 0;
      iVar6 = 0;
      iVar11 = 4;
      do {
        iVar10 = *(int *)(param_10[0x1c1] + iVar6 + 0x1c);
        if ((-1 < iVar10) && (iVar10 != *(int *)(param_10[0x1c0] + 0x14))) {
          param_10[0x1c0] = param_10[0x1c1];
          uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))
                            (*(undefined4 *)(param_10[0x1c1] + iVar7 * 4 + 0x1c));
          param_10[0x1c1] = uVar5;
          break;
        }
        iVar6 = iVar6 + 4;
        iVar7 = iVar7 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      *(undefined *)((int)param_10 + 10) = 6;
    }
    break;
  case 6:
    FUN_80146fa0();
    FUN_8013d8f0((double)FLOAT_803e3118,(short *)param_9,(int)param_10,
                 (float *)(param_10[0x1c1] + 8),'\x01');
    iVar6 = FUN_80139a48();
    if (iVar6 == 0) {
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar8 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar8 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar8 = false;
      }
      else {
        bVar8 = true;
      }
      if (bVar8) {
        FUN_80139a4c((double)FLOAT_803e30cc,(int)param_9,8,0);
        param_10[0x1e7] = FLOAT_803e30d0;
        param_10[0x20e] = FLOAT_803e306c;
        FUN_80146fa0();
      }
      else {
        FUN_80139a4c((double)FLOAT_803e30d4,(int)param_9,0,0);
        FUN_80146fa0();
      }
      param_10[0x15] = param_10[0x15] & 0xffffdfef;
      *(undefined *)((int)param_10 + 10) = 7;
    }
    break;
  case 7:
    FUN_80146fa0();
    iVar6 = FUN_800db47c((float *)(param_10[1] + 0x18),(undefined *)0x0);
    iVar7 = FUN_800db47c((float *)(param_9 + 0xc),(undefined *)0x0);
    if (iVar7 == iVar6) {
      *(undefined *)(param_10 + 2) = 1;
      *(undefined *)((int)param_10 + 10) = 0;
      fVar1 = FLOAT_803e306c;
      param_10[0x1c7] = FLOAT_803e306c;
      param_10[0x1c8] = fVar1;
      param_10[0x15] = param_10[0x15] & 0xffffffef;
      param_10[0x15] = param_10[0x15] & 0xfffeffff;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      param_10[0x15] = param_10[0x15] & 0xfffbffff;
      *(undefined *)((int)param_10 + 0xd) = 0xff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80142100
 * EN v1.0 Address: 0x80142100
 * EN v1.0 Size: 1948b
 * EN v1.1 Address: 0x80142374
 * EN v1.1 Size: 1336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80142100(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 *param_10,undefined4 param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  ushort uVar2;
  float fVar3;
  int iVar4;
  undefined4 uVar5;
  bool bVar7;
  char cVar8;
  uint uVar6;
  int iVar9;
  double dVar10;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  local_28[0] = DAT_803e305c;
  iVar9 = param_10[9];
  bVar1 = *(byte *)((int)param_10 + 10);
  if (bVar1 == 2) {
    iVar9 = FUN_8013b368((double)FLOAT_803e30a8,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,iVar9,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar9 == 0) {
      param_10[0x15] = param_10[0x15] | 0x10;
      *(undefined *)((int)param_10 + 10) = 3;
      param_10[0x1c0] = FLOAT_803e306c;
      FUN_800068d0(param_9,0x13d);
      FUN_80139a4c((double)FLOAT_803e31a0,param_9,0xe,0x4000000);
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      iVar4 = iVar9 + 0x18;
      iVar9 = 2;
      uVar5 = FUN_800da700(iVar4,0xffffffff,2);
      param_10[0x1c3] = uVar5;
      if ((param_10[0x1c3] != 0) &&
         (dVar10 = FUN_80017708((float *)(param_10[9] + 0x18),(float *)(param_10[0x1c3] + 8)),
         (double)FLOAT_803e31a4 < dVar10)) {
        param_10[0x1c3] = 0;
      }
      *(undefined *)((int)param_10 + 10) = 1;
    }
    iVar9 = FUN_8013b368((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,iVar9,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar9 == 0) {
      if (param_10[0x1c3] == 0) {
        param_10[0x15] = param_10[0x15] | 0x10;
        *(undefined *)((int)param_10 + 10) = 3;
        param_10[0x1c0] = FLOAT_803e306c;
        uStack_1c = FUN_80017760(0x28,0x50);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        param_10[0x1c4] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e30f0);
        FUN_800068d0(param_9,0x13d);
        FUN_80139a4c((double)FLOAT_803e31a0,param_9,0xe,0x4000000);
      }
      else {
        *(undefined *)((int)param_10 + 10) = 2;
        if (param_10[10] != param_10[0x1c3] + 8) {
          param_10[10] = param_10[0x1c3] + 8;
          param_10[0x15] = param_10[0x15] & 0xfffffbff;
          *(undefined2 *)((int)param_10 + 0xd2) = 0;
        }
      }
    }
    else if (iVar9 == 2) {
      *(undefined *)(param_10 + 2) = 1;
      *(undefined *)((int)param_10 + 10) = 0;
      fVar3 = FLOAT_803e306c;
      param_10[0x1c7] = FLOAT_803e306c;
      param_10[0x1c8] = fVar3;
      param_10[0x15] = param_10[0x15] & 0xffffffef;
      param_10[0x15] = param_10[0x15] & 0xfffeffff;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      param_10[0x15] = param_10[0x15] & 0xfffbffff;
      *(undefined *)((int)param_10 + 0xd) = 0xff;
    }
  }
  else if (bVar1 == 4) {
    param_10[0x1c4] = (float)param_10[0x1c4] - FLOAT_803dc074;
    if ((float)param_10[0x1c4] <= FLOAT_803e306c) {
      uStack_1c = FUN_80017760(0x28,0x50);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      param_10[0x1c4] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e30f0);
      param_10[0x1c4] = (float)param_10[0x1c4] * FLOAT_803e30b4;
      iVar4 = *(int *)(param_9 + 0xb8);
      if (((*(byte *)(iVar4 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
          (bVar7 = FUN_800067f0(param_9,0x10), !bVar7)))) {
        FUN_80039468(param_9,iVar4 + 0x3a8,0x360,0x500,0xffffffff,0);
      }
    }
    dVar10 = (double)(**(code **)(**(int **)(iVar9 + 0x68) + 0x20))(iVar9,param_9);
    *(float *)(param_9 + 0xc) =
         -(float)((double)(float)param_10[0xb] * dVar10 - (double)(float)param_10[0x1c1]);
    *(float *)(param_9 + 0x14) =
         -(float)((double)(float)param_10[0xc] * dVar10 - (double)(float)param_10[0x1c2]);
    cVar8 = (**(code **)(**(int **)(iVar9 + 0x68) + 0x24))(iVar9);
    if (cVar8 != '\0') {
      FUN_800068cc();
      *(char *)*param_10 = *(char *)*param_10 + -4;
      *(undefined *)(param_10 + 2) = 1;
      *(undefined *)((int)param_10 + 10) = 0;
      fVar3 = FLOAT_803e306c;
      param_10[0x1c7] = FLOAT_803e306c;
      param_10[0x1c8] = fVar3;
      param_10[0x15] = param_10[0x15] & 0xffffffef;
      param_10[0x15] = param_10[0x15] & 0xfffeffff;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      param_10[0x15] = param_10[0x15] & 0xfffbffff;
      *(undefined *)((int)param_10 + 0xd) = 0xff;
      uVar6 = FUN_80017760(0,1);
      uVar2 = *(ushort *)((int)local_28 + uVar6 * 2);
      iVar9 = *(int *)(param_9 + 0xb8);
      if ((((*(byte *)(iVar9 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)))) &&
         (bVar7 = FUN_800067f0(param_9,0x10), !bVar7)) {
        FUN_80039468(param_9,iVar9 + 0x3a8,uVar2,0x500,0xffffffff,0);
      }
    }
  }
  else if (bVar1 < 4) {
    param_10[0x1c0] = (float)param_10[0x1c0] + FLOAT_803dc074;
    param_10[0x1c4] = (float)param_10[0x1c4] - FLOAT_803dc074;
    if (FLOAT_803e3188 <= (float)param_10[0x1c0]) {
      *(undefined *)((int)param_10 + 10) = 4;
      param_10[0x1c1] = *(undefined4 *)(param_9 + 0x18);
      param_10[0x1c2] = *(undefined4 *)(param_9 + 0x20);
      iVar9 = param_10[0x1c3];
      if (iVar9 != 0) {
        param_10[0xb] = *(float *)(iVar9 + 8) - *(float *)(param_10[9] + 0x18);
        param_10[0xc] = *(float *)(iVar9 + 0x10) - *(float *)(param_10[9] + 0x20);
        dVar10 = FUN_80293900((double)((float)param_10[0xb] * (float)param_10[0xb] +
                                      (float)param_10[0xc] * (float)param_10[0xc]));
        if ((double)FLOAT_803e306c != dVar10) {
          param_10[0xb] = (float)((double)(float)param_10[0xb] / dVar10);
          param_10[0xc] = (float)((double)(float)param_10[0xc] / dVar10);
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014289c
 * EN v1.0 Address: 0x8014289C
 * EN v1.0 Size: 1752b
 * EN v1.1 Address: 0x801428AC
 * EN v1.1 Size: 1264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014289c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int *param_10,undefined4 param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  float fVar2;
  uint uVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  undefined2 *puVar7;
  
  puVar7 = (undefined2 *)0x0;
  if ((param_10[0x15] & 0x10U) == 0) {
    if (*(char *)(param_10 + 500) != '\0') {
      if (*(char *)(param_10 + 500) == '\x01') {
        iVar6 = param_10[0x1f5];
        iVar5 = *(int *)(param_9 + 0x5c);
        if ((param_9[0x58] & 0x1000) == 0) {
          if ((*(uint *)(iVar5 + 0x54) & 0x10) == 0) {
            *(int *)(iVar5 + 0x24) = iVar6;
            if (*(int *)(iVar5 + 0x28) != iVar6 + 0x18) {
              *(int *)(iVar5 + 0x28) = iVar6 + 0x18;
              *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) & 0xfffffbff;
              *(undefined2 *)(iVar5 + 0xd2) = 0;
            }
            *(undefined *)(iVar5 + 10) = 0;
            *(undefined *)(iVar5 + 8) = 10;
          }
          else {
            *(undefined *)(iVar5 + 2000) = 1;
            *(int *)(iVar5 + 0x7d4) = iVar6;
            *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) | 0x10000;
          }
        }
        iVar5 = FUN_801451dc((int)param_9,param_10);
        if ((iVar5 == 0) &&
           (iVar5 = FUN_8013b368((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,
                                 param_7,param_8,param_9,param_10,iVar6,param_12,param_13,param_14,
                                 param_15,param_16), iVar5 == 0)) {
          param_10[0x1d0] = (int)((float)param_10[0x1d0] - FLOAT_803dc074);
          if ((float)param_10[0x1d0] <= FLOAT_803e306c) {
            uVar3 = FUN_80017760(500,0x2ee);
            param_10[0x1d0] =
                 (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
            iVar5 = *(int *)(param_9 + 0x5c);
            if (((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < (short)param_9[0x50] || ((short)param_9[0x50] < 0x29)) &&
                (bVar4 = FUN_800067f0((int)param_9,0x10), !bVar4)))) {
              FUN_80039468(param_9,iVar5 + 0x3a8,0x360,0x500,0xffffffff,0);
            }
          }
          if (FLOAT_803e306c == (float)param_10[0xab]) {
            bVar4 = false;
          }
          else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
            bVar4 = true;
          }
          else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
            bVar4 = false;
          }
          else {
            bVar4 = true;
          }
          if (bVar4) {
            FUN_80139a4c((double)FLOAT_803e30cc,(int)param_9,8,0);
            param_10[0x1e7] = (int)FLOAT_803e30d0;
            param_10[0x20e] = (int)FLOAT_803e306c;
            FUN_80146fa0();
          }
          else {
            sVar1 = param_9[0x50];
            if (sVar1 != 0x31) {
              if ((sVar1 < 0x31) && (sVar1 == 0xd)) {
                if ((param_10[0x15] & 0x8000000U) != 0) {
                  FUN_80139a4c((double)FLOAT_803e30cc,(int)param_9,0x31,0);
                }
              }
              else {
                FUN_80139a4c((double)FLOAT_803e30d4,(int)param_9,0xd,0);
              }
            }
            FUN_80146fa0();
          }
        }
      }
      *(undefined *)(param_10 + 500) = 0;
      return;
    }
    puVar7 = (undefined2 *)FUN_80145120((int)param_9,(int)param_10);
  }
  if (puVar7 == (undefined2 *)0x0) {
    param_10[0x1c7] = (int)((float)param_10[0x1c7] - FLOAT_803dc074);
    if ((float)param_10[0x1c7] < FLOAT_803e306c) {
      param_10[0x1c7] = (int)FLOAT_803e306c;
    }
    FUN_80144e40((int)param_9,(int)param_10);
    iVar5 = (*(code *)(&PTR_FUN_8031dfa4)[*(byte *)((int)param_10 + 10)])(param_9,param_10);
    if (iVar5 == 0) {
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar4 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_80139a4c((double)FLOAT_803e30cc,(int)param_9,8,0);
        param_10[0x1e7] = (int)FLOAT_803e30d0;
        param_10[0x20e] = (int)FLOAT_803e306c;
      }
      else {
        FUN_80139a4c((double)FLOAT_803e31a8,(int)param_9,0x25,0);
      }
    }
  }
  else {
    *(undefined *)(param_10 + 0xdd) = 2;
    (**(code **)(*DAT_803dd728 + 0x20))(param_9,param_10 + 0x3e);
    *(undefined *)(param_10 + 2) = 1;
    *(undefined *)((int)param_10 + 10) = 0;
    fVar2 = FLOAT_803e306c;
    param_10[0x1c7] = (int)FLOAT_803e306c;
    param_10[0x1c8] = (int)fVar2;
    param_10[0x15] = param_10[0x15] & 0xffffffef;
    param_10[0x15] = param_10[0x15] & 0xfffeffff;
    param_10[0x15] = param_10[0x15] & 0xfffdffff;
    param_10[0x15] = param_10[0x15] & 0xfffbffff;
    *(undefined *)((int)param_10 + 0xd) = 0xff;
    *(undefined4 *)(param_9 + 6) = *(undefined4 *)(puVar7 + 6);
    *(undefined4 *)(param_9 + 8) = *(undefined4 *)(puVar7 + 8);
    *(undefined4 *)(param_9 + 10) = *(undefined4 *)(puVar7 + 10);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(puVar7 + 0xc);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(puVar7 + 0xe);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(puVar7 + 0x10);
    FUN_80036154((int)param_9);
    *param_9 = *puVar7;
    *(undefined *)((int)param_10 + 9) = 0;
    fVar2 = FLOAT_803e306c;
    param_10[4] = (int)FLOAT_803e306c;
    param_10[5] = (int)fVar2;
    param_10[0x38] = *(int *)(puVar7 + 0xc);
    param_10[0x39] = *(int *)(puVar7 + 0xe);
    param_10[0x3a] = *(int *)(puVar7 + 0x10);
    param_10[0x15] = param_10[0x15] | 0x80000;
    param_10[0x15] = param_10[0x15] & 0xffffdfff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80142f74
 * EN v1.0 Address: 0x80142F74
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x80142D9C
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80142f74(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10,undefined4 param_11,undefined4 param_12,byte param_13,uint param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar2;
  char cVar3;
  uint uVar1;
  float *pfVar4;
  int iVar5;
  double dVar6;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  pfVar4 = &local_28;
  FUN_80039580(*(int *)(param_10 + 0x24),0,pfVar4);
  dVar6 = FUN_80017708(&local_28,(float *)(param_10 + 0x72c));
  if ((double)FLOAT_803e30b4 < dVar6) {
    *(float *)(param_10 + 0x72c) = local_28;
    *(undefined4 *)(param_10 + 0x730) = local_24;
    *(undefined4 *)(param_10 + 0x734) = local_20;
  }
  if ((*(byte *)(param_10 + 0x728) >> 5 & 1) == 0) {
    cVar3 = FUN_8013b368((double)FLOAT_803e3158,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,(int)pfVar4,param_12,param_13,param_14,param_15,
                         param_16);
    if (cVar3 != '\x01') {
      *(byte *)(param_10 + 0x728) = *(byte *)(param_10 + 0x728) & 0xdf | 0x20;
      uVar1 = FUN_80017760(0x35e,0x35f);
      iVar5 = *(int *)(param_9 + 0xb8);
      if (((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
          (bVar2 = FUN_800067f0(param_9,0x10), !bVar2)))) {
        FUN_80039468(param_9,iVar5 + 0x3a8,(ushort)uVar1,0x500,0xffffffff,0);
      }
      return 0;
    }
  }
  else {
    bVar2 = FUN_800067f0(param_9,0x10);
    if (bVar2) {
      return 0;
    }
    FUN_80145074(param_9,param_10);
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80143160
 * EN v1.0 Address: 0x80143160
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x80142EF4
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80143160(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 uVar4;
  bool bVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  double extraout_f1;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  if (*(short *)(uVar1 + 0xa0) == 0x1a) {
    dVar9 = (double)*(float *)(uVar1 + 0x98);
    if ((dVar9 <= (double)FLOAT_803e313c) || ((*(uint *)(iVar6 + 0x54) & 0x800) != 0)) {
      if ((*(uint *)(iVar6 + 0x54) & 0x8000000) != 0) {
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffff7ff;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x1000;
        iVar8 = 0;
        iVar7 = iVar6;
        do {
          FUN_801778d0(*(int *)(iVar7 + 0x700));
          iVar7 = iVar7 + 4;
          iVar8 = iVar8 + 1;
        } while (iVar8 < 7);
        FUN_800068cc();
        iVar7 = *(int *)(uVar1 + 0xb8);
        if (((*(byte *)(iVar7 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(uVar1 + 0xa0) || (*(short *)(uVar1 + 0xa0) < 0x29)) &&
            (bVar5 = FUN_800067f0(uVar1,0x10), !bVar5)))) {
          FUN_80039468(uVar1,iVar7 + 0x3a8,0x29d,0,0xffffffff,0);
        }
        *(undefined *)(iVar6 + 10) = 10;
      }
    }
    else {
      uVar2 = FUN_80017ae8();
      if ((uVar2 & 0xff) != 0) {
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x800;
        iVar7 = 0;
        do {
          puVar3 = FUN_80017aa4(0x24,0x4f0);
          *(undefined *)(puVar3 + 2) = 2;
          *(undefined *)((int)puVar3 + 5) = 1;
          puVar3[0xd] = (short)iVar7;
          uVar4 = FUN_80017ae4(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                               5,*(undefined *)(uVar1 + 0xac),0xffffffff,*(uint **)(uVar1 + 0x30),
                               in_r8,in_r9,in_r10);
          *(undefined4 *)(iVar6 + 0x700) = uVar4;
          iVar6 = iVar6 + 4;
          iVar7 = iVar7 + 1;
          dVar9 = extraout_f1;
        } while (iVar7 < 7);
        FUN_80006824(uVar1,0x3db);
        FUN_800068d0(uVar1,0x3dc);
      }
    }
  }
  else {
    FUN_80139a4c((double)FLOAT_803e3074,uVar1,0x1a,0);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801433c8
 * EN v1.0 Address: 0x801433C8
 * EN v1.0 Size: 556b
 * EN v1.1 Address: 0x801430B4
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_801433c8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,undefined4 param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  
  puVar5 = &DAT_802c295c;
  local_28 = DAT_802c295c;
  local_24 = DAT_802c2960;
  local_20 = DAT_802c2964;
  local_1c = DAT_802c2968;
  local_18 = DAT_802c296c;
  iVar1 = FUN_801451dc(param_9,param_10);
  if (iVar1 != 0) {
    param_10[0x1c8] = (int)FLOAT_803e306c;
    param_10[0x15] = param_10[0x15] & 0xffffffef;
    *(undefined *)((int)param_10 + 10) = 0;
    return true;
  }
  iVar4 = *DAT_803dd6e8;
  iVar1 = (**(code **)(iVar4 + 0x24))(&local_28,5);
  if (iVar1 != 2) {
    if (iVar1 < 2) {
      if (iVar1 < 0) goto LAB_801431cc;
    }
    else if (5 < iVar1) goto LAB_801431cc;
    iVar1 = *(int *)(param_9 + 0xb8);
    if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
        (bVar2 = FUN_800067f0(param_9,0x10), !bVar2)))) {
      iVar4 = 0x35d;
      puVar5 = (undefined4 *)0x500;
      param_13 = 0xff;
      param_14 = 0;
      FUN_80039468(param_9,iVar1 + 0x3a8,0x35d,0x500,0xffffffff,0);
    }
  }
LAB_801431cc:
  if (FLOAT_803e306c == (float)param_10[0x1c8]) {
    param_10[0x15] = param_10[0x15] & 0xffffffef;
    *(undefined *)((int)param_10 + 10) = 0;
  }
  cVar3 = FUN_8013b368((double)FLOAT_803e3098,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,param_10,iVar4,puVar5,param_13,param_14,param_15,param_16);
  return cVar3 == '\x01';
}

/*
 * --INFO--
 *
 * Function: FUN_801435f4
 * EN v1.0 Address: 0x801435F4
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80143238
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801435f4(int param_1,int *param_2)
{
  short sVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  undefined auStack_28 [8];
  float local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar3 = FUN_801451dc(param_1,param_2);
  if (iVar3 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 0x2e) {
      if (((param_2[0x15] & 0x8000000U) != 0) &&
         ((((param_2[0x15] & 0x10000U) != 0 || (uVar4 = FUN_80017760(0,2), uVar4 == 0)) ||
          (FLOAT_803e306c < (float)param_2[0x1c8])))) {
        FUN_80139a4c((double)FLOAT_803e307c,param_1,0x2f,0);
      }
      local_1c = *(undefined4 *)(param_1 + 0x18);
      local_18 = *(undefined4 *)(param_1 + 0x1c);
      local_14 = *(undefined4 *)(param_1 + 0x20);
      local_20 = FLOAT_803e3080;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7e6,auStack_28,0x200001,0xffffffff,0);
    }
    else if (sVar1 < 0x2e) {
      if ((0x2b < sVar1) && ((param_2[0x15] & 0x8000000U) != 0)) {
        FUN_80139a4c((double)FLOAT_803e312c,param_1,0x2e,0);
      }
    }
    else if ((sVar1 < 0x30) && ((param_2[0x15] & 0x8000000U) != 0)) {
      if (FLOAT_803e306c == (float)param_2[0xab]) {
        bVar2 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_2[0xac]) {
        bVar2 = true;
      }
      else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e30a4) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      if (bVar2) {
        FUN_80139a4c((double)FLOAT_803e30cc,param_1,8,0);
        param_2[0x1e7] = (int)FLOAT_803e30d0;
        param_2[0x20e] = (int)FLOAT_803e306c;
        FUN_80146fa0();
      }
      else {
        FUN_80139a4c((double)FLOAT_803e30d4,param_1,0,0);
        FUN_80146fa0();
      }
      param_2[0x15] = param_2[0x15] & 0xffffffef;
      *(undefined *)((int)param_2 + 10) = 0;
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80143854
 * EN v1.0 Address: 0x80143854
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x80143468
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80143854(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int *param_10,int param_11,undefined4 param_12,byte param_13,uint param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  char cVar3;
  bool bVar4;
  uint uVar2;
  
  iVar1 = FUN_801451dc(param_9,param_10);
  if ((iVar1 == 0) &&
     (cVar3 = FUN_8013b368((double)FLOAT_803e30a8,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                           param_16), cVar3 != '\x01')) {
    if (param_10[0x1ec] == 0) {
      uVar2 = FUN_80017760(0,6);
      if (((int)uVar2 < 5) && (-1 < (int)uVar2)) {
        FUN_80145074(param_9,(int)param_10);
      }
      else {
        FUN_80144dc0();
      }
    }
    else {
      iVar1 = *(int *)(param_9 + 0xb8);
      if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
          (bVar4 = FUN_800067f0(param_9,0x10), !bVar4)))) {
        FUN_80039468(param_9,iVar1 + 0x3a8,0x357,0,0xffffffff,0);
      }
      FUN_80139a4c((double)FLOAT_803e31ac,param_9,0x26,0);
      *(undefined *)((int)param_10 + 10) = 5;
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80143a14
 * EN v1.0 Address: 0x80143A14
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80143598
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80143a14(int param_1,int *param_2)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = FUN_801451dc(param_1,param_2);
  if (iVar2 == 0) {
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 0x24) {
      if (((param_2[0x15] & 0x8000000U) != 0) && (uVar3 = FUN_80017760(0,3), uVar3 == 0)) {
        *(undefined *)((int)param_2 + 10) = 0;
      }
    }
    else if (((sVar1 < 0x24) && (0x22 < sVar1)) && ((param_2[0x15] & 0x8000000U) != 0)) {
      FUN_80139a4c((double)FLOAT_803e3108,param_1,0x24,0);
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80143abc
 * EN v1.0 Address: 0x80143ABC
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80143654
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80143abc(int param_1,int *param_2)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = FUN_801451dc(param_1,param_2);
  if (iVar2 == 0) {
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 0x22) {
      if (((param_2[0x15] & 0x8000000U) != 0) && (uVar3 = FUN_80017760(0,3), uVar3 == 0)) {
        *(undefined *)((int)param_2 + 10) = 0;
      }
    }
    else if (((sVar1 < 0x22) && (0x20 < sVar1)) && ((param_2[0x15] & 0x8000000U) != 0)) {
      FUN_80139a4c((double)FLOAT_803e3108,param_1,0x22,0);
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80143b64
 * EN v1.0 Address: 0x80143B64
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x80143710
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80143b64(int param_1,int *param_2)
{
  int iVar1;
  bool bVar2;
  int iVar3;
  
  iVar1 = FUN_801451dc(param_1,param_2);
  if (iVar1 == 0) {
    for (iVar1 = 0; iVar1 < *(char *)((int)param_2 + 0x827); iVar1 = iVar1 + 1) {
      if ((((*(char *)((int)param_2 + iVar1 + 0x81f) == '\0') &&
           (iVar3 = *(int *)(param_1 + 0xb8), (*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0)) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (bVar2 = FUN_800067f0(param_1,0x10), !bVar2)) {
        FUN_80039468(param_1,iVar3 + 0x3a8,0x357,0,0xffffffff,0);
      }
    }
    iVar1 = FUN_801451dc(param_1,param_2);
    if (((iVar1 == 0) && ((param_2[0x15] & 0x8000000U) != 0)) &&
       (param_2[8] == (int)*(short *)(param_1 + 0xa0))) {
      *(undefined *)((int)param_2 + 10) = 0;
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80143c64
 * EN v1.0 Address: 0x80143C64
 * EN v1.0 Size: 972b
 * EN v1.1 Address: 0x80143838
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80143c64(int param_1,int *param_2)
{
  char cVar1;
  short sVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  undefined auStack_28 [12];
  int local_1c;
  float local_18;
  int local_14;
  
  iVar5 = FUN_801451dc(param_1,param_2);
  if (iVar5 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    sVar2 = *(short *)(param_1 + 0xa0);
    if (sVar2 == 0x2a) {
      param_2[0x1cf] = (int)((float)param_2[0x1cf] - FLOAT_803dc074);
      if ((float)param_2[0x1cf] <= FLOAT_803e306c) {
        if (((param_2[0x15] & 0x10000U) != 0) || (FLOAT_803e306c < (float)param_2[0x1c8])) {
          FUN_80139a4c((double)FLOAT_803e307c,param_1,0x2b,0);
        }
        else {
          iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
          if (iVar5 == 0) {
            FUN_80139a4c((double)FLOAT_803e31ac,param_1,0x2c,0);
            *(undefined *)((int)param_2 + 10) = 9;
          }
        }
      }
      for (iVar5 = 0; iVar5 < *(char *)((int)param_2 + 0x827); iVar5 = iVar5 + 1) {
        cVar1 = *(char *)((int)param_2 + iVar5 + 0x81f);
        if (cVar1 == '\0') {
          FUN_80039468(param_1,param_2 + 0xea,0x390,0x500,0xffffffff,0);
        }
        else if (cVar1 == '\a') {
          FUN_80039468(param_1,param_2 + 0xea,0x391,0x100,0xffffffff,0);
        }
      }
      fVar3 = (float)param_2[0x1d1] - FLOAT_803dc074;
      param_2[0x1d1] = (int)fVar3;
      if (fVar3 <= FLOAT_803e306c) {
        if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
          local_1c = param_2[0x102];
          local_18 = FLOAT_803e3088 + (float)param_2[0x103];
          local_14 = param_2[0x104];
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7f0,auStack_28,0x200001,0xffffffff,0);
        }
        param_2[0x1d1] = (int)FLOAT_803e3158;
      }
    }
    else if (sVar2 < 0x2a) {
      if ((0x28 < sVar2) && ((param_2[0x15] & 0x8000000U) != 0)) {
        FUN_80139a4c((double)FLOAT_803e31b0,param_1,0x2a,0);
      }
    }
    else if ((sVar2 < 0x2c) && ((param_2[0x15] & 0x8000000U) != 0)) {
      if (FLOAT_803e306c == (float)param_2[0xab]) {
        bVar4 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_2[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e30a4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_80139a4c((double)FLOAT_803e30cc,param_1,8,0);
        param_2[0x1e7] = (int)FLOAT_803e30d0;
        param_2[0x20e] = (int)FLOAT_803e306c;
        FUN_80146fa0();
      }
      else {
        FUN_80139a4c((double)FLOAT_803e30d4,param_1,0,0);
        FUN_80146fa0();
      }
      param_2[0x15] = param_2[0x15] & 0xffffffef;
      *(undefined *)((int)param_2 + 10) = 0;
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80144030
 * EN v1.0 Address: 0x80144030
 * EN v1.0 Size: 1136b
 * EN v1.1 Address: 0x80143B5C
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80144030(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int *param_10)
{
  float fVar1;
  int iVar2;
  bool bVar5;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar6;
  char local_28 [28];
  
  iVar2 = FUN_801451dc(param_9,param_10);
  if (iVar2 == 0) {
    iVar2 = FUN_8012efc4();
    if (iVar2 == 0xc1) {
      *(undefined *)((int)param_10 + 10) = 0;
    }
    else {
      param_10[0x1ce] = (int)((float)param_10[0x1ce] - FLOAT_803dc074);
      dVar6 = (double)(float)param_10[0x1ce];
      if (dVar6 < (double)FLOAT_803e306c) {
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar5 = FUN_800067f0(param_9,0x10), !bVar5)))) {
          in_r8 = 0;
          dVar6 = (double)FUN_80039468(param_9,iVar2 + 0x3a8,0x29a,0x100,0xffffffff,0);
        }
        param_10[0x1ce] = (int)FLOAT_803e30d0;
      }
      if ((param_10[0x1ee] == 0) && (uVar3 = FUN_80017ae8(), (uVar3 & 0xff) != 0)) {
        puVar4 = FUN_80017aa4(0x20,0x17b);
        local_28[0] = -1;
        local_28[1] = -1;
        local_28[2] = -1;
        if (param_10[0x1ea] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 6] = '\x01';
        }
        if (param_10[0x1ec] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 4 & 3] = '\x01';
        }
        if (param_10[0x1ee] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 2 & 3] = '\x01';
        }
        if (local_28[0] == -1) {
          uVar3 = 0;
        }
        else if (local_28[1] == -1) {
          uVar3 = 1;
        }
        else if (local_28[2] == -1) {
          uVar3 = 2;
        }
        else if (local_28[3] == -1) {
          uVar3 = 3;
        }
        else {
          uVar3 = 0xffffffff;
        }
        *(byte *)(param_10 + 0x1ef) =
             (byte)((uVar3 & 0xff) << 2) & 0xc | *(byte *)(param_10 + 0x1ef) & 0xf3;
        iVar2 = FUN_80017ae4(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,4,
                             0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,in_r10);
        param_10[0x1ee] = iVar2;
        FUN_800381f8(param_9,param_10[0x1ee],*(byte *)(param_10 + 0x1ef) >> 2 & 3);
        fVar1 = FLOAT_803e306c;
        param_10[0x1f0] = (int)FLOAT_803e306c;
        param_10[0x1f1] = (int)fVar1;
        param_10[0x1f2] = (int)fVar1;
      }
      iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
      if (((iVar2 != 0) && ((float)param_10[0x1c7] <= FLOAT_803e306c)) &&
         (uVar3 = FUN_80017690(0xdd), uVar3 != 0)) {
        FUN_80139a4c((double)FLOAT_803e30d4,param_9,0x29,0);
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar5 = FUN_800067f0(param_9,0x10), !bVar5)))) {
          FUN_80039468(param_9,iVar2 + 0x3a8,0x354,0x1000,0xffffffff,0);
        }
        param_10[0x15] = param_10[0x15] | 0x10;
        *(undefined *)((int)param_10 + 10) = 4;
        uVar3 = FUN_80017760(0x78,0xf0);
        param_10[0x1cf] =
             (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
      }
    }
  }
  else {
    *(undefined *)((int)param_10 + 10) = 0;
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_801444a0
 * EN v1.0 Address: 0x801444A0
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x80143E8C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801444a0(int param_1,int *param_2)
{
  int iVar1;
  
  iVar1 = FUN_801451dc(param_1,param_2);
  if (((iVar1 == 0) && ((param_2[0x15] & 0x8000000U) != 0)) &&
     (param_2[8] == (int)*(short *)(param_1 + 0xa0))) {
    *(undefined *)((int)param_2 + 10) = 0;
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80144508
 * EN v1.0 Address: 0x80144508
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80143F00
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80144508(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int *param_10,int param_11,undefined4 param_12,byte param_13,uint param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_801451dc(param_9,param_10);
  if (iVar1 == 0) {
    iVar1 = FUN_8013b368((double)FLOAT_803e3098,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar1 == 1) {
      if (FLOAT_803e306c == (float)param_10[0x1c7]) {
        *(undefined *)((int)param_10 + 10) = 0;
      }
      uVar2 = 1;
    }
    else {
      *(undefined *)((int)param_10 + 10) = 0;
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80144660
 * EN v1.0 Address: 0x80144660
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x80143F8C
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80144660(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int *param_10,int param_11,undefined4 param_12,byte param_13,uint param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  char cVar3;
  bool bVar4;
  undefined4 uVar2;
  int iVar5;
  
  param_10[9] = param_10[1];
  if (param_10[10] != param_10[9] + 0x18) {
    param_10[10] = param_10[9] + 0x18;
    param_10[0x15] = param_10[0x15] & 0xfffffbff;
    *(undefined2 *)((int)param_10 + 0xd2) = 0;
  }
  if (FLOAT_803e306c == (float)param_10[0x1c7]) {
    *(undefined *)((int)param_10 + 0xd) = 0xff;
    fVar1 = FLOAT_803e3158;
  }
  else {
    fVar1 = FLOAT_803e3098;
    if ((param_10[0x15] & 0x20000U) != 0) {
      *(undefined *)((int)param_10 + 0xd) = 0;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      fVar1 = FLOAT_803e3098;
    }
  }
  cVar3 = FUN_8013b368((double)fVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                       ,param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  if (cVar3 == '\x01') {
    *(byte *)(param_10 + 0x1ca) = *(byte *)(param_10 + 0x1ca) & 0x7f | 0x80;
    uVar2 = 1;
  }
  else {
    if ((((cVar3 == '\x02') && ((param_10[0x15] & 2U) != 0)) &&
        (iVar5 = *(int *)(param_9 + 0xb8), (*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0)) &&
       (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
        (bVar4 = FUN_800067f0(param_9,0x10), !bVar4)))) {
      FUN_80039468(param_9,iVar5 + 0x3a8,0x35d,0x500,0xffffffff,0);
    }
    if (FLOAT_803e306c == (float)param_10[0xab]) {
      bVar4 = false;
    }
    else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
      bVar4 = true;
    }
    else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
      bVar4 = false;
    }
    else {
      bVar4 = true;
    }
    if (bVar4) {
      uVar2 = 0;
    }
    else {
      uVar2 = FUN_80144904(param_9,param_10);
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80144904
 * EN v1.0 Address: 0x80144904
 * EN v1.0 Size: 1212b
 * EN v1.1 Address: 0x8014415C
 * EN v1.1 Size: 1004b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80144904(int param_1,int *param_2)
{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  bool bVar4;
  
  iVar1 = FUN_801451dc(param_1,param_2);
  if (iVar1 == 0) {
    if (FLOAT_803e306c < (float)param_2[0x1e7]) {
      FUN_80139a4c((double)FLOAT_803e307c,param_1,0x1b,0);
      *(undefined *)((int)param_2 + 10) = 2;
      param_2[0x1e7] = (int)FLOAT_803e306c;
      uVar2 = 1;
    }
    else {
      if (*(char *)(param_2 + 0x1ca) < '\0') {
        param_2[0x1c9] = (int)FLOAT_803e31b4;
        *(byte *)(param_2 + 0x1ca) = *(byte *)(param_2 + 0x1ca) & 0x7f;
        *(byte *)(param_2 + 0x1ca) = *(byte *)(param_2 + 0x1ca) & 0xbf | 0x40;
      }
      if ((*(byte *)(param_2 + 0x1ca) >> 6 & 1) == 0) {
        bVar4 = FUN_800067f0(param_1,0x10);
        if (bVar4) {
          uVar2 = 1;
        }
        else {
          iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
          if (iVar1 == 0) {
            param_2[0x15] = param_2[0x15] & 0xdfffffff;
          }
          iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
          if ((iVar1 == 0) || ((param_2[0x15] & 0x20000000U) != 0)) {
            if (*(byte *)*param_2 < 4) {
              FUN_80139a4c((double)FLOAT_803e30d4,param_1,0x14,0);
              *(undefined *)((int)param_2 + 10) = 3;
              param_2[0x1ce] = (int)FLOAT_803e30d0;
              uVar2 = 1;
            }
            else {
              param_2[0x1c9] = (int)((float)param_2[0x1c9] - FLOAT_803dc074);
              if (FLOAT_803e306c < (float)param_2[0x1c9]) {
                uVar2 = 0;
              }
              else {
                uVar3 = FUN_80017760(200,500);
                param_2[0x1c9] =
                     (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0)
                ;
                if (*(byte *)*param_2 < 8) {
                  FUN_80139a4c((double)FLOAT_803e30d4,param_1,0x14,0);
                  *(undefined *)((int)param_2 + 10) = 3;
                  param_2[0x1ce] = (int)FLOAT_803e30d0;
                  uVar2 = 1;
                }
                else {
                  if ((float)param_2[0x1c7] <= FLOAT_803e306c) {
                    if (param_2[0x1ec] == 0) {
                      uVar3 = FUN_80017760(0,6);
                      if (((int)uVar3 < 5) && (-1 < (int)uVar3)) {
                        FUN_80145074(param_1,(int)param_2);
                      }
                      else {
                        FUN_80144dc0();
                      }
                    }
                    else {
                      iVar1 = *(int *)(param_1 + 0xb8);
                      if ((((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
                          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)
                           ))) && (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
                        FUN_80039468(param_1,iVar1 + 0x3a8,0x357,0,0xffffffff,0);
                      }
                      FUN_80139a4c((double)FLOAT_803e31ac,param_1,0x26,0);
                      *(undefined *)((int)param_2 + 10) = 5;
                    }
                  }
                  else {
                    FUN_80145074(param_1,(int)param_2);
                  }
                  uVar2 = 1;
                }
              }
            }
          }
          else {
            param_2[0x15] = param_2[0x15] | 0x20000000;
            iVar1 = *(int *)(param_1 + 0xb8);
            if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
                (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)))) {
              FUN_80039468(param_1,iVar1 + 0x3a8,0x353,0x500,0xffffffff,0);
            }
            uVar2 = 0;
          }
        }
      }
      else {
        param_2[0x1c9] = (int)((float)param_2[0x1c9] - FLOAT_803dc074);
        if ((float)param_2[0x1c9] <= FLOAT_803e306c) {
          param_2[0x1c7] = (int)FLOAT_803e30c8;
          uVar3 = FUN_80017760(200,500);
          param_2[0x1c9] =
               (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
          *(byte *)(param_2 + 0x1ca) = *(byte *)(param_2 + 0x1ca) & 0xbf;
          *(undefined *)((int)param_2 + 10) = 1;
        }
        uVar2 = 0;
      }
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80144dc0
 * EN v1.0 Address: 0x80144DC0
 * EN v1.0 Size: 692b
 * EN v1.1 Address: 0x80144548
 * EN v1.1 Size: 740b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80144dc0(void)
{
  short *psVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  bool bVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  double dVar9;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar10;
  float local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar10 = FUN_80286840();
  psVar1 = (short *)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  uVar8 = 1;
  uVar7 = 3;
  local_38[0] = FLOAT_803e31b4;
  iVar2 = FUN_80037008(0x4d,psVar1,local_38);
  if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x800) != 0)) {
    uVar8 = 0;
  }
  iVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if ((iVar3 == 0) || (uVar4 = FUN_80017690(0xdd), uVar4 == 0)) {
    uVar7 = 2;
  }
  uVar7 = FUN_80017760(uVar8,uVar7);
  if (uVar7 == 2) {
    FUN_80139a4c((double)FLOAT_803e31c0,(int)psVar1,0x2d,0);
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x10;
    *(undefined *)(iVar6 + 10) = 9;
  }
  else if ((int)uVar7 < 2) {
    if (uVar7 == 0) {
      *(int *)(iVar6 + 0x24) = iVar2;
      FUN_80039580(iVar2,0,(float *)(iVar6 + 0x72c));
      if (*(int *)(iVar6 + 0x28) != iVar6 + 0x72c) {
        *(int *)(iVar6 + 0x28) = iVar6 + 0x72c;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar6 + 0xd2) = 0;
      }
      *(byte *)(iVar6 + 0x728) = *(byte *)(iVar6 + 0x728) & 0xdf;
      *(undefined *)(iVar6 + 10) = 0xc;
    }
    else if (-1 < (int)uVar7) {
      uVar7 = FUN_80017760(0x20,0xff);
      uStack_2c = (int)(short)((*psVar1 + (short)uVar7) * 0x100) ^ 0x80000000;
      local_30 = 0x43300000;
      dVar9 = (double)FUN_80293f90();
      *(float *)(iVar6 + 0x72c) = (float)(DOUBLE_803e31b8 * -dVar9 + (double)*(float *)(psVar1 + 6))
      ;
      *(undefined4 *)(iVar6 + 0x730) = *(undefined4 *)(psVar1 + 8);
      dVar9 = (double)FUN_80294964();
      *(float *)(iVar6 + 0x734) =
           (float)((double)FLOAT_803e3114 * -dVar9 + (double)*(float *)(psVar1 + 10));
      if (*(int *)(iVar6 + 0x28) != iVar6 + 0x72c) {
        *(int *)(iVar6 + 0x28) = iVar6 + 0x72c;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar6 + 0xd2) = 0;
      }
      *(undefined *)(iVar6 + 10) = 8;
    }
  }
  else if ((int)uVar7 < 4) {
    FUN_80139a4c((double)FLOAT_803e30d4,(int)psVar1,0x29,0);
    iVar2 = *(int *)(psVar1 + 0x5c);
    if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < psVar1[0x50] || (psVar1[0x50] < 0x29)) &&
        (bVar5 = FUN_800067f0((int)psVar1,0x10), !bVar5)))) {
      FUN_80039468(psVar1,iVar2 + 0x3a8,0x354,0x1000,0xffffffff,0);
    }
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x10;
    *(undefined *)(iVar6 + 10) = 4;
    uStack_2c = FUN_80017760(0x78,0xf0);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(iVar6 + 0x73c) = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e30f0);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80145074
 * EN v1.0 Address: 0x80145074
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8014482C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80145074(int param_1,int param_2)
{
  uint uVar1;
  bool bVar2;
  int iVar3;
  
  uVar1 = FUN_80017760(0,4);
  if (uVar1 == 2) {
    FUN_80139a4c((double)FLOAT_803e3108,param_1,0x21,0);
    *(undefined *)(param_2 + 10) = 6;
  }
  else if ((int)uVar1 < 2) {
    if (uVar1 == 0) {
      FUN_80139a4c((double)FLOAT_803e30d4,param_1,0,0);
      *(undefined *)(param_2 + 10) = 2;
    }
    else if (-1 < (int)uVar1) {
      iVar3 = *(int *)(param_1 + 0xb8);
      if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
          (bVar2 = FUN_800067f0(param_1,0x10), !bVar2)))) {
        FUN_80039468(param_1,iVar3 + 0x3a8,0x357,0,0xffffffff,0);
      }
      FUN_80139a4c((double)FLOAT_803e31ac,param_1,0x26,0);
      *(undefined *)(param_2 + 10) = 5;
    }
  }
  else if (uVar1 == 4) {
    FUN_80139a4c((double)FLOAT_803e31a8,param_1,0x25,0);
    *(undefined *)(param_2 + 10) = 2;
  }
  else if ((int)uVar1 < 4) {
    FUN_80139a4c((double)FLOAT_803e3108,param_1,0x23,0);
    *(undefined *)(param_2 + 10) = 7;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801451dc
 * EN v1.0 Address: 0x801451DC
 * EN v1.0 Size: 1244b
 * EN v1.1 Address: 0x80144994
 * EN v1.1 Size: 1348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801451dc(int param_1,int *param_2)
{
  bool bVar1;
  char cVar2;
  char cVar3;
  byte bVar5;
  uint uVar4;
  uint uVar6;
  int iVar7;
  short local_18 [4];
  
  bVar1 = false;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  uVar6 = FUN_80017690(0xc1);
  uVar6 = uVar6 & 0xff;
  if (uVar6 != 0) {
    FUN_8011e824(local_18);
    bVar1 = local_18[0] == 0xc1;
    iVar7 = FUN_8012efc4();
    if (iVar7 == 0xc1) {
      bVar1 = true;
    }
  }
  if (bVar1) {
    if ((*(byte *)(param_1 + 0xaf) & 1) == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_80017a6c(param_1,0,0,0,'\0','\x04');
    }
    else {
      iVar7 = (**(code **)(*DAT_803dd6e8 + 0x20))(0xc1);
      if (iVar7 != 0) {
        cVar2 = *(char *)*param_2;
        cVar3 = ((char *)*param_2)[1];
        if (cVar2 == cVar3) {
          iVar7 = *(int *)(param_1 + 0xb8);
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 1;
          if (FLOAT_803e306c == *(float *)(iVar7 + 0x2ac)) {
            bVar1 = false;
          }
          else if (FLOAT_803e30a0 == *(float *)(iVar7 + 0x2b0)) {
            bVar1 = true;
          }
          else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= FLOAT_803e30a4) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            FUN_80139a4c((double)FLOAT_803e30cc,param_1,8,0);
            *(float *)(iVar7 + 0x79c) = FLOAT_803e30d0;
            *(float *)(iVar7 + 0x838) = FLOAT_803e306c;
            FUN_80146fa0();
          }
          else {
            FUN_80139a4c((double)FLOAT_803e30d4,param_1,0,0);
            FUN_80146fa0();
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_1,0xffffffff);
          *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
        }
        else {
          bVar5 = cVar3 - cVar2;
          uVar4 = (uint)(bVar5 >> 2);
          if ((bVar5 & 3) != 0) {
            uVar4 = uVar4 + 1;
          }
          if (uVar6 < uVar4) {
            *(char *)((int)param_2 + 0x82d) = cVar2 + (char)(uVar6 << 2);
            FUN_80017698(0xc1,0);
          }
          else {
            *(char *)((int)param_2 + 0x82d) = cVar2 + (char)(uVar4 << 2);
            FUN_80017698(0xc1,uVar6 - uVar4);
          }
          if (*(byte *)(*param_2 + 1) < *(byte *)((int)param_2 + 0x82d)) {
            *(byte *)((int)param_2 + 0x82d) = *(byte *)(*param_2 + 1);
          }
          iVar7 = *(int *)(param_1 + 0xb8);
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
          if (FLOAT_803e306c == *(float *)(iVar7 + 0x2ac)) {
            bVar1 = false;
          }
          else if (FLOAT_803e30a0 == *(float *)(iVar7 + 0x2b0)) {
            bVar1 = true;
          }
          else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= FLOAT_803e30a4) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            FUN_80139a4c((double)FLOAT_803e30cc,param_1,8,0);
            *(float *)(iVar7 + 0x79c) = FLOAT_803e30d0;
            *(float *)(iVar7 + 0x838) = FLOAT_803e306c;
            FUN_80146fa0();
          }
          else {
            FUN_80139a4c((double)FLOAT_803e30d4,param_1,0,0);
            FUN_80146fa0();
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
          *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
          param_2[0x15] = param_2[0x15] | 0x40000000;
        }
        FUN_80006ba8(0,0x100);
        return 1;
      }
    }
  }
  else {
    uVar6 = FUN_80017690(0x4e3);
    uVar6 = uVar6 & 0xff;
    if ((uVar6 != 0xff) && (iVar7 = FUN_8012efc4(), iVar7 == -1)) {
      if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
        FUN_80017698(0x4e3,0xff);
        iVar7 = *(int *)(param_1 + 0xb8);
        *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
        if (uVar6 != 2) {
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 1;
        }
        if (FLOAT_803e306c == *(float *)(iVar7 + 0x2ac)) {
          bVar1 = false;
        }
        else if (FLOAT_803e30a0 == *(float *)(iVar7 + 0x2b0)) {
          bVar1 = true;
        }
        else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= FLOAT_803e30a4) {
          bVar1 = false;
        }
        else {
          bVar1 = true;
        }
        if (bVar1) {
          FUN_80139a4c((double)FLOAT_803e30cc,param_1,8,0);
          *(float *)(iVar7 + 0x79c) = FLOAT_803e30d0;
          *(float *)(iVar7 + 0x838) = FLOAT_803e306c;
          FUN_80146fa0();
        }
        else {
          FUN_80139a4c((double)FLOAT_803e30d4,param_1,0,0);
          FUN_80146fa0();
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(uVar6,param_1,0xffffffff);
        *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
        FUN_80006ba8(0,0x100);
        return 1;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_80017a6c(param_1,0,0,0,'\0','\x02');
    }
  }
  return 0;
}
