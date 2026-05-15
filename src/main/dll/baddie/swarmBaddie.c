#include "ghidra_import.h"
#include "main/dll/baddie/swarmBaddie.h"

extern undefined4 FUN_80006868();
extern char FUN_80006884();
extern undefined4 FUN_80006894();
extern undefined4 FUN_800068a0();
extern undefined4 FUN_80006954();
extern undefined4 FUN_8000695c();
extern undefined4 FUN_80006960();
extern undefined4 FUN_80006984();
extern undefined4 FUN_80006988();
extern undefined4 FUN_800069b0();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_800069d4();
extern double FUN_800069f8();
extern undefined4 FUN_80006a00();
extern undefined4 FUN_80006c64();
extern undefined4 FUN_80006c94();
extern undefined4 FUN_80006c9c();
extern undefined4 FUN_80017484();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a54();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_800709d8();
extern undefined4 FUN_800709dc();
extern undefined4 FUN_800709e0();
extern undefined8 FUN_800709e8();
extern int FUN_8020a68c();
extern int FUN_8020a694();
extern ushort FUN_8020a6a0();
extern int FUN_8020a6a8();
extern int FUN_8020a6b0();
extern uint FUN_8020a6b8();
extern int FUN_8020a6fc();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_80286824();
extern undefined4 FUN_8028682c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028fde8();
extern undefined4 FUN_80293994();

extern undefined4 DAT_8031bb84;
extern undefined4 DAT_8031bb8a;
extern undefined4 DAT_8031cbe0;
extern undefined4 DAT_8031cbf8;
extern undefined4 DAT_803a9610;
extern undefined4 DAT_803a9638;
extern undefined4 DAT_803a963c;
extern undefined4 DAT_803a9644;
extern undefined4 DAT_803a96f0;
extern undefined4 DAT_803a96f4;
extern undefined4 DAT_803a96f8;
extern undefined4 DAT_803a96fc;
extern undefined4 DAT_803a9700;
extern undefined4 DAT_803a9704;
extern undefined4 DAT_803a9760;
extern int DAT_803aa058;
extern undefined4 DAT_803aa0a0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc6d8;
extern undefined4 DAT_803dc7c8;
extern undefined4* DAT_803dd6e8;
extern undefined4 DAT_803dd970;
extern undefined4 DAT_803de3fc;
extern undefined4 DAT_803de428;
extern undefined4 DAT_803de429;
extern undefined4 DAT_803de44c;
extern undefined4 DAT_803de460;
extern undefined4 DAT_803de4b8;
extern undefined4 DAT_803de4d4;
extern undefined4 DAT_803de4d6;
extern undefined4 DAT_803de4d8;
extern undefined4 DAT_803de4da;
extern undefined4 DAT_803de4db;
extern undefined4 DAT_803de548;
extern undefined4 DAT_803de54a;
extern undefined4 DAT_803de550;
extern undefined4 DAT_803e2a88;
extern undefined4 DAT_803e2a8c;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc70c;
extern f32 FLOAT_803de54c;
extern f32 FLOAT_803e2abc;
extern f32 FLOAT_803e2adc;
extern f32 FLOAT_803e2ae8;
extern f32 FLOAT_803e2c1c;
extern f32 FLOAT_803e2c20;
extern f32 FLOAT_803e2c2c;
extern f32 FLOAT_803e2c90;
extern f32 FLOAT_803e2ca4;
extern f32 FLOAT_803e2cc0;
extern f32 FLOAT_803e2cc4;
extern f32 FLOAT_803e2cc8;
extern f32 FLOAT_803e2ccc;
extern f32 FLOAT_803e2cd0;
extern f32 FLOAT_803e2cd4;
extern f32 FLOAT_803e2cd8;
extern f32 FLOAT_803e2cdc;
extern f32 FLOAT_803e2ce0;
extern f32 FLOAT_803e2ce4;
extern f32 FLOAT_803e2ce8;

/*
 * --INFO--
 *
 * Function: FUN_80125424
 * EN v1.0 Address: 0x80125424
 * EN v1.0 Size: 1880b
 * EN v1.1 Address: 0x80125708
 * EN v1.1 Size: 1920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80125424(void)
{
  ushort uVar1;
  short sVar3;
  uint uVar2;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  undefined8 local_b8;
  undefined8 local_a8;
  
  FUN_80286824();
  if (DAT_803de4da != '\0') {
    if (DAT_803de428 == '\0') {
      DAT_803de4d8 = DAT_803de4d8 + (ushort)DAT_803dc070 * 5;
      if (0x152 < DAT_803de4d8) {
        DAT_803de4d8 = 0x152;
        DAT_803de4da = '\0';
        if (*(int *)(&DAT_8031bb84 + (uint)DAT_803de4db * 0xc) != -1) {
          FUN_80006894();
          FUN_80006868();
        }
      }
      DAT_803de4d6 = DAT_803de4d6 + (ushort)DAT_803dc070 * -10;
      DAT_803de4d4 = DAT_803de4d4 + (ushort)DAT_803dc070 * -0x17;
    }
    else {
      DAT_803de4d8 = DAT_803de4d8 + (ushort)DAT_803dc070 * -5;
      if (DAT_803de4d8 < 0x122) {
        DAT_803de4d8 = 0x122;
      }
      DAT_803de4d6 = DAT_803de4d6 + (ushort)DAT_803dc070 * 10;
      DAT_803de4d4 = DAT_803de4d4 + (ushort)DAT_803dc070 * 0x17;
    }
    uVar1 = DAT_803de4d8;
    if (DAT_803de4d4 < 0) {
      sVar3 = 0;
    }
    else {
      sVar3 = DAT_803de4d4;
      if (0xff < DAT_803de4d4) {
        sVar3 = 0xff;
      }
    }
    uVar8 = (uint)sVar3;
    uVar2 = (uint)DAT_803de4d6;
    if (0x6e < uVar2) {
      uVar2 = 0x6e;
    }
    uVar9 = (uint)DAT_803de4d8;
    uVar6 = (uint)(byte)(&DAT_8031bb8a)[(uint)DAT_803de4db * 0xc];
    if (uVar6 == 2) {
      uVar7 = 0x186;
    }
    else if ((uVar6 < 2) || (3 < uVar6)) {
      uVar7 = 0x19a;
    }
    else {
      uVar7 = 0x195;
    }
    DAT_803de4d4 = sVar3;
    DAT_803de4d6 = (short)uVar2;
    FUN_8025da88(0x1ea,uVar9,0x78,uVar2);
    FUN_800709dc((double)FLOAT_803e2cc0,
                 (double)(float)((double)CONCAT44(0x43300000,uVar9 ^ 0x80000000) - DOUBLE_803e2af8),
                 0x78,uVar2);
    dVar10 = FUN_800069f8();
    FLOAT_803dc70c = (float)dVar10;
    FUN_80006a00((double)FLOAT_803e2cc4);
    FUN_80006954(1);
    DAT_803de460 = FUN_800069b0();
    FUN_800069b8();
    dVar10 = (double)FLOAT_803e2abc;
    FUN_80006960(dVar10,dVar10,dVar10);
    FUN_8000695c(0x8000,0,0);
    FUN_80006984();
    FUN_800069d4();
    local_b8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 4));
    FUN_8025da64((double)FLOAT_803e2cc8,
                 (double)((float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e2af8)
                         - FLOAT_803e2ca4),(double)(float)(local_b8 - DOUBLE_803e2b08),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6)) -
                                DOUBLE_803e2b08),(double)FLOAT_803e2abc,(double)FLOAT_803e2ae8);
    if ((&DAT_803aa058)[uVar6] != 0) {
      FUN_8002fc3c((double)*(float *)(&DAT_8031cbf8 + uVar6 * 4),(double)FLOAT_803dc074);
      if (0x90000000 < *(uint *)((&DAT_803aa058)[uVar6] + 0x4c)) {
        *(undefined4 *)((&DAT_803aa058)[uVar6] + 0x4c) = 0;
      }
      *(undefined *)((&DAT_803aa058)[uVar6] + 0x37) = 0xff;
      FUN_8003b878(0,0,0,0,(&DAT_803aa058)[uVar6],1);
      iVar4 = FUN_80017a54((&DAT_803aa058)[uVar6]);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
    }
    FUN_80006954(0);
    if (DAT_803de460 != 0) {
      FUN_800069bc();
    }
    FUN_80006984();
    FUN_80006a00((double)FLOAT_803dc70c);
    FUN_800069d4();
    FUN_80006988();
    FUN_8025da88(0,0,0x280,0x1e0);
    DAT_803de3fc = DAT_803de3fc + 1;
    dVar12 = (double)FLOAT_803e2ccc;
    dVar14 = (double)FLOAT_803e2cd0;
    dVar15 = (double)FLOAT_803e2c90;
    dVar10 = DOUBLE_803e2af8;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 4) {
      dVar11 = (double)FUN_80293994();
      dVar13 = (double)(float)(dVar12 * dVar11);
      dVar11 = (double)FUN_80293994();
      dVar11 = (double)(float)(dVar12 * dVar11 + dVar13);
      uVar6 = (uint)((float)((double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000U) - dVar10) *
                    (float)(dVar14 + dVar11));
      if ((int)uVar6 < 0) {
        uVar6 = 0;
      }
      uVar7 = randomGetRange(0,0x1e);
      uVar5 = randomGetRange(0,0x1e);
      if (0xff < (int)uVar6) {
        uVar6 = 0xff;
      }
      FUN_800709d8((double)FLOAT_803e2cc0,
                   (double)(float)((double)CONCAT44(0x43300000,uVar9 + iVar4 ^ 0x80000000) - dVar10)
                   ,DAT_803a9760,uVar6 & 0xff,0x100,0x78,2,uVar5 << 1,uVar7 << 1);
      uVar6 = (uint)((float)((double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000U) - dVar10) *
                    (float)(dVar15 + dVar11));
      if ((int)uVar6 < 0) {
        uVar6 = 0;
      }
      uVar7 = randomGetRange(0,0x1e);
      uVar5 = randomGetRange(0,0x1e);
      if (0xff < (int)uVar6) {
        uVar6 = 0xff;
      }
      FUN_800709d8((double)FLOAT_803e2cc0,
                   (double)(float)((double)CONCAT44(0x43300000,uVar9 + iVar4 + 2 ^ 0x80000000) -
                                  dVar10),DAT_803a9760,uVar6 & 0xff,0x100,0x78,2,uVar5 << 1,
                   uVar7 << 1);
    }
    uVar9 = (uint)(short)uVar1;
    uVar6 = uVar9 - 5;
    FUN_800709e8((double)FLOAT_803e2cd4,
                 (double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9638,uVar8 & 0xff,0x100);
    local_a8 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
    FUN_800709e0((double)FLOAT_803e2cc0,(double)(float)(local_a8 - DOUBLE_803e2af8),DAT_803a9644,
                 uVar8 & 0xff,0x100,0x78,5,0);
    iVar4 = (int)(short)uVar2;
    FUN_800709e0((double)FLOAT_803e2cd4,
                 (double)(float)((double)CONCAT44(0x43300000,uVar9 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a963c,uVar8 & 0xff,0x100,5,iVar4,0);
    uVar2 = uVar9 + iVar4;
    local_b8 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    FUN_800709e0((double)FLOAT_803e2cc0,(double)(float)(local_b8 - DOUBLE_803e2af8),DAT_803a9644,
                 uVar8 & 0xff,0x100,0x78,5,2);
    FUN_800709e0((double)FLOAT_803e2cd8,
                 (double)(float)((double)CONCAT44(0x43300000,uVar9 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a963c,uVar8 & 0xff,0x100,5,iVar4,1);
    FUN_800709e0((double)FLOAT_803e2cd8,
                 (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9638,uVar8 & 0xff,0x100,5,5,3);
    FUN_800709e0((double)FLOAT_803e2cd8,
                 (double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9638,uVar8 & 0xff,0x100,5,5,1);
    FUN_800709e0((double)FLOAT_803e2cd4,
                 (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9638,uVar8 & 0xff,0x100,5,5,2);
  }
  FUN_80286870();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80125b7c
 * EN v1.0 Address: 0x80125B7C
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x80125E88
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80125b7c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  short sVar1;
  ushort uVar2;
  char cVar3;
  int iVar4;
  undefined8 extraout_f1;
  
  if (DAT_803de4da == '\0') {
    if ((param_9 < 0) || (0x14 < param_9)) {
      param_9 = 0x14;
    }
    DAT_803de4da = '\x01';
    DAT_803de4db = (undefined)param_9;
    iVar4 = param_9 * 0xc;
    if ((*(int *)(&DAT_8031bb84 + iVar4) != -1) && (cVar3 = FUN_80006884(), cVar3 == '\0')) {
      FUN_800068a0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    if (*(char *)(iVar4 + -0x7fce4475) == '\0') {
      sVar1 = *(short *)(iVar4 + -0x7fce4474);
      uVar2 = *(ushort *)(iVar4 + -0x7fce4478);
      if ((uVar2 != 0xffffffff) && (DAT_803dc6d8 == 0xffff)) {
        FUN_80006c9c(0x7c);
        DAT_803de428 = 1;
        DAT_803de550 = 0;
        DAT_803de548 = 0;
        FLOAT_803de54c =
             (float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) - DOUBLE_803e2af8);
        DAT_803dc6d8 = uVar2;
        DAT_803de54a = sVar1;
        FUN_80006c94((undefined4 *)&DAT_803aa0a0);
        DAT_803de429 = 0;
      }
    }
    else {
      (**(code **)(*DAT_803dd6e8 + 0x38))(*(undefined2 *)(iVar4 + -0x7fce4478),0,0,0);
    }
    DAT_803de4d8 = 0x159;
    DAT_803de4d6 = 0;
    DAT_803de4d4 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80125d3c
 * EN v1.0 Address: 0x80125D3C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x80125FE8
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80125d3c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = 0;
  piVar3 = &DAT_803aa058;
  do {
    iVar1 = *piVar3;
    if (iVar1 != 0) {
      if (0x90000000 < *(uint *)(iVar1 + 0x4c)) {
        *(undefined4 *)(iVar1 + 0x4c) = 0;
      }
      param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar3
                            );
      *piVar3 = 0;
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80125e30
 * EN v1.0 Address: 0x80125E30
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x80126070
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80125e30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar6;
  int *piVar7;
  int iVar8;
  
  iVar8 = 0;
  piVar7 = &DAT_803aa058;
  puVar6 = &DAT_8031cbe0;
  do {
    if (((iVar8 == 3) || (iVar8 == 2)) || (iVar8 == 1)) {
      if (*piVar7 == 0) {
        puVar2 = FUN_80017aa4(0x20,(short)*puVar6);
        uVar4 = 0xffffffff;
        uVar5 = 0;
        iVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                             4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        *piVar7 = iVar3;
        fVar1 = FLOAT_803e2abc;
        *(float *)(*piVar7 + 0xc) = FLOAT_803e2abc;
        *(float *)(*piVar7 + 0x10) = fVar1;
        *(float *)(*piVar7 + 0x14) = FLOAT_803e2adc;
        *(undefined2 *)*piVar7 = 0x7447;
        *(float *)(*piVar7 + 8) = FLOAT_803e2cdc;
        if (0x90000000 < *(uint *)(*piVar7 + 0x4c)) {
          *(undefined4 *)(*piVar7 + 0x4c) = 0;
        }
        param_1 = FUN_800305f8((double)FLOAT_803e2abc,param_2,param_3,param_4,param_5,param_6,
                               param_7,param_8,*piVar7,1,0,uVar4,uVar5,in_r8,in_r9,in_r10);
      }
    }
    else {
      *piVar7 = 0;
    }
    piVar7 = piVar7 + 1;
    puVar6 = puVar6 + 1;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 6);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80126044
 * EN v1.0 Address: 0x80126044
 * EN v1.0 Size: 1184b
 * EN v1.1 Address: 0x80126188
 * EN v1.1 Size: 1064b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80126044(void)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  ushort uVar9;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar10;
  byte bVar11;
  undefined8 uVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f31;
  double dVar15;
  double in_ps31_1;
  undefined4 local_58;
  undefined local_54;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined8 local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_8028682c();
  iVar3 = FUN_8020a6fc();
  local_58 = DAT_803e2a88;
  local_54 = DAT_803e2a8c;
  if (iVar3 != 0) {
    if (DAT_803de44c == '\0') {
      local_40 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
      uStack_44 = (int)DAT_803de4b8 ^ 0x80000000;
      iVar7 = (int)-(FLOAT_803e2c20 * (float)(local_40 - DOUBLE_803e2b08) -
                    (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8));
      local_50 = (double)(longlong)iVar7;
      DAT_803de4b8 = (short)iVar7;
      if (DAT_803de4b8 < 0) {
        DAT_803de4b8 = 0;
      }
    }
    else {
      local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
      uStack_44 = (int)DAT_803de4b8 ^ 0x80000000;
      iVar7 = (int)(FLOAT_803e2c20 * (float)(local_50 - DOUBLE_803e2b08) +
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8));
      local_40 = (double)(longlong)iVar7;
      DAT_803de4b8 = (short)iVar7;
      if (0xff < DAT_803de4b8) {
        DAT_803de4b8 = 0xff;
      }
    }
    local_48 = 0x43300000;
    dVar14 = (double)FLOAT_803e2c20;
    uVar4 = FUN_8020a6b8(iVar3);
    iVar5 = FUN_8020a6b0(iVar3);
    iVar6 = FUN_8020a6a8(iVar3);
    iVar7 = FUN_8020a694(iVar3);
    iVar8 = FUN_8020a68c(iVar3);
    if (iVar8 < iVar7) {
      iVar7 = iVar8;
    }
    dVar13 = DOUBLE_803e2af8;
    for (uVar10 = 0; uVar1 = uVar10 & 0xff, (int)uVar1 < iVar5 >> 2; uVar10 = uVar10 + 1) {
      if ((int)uVar1 < (int)uVar4 >> 2) {
        iVar2 = 0x16;
      }
      else {
        iVar2 = (uVar4 & 3) + 0x12;
        if ((int)uVar4 >> 2 < (int)uVar1) {
          iVar2 = 0x12;
        }
      }
      local_40 = (double)CONCAT44(0x43300000,uVar1 * 0x21 + 0x1e ^ 0x80000000);
      FUN_800709e8((double)(float)(local_40 - dVar13),(double)FLOAT_803e2c2c,(&DAT_803a9610)[iVar2],
                   (int)DAT_803de4b8 & 0xff,0x100);
    }
    dVar13 = DOUBLE_803e2af8;
    for (bVar11 = 0; bVar11 < 3; bVar11 = bVar11 + 1) {
      iVar5 = (uint)bVar11 * 0x1c;
      local_40 = (double)CONCAT44(0x43300000,iVar5 + 0x1eU ^ 0x80000000);
      FUN_800709e8((double)(float)(local_40 - dVar13),(double)FLOAT_803e2ce0,DAT_803a96f0,
                   (int)DAT_803de4b8 & 0xff,0x100);
      if ((int)(uint)bVar11 < iVar6) {
        local_40 = (double)CONCAT44(0x43300000,iVar5 + 0x23U ^ 0x80000000);
        FUN_800709e8((double)(float)(local_40 - DOUBLE_803e2af8),(double)FLOAT_803e2ce4,DAT_803a96f4
                     ,(int)DAT_803de4b8 & 0xff,0x100);
      }
    }
    if (*(char *)(iVar3 + 0xac) != '&') {
      FUN_800709e8((double)FLOAT_803e2ce8,(double)FLOAT_803e2c2c,DAT_803a9704,
                   (int)DAT_803de4b8 & 0xff,0x100);
      dVar13 = DOUBLE_803e2af8;
      for (uVar4 = 0; dVar15 = DOUBLE_803e2af8, (int)(uVar4 & 0xff) < iVar7; uVar4 = uVar4 + 1) {
        local_40 = (double)CONCAT44(0x43300000,(uVar4 & 0xff) * -0x14 + 0x244 ^ 0x80000000);
        FUN_800709e8((double)(float)(local_40 - dVar13),(double)FLOAT_803e2c1c,DAT_803a9700,
                     (int)DAT_803de4b8 & 0xff,0x100);
      }
      for (; uVar10 = uVar4 & 0xff, (int)uVar10 < iVar8; uVar4 = uVar4 + 1) {
        local_40 = (double)CONCAT44(0x43300000,uVar10 * -0x14 + 0x244 ^ 0x80000000);
        FUN_800709e8((double)(float)(local_40 - dVar15),(double)FLOAT_803e2c1c,DAT_803a96fc,
                     (int)DAT_803de4b8 & 0xff,0x100);
      }
      local_40 = (double)CONCAT44(0x43300000,uVar10 * -0x14 + 0x23c ^ 0x80000000);
      dVar13 = (double)FLOAT_803e2c2c;
      uVar12 = FUN_800709e8((double)(float)(local_40 - DOUBLE_803e2af8),dVar13,DAT_803a96f8,
                            (int)DAT_803de4b8 & 0xff,0x100);
      uVar9 = FUN_8020a6a0(iVar3);
      FUN_8028fde8(uVar12,dVar13,dVar14,in_f4,in_f5,in_f6,in_f7,in_f8,(int)&local_58,&DAT_803dc7c8,
                   (uint)uVar9,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    FUN_80017484(0xff,0xff,0xff,(byte)DAT_803de4b8);
    FUN_80006c64(&local_58,0x93,0x23a,0x41);
    FUN_80125424();
  }
  FUN_80286878();
  return;
}
