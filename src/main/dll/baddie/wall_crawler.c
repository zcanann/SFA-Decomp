#include "ghidra_import.h"
#include "main/dll/baddie/wall_crawler.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006948();
extern undefined8 FUN_80006b84();
extern undefined4 FUN_80006b98();
extern undefined8 FUN_80006ba8();
extern char FUN_80006bb8();
extern char FUN_80006bc0();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern int FUN_80006c54();
extern undefined4 FUN_80006c6c();
extern undefined4 FUN_80006c90();
extern undefined4 FUN_80006c94();
extern void* FUN_80006c9c();
extern undefined4 FUN_80017460();
extern void* FUN_80017470();
extern undefined8 FUN_80017484();
extern int FUN_80017674();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_800176c0();
extern undefined4 FUN_800176c8();
extern int FUN_800176d0();
extern double FUN_80017714();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017b10();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_800533cc();
extern undefined8 FUN_80053c98();
extern undefined8 FUN_800709e8();
extern uint FUN_800ea9ac();
extern int FUN_80100c90();
extern undefined8 FUN_8011e880();
extern undefined4 FUN_8011ebb8();
extern undefined4 FUN_8011f438();
extern undefined4 FUN_80122a48();
extern undefined4 FUN_80122a4c();
extern undefined8 FUN_80122b14();
extern undefined4 FUN_801242dc();
extern int fn_801244B0();
extern undefined8 FUN_801249bc();
extern undefined8 FUN_80126044();
extern undefined8 FUN_801262cc();
extern undefined4 FUN_801291ac();
extern undefined4 FUN_801294d8();
extern undefined4 FUN_8012a21c();
extern undefined4 FUN_8012c1c0();
extern undefined4 FUN_8012cd38();
extern undefined8 FUN_8012dab8();
extern undefined4 FUN_8012fcec();
extern undefined8 FUN_8012fdac();
extern int FUN_8020a6fc();
extern undefined8 FUN_8025da88();
extern undefined8 FUN_80286838();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80294be4();
extern int FUN_80294c38();
extern int FUN_80294dbc();

extern undefined4 DAT_803a9f84;
extern undefined4 DAT_803a9fa4;
extern undefined4 DAT_803aa0a0;
extern undefined4 DAT_803aa0a4;
extern undefined4 DAT_803aa0a8;
extern undefined4 DAT_803aa0ac;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc084;
extern undefined4 DAT_803dc6cc;
extern undefined4 DAT_803dc6ce;
extern undefined4 DAT_803dc6d2;
extern undefined4 DAT_803dc6d4;
extern undefined4 DAT_803dc6d6;
extern undefined4 DAT_803dc6d8;
extern undefined4 DAT_803dc6f8;
extern undefined4* DAT_803dd6d0;
extern undefined4 DAT_803de3b0;
extern undefined4 DAT_803de3db;
extern undefined4 DAT_803de3f2;
extern undefined4 DAT_803de3fe;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de40e;
extern undefined4 DAT_803de413;
extern undefined4 DAT_803de414;
extern undefined4 DAT_803de415;
extern undefined4 DAT_803de416;
extern undefined4 DAT_803de41a;
extern undefined4 DAT_803de41c;
extern undefined4 DAT_803de41e;
extern undefined4 DAT_803de420;
extern undefined4 DAT_803de428;
extern undefined4 DAT_803de429;
extern undefined4 DAT_803de42a;
extern undefined4 DAT_803de42c;
extern undefined4 DAT_803de434;
extern undefined4 DAT_803de436;
extern undefined4 DAT_803de439;
extern undefined4 DAT_803de43a;
extern undefined4 DAT_803de454;
extern undefined4 DAT_803de455;
extern undefined4 DAT_803de4a8;
extern undefined4 DAT_803de4ac;
extern undefined4 DAT_803de50c;
extern undefined4 DAT_803de50e;
extern undefined4 DAT_803de510;
extern undefined4 DAT_803de512;
extern undefined4 DAT_803de518;
extern undefined4 DAT_803de51e;
extern undefined4 DAT_803de520;
extern undefined4 DAT_803de524;
extern undefined4 DAT_803de528;
extern undefined4 DAT_803de52c;
extern undefined4 DAT_803de536;
extern undefined4 DAT_803de537;
extern undefined4 DAT_803de540;
extern undefined4 DAT_803de544;
extern undefined4 DAT_803de548;
extern undefined4 DAT_803de54a;
extern undefined4 DAT_803de550;
extern undefined4 DAT_803de552;
extern undefined4 DAT_803de556;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de54c;
extern f32 FLOAT_803e2abc;
extern f32 FLOAT_803e2af0;
extern f32 FLOAT_803e2e60;
extern void* PTR_DAT_8031c228;
extern void* PTR_DAT_8031c238;

/*
 * --INFO--
 *
 * Function: FUN_8012eb7c
 * EN v1.0 Address: 0x8012EB7C
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x8012EBBC
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012eb7c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined *puVar1;
  byte *pbVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  int local_18 [4];
  
  puVar1 = FUN_80006c9c(0x7c);
  if ((DAT_803dc6d8 != 0xffff) && ((int)DAT_803de550 != 0)) {
    uVar4 = 0xff;
    uVar5 = (int)DAT_803de550 & 0xff;
    uVar7 = FUN_80017484(0xff,0xff,0xff,(byte)DAT_803de550);
    if (DAT_803de54a == -1) {
      puVar1[0x1e] = (char)DAT_803de550;
      FUN_80006c90((uint)DAT_803dc6d8,&DAT_803aa0a0);
    }
    else {
      pbVar2 = (byte *)FUN_80017460(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    (uint)DAT_803dc6d8,DAT_803aa0a4,uVar4,uVar5,in_r7,in_r8,in_r9,
                                    in_r10);
      iVar3 = FUN_80006c54(pbVar2,local_18);
      iVar6 = 0x7a;
      if ((iVar3 == 0xf8f7) && (iVar3 = FUN_80006c54(pbVar2 + local_18[0],local_18), iVar3 == 5)) {
        iVar6 = 0x7c;
      }
      puVar1 = FUN_80006c9c(iVar6);
      puVar1[0x1e] = (char)DAT_803de550;
      FUN_80006c6c(pbVar2,iVar6);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8012ed00
 * EN v1.0 Address: 0x8012ED00
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x8012ECB8
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012ed00(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  ushort *puVar2;
  
  FUN_80017a98();
  if (DAT_803de428 == '\0') {
    DAT_803de550 = DAT_803de550 + (ushort)DAT_803dc070 * -8;
    if (DAT_803de550 < 0) {
      DAT_803de550 = 0;
    }
  }
  else {
    if (DAT_803de548 != '\0') {
      (**(code **)(*DAT_803dd6d0 + 0x5c))(0x41,1);
    }
    DAT_803de550 = 0xff;
  }
  if (DAT_803de550 == 0) {
    DAT_803dc6d8 = 0xffff;
  }
  else if ((int)DAT_803de54a == 0xffffffff) {
    uVar1 = FUN_80006c00(0);
    DAT_803aa0ac = (int)((uVar1 & 0x100) != 0);
    if (DAT_803aa0a8 == 1) {
      FUN_80006ba8(0,0x100);
      DAT_803de524 = DAT_803de524 & 0xfffffeff;
      DAT_803de428 = '\0';
      if (DAT_803de429 != '\0') {
        FUN_800176c8(0);
        DAT_803de429 = '\0';
      }
    }
    if (DAT_803de428 != '\0') {
      FUN_80006b98();
    }
  }
  else {
    FLOAT_803de54c = FLOAT_803de54c - FLOAT_803dc074;
    if (FLOAT_803de54c <= FLOAT_803e2abc) {
      FLOAT_803de54c =
           (float)((double)CONCAT44(0x43300000,(int)DAT_803de54a ^ 0x80000000) - DOUBLE_803e2af8);
      DAT_803aa0a4 = DAT_803aa0a4 + 1;
      puVar2 = FUN_80017470(DOUBLE_803e2af8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (uint)DAT_803dc6d8);
      if ((int)(uint)puVar2[1] <= DAT_803aa0a4) {
        DAT_803aa0a4 = puVar2[1] - 1;
        DAT_803de428 = '\0';
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8012ef0c
 * EN v1.0 Address: 0x8012EF0C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8012EE7C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8012ef0c(void)
{
  return (int)DAT_803de428;
}

/*
 * --INFO--
 *
 * Function: FUN_8012ef14
 * EN v1.0 Address: 0x8012EF14
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x8012EE94
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012ef14(int param_1,undefined4 param_2,undefined4 param_3,int param_4)
{
  if ((param_1 != -1) && (DAT_803dc6d8 == -1)) {
    FUN_80006c9c(0x7c);
    DAT_803de428 = 1;
    DAT_803de550 = 0;
    DAT_803dc6d8 = (short)param_1;
    DAT_803de54a = 0xffff;
    DAT_803de548 = 1;
    FUN_80006c94((undefined4 *)&DAT_803aa0a0);
    if (param_4 == 0) {
      DAT_803de429 = 0;
    }
    else {
      FUN_800176c8(1);
      FUN_800176c0(0xff);
      DAT_803de429 = 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8012efc4
 * EN v1.0 Address: 0x8012EFC4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8012F000
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8012efc4(void)
{
  return (int)DAT_803de540;
}

/*
 * --INFO--
 *
 * Function: fn_8012F04C
 * EN v1.0 Address: 0x8012EFCC
 * EN v1.0 Size: 1912b
 * EN v1.1 Address: 0x8012F04C
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8012F04C(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  float local_38;
  float local_34[2];
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar7 = FUN_80286840();
  uVar1 = (undefined4)((ulonglong)uVar7 >> 0x20);
  uVar5 = (undefined4)uVar7;
  uVar7 = extraout_f1;
  iVar2 = FUN_80017a98();
  iVar3 = FUN_8020a6fc();
  iVar4 = FUN_80017674();
  if (iVar4 == 0) {
    if (iVar3 == 0) {
      uVar7 = FUN_801262cc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar7 = FUN_8012dab8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar5
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      if (DAT_803de3fe != '\0') {
        FUN_8012cd38(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      FUN_80294be4(iVar2);
      uVar7 = FUN_8025da88(0,0,0x280,0x1e0);
      if ((iVar2 != 0) && (DAT_803de400 == '\0')) {
        iVar3 = FUN_80294c38(iVar2,local_34,&local_38);
        if (iVar3 != 0) {
          FUN_800533cc(DAT_803de544,&DAT_803de4ac,&DAT_803de4a8);
          param_3 = (double)FLOAT_803e2af0;
          uStack_2c = (uint)*(ushort *)(DAT_803de544 + 10);
          local_34[1] = 176.0f;
          uStack_24 = (uint)*(ushort *)(DAT_803de544 + 0xc);
          local_28 = 0x43300000;
          param_2 = -(double)(float)(param_3 *
                                    (double)(float)((double)CONCAT44(0x43300000,uStack_24) -
                                                   DOUBLE_803e2b08) - (double)local_38);
          uVar7 = FUN_800709e8(-(double)(float)(param_3 *
                                               (double)(float)((double)CONCAT44(0x43300000,uStack_2c
                                                                              ) - DOUBLE_803e2b08)
                                               - (double)local_34[0]),param_2,DAT_803de544,0x96,
                               0x100);
        }
        FUN_8011f438(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      uVar6 = 0x1e0;
      uVar7 = FUN_8025da88(0,0,0x280,0x1e0);
      if (iVar2 != 0) {
        uVar7 = FUN_80122b14(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                             uVar5,param_11,uVar6,param_13,param_14,param_15,param_16);
        FUN_8012eb7c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        uVar7 = FUN_801249bc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1);
      }
      if (DAT_803de3db != '\0') {
        FUN_801291ac(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      FUN_80006948();
    }
    else {
      uVar7 = FUN_80126044();
      uVar7 = FUN_801262cc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8012eb7c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8012dab8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar5,
                   param_11,param_12,param_13,param_14,param_15,param_16);
    }
    FUN_8011ebb8();
    uVar7 = FUN_8011e880();
    if (-1 < DAT_803dc6f8) {
      FUN_801294d8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    DAT_803de42a = 0;
    DAT_803de42c = 0;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8012f744
 * EN v1.0 Address: 0x8012F744
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8012F288
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012f744(undefined2 param_1)
{
  DAT_803de439 = 1;
  DAT_803de50c = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8012f758
 * EN v1.0 Address: 0x8012F758
 * EN v1.0 Size: 3004b
 * EN v1.1 Address: 0x8012F298
 * EN v1.1 Size: 2676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012f758(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  bool bVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  char cVar8;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar9;
  short sVar10;
  undefined unaff_r29;
  undefined8 uVar11;
  double dVar12;
  
  uVar11 = FUN_80286838();
  uVar9 = extraout_r4;
  iVar4 = FUN_80017a98();
  iVar5 = FUN_80017a90();
  bVar2 = false;
  bVar1 = true;
  DAT_803de524 = FUN_80006c00(0);
  uVar6 = FUN_80006c10(0);
  sVar10 = DAT_803de51e;
  DAT_803de518 = uVar6;
  if (DAT_803de52c == '\0') {
    cVar8 = FUN_80006bc0(0);
    uVar11 = FUN_80006ba8(0,0xf0000);
    uVar6 = 0xfff0fff7;
    DAT_803de524 = DAT_803de524 & 0xfff0fff7;
    uVar9 = extraout_r4_00;
    sVar10 = (short)cVar8;
    DAT_803de518 = DAT_803de518 & 0xfff0fff7;
  }
  FUN_8012a21c(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar6,uVar9,param_11,
               param_12,param_13,param_14,param_15,param_16);
  if ((-1 < DAT_803dc6f8) && (uVar6 = FUN_80006c00(0), (uVar6 & 0x100) != 0)) {
    FUN_80006ba8(0,0x100);
    DAT_803dc6f8 = -1;
    FUN_800176c8(0);
    FUN_800067c0((int *)0x23,0);
  }
  if (iVar4 == 0) goto LAB_8012fca8;
  if (DAT_803de3db != '\0') {
    FUN_8012c1c0();
  }
  iVar7 = FUN_80294dbc(iVar4);
  if ((((iVar7 == 0) && (iVar7 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar7 != 0x44)) &&
      ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) && (DAT_803de400 == '\0')) {
    if ((int)DAT_803de434 != 0) {
      FUN_80006ba8(0,(int)DAT_803de434);
      DAT_803de524 = DAT_803de524 & ~(int)DAT_803de434;
      DAT_803de518 = DAT_803de518 & ~(int)DAT_803de434;
    }
  }
  else {
    FUN_80006ba8(0,0xf0000);
    DAT_803de524 = DAT_803de524 & 0xfff0fff7;
    DAT_803de518 = DAT_803de518 & 0xfff0fff7;
  }
  iVar7 = FUN_80294dbc(iVar4);
  if (((((iVar7 == 0) && (iVar7 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar7 != 0x44)) &&
       (((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0 &&
        ((DAT_803de434 == '\0' && (DAT_803de400 == '\0')))))) &&
      (iVar7 = FUN_800176d0(), iVar7 == 0)) && (DAT_803de3db == '\0')) {
    if (DAT_803de52c != '\0') {
      DAT_803de518 = DAT_803de520;
      DAT_803de524 = DAT_803de520;
    }
  }
  else {
    bVar1 = false;
    DAT_803de524 = DAT_803de524 & 0xfff0ffff | 0x200;
  }
  sVar3 = DAT_803de41c - DAT_803de41e;
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  uVar6 = FUN_80017690(0x9d5);
  if (uVar6 != 0) {
    uVar6 = FUN_800ea9ac();
    if ((int)DAT_803de3b0 < (int)(uVar6 & 0xffff)) {
      DAT_803de3f2 = 1;
      DAT_803dc6cc = 3;
      DAT_803de3b0 = uVar6 & 0xffff;
    }
    FUN_80017698(0x9d5,0);
  }
  if (bVar1) {
    cVar8 = FUN_80006bc0(0);
    if (cVar8 < '\0') {
      cVar8 = FUN_80006bc0(0);
      iVar7 = -(int)cVar8;
    }
    else {
      cVar8 = FUN_80006bc0(0);
      iVar7 = (int)cVar8;
    }
    if (iVar7 < 6) {
      cVar8 = FUN_80006bb8(0);
      if (cVar8 < '\0') {
        cVar8 = FUN_80006bb8(0);
        iVar7 = -(int)cVar8;
      }
      else {
        cVar8 = FUN_80006bb8(0);
        iVar7 = (int)cVar8;
      }
      if (iVar7 < 6) goto LAB_8012f7ec;
    }
    if (DAT_803de415 == '\0') {
      if (DAT_803de556 == 0) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
    if (bVar1) {
      FUN_80006ba8(0,0xf0000);
      DAT_803de524 = 0;
      iVar7 = FUN_80100c90();
      if (iVar7 == 4) {
        DAT_803de524 = DAT_803de524 | 0x80000;
      }
      else {
        iVar7 = FUN_80100c90();
        if (iVar7 == 9) {
          DAT_803de524 = DAT_803de524 | 0x40000;
        }
        else if ((((iVar5 == 0) || (DAT_803a9f84 == 0)) || (3 < DAT_803a9fa4)) ||
                (dVar12 = FUN_80017714((float *)(iVar4 + 0x18),(float *)(iVar5 + 0x18)),
                (double)FLOAT_803e2e60 <= dVar12)) {
          if (((iVar5 == 0) || (uVar6 = FUN_80017690(0x4e4), uVar6 == 0)) ||
             (iVar4 = FUN_80100c90(), iVar4 != 8)) {
            if (DAT_803de536 == '\x01') {
LAB_8012f798:
              iVar4 = fn_801244B0((short *)PTR_DAT_8031c238,'\0');
              if ((iVar4 == 0) && (iVar4 = fn_801244B0((short *)PTR_DAT_8031c228,'\0'), iVar4 != 0)
                 ) {
                DAT_803de524 = DAT_803de524 | 0x80000;
              }
              else {
                DAT_803de524 = DAT_803de524 | 0x40000;
              }
            }
            else if (DAT_803de536 < '\x01') {
              if (-1 < DAT_803de536) {
LAB_8012f750:
                iVar4 = fn_801244B0((short *)PTR_DAT_8031c228,'\0');
                if ((iVar4 == 0) &&
                   (iVar4 = fn_801244B0((short *)PTR_DAT_8031c238,'\0'), iVar4 != 0))
                goto LAB_8012f798;
                DAT_803de524 = DAT_803de524 | 0x80000;
              }
            }
            else if (DAT_803de536 < '\x03') {
              if (iVar5 == 0) goto LAB_8012f750;
              DAT_803de524 = DAT_803de524 | 0x20000;
            }
          }
          else {
            DAT_803de524 = DAT_803de524 | 0x20000;
          }
        }
        else {
          DAT_803de524 = DAT_803de524 | 0x80000;
          bVar2 = true;
        }
      }
    }
  }
LAB_8012f7ec:
  if ((((DAT_803de524 & 0x20000) == 0) || (iVar5 == 0)) || (DAT_803de454 == 2)) {
LAB_8012f884:
    if (((DAT_803de524 & 0x80000) != 0) && (DAT_803de454 != 3)) {
      if (DAT_803de415 == '\0') {
        if (DAT_803de556 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      if (bVar1) {
        uVar11 = FUN_80006ba8(0,0x80000);
        DAT_803de41c = -0x5556;
        DAT_803de41e = -0x5556;
        DAT_803de455 = 3;
        DAT_803de537 = 0;
        DAT_803de536 = '\0';
        uVar11 = FUN_8012fdac(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
        if (bVar2) {
          FUN_8012fcec(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0xc1);
        }
        goto LAB_8012fb2c;
      }
    }
    if (((DAT_803de524 & 0x40000) != 0) && (DAT_803de454 != 4)) {
      if (DAT_803de415 == '\0') {
        if (DAT_803de556 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      if (bVar1) {
        uVar11 = FUN_80006ba8(0,0x40000);
        DAT_803de41c = 0x5555;
        DAT_803de41e = 0x5555;
        DAT_803de455 = 4;
        DAT_803de537 = 1;
        DAT_803de536 = '\x01';
        FUN_8012fdac(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,1);
        goto LAB_8012fb2c;
      }
    }
    iVar4 = (int)sVar10;
    if (iVar4 < 0) {
      iVar4 = -iVar4;
    }
    if (0xe < iVar4) {
      iVar4 = (int)DAT_803de40e;
      if (iVar4 < 0) {
        iVar4 = -iVar4;
      }
      if ((iVar4 < 0xf) && (DAT_803de416 == 0)) {
        if (DAT_803de415 == '\0') {
          bVar1 = false;
        }
        else if (DAT_803de556 == DAT_803dc6ce) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
        if (bVar1) {
          iVar4 = (int)sVar3;
          if (iVar4 < 0) {
            iVar4 = -iVar4;
          }
          if (iVar4 < 10000) {
            iVar4 = 1;
            DAT_803de41a = 0xffff;
            if (sVar10 < 0) {
              iVar4 = -1;
              DAT_803de41a = 1;
            }
            uVar6 = (uint)DAT_803de454 + iVar4 & 0xff;
            if (4 < uVar6) {
              uVar6 = 2;
            }
            if (uVar6 < 2) {
              uVar6 = 4;
            }
            if (uVar6 == 3) {
              DAT_803de41e = -0x5556;
              unaff_r29 = 0;
            }
            else if (uVar6 < 3) {
              if (1 < uVar6) {
                DAT_803de41e = 0;
                unaff_r29 = 2;
              }
            }
            else if (uVar6 < 5) {
              DAT_803de41e = 0x5555;
              unaff_r29 = 1;
            }
            if (uVar6 != (int)(char)DAT_803de454) {
              DAT_803de455 = (byte)uVar6;
              DAT_803de537 = unaff_r29;
            }
            goto LAB_8012fb2c;
          }
        }
      }
    }
    iVar4 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar4 == 0x4e) {
      DAT_803de415 = '\0';
    }
  }
  else {
    if (DAT_803de415 == '\0') {
      if (DAT_803de556 == 0) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
    if (!bVar1) goto LAB_8012f884;
    uVar11 = FUN_80006ba8(0,0x20000);
    DAT_803de41c = 0;
    DAT_803de41e = 0;
    DAT_803de455 = 2;
    DAT_803de537 = 2;
    DAT_803de536 = '\x02';
    FUN_8012fdac(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,2);
  }
LAB_8012fb2c:
  if (DAT_803de455 != 0) {
    if (DAT_803de415 == '\0') {
      FUN_80006824(0,0xf5);
    }
    else {
      FUN_80006824(0,0x37b);
    }
    DAT_803de415 = '\x01';
    DAT_803de454 = DAT_803de455;
    DAT_803de524 = 0;
    DAT_803de436 = 0;
    DAT_803de455 = 0;
  }
  DAT_803de40e = sVar10;
  FUN_80122a48();
  if (DAT_803de413 != '\0') {
    FUN_801242dc();
  }
  FUN_80122a4c();
  DAT_803de528 = DAT_803de528 + 1;
  if (2 < DAT_803de528) {
    DAT_803de528 = 2;
  }
  DAT_803dc6d6 = (**(code **)(*DAT_803dd6d0 + 100))();
  if (DAT_803de512 < 0) {
    if (DAT_803de420 == '\0') {
      if (DAT_803de552 == 0) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
    if (bVar1) {
      DAT_803dc6d4 = 0x140;
      DAT_803dc6d2 = 0x154;
    }
  }
  else {
    DAT_803dc6d2 = DAT_803de50e;
    DAT_803dc6d4 = DAT_803de510;
    DAT_803dc6d6 = DAT_803de512;
  }
  DAT_803de512 = -1;
  DAT_803de43a = DAT_803de439;
  if (DAT_803de439 != '\0') {
    DAT_803de439 = '\0';
    DAT_803dc6d6 = DAT_803de50c;
  }
  bVar1 = DAT_803dc6d6 < 0;
  if (bVar1) {
    DAT_803dc6d6 = -1;
  }
  DAT_803de420 = !bVar1;
  FUN_80006ba8(0,0xe0000);
  DAT_803de434 = '\0';
LAB_8012fca8:
  if (DAT_803de414 != '\0') {
    DAT_803de414 = '\0';
    FUN_800176c8(0);
    uVar9 = 1;
    FUN_80042b9c(0,0,1);
    DAT_803dc084 = 0xff;
    uVar11 = FUN_80006b84(4);
    uVar11 = FUN_80053c98(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x12,'\0',
                          uVar9,param_12,param_13,param_14,param_15,param_16);
    FUN_80017b10(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  FUN_80286884();
  return;
}

/* ===== EN v1.0 retargeted leaves ==========================================
 * Hand-ported helpers below pair by name in objdiff against the live v1.0
 * asm at build/GSAE01/asm/main/dll/baddie/wall_crawler.s. The legacy
 * FUN_xxxx scaffold above is at pre-v1.0 addresses and produces no
 * matches; new fn_xxxxxxxx helpers are appended in batches. */

extern s8  lbl_803DD8B8;
extern s16 lbl_803DD8C0;
extern s16 lbl_803DD8C2;

/* EN v1.0 0x8012EBC8  size: 8b   s16 getter for lbl_803DD8C0. */
s16 fn_8012EBC8(void)
{
    return lbl_803DD8C0;
}

/* EN v1.0 0x8012EBD0  size: 36b  Match-and-consume helper. If the s32
 * argument equals the active id at lbl_803DD8C2, clear the busy flag
 * lbl_803DD8B8 and return 1; else return 0. */
#pragma scheduling off
#pragma peephole off
int GameUI_isItemBeingUsed(s32 id)
{
    if (id == lbl_803DD8C2) {
        lbl_803DD8B8 = 0;
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x8012EBF4  size: 32b  Sign-of-active-id predicate. Returns 1
 * when the current id at lbl_803DD8C2 is non-negative, 0 otherwise. */
int GameUI_isAnyItemBeingUsed(void)
{
    s32 activeId = lbl_803DD8C2;
    s32 inverted = activeId ^ -1;

    return (u32)((inverted >> 1) - (inverted & activeId)) >> 31;
}

/* EN v1.0 0x8012EB7C  size: 76b  Linear search through a 4-byte array
 * for the active id at lbl_803DD8C2. On hit, clears the busy flag at
 * lbl_803DD8B8 and returns the matched value; on miss returns -1. */
#pragma scheduling off
#pragma peephole off
s32 GameUI_isOneOfItemsBeingUsed(s32* arr, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        if (lbl_803DD8C2 == arr[i]) {
            lbl_803DD8B8 = 0;
            return arr[i];
        }
    }
    return -1;
}
#pragma peephole reset
#pragma scheduling reset

extern u8  lbl_803DD7B9;
extern s16 lbl_803DD88C;
extern u8  lbl_803DBA72;
extern s8  shouldCloseCMenu;

/* EN v1.0 0x8012EF30  size: 16b  Latch helper: set busy byte
 * lbl_803DD7B9 and stash s16 arg in lbl_803DD88C. */
#pragma scheduling off
#pragma peephole off
void fn_8012EF30(s16 val)
{
    lbl_803DD7B9 = 1;
    lbl_803DD88C = val;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x8012FB88  size: 8b  u8 setter for lbl_803DBA72. */
void GameUI_setUnusedHudSetting(u8 val)
{
    lbl_803DBA72 = val;
}

/* EN v1.0 0x8012FB90  size: 12b  s8 setter for shouldCloseCMenu. Target
 * emits `extsb r0,r3; stb r0` triple. Forced via #pragma peephole off. */
#pragma peephole off
void CMenu_SetShouldClose(int val)
{
    shouldCloseCMenu = (s8)val;
}
#pragma peephole reset

extern u8 mapScreenVisible;
extern u8 lbl_803DD7C5;
extern u8 cMenuEnabled;
extern void fn_8012D96C(void);
extern void fn_8012DD14(void);
extern void fn_8012DF68(void);
extern void fn_8012E880(void);

/* EN v1.0 0x8012FB2C  size: 92b  Per-frame state advance dispatcher.
 * Gated on the lbl_803DD7C5 enable flag; when zero, fast-returns 0.
 * Otherwise: optionally runs fn_8012D96C (if mapScreenVisible set), runs
 * fn_8012DD14, optionally runs fn_8012DF68 (if cMenuEnabled set),
 * runs fn_8012E880, returns 0. */
int GameUI_run(void)
{
    if (lbl_803DD7C5 == 0) return 0;
    if (mapScreenVisible != 0) fn_8012D96C();
    fn_8012DD14();
    if (cMenuEnabled != 0) fn_8012DF68();
    fn_8012E880();
    return 0;
}
