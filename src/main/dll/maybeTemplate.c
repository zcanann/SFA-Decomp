#include "ghidra_import.h"
#include "main/dll/maybeTemplate.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006c64();
extern undefined4 FUN_80006c78();
extern undefined4 FUN_80017448();
extern void* FUN_80017470();
extern undefined4 FUN_80017484();
extern int FUN_8001748c();
extern undefined8 FUN_80017494();
extern int FUN_800176d0();
extern undefined4 FUN_80017a90();
extern int FUN_80017a98();
extern undefined8 FUN_80053754();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_8005d370();
extern undefined4 FUN_800709d8();
extern undefined8 FUN_800709e0();
extern undefined8 FUN_800709e8();
extern undefined4 FUN_8011e458();
extern undefined4 FUN_8011e45c();
extern undefined4 FUN_8011e460();
extern undefined4 FUN_801246cc();
extern undefined8 FUN_8025da88();
extern undefined8 FUN_80286820();
extern undefined8 FUN_80286824();
extern int FUN_8028683c();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286888();
extern undefined8 FUN_8028fde8();
extern uint FUN_80294be4();
extern undefined4 FUN_80294d20();
extern int FUN_80294d38();
extern int FUN_80294d44();
extern int FUN_80294d50();
extern undefined4 FUN_80294d58();
extern undefined4 builtin_strncpy();

extern undefined4 DAT_8031c340;
extern undefined4 DAT_8031c341;
extern undefined4 DAT_803a9610;
extern undefined4 DAT_803a9614;
extern undefined4 DAT_803a9618;
extern undefined4 DAT_803a961c;
extern undefined4 DAT_803a9620;
extern undefined4 DAT_803a9624;
extern undefined4 DAT_803a9628;
extern undefined4 DAT_803a962c;
extern undefined4 DAT_803a9630;
extern undefined4 DAT_803a9634;
extern undefined4 DAT_803a9694;
extern undefined4 DAT_803a96ac;
extern undefined4 DAT_803a96b0;
extern undefined4 DAT_803a96b4;
extern undefined4 DAT_803a96b8;
extern undefined4 DAT_803a96bc;
extern undefined4 DAT_803a96c0;
extern undefined4 DAT_803a96c4;
extern undefined4 DAT_803a96d4;
extern undefined4 DAT_803a96d8;
extern undefined4 DAT_803a96dc;
extern undefined4 DAT_803a9898;
extern undefined4 DAT_803a98d8;
extern undefined4 DAT_803a9e18;
extern undefined4 DAT_803a9f18;
extern undefined4 DAT_803a9f4c;
extern float* DAT_803a9f50;
extern undefined4 DAT_803a9f54;
extern float* DAT_803a9f58;
extern float* DAT_803a9f5c;
extern undefined4 DAT_803a9f60;
extern float* DAT_803a9f74;
extern float* DAT_803a9f78;
extern float* DAT_803a9f7c;
extern undefined4 DAT_803a9f80;
extern undefined4 DAT_803a9f84;
extern undefined4 DAT_803a9f88;
extern undefined4 DAT_803a9f8c;
extern undefined4 DAT_803a9f90;
extern undefined4 DAT_803a9f94;
extern undefined4 DAT_803a9fa0;
extern undefined4 DAT_803a9fa8;
extern undefined4 DAT_803a9fb4;
extern undefined4 DAT_803a9fc4;
extern undefined4 DAT_803a9fc8;
extern undefined4 DAT_803a9fcc;
extern undefined4 DAT_803a9fd0;
extern undefined4 DAT_803a9fd4;
extern undefined4 DAT_803a9fd8;
extern undefined4 DAT_803a9fe4;
extern undefined4 DAT_803aa008;
extern undefined4 DAT_803aa00c;
extern undefined4 DAT_803aa010;
extern undefined4 DAT_803aa014;
extern undefined4 DAT_803aa018;
extern undefined4 DAT_803aa01c;
extern undefined4 DAT_803aa020;
extern undefined4 DAT_803aa024;
extern undefined4 DAT_803aa028;
extern undefined4 DAT_803aa02c;
extern undefined4 DAT_803aa030;
extern undefined4 DAT_803aa034;
extern undefined4 DAT_803aa038;
extern undefined4 DAT_803aa03c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc6d0;
extern undefined4 DAT_803dc6d6;
extern undefined4 DAT_803dc734;
extern undefined4 DAT_803dc736;
extern undefined4 DAT_803dc738;
extern undefined4 DAT_803dc73c;
extern undefined4 DAT_803dc740;
extern undefined4 DAT_803dc744;
extern undefined4 DAT_803dc7b0;
extern undefined4 DAT_803dc7b8;
extern undefined4 DAT_803dc7c0;
extern undefined4 DAT_803dc7c4;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de3db;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de412;
extern undefined4 DAT_803de413;
extern undefined4 DAT_803de416;
extern undefined4 DAT_803de418;
extern undefined4 DAT_803de420;
extern undefined4 DAT_803de422;
extern undefined4 DAT_803de42a;
extern undefined4 DAT_803de42c;
extern undefined4 DAT_803de42e;
extern undefined4 DAT_803de430;
extern undefined4 DAT_803de431;
extern undefined4 DAT_803de432;
extern undefined4 DAT_803de433;
extern undefined4 DAT_803de450;
extern undefined4 DAT_803de4c0;
extern byte DAT_803de4c8;
extern undefined4 DAT_803de4f0;
extern undefined4 DAT_803de4f4;
extern undefined4 DAT_803de4f6;
extern undefined4 DAT_803de4fc;
extern undefined4 DAT_803de530;
extern undefined4 DAT_803de534;
extern undefined4 DAT_803de536;
extern undefined4 DAT_803de552;
extern undefined4 DAT_803de554;
extern undefined4 DAT_803e2a98;
extern undefined4 DAT_803e2a9c;
extern undefined4 DAT_803e2aa0;
extern undefined4 DAT_803e2aa4;
extern undefined4 DAT_803e2aa8;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b28;
extern f32 lbl_803DC074;
extern f32 lbl_803DC6DC;
extern f32 lbl_803DC6E0;
extern f32 lbl_803DC6E4;
extern f32 lbl_803DC6E8;
extern f32 lbl_803DC6EC;
extern f32 lbl_803DE468;
extern f32 lbl_803DE4BC;
extern f32 lbl_803DE4C4;
extern f32 lbl_803DE4F8;
extern f32 lbl_803E2ABC;
extern f32 lbl_803E2AE8;
extern f32 lbl_803E2AF0;
extern f32 lbl_803E2B40;
extern f32 lbl_803E2C1C;
extern f32 lbl_803E2C20;
extern f32 lbl_803E2C28;
extern f32 lbl_803E2C34;
extern f32 lbl_803E2C38;
extern f32 lbl_803E2C3C;
extern f32 lbl_803E2C40;
extern f32 lbl_803E2C44;
extern f32 lbl_803E2C48;
extern f32 lbl_803E2C4C;
extern f32 lbl_803E2C50;
extern f32 lbl_803E2C54;
extern f32 lbl_803E2C58;
extern f32 lbl_803E2C5C;
extern f32 lbl_803E2C60;
extern f32 lbl_803E2C64;
extern f32 lbl_803E2C68;
extern f32 lbl_803E2C6C;
extern f32 lbl_803E2C70;
extern f32 lbl_803E2C74;
extern f32 lbl_803E2C78;
extern f32 lbl_803E2C7C;
extern f32 lbl_803E2C80;
extern f32 lbl_803E2C84;
extern f32 lbl_803E2C88;
extern f32 lbl_803E2C8C;
extern f32 lbl_803E2C90;
extern f32 lbl_803E2C94;
extern f32 lbl_803E2C98;
extern char s__02d__02d_8031cd00[];
extern undefined uRam803de4c9;
extern undefined2 uRam803de4ca;
extern undefined uRam803de4cb;
extern undefined4 uRam803de4cc;
extern undefined uRam803de4cd;
extern undefined2 uRam803de4ce;

/*
 * --INFO--
 *
 * Function: FUN_80121c4c
 * EN v1.0 Address: 0x80121C4C
 * EN v1.0 Size: 2396b
 * EN v1.1 Address: 0x80121F30
 * EN v1.1 Size: 2472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80121c4c(undefined4 param_1,undefined4 param_2,uint param_3)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_80286824();
  iVar6 = DAT_803a9fe4;
  iVar3 = DAT_803a9fcc;
  uVar2 = (uint)((ulonglong)uVar13 >> 0x20);
  iVar4 = (int)uVar13;
  iVar11 = DAT_803a9fe4 + -0xd;
  iVar12 = DAT_803a9fcc;
  if (7 < DAT_803a9fcc) {
    iVar12 = 7;
  }
  if (iVar12 != 0) {
    iVar12 = iVar12 + 1;
  }
  iVar8 = 8 - iVar12;
  iVar9 = DAT_803a9fcc + -7;
  if (iVar11 < DAT_803a9fcc + -7) {
    iVar9 = iVar11;
  }
  if (iVar9 < 1) {
    iVar9 = 0;
  }
  iVar7 = iVar11 - iVar9;
  iVar1 = (DAT_803a9fcc + -7) - iVar11;
  if (5 < iVar1) {
    iVar1 = 5;
  }
  if (iVar1 < 1) {
    iVar1 = 0;
  }
  if (DAT_803a9fcc == DAT_803a9fe4) {
    iVar1 = 7;
  }
  iVar10 = 0x10 - iVar1;
  uVar5 = (undefined)((ulonglong)uVar13 >> 0x20);
  if ((param_3 & 0xff) == 0) {
    FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,DAT_803dc740 ^ 0x80000000) -
                                DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                DOUBLE_803e2af8),DAT_803a96ac,uVar2,0x100);
  }
  else {
    FUN_8011e460((double)(float)((double)CONCAT44(0x43300000,DAT_803dc738 ^ 0x80000000) -
                                DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                DOUBLE_803e2af8),DAT_803a96ac,iVar4,uVar5,0x100,0);
  }
  if (iVar12 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,DAT_803dc740 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b0,uVar2,0x100,iVar12,0x12,0);
    }
    else {
      FUN_8011e45c((double)(float)((double)CONCAT44(0x43300000,DAT_803dc738 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b0,iVar4,uVar5,0x100,iVar12,0x12,0);
    }
  }
  if (iVar8 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709d8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar12 + DAT_803dc740 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b4,uVar2,0x100,iVar8,0x12,iVar12,0);
    }
    else {
      FUN_8011e458((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar12 + DAT_803dc738 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b4,iVar4,uVar5,iVar8,0x12,iVar12,0);
    }
  }
  if (iVar9 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,DAT_803dc740 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b8,uVar2,0x100,iVar9,0x12,0);
    }
    else {
      FUN_8011e45c((double)(float)((double)CONCAT44(0x43300000,DAT_803dc738 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b8,iVar4,uVar5,0x100,iVar9,0x12,0);
    }
  }
  if (iVar7 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar9 + DAT_803dc740 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96bc,uVar2,0x100,iVar7,0x12,0);
    }
    else {
      FUN_8011e45c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar9 + DAT_803dc738 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96bc,iVar4,uVar5,0x100,iVar7,0x12,0);
    }
  }
  if (iVar1 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + DAT_803dc740 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96c0,uVar2,0x100,iVar1,0x12,0);
    }
    else {
      FUN_8011e45c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + DAT_803dc738 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96c0,iVar4,uVar5,0x100,iVar1,0x12,0);
    }
  }
  if (iVar10 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709d8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + iVar1 + DAT_803dc740 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96c4,uVar2,0x100,iVar10,0x12,iVar1,0);
    }
    else {
      FUN_8011e458((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + iVar1 + DAT_803dc738 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96c4,iVar4,uVar5,iVar10,0x12,iVar1,0);
    }
  }
  iVar3 = iVar3 - (uint)DAT_803de433;
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  if (iVar3 != 0) {
    iVar3 = iVar3 + 1;
  }
  if (iVar3 == iVar6) {
    iVar3 = iVar3 + 1;
  }
  iVar6 = iVar3;
  if (8 < iVar3) {
    iVar6 = 8;
  }
  iVar12 = iVar12 - iVar6;
  iVar8 = iVar3 + -8;
  if (iVar11 < iVar3 + -8) {
    iVar8 = iVar11;
  }
  if (iVar8 < 1) {
    iVar8 = 0;
  }
  iVar9 = iVar9 - iVar8;
  iVar3 = (iVar3 + -8) - iVar11;
  if (8 < iVar3) {
    iVar3 = 8;
  }
  if (iVar3 < 1) {
    iVar3 = 0;
  }
  iVar1 = iVar1 - iVar3;
  if (iVar12 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709d8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar6 + DAT_803dc740 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96d4,uVar2,0x100,iVar12,0x12,iVar6,0);
    }
    else {
      FUN_8011e458((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar6 + DAT_803dc738 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96d4,iVar4,uVar5,iVar12,0x12,iVar6,0);
    }
  }
  if (iVar9 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar8 + DAT_803dc740 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96d8,uVar2,0x100,iVar9,0x12,0);
    }
    else {
      FUN_8011e45c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar8 + DAT_803dc738 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96d8,iVar4,uVar5,0x100,iVar9,0x12,0);
    }
  }
  if (iVar1 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + iVar3 + DAT_803dc740 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96dc,uVar2,0x100,iVar1,0x12,0);
    }
    else {
      FUN_8011e45c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + iVar3 + DAT_803dc738 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96dc,iVar4,uVar5,0x100,iVar1,0x12,0);
    }
  }
  FUN_80286870();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801225a8
 * EN v1.0 Address: 0x801225A8
 * EN v1.0 Size: 1184b
 * EN v1.1 Address: 0x801228D8
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801225a8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,short param_11,uint param_12,uint param_13,
                 int *param_14,uint param_15,undefined4 param_16)
{
  int iVar1;
  short extraout_r4;
  uint uVar2;
  int iVar3;
  byte bVar4;
  int *piVar5;
  uint uVar6;
  undefined8 uVar7;
  double dVar8;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined8 local_30;
  undefined8 local_28;
  
  iVar1 = FUN_8028683c();
  local_3c = DAT_803e2a9c;
  local_38 = DAT_803e2aa0;
  local_44 = DAT_803e2aa4;
  local_40 = DAT_803e2aa8;
  if ((param_12 & 0xff) == 0) goto LAB_80122bc8;
  local_30 = (double)CONCAT44(0x43300000,param_13 ^ 0x80000000);
  if ((float)(local_30 - DOUBLE_803e2af8) < lbl_803E2C1C) {
LAB_80122988:
    local_30 = (double)CONCAT44(0x43300000,0x23fU - *param_14 ^ 0x80000000);
    dVar8 = (double)lbl_803E2C38;
    uVar2 = param_12;
    piVar5 = param_14;
    uVar6 = param_15;
    uVar7 = FUN_800709e8((double)(float)(local_30 - DOUBLE_803e2af8),dVar8,(&DAT_803a9610)[iVar1],
                         param_12,0x100);
    if (iVar1 == 0x1e) {
      if ((param_15 & 0xff) == 0) {
        FUN_8028fde8(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)&local_3c,
                     &DAT_803dc7b8,(int)extraout_r4,uVar2,param_13,piVar5,uVar6,param_16);
      }
      else {
        iVar1 = (int)extraout_r4;
        if (iVar1 < 0) {
          iVar1 = -iVar1;
        }
        iVar3 = (int)param_11;
        uVar7 = FUN_8028fde8(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                             (int)&local_3c,s__02d__02d_8031cd00,iVar1,iVar3,param_13,piVar5,uVar6,
                             param_16);
        iVar1 = (int)extraout_r4;
        if (iVar1 < 0) {
          iVar1 = -iVar1;
        }
        FUN_8028fde8(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)&local_44,
                     &DAT_803dc7b0,iVar1,iVar3,param_13,piVar5,uVar6,param_16);
      }
    }
    else {
      FUN_8028fde8(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)&local_3c,
                   &DAT_803dc7c0,(int)extraout_r4,uVar2,param_13,piVar5,uVar6,param_16);
    }
    iVar1 = FUN_8001748c();
    FUN_80017494(3,3);
    FUN_80017448(&local_3c,&local_48,(undefined4 *)0x0,(float *)0x0,(float *)0x0,0xffffffff);
    bVar4 = (byte)param_12;
    if (((param_15 & 0xff) == 0) && (param_11 <= extraout_r4)) {
      FUN_80017484(0,0xff,0,bVar4);
    }
    else {
      FUN_80017484(0xff,0xff,0xff,bVar4);
    }
    local_30 = (double)CONCAT44(0x43300000,0x24fU - *param_14 ^ 0x80000000);
    iVar3 = (int)-(lbl_803E2AF0 * local_48 - (float)(local_30 - DOUBLE_803e2af8));
    local_28 = (double)(longlong)iVar3;
    FUN_80006c64(&local_3c,0x93,iVar3,0x1a9);
    if ((param_15 & 0xff) != 0) {
      if (extraout_r4 < 0) {
        FUN_80017484(0xff,0,0,bVar4);
      }
      else {
        FUN_80017484(0,0xff,0,bVar4);
      }
      local_28 = (double)CONCAT44(0x43300000,0x24fU - *param_14 ^ 0x80000000);
      iVar3 = (int)-(lbl_803E2AF0 * local_48 - (float)(local_28 - DOUBLE_803e2af8));
      local_30 = (double)(longlong)iVar3;
      FUN_80006c64(&local_44,0x93,iVar3,0x1a9);
    }
    FUN_80017494(iVar1,3);
  }
  else {
    local_30 = (double)CONCAT44(0x43300000,param_13 ^ 0x80000000);
    if (((lbl_803E2C28 < (float)(local_30 - DOUBLE_803e2af8)) || ((param_13 & 8) != 0)) ||
       (iVar1 == 0x1e)) goto LAB_80122988;
  }
  *param_14 = *param_14 + 0x28;
LAB_80122bc8:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80122a48
 * EN v1.0 Address: 0x80122A48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80122BE0
 * EN v1.1 Size: 2064b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80122a48(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80122a4c
 * EN v1.0 Address: 0x80122A4C
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x801233F0
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80122a4c(void)
{
  if (DAT_803de420 == '\0') {
    if ((DAT_803de552 == 0) &&
       (DAT_803de422 = DAT_803de422 + (ushort)DAT_803dc070 * -0x20, DAT_803de422 < 0)) {
      DAT_803de422 = 0;
    }
  }
  else {
    DAT_803de422 = DAT_803de422 + (ushort)DAT_803dc070 * 0x20;
    if (0xff < DAT_803de422) {
      DAT_803de422 = 0xff;
    }
  }
  if ((DAT_803de420 == '\0') || (DAT_803de422 != 0xff)) {
    DAT_803de552 = DAT_803de552 + (ushort)DAT_803dc070 * -4;
    if (DAT_803de552 < 0) {
      DAT_803de552 = 0;
    }
  }
  else {
    DAT_803de552 = DAT_803de552 + (ushort)DAT_803dc070 * 4;
    if (DAT_803dc6d0 < DAT_803de552) {
      DAT_803de552 = DAT_803dc6d0;
    }
  }
  if (DAT_803de422 != 0) {
    return;
  }
  DAT_803dc6d6 = 0xffff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80122b14
 * EN v1.0 Address: 0x80122B14
 * EN v1.0 Size: 4332b
 * EN v1.1 Address: 0x801234E8
 * EN v1.1 Size: 3684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80122b14(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  short sVar2;
  int iVar3;
  short sVar4;
  int iVar5;
  ushort *puVar6;
  int extraout_r4;
  int extraout_r4_00;
  int extraout_r4_01;
  char *pcVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  byte bVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  byte *pbVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  double dVar19;
  undefined8 extraout_f1;
  undefined8 uVar20;
  double dVar21;
  double dVar22;
  undefined8 uVar23;
  int iStack_d8;
  int iStack_d4;
  int iStack_d0;
  int iStack_cc;
  int iStack_c8;
  int iStack_c4;
  int iStack_c0;
  int iStack_bc;
  int iStack_b8;
  int iStack_b4;
  int local_b0;
  int local_ac;
  undefined4 local_a8;
  char local_a4 [68];
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  
  uVar23 = FUN_80286820();
  iVar9 = (int)uVar23;
  uVar10 = param_11;
  uVar20 = extraout_f1;
  iVar5 = FUN_80017a98();
  sVar2 = DAT_803de418;
  local_a8 = DAT_803e2a98;
  uVar16 = 0;
  if ((DAT_803de418 != 0) && (DAT_803de413 != '\0')) {
    iVar13 = 3;
    iVar12 = 1;
    iVar9 = 0;
    if (0 < DAT_803de530) {
      if (8 < DAT_803de530) {
        pcVar7 = local_a4;
        uVar17 = DAT_803de530 - 1U >> 3;
        if (0 < DAT_803de530 + -8) {
          do {
            *pcVar7 = '\0';
            pcVar7[1] = '\0';
            pcVar7[2] = '\0';
            pcVar7[3] = '\0';
            pcVar7[4] = '\0';
            pcVar7[5] = '\0';
            pcVar7[6] = '\0';
            pcVar7[7] = '\0';
            pcVar7 = pcVar7 + 8;
            iVar9 = iVar9 + 8;
            uVar17 = uVar17 - 1;
          } while (uVar17 != 0);
        }
      }
      pcVar7 = local_a4 + iVar9;
      iVar3 = DAT_803de530 - iVar9;
      if (iVar9 < DAT_803de530) {
        do {
          *pcVar7 = '\0';
          pcVar7 = pcVar7 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
    pcVar7 = local_a4 + DAT_803de530;
    uVar17 = 3 - DAT_803de530;
    if (DAT_803de530 < 3) {
      uVar18 = uVar17 >> 3;
      if (uVar18 != 0) {
        do {
          builtin_strncpy(pcVar7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
          pcVar7 = pcVar7 + 8;
          uVar18 = uVar18 - 1;
        } while (uVar18 != 0);
        uVar17 = uVar17 & 7;
        if (uVar17 == 0) goto LAB_80123640;
      }
      do {
        *pcVar7 = '\x01';
        pcVar7 = pcVar7 + 1;
        uVar17 = uVar17 - 1;
      } while (uVar17 != 0);
    }
LAB_80123640:
    if (DAT_803de530 < 3) {
      DAT_803de530 = 3;
    }
    if (DAT_803de416 < 1) {
      if ((DAT_803de416 < 0) && (iVar13 = 4, DAT_803de416 < -0x32)) {
        iVar12 = 0;
      }
    }
    else {
      iVar12 = 2;
      iVar13 = 4;
      if (0x32 < DAT_803de416) {
        iVar12 = 3;
      }
    }
    iVar9 = DAT_803de534 - iVar12;
    if (iVar9 < 0) {
      iVar9 = iVar9 + DAT_803de530;
    }
    if (DAT_803de530 <= iVar9) {
      iVar9 = iVar9 - DAT_803de530;
    }
    iVar3 = (int)DAT_803de418;
    DAT_803aa024 = 0;
    pbVar15 = &DAT_803de4c8;
    DAT_803de4c8 = 0;
    DAT_803aa008 = 0;
    DAT_803aa028 = 0;
    uRam803de4c9 = 0;
    DAT_803aa00c = 0;
    DAT_803aa02c = 0;
    uRam803de4ca = 0;
    DAT_803aa010 = 0;
    DAT_803aa030 = 0;
    uRam803de4cb = 0;
    DAT_803aa014 = 0;
    DAT_803aa034 = 0;
    uRam803de4cc = 0;
    DAT_803aa018 = 0;
    DAT_803aa038 = 0;
    uRam803de4cd = 0;
    DAT_803aa01c = 0;
    DAT_803aa03c = 0;
    uRam803de4ce = 0;
    DAT_803aa020 = 0;
    for (iVar14 = 0; iVar14 < iVar13; iVar14 = iVar14 + 1) {
      if (local_a4[iVar9] == '\0') {
        FUN_8025da88(0,0,0x280,0x1e0);
        iVar8 = (iVar14 + 3) - iVar12;
        (&DAT_803aa024)[iVar8] = (&DAT_803a9e18)[iVar9];
        (&DAT_803aa008)[iVar8] = (uint)(byte)(&DAT_803a98d8)[iVar9];
        if (1 < (byte)(&DAT_803a9898)[iVar9]) {
          (&DAT_803de4c8)[iVar8] = (&DAT_803a9898)[iVar9];
        }
      }
      iVar9 = iVar9 + 1;
      if (DAT_803de530 <= iVar9) {
        iVar9 = iVar9 - DAT_803de530;
      }
    }
    FUN_8025da88(0,0,0x280,0x1e0);
    FUN_801246cc((int)((ulonglong)uVar23 >> 0x20),(int)uVar23,param_11);
    iVar9 = 0;
    iVar12 = 0;
    do {
      if (1 < *pbVar15) {
        iVar13 = (int)(short)(DAT_803de416 + (short)iVar12);
        sVar4 = sVar2;
        if (iVar13 < DAT_803dc734) {
          sVar4 = sVar2 + (short)(iVar13 - DAT_803dc734) * 8;
        }
        if (DAT_803dc736 < iVar13) {
          sVar4 = sVar4 + (short)(iVar13 - DAT_803dc736) * -8;
        }
        if (sVar4 < 0) {
          sVar4 = 0;
        }
        if (0xff < sVar4) {
          sVar4 = 0xff;
        }
        iVar13 = (int)((int)sVar4 * (uint)DAT_803de554) / 0xff +
                 ((int)((int)sVar4 * (uint)DAT_803de554) >> 0x1f);
        bVar11 = (char)iVar13 - (char)(iVar13 >> 0x1f);
        uVar10 = 0x1e0;
        uVar20 = FUN_8025da88(0,0,0x280,0x1e0);
        FUN_8028fde8(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)&local_a8,
                     &DAT_803dc7c0,(uint)*pbVar15,uVar10,param_13,param_14,param_15,param_16);
        FUN_80017484(0,0,0,bVar11);
        FUN_80006c64(&local_a8,0x93,0x247,(int)DAT_803de416 + iVar12 + 0x2b);
        FUN_80017484(0xff,0xff,0xff,bVar11);
        FUN_80006c64(&local_a8,0x93,0x246,(int)DAT_803de416 + iVar12 + 0x2a);
      }
      pbVar15 = pbVar15 + 1;
      iVar12 = iVar12 + 0x32;
      iVar9 = iVar9 + 1;
    } while (iVar9 < 7);
    iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f);
    FUN_800709e8((double)lbl_803E2C4C,(double)lbl_803E2C50,DAT_803a9694,
                 iVar9 - (iVar9 >> 0x1f) & 0xff,0x100);
    iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f);
    FUN_800709e0((double)lbl_803E2C54,(double)lbl_803E2C50,DAT_803a9694,
                 iVar9 - (iVar9 >> 0x1f) & 0xff,0x100,0x12,10,1);
    iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f);
    FUN_800709e0((double)lbl_803E2C4C,(double)lbl_803E2C58,DAT_803a9694,
                 iVar9 - (iVar9 >> 0x1f) & 0xff,0x100,0x12,10,2);
    param_2 = (double)lbl_803E2C58;
    iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f);
    uVar10 = 0x100;
    param_12 = 0x12;
    param_13 = 10;
    param_14 = 3;
    uVar20 = FUN_800709e0((double)lbl_803E2C54,param_2,DAT_803a9694,iVar9 - (iVar9 >> 0x1f) & 0xff
                          ,0x100,0x12,10,3);
    iVar9 = extraout_r4;
    if ((iVar5 != 0) && (uVar17 = FUN_80294be4(iVar5), uVar17 != 0)) {
      if (DAT_803de536 == '\x01') {
        uVar16 = 0x5a;
      }
      else if (DAT_803de536 < '\x01') {
        if (-1 < DAT_803de536) {
          uVar16 = 0x59;
        }
      }
      else if (DAT_803de536 < '\x03') {
        uVar16 = 0x58;
      }
      param_2 = (double)lbl_803E2C34;
      iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f)
      ;
      uVar10 = 0x100;
      uVar20 = FUN_800709e8((double)lbl_803E2C5C,param_2,(&DAT_803a9610)[uVar16],
                            iVar9 - (iVar9 >> 0x1f) & 0xff,0x100);
      iVar9 = extraout_r4_00;
    }
  }
  if ((DAT_803de4f0 != 0) && (iVar9 = (int)DAT_803de4f6, iVar9 != DAT_803de4f4)) {
    uVar20 = FUN_80053754();
    DAT_803de4f6 = -1;
    DAT_803de4f0 = 0;
    iVar9 = extraout_r4_01;
  }
  if ((DAT_803de4f0 == 0) && (0 < DAT_803de4f4)) {
    DAT_803de4f6 = DAT_803de4f4;
    DAT_803de4f0 = FUN_8005398c(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                (int)DAT_803de4f4,iVar9,uVar10,param_12,param_13,param_14,param_15,
                                param_16);
  }
  dVar22 = (double)lbl_803DE4BC;
  if (dVar22 == (double)lbl_803E2ABC) goto LAB_8012431c;
  local_60 = (double)(longlong)(int)lbl_803DE4BC;
  FUN_800709e8((double)lbl_803E2C60,(double)lbl_803E2C1C,DAT_803a9610,(int)lbl_803DE4BC,0x100)
  ;
  local_58 = (double)(longlong)(int)lbl_803DE4BC;
  FUN_800709e8((double)lbl_803E2C64,(double)lbl_803E2C68,DAT_803a9614,(int)lbl_803DE4BC,0x100)
  ;
  dVar21 = (double)lbl_803E2C70;
  local_50 = (double)(longlong)(int)lbl_803DE4BC;
  FUN_800709e8((double)lbl_803E2C6C,dVar21,DAT_803a9618,(int)lbl_803DE4BC,0x100);
  if ((DAT_803de431 & 8) == 0) {
    dVar21 = (double)lbl_803E2C78;
    local_50 = (double)(longlong)(int)lbl_803DE4BC;
    FUN_800709e8((double)lbl_803E2C74,dVar21,DAT_803a9634,(int)lbl_803DE4BC,0x100);
  }
  if ((DAT_803de42a == 0) || (DAT_803de42a == 0x1c)) {
    dVar21 = (double)lbl_803E2C7C;
    local_48 = (double)(longlong)(int)lbl_803DE4BC;
    FUN_800709e8((double)lbl_803E2C4C,dVar21,DAT_803a961c,(int)lbl_803DE4BC,0x100);
    DAT_803de42e = 0;
    DAT_803de431 = 0;
  }
  else {
    if (DAT_803de42a != DAT_803de42e) {
      DAT_803de431 = 0x3f;
    }
    if (DAT_803de431 != 0) {
      DAT_803de431 = DAT_803de431 - 1;
    }
    if ((DAT_803de431 & 8) == 0) {
      local_50 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_80017484(200,0xe6,0xff,(byte)(int)lbl_803DE4BC);
    }
    else {
      local_50 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_80017484(0x32,0x32,0xff,(byte)(int)lbl_803DE4BC);
    }
    iVar9 = FUN_8001748c();
    uVar20 = FUN_80017494(3,3);
    uVar17 = (uint)DAT_803de42a;
    if ((int)uVar17 < 0x3e9) {
      for (bVar11 = 0; bVar11 < 0x1d; bVar11 = bVar11 + 1) {
        if (uVar17 == (byte)(&DAT_8031c340)[(uint)bVar11 * 2]) {
          uVar16 = (uint)bVar11;
        }
      }
      puVar6 = FUN_80017470(uVar20,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,0x2ad);
    }
    else {
      puVar6 = FUN_80017470(uVar20,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,uVar17);
      uVar16 = 1;
    }
    if ((uVar16 == 0) || (puVar6 == (ushort *)0x0)) {
LAB_80123e30:
      local_48 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_800709e8((double)lbl_803E2C80,(double)lbl_803E2C7C,DAT_803a962c,(int)lbl_803DE4BC,
                   0x100);
    }
    else {
      uVar17 = (uint)(byte)(&DAT_8031c341)[uVar16 * 2];
      if (puVar6[1] <= uVar17) goto LAB_80123e30;
      uVar10 = *(undefined4 *)(*(int *)(puVar6 + 4) + uVar17 * 4);
      iVar5 = FUN_8001748c();
      FUN_80017494(3,3);
      FUN_80006c78(uVar10,8,0,0,&iStack_c8,&iStack_c4,&iStack_c0,&iStack_bc);
      FUN_80006c64(uVar10,8,0,0);
      FUN_80017494(iVar5,3);
      FUN_80006c78(*(undefined4 *)
                    (*(int *)(puVar6 + 4) + (uint)(byte)(&DAT_8031c341)[uVar16 * 2] * 4),8,0,0,
                   &local_ac,&local_b0,&iStack_b4,&iStack_b8);
      iVar5 = (local_b0 - local_ac) + -0x19;
      if (iVar5 < 1) {
        iVar5 = 1;
      }
      local_50 = (double)CONCAT44(0x43300000,0x219U - iVar5 ^ 0x80000000);
      local_58 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_800709e0((double)(float)(local_50 - DOUBLE_803e2af8),(double)lbl_803E2C7C,DAT_803a9630,
                   (int)lbl_803DE4BC,0x100,iVar5,0x16,0);
      local_60 = (double)CONCAT44(0x43300000,0x20dU - iVar5 ^ 0x80000000);
      local_48 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_800709e8((double)(float)(local_60 - DOUBLE_803e2af8),(double)lbl_803E2C7C,DAT_803a962c,
                   (int)lbl_803DE4BC,0x100);
    }
    DAT_803de42e = DAT_803de42a;
    dVar21 = (double)lbl_803E2C7C;
    local_48 = (double)(longlong)(int)lbl_803DE4BC;
    FUN_800709e8((double)lbl_803E2C4C,dVar21,DAT_803a9624,(int)lbl_803DE4BC,0x100);
    FUN_80017494(iVar9,3);
  }
  if (DAT_803de42c == '\0') {
    local_48 = (double)(longlong)(int)lbl_803DE4BC;
    FUN_800709e8((double)lbl_803E2C4C,(double)lbl_803E2C8C,DAT_803a9620,(int)lbl_803DE4BC,
                 0x100);
    DAT_803de430 = '\0';
  }
  else {
    if (DAT_803de42c != DAT_803de430) {
      DAT_803de432 = 0x3f;
    }
    if (DAT_803de432 != 0) {
      DAT_803de432 = DAT_803de432 - 1;
    }
    if ((DAT_803de432 & 8) == 0) {
      local_48 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_80017484(200,0xe6,0xff,(byte)(int)lbl_803DE4BC);
    }
    else {
      local_48 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_80017484(0x32,0x32,0xff,(byte)(int)lbl_803DE4BC);
    }
    uVar16 = 0;
    for (bVar11 = 0; bVar11 < 0x1d; bVar11 = bVar11 + 1) {
      if (DAT_803de42c == (&DAT_8031c340)[(uint)bVar11 * 2]) {
        uVar16 = (uint)bVar11;
      }
    }
    iVar9 = FUN_8001748c();
    uVar20 = FUN_80017494(3,3);
    puVar6 = FUN_80017470(uVar20,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,0x2ad);
    if ((uVar16 == 0) || (puVar6 == (ushort *)0x0)) {
LAB_80124120:
      local_48 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_800709e8((double)lbl_803E2C88,(double)lbl_803E2C84,DAT_803a962c,(int)lbl_803DE4BC,
                   0x100);
    }
    else {
      uVar17 = (uint)(byte)(&DAT_8031c341)[uVar16 * 2];
      if (puVar6[1] <= uVar17) goto LAB_80124120;
      uVar10 = *(undefined4 *)(*(int *)(puVar6 + 4) + uVar17 * 4);
      iVar5 = FUN_8001748c();
      FUN_80017494(3,3);
      FUN_80006c78(uVar10,9,0,0,&iStack_d8,&iStack_d4,&iStack_d0,&iStack_cc);
      FUN_80006c64(uVar10,9,0,0);
      FUN_80017494(iVar5,3);
      FUN_80006c78(*(undefined4 *)
                    (*(int *)(puVar6 + 4) + (uint)(byte)(&DAT_8031c341)[uVar16 * 2] * 4),9,0,0,
                   &local_ac,&local_b0,&iStack_b4,&iStack_b8);
      iVar5 = (local_b0 - local_ac) + -7;
      if (iVar5 < 1) {
        iVar5 = 1;
      }
      local_48 = (double)CONCAT44(0x43300000,0x219U - iVar5 ^ 0x80000000);
      local_50 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_800709e0((double)(float)(local_48 - DOUBLE_803e2af8),(double)lbl_803E2C84,DAT_803a9630,
                   (int)lbl_803DE4BC,0x100,iVar5,0x16,0);
      local_58 = (double)CONCAT44(0x43300000,0x20dU - iVar5 ^ 0x80000000);
      local_60 = (double)(longlong)(int)lbl_803DE4BC;
      FUN_800709e8((double)(float)(local_58 - DOUBLE_803e2af8),(double)lbl_803E2C84,DAT_803a962c,
                   (int)lbl_803DE4BC,0x100);
    }
    DAT_803de430 = DAT_803de42c;
    local_48 = (double)(longlong)(int)lbl_803DE4BC;
    FUN_800709e8((double)lbl_803E2C4C,(double)lbl_803E2C8C,DAT_803a9628,(int)lbl_803DE4BC,
                 0x100);
    FUN_80017494(iVar9,3);
  }
  if (DAT_803de4f0 == 0) {
    local_48 = (double)(longlong)(int)lbl_803DE4BC;
    FUN_80017484(0xff,0xff,0xff,(byte)(int)lbl_803DE4BC);
    iVar9 = FUN_8001748c();
    FUN_80017494(3,3);
    FUN_80006c64(&DAT_803dc7c4,0x93,0x216,0x22);
    FUN_80017494(iVar9,3);
  }
  else {
    fVar1 = lbl_803E2AE8;
    if (DAT_803de4fc != '\0') {
      fVar1 = lbl_803E2C90;
    }
    dVar21 = (double)fVar1;
    dVar22 = (double)lbl_803DE468;
    if (dVar22 <= dVar21) {
      dVar19 = DOUBLE_803e2b28 + dVar22;
      if (dVar21 < DOUBLE_803e2b28 + dVar22) {
        dVar19 = dVar21;
      }
    }
    else {
      dVar19 = dVar22 - DOUBLE_803e2b28;
      if (dVar22 - DOUBLE_803e2b28 < dVar21) {
        dVar19 = dVar21;
      }
    }
    lbl_803DE468 = (float)dVar19;
    lbl_803DE4F8 =
         lbl_803DE4F8 -
         (lbl_803DC6DC + (lbl_803DC074 * (lbl_803DE4F8 - lbl_803DC6DC)) / lbl_803DC6EC);
    fVar1 = lbl_803E2AE8;
    if (lbl_803DE4F8 <= lbl_803E2ABC) {
      lbl_803DE4F8 = lbl_803E2ABC;
      fVar1 = lbl_803DE468;
    }
    lbl_803DE468 = fVar1;
    local_48 = (double)(longlong)(int)(lbl_803DE468 * lbl_803DE4BC);
    uVar16 = (uint)(lbl_803DC6E8 * lbl_803DE4F8 + lbl_803E2C98);
    local_50 = (double)(longlong)(int)uVar16;
    FUN_800709e8((double)(lbl_803DC6E0 * lbl_803DE4F8 + lbl_803E2C94),
                 (double)(lbl_803DC6E4 * lbl_803DE4F8 + lbl_803E2C1C),DAT_803de4f0,
                 (int)(lbl_803DE468 * lbl_803DE4BC),uVar16);
  }
LAB_8012431c:
  FUN_8005d370(0,0xff,0xff,0xff,0xff);
  FUN_8028686c();
  return;
}
