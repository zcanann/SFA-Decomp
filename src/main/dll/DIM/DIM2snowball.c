#include "ghidra_import.h"
#include "main/dll/DIM/DIM2snowball.h"

extern undefined8 FUN_80008b74();
extern undefined8 FUN_80008cbc();
extern undefined4 FUN_8000a538();
extern undefined8 FUN_8000bb38();
extern undefined4 FUN_8000da78();
extern int FUN_80010340();
extern undefined4 FUN_80010a8c();
extern undefined4 FUN_80010de0();
extern undefined4 FUN_800168a8();
extern undefined8 FUN_80019940();
extern undefined8 FUN_8001f7e0();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern int FUN_80021884();
extern undefined4 FUN_80021c64();
extern uint FUN_80022264();
extern undefined4 FUN_80022790();
extern undefined4 FUN_800238c4();
extern int FUN_80023d8c();
extern undefined4 FUN_80027a44();
extern undefined4 FUN_80027a90();
extern undefined4 FUN_8002ba34();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern int FUN_8002e1ac();
extern int FUN_8002e1f4();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036548();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_800395a4();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80043604();
extern undefined4 FUN_8005517c();
extern int FUN_80064248();
extern int FUN_80065fcc();
extern int FUN_800e8a48();
extern undefined4 FUN_800ea564();
extern undefined4 FUN_801d84c4();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb80;
extern undefined4 DAT_803dcb88;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e56e8;
extern f64 DOUBLE_803e5708;
extern f64 DOUBLE_803e5730;
extern f64 DOUBLE_803e5760;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803e56bc;
extern f32 FLOAT_803e56c0;
extern f32 FLOAT_803e56d8;
extern f32 FLOAT_803e56dc;
extern f32 FLOAT_803e56e0;
extern f32 FLOAT_803e56e4;
extern f32 FLOAT_803e56f4;
extern f32 FLOAT_803e56f8;
extern f32 FLOAT_803e56fc;
extern f32 FLOAT_803e5710;
extern f32 FLOAT_803e5714;
extern f32 FLOAT_803e5718;
extern f32 FLOAT_803e571c;
extern f32 FLOAT_803e5720;
extern f32 FLOAT_803e5724;
extern f32 FLOAT_803e5728;
extern f32 FLOAT_803e573c;
extern f32 FLOAT_803e5740;
extern f32 FLOAT_803e5744;
extern f32 FLOAT_803e5748;
extern f32 FLOAT_803e574c;
extern f32 FLOAT_803e5754;
extern f32 FLOAT_803e5758;
extern f32 FLOAT_803e5768;

/*
 * --INFO--
 *
 * Function: FUN_801b69b0
 * EN v1.0 Address: 0x801B6464
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801B69B0
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b69b0(void)
{
  FUN_8000a538((int *)0xa1,0);
  FUN_8000a538((int *)0xed,0);
  FUN_8005517c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b69e8
 * EN v1.0 Address: 0x801B649C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B69E8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b69e8(int param_1)
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
 * Function: FUN_801b6a18
 * EN v1.0 Address: 0x801B64C4
 * EN v1.0 Size: 2144b
 * EN v1.1 Address: 0x801B6A18
 * EN v1.1 Size: 1352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b6a18(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  iVar1 = FUN_8028683c();
  uVar7 = extraout_f1;
  uVar2 = FUN_80020078(0xd0b);
  uVar3 = FUN_80020078(0xd0c);
  uVar4 = FUN_80020078(0xd0d);
  uVar5 = FUN_80020078(0xd0e);
  pfVar6 = *(float **)(iVar1 + 0xb8);
  if ((((((uVar2 & 0xff) != 0) && (-1 < *(char *)((int)pfVar6 + 0xe))) ||
       (((uVar3 & 0xff) != 0 && ((*(byte *)((int)pfVar6 + 0xe) >> 6 & 1) == 0)))) ||
      (((uVar4 & 0xff) != 0 && ((*(byte *)((int)pfVar6 + 0xe) >> 5 & 1) == 0)))) ||
     (((uVar5 & 0xff) != 0 && ((*(byte *)((int)pfVar6 + 0xe) >> 4 & 1) == 0)))) {
    uVar7 = FUN_8000bb38(0,0x109);
  }
  *(byte *)((int)pfVar6 + 0xe) = (byte)((uVar2 & 0xff) << 7) | *(byte *)((int)pfVar6 + 0xe) & 0x7f;
  *(byte *)((int)pfVar6 + 0xe) =
       (byte)((uVar3 & 0xff) << 6) & 0x40 | *(byte *)((int)pfVar6 + 0xe) & 0xbf;
  *(byte *)((int)pfVar6 + 0xe) =
       (byte)((uVar4 & 0xff) << 5) & 0x20 | *(byte *)((int)pfVar6 + 0xe) & 0xdf;
  *(byte *)((int)pfVar6 + 0xe) =
       (byte)((uVar5 & 0xff) << 4) & 0x10 | *(byte *)((int)pfVar6 + 0xe) & 0xef;
  if (((*(byte *)((int)pfVar6 + 0xe) >> 3 & 1) == 0) && (uVar2 = FUN_80020078(0xa21), uVar2 != 0)) {
    uVar7 = FUN_8000bb38(0,0x109);
    *(byte *)((int)pfVar6 + 0xe) = *(byte *)((int)pfVar6 + 0xe) & 0xf7 | 8;
  }
  if (*(int *)(iVar1 + 0xf4) != 0) {
    uVar2 = FUN_80020078(0xa82);
    if ((uVar2 == 0) ||
       ((uVar2 = FUN_80020078(0x17), uVar2 != 0 && (uVar2 = FUN_80020078(0xead), uVar2 == 0)))) {
      if (*(int *)(iVar1 + 0xf4) == 2) {
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x160
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15a
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15c
                             ,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15f,0,in_r7
                     ,in_r8,in_r9,in_r10);
      }
      else {
        uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x160
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15a
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15c
                             ,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15f,0,in_r7
                     ,in_r8,in_r9,in_r10);
      }
    }
    *(undefined4 *)(iVar1 + 0xf4) = 0;
  }
  if (*(char *)((int)pfVar6 + 0xd) == '\0') {
    uVar2 = FUN_80020078(0x651);
    if (uVar2 != 0) {
      (**(code **)(*DAT_803dd72c + 0x50))(0x13,0xd,1);
      *(undefined *)((int)pfVar6 + 0xd) = 1;
    }
  }
  else {
    uVar2 = FUN_80020078(0x651);
    if (uVar2 == 0) {
      (**(code **)(*DAT_803dd72c + 0x50))(0x13,0xd,0);
      *(undefined *)((int)pfVar6 + 0xd) = 0;
    }
  }
  if (FLOAT_803e56bc < *pfVar6) {
    uVar7 = FUN_80019940(0xff,0xff,0xff,0xff);
    FUN_800168a8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x430);
    *pfVar6 = *pfVar6 - FLOAT_803dc074;
    if (*pfVar6 < FLOAT_803e56bc) {
      *pfVar6 = FLOAT_803e56bc;
    }
  }
  if (*(char *)(pfVar6 + 3) == '\0') {
    uVar2 = FUN_80020078(0x3e2);
    uVar3 = FUN_80020078(0x3e3);
    *(byte *)(pfVar6 + 3) = (byte)uVar3 & (byte)uVar2;
    if (*(char *)(pfVar6 + 3) != '\0') {
      (**(code **)(*DAT_803dd6e8 + 0x38))(0x4ba,0x14,0x8c,1);
    }
  }
  uVar3 = FUN_80020078(0x3e2);
  uVar2 = FUN_80020078(0x3e3);
  uVar2 = countLeadingZeros(uVar2);
  uVar3 = uVar2 >> 5 & uVar3;
  uVar2 = uVar3 & 0xff;
  if (uVar2 != *(byte *)(pfVar6 + 2)) {
    FUN_800201ac(1000,uVar2);
    *(char *)(pfVar6 + 2) = (char)uVar3;
  }
  uVar2 = FUN_80020078(0x8a5);
  if (((uVar2 & 0xff) == 0) && (uVar2 = FUN_80020078(0x89d), uVar2 != 0)) {
    FUN_800201ac(0x8a4,1);
  }
  iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar1 == 0) {
    if ((*(short *)((int)pfVar6 + 10) != 0xe2) &&
       (*(undefined2 *)((int)pfVar6 + 10) = 0xe2, ((uint)pfVar6[1] & 4) != 0)) {
      FUN_8000a538((int *)0xc5,0);
      FUN_8000a538((int *)0xe2,1);
    }
  }
  else if ((*(short *)((int)pfVar6 + 10) != 0xc5) &&
          (*(undefined2 *)((int)pfVar6 + 10) = 0xc5, ((uint)pfVar6[1] & 4) != 0)) {
    FUN_8000a538((int *)0xe2,0);
    FUN_8000a538((int *)0xc5,1);
  }
  FUN_801d84c4(pfVar6 + 1,1,0x1a7,0x64b,0xc1e,(int *)0xa1);
  FUN_801d84c4(pfVar6 + 1,2,0x1a8,0xc0,0xc1f,(int *)0xcf);
  FUN_801d84c4(pfVar6 + 1,4,0x1ba,0x1b9,0xc20,(int *)(int)*(short *)((int)pfVar6 + 10));
  FUN_801d84c4(pfVar6 + 1,8,-1,-1,0xd8f,(int *)0xdc);
  FUN_801d84c4(pfVar6 + 1,0x10,0x1a7,0x64b,0xc1e,(int *)0xed);
  FUN_801d84c4(pfVar6 + 1,0x20,0x1a8,0xc0,0xc1f,(int *)0x36);
  FUN_801d84c4(pfVar6 + 1,0x40,0x1ba,0x1b9,0xc20,(int *)0x35);
  FUN_801d84c4(pfVar6 + 1,0x100,-1,-1,0x3e2,(int *)0x2b);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b6f60
 * EN v1.0 Address: 0x801B6D24
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x801B6F60
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b6f60(int param_1)
{
  int iVar1;
  uint uVar2;
  byte bVar3;
  float *pfVar4;
  
  FUN_80022264(0,0xb);
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(undefined *)(pfVar4 + 2) = 0;
  *pfVar4 = FLOAT_803e56c0;
  iVar1 = FUN_800e8a48();
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  for (bVar3 = 1; bVar3 < 0x27; bVar3 = bVar3 + 1) {
    FUN_800ea564();
  }
  uVar2 = FUN_80020078(0xdc);
  *(char *)(pfVar4 + 3) = (char)uVar2;
  FUN_800201ac(0xf0a,0);
  uVar2 = FUN_80020078(0x89d);
  if ((uVar2 != 0) && (uVar2 = FUN_80020078(0x8a5), uVar2 == 0)) {
    FUN_800201ac(0x89d,0);
  }
  uVar2 = FUN_80020078(0xd0b);
  *(byte *)((int)pfVar4 + 0xe) = (byte)((uVar2 & 0xff) << 7) | *(byte *)((int)pfVar4 + 0xe) & 0x7f;
  uVar2 = FUN_80020078(0xd0c);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar2 & 0xff) << 6) & 0x40 | *(byte *)((int)pfVar4 + 0xe) & 0xbf;
  uVar2 = FUN_80020078(0xd0d);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar2 & 0xff) << 5) & 0x20 | *(byte *)((int)pfVar4 + 0xe) & 0xdf;
  uVar2 = FUN_80020078(0xd0e);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar2 & 0xff) << 4) & 0x10 | *(byte *)((int)pfVar4 + 0xe) & 0xef;
  uVar2 = FUN_80020078(0xa21);
  *(byte *)((int)pfVar4 + 0xe) =
       (byte)((uVar2 & 0xff) << 3) & 8 | *(byte *)((int)pfVar4 + 0xe) & 0xf7;
  (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(param_1 + 0xac),1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  FUN_80043604(0,0,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b710c
 * EN v1.0 Address: 0x801B6EB8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B710C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b710c(int param_1)
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
 * Function: FUN_801b7144
 * EN v1.0 Address: 0x801B6EE0
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x801B7144
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7144(undefined2 *param_1,int param_2)
{
  int iVar1;
  uint uVar2;
  
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar2 != 0) {
    uVar2 = (int)*(short *)(param_2 + 0x1a) << 0xd;
    iVar1 = (int)uVar2 / 0x2d +
            ((int)(uVar2 | (uint)(int)*(short *)(param_2 + 0x1a) >> 0x13) >> 0x1f);
    param_1[1] = (short)iVar1 - (short)(iVar1 >> 0x1f);
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0xe000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b71f4
 * EN v1.0 Address: 0x801B6F88
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801B71F4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b71f4(int param_1)
{
  FUN_8003b9ec(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b721c
 * EN v1.0 Address: 0x801B6FA8
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801B721C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b721c(int param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar2 = FUN_8002ba84();
  if (iVar2 != 0) {
    bVar1 = *pbVar4;
    if (bVar1 == 2) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x38))(iVar2,param_1);
      *pbVar4 = 3;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        uVar3 = FUN_80020078(0xa1b);
        if (uVar3 != 0) {
          FUN_800201ac(0x4e4,0);
          FUN_800201ac(0x4e5,0);
          *pbVar4 = 1;
        }
      }
      else {
        *pbVar4 = 2;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b7328
 * EN v1.0 Address: 0x801B7064
 * EN v1.0 Size: 552b
 * EN v1.1 Address: 0x801B7328
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7328(uint param_1)
{
  char cVar1;
  int iVar2;
  short *psVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined auStack_78 [8];
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  cVar1 = *(char *)((int)psVar3 + 3);
  if (cVar1 == '\x01') {
    *(float *)(psVar3 + 2) = *(float *)(psVar3 + 2) + FLOAT_803dc074;
    if (FLOAT_803e56dc < *(float *)(psVar3 + 2)) {
      *(undefined *)((int)psVar3 + 3) = 2;
      FUN_8000bb38(0,0x109);
      FUN_8000bb38(param_1,0x47b);
      iVar2 = 0x1e;
      dVar5 = (double)FLOAT_803e56e0;
      dVar6 = (double)FLOAT_803e56e4;
      dVar4 = DOUBLE_803e56e8;
      do {
        uStack_5c = FUN_80022264(0xffffff9c,100);
        uStack_5c = uStack_5c ^ 0x80000000;
        local_60 = 0x43300000;
        local_6c = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar4));
        uStack_54 = FUN_80022264(0,0x15e);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_68 = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - dVar4));
        uStack_4c = FUN_80022264(0xffffff9c,100);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_64 = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar4));
        local_70 = (float)dVar6;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fb,auStack_78,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fc,auStack_78,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_6c = FLOAT_803e56e0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e56e8);
    uStack_54 = FUN_80022264(0,0x15e);
    uStack_54 = uStack_54 ^ 0x80000000;
    local_58 = 0x43300000;
    local_68 = FLOAT_803e56e0 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e56e8);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_64 = FLOAT_803e56e0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e56e8);
    local_70 = FLOAT_803e56e4;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fc,auStack_78,2,0xffffffff,0);
  }
  else if (cVar1 < '\x01') {
    if (-1 < cVar1) {
      if (*(char *)(psVar3 + 1) < '\x01') {
        if ((int)*psVar3 != 0xffffffff) {
          FUN_800201ac((int)*psVar3,1);
          FUN_80035ff8(param_1);
          *(undefined *)((int)psVar3 + 3) = 1;
          *(float *)(psVar3 + 2) = FLOAT_803e56d8;
        }
      }
      else {
        iVar2 = FUN_8002ba84();
        if (iVar2 != 0) {
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,4);
          }
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        }
      }
    }
  }
  else if (cVar1 < '\x03') {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b7678
 * EN v1.0 Address: 0x801B728C
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801B7678
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7678(int param_1,int param_2)
{
  uint uVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0xb8);
  *(char *)(psVar2 + 1) = (char)*(undefined2 *)(param_2 + 0x1a);
  *psVar2 = *(short *)(param_2 + 0x1e);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  if (((int)*psVar2 != 0xffffffff) && (uVar1 = FUN_80020078((int)*psVar2), uVar1 != 0)) {
    FUN_80035ff8(param_1);
    *(undefined *)((int)psVar2 + 3) = 2;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b7708
 * EN v1.0 Address: 0x801B7314
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B7708
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7708(int param_1,undefined4 param_2,float *param_3,float *param_4)
{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  if (pfVar3[4] == 0.0) {
    FUN_8000a538((int *)0xdf,1);
  }
  pfVar3[4] = 2.8026e-44;
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar2 == 0x49b23) {
    uVar1 = FUN_80020078(0xc5c);
    if ((uVar1 != 0) && (uVar1 = FUN_80020078(0xc5b), uVar1 == 0)) {
      *param_3 = *pfVar3;
      *param_4 = pfVar3[1];
    }
    uVar1 = FUN_80020078(0xc5b);
    if ((uVar1 != 0) && (uVar1 = FUN_80020078(0xc5c), uVar1 == 0)) {
      *param_3 = -*pfVar3;
      *param_4 = -pfVar3[1];
    }
    uVar1 = FUN_80020078(0xc5b);
    if (uVar1 != 0) {
      FUN_800201ac(0xc5c,0);
    }
    uVar1 = FUN_80020078(0xc5b);
    if (uVar1 == 0) {
      FUN_800201ac(0xc5c,1);
    }
  }
  else if ((iVar2 < 0x49b23) && (iVar2 == 0x1ea9)) {
    *param_3 = *pfVar3;
    *param_4 = pfVar3[1];
  }
  else {
    *param_3 = *pfVar3;
    *param_4 = pfVar3[1];
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b7874
 * EN v1.0 Address: 0x801B7478
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801B7874
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7874(int param_1)
{
  FUN_8003709c(param_1,0x16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b7898
 * EN v1.0 Address: 0x801B749C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B7898
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7898(int param_1)
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
 * Function: FUN_801b78cc
 * EN v1.0 Address: 0x801B74C4
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x801B78CC
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b78cc(uint param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8000bb38(param_1,0x1f5);
  if ((*(int *)(iVar2 + 0x10) != 0) &&
     (*(int *)(iVar2 + 0x10) = *(int *)(iVar2 + 0x10) + -1, *(int *)(iVar2 + 0x10) == 0)) {
    FUN_8000a538((int *)0xdf,0);
  }
  if (*(int *)(*(int *)(param_1 + 0x4c) + 0x14) == 0x49b23) {
    uVar1 = FUN_80020078(0xc61);
    if ((uVar1 != 0) &&
       (*(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) + FLOAT_803dc074,
       FLOAT_803e56f4 < *(float *)(iVar2 + 0xc))) {
      uVar1 = FUN_80020078(0xc5b);
      if (uVar1 == 0) {
        uVar1 = FUN_80020078(0xc5c);
        if (uVar1 != 0) {
          FUN_800201ac(0xc5c,0);
          FUN_800201ac(0xc5b,1);
        }
      }
      else {
        FUN_800201ac(0xc5c,1);
        FUN_800201ac(0xc5b,0);
      }
      *(float *)(iVar2 + 0xc) = FLOAT_803e56f8;
    }
    uVar1 = FUN_80020078(0xc5b);
    if (uVar1 != 0) {
      FUN_800201ac(0xc5c,0);
    }
    uVar1 = FUN_80020078(0xc5b);
    if (uVar1 == 0) {
      FUN_800201ac(0xc5c,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b7a20
 * EN v1.0 Address: 0x801B7604
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x801B7A20
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7a20(undefined2 *param_1,int param_2)
{
  float *pfVar1;
  double dVar2;
  double dVar3;
  
  dVar3 = (double)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000)
                          - DOUBLE_803e5708) / FLOAT_803e56fc);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar1 = *(float **)(param_1 + 0x5c);
  dVar2 = (double)FUN_802945e0();
  *pfVar1 = (float)(dVar3 * dVar2);
  dVar2 = (double)FUN_80294964();
  pfVar1[1] = (float)(dVar3 * dVar2);
  pfVar1[3] = FLOAT_803e56f8;
  pfVar1[4] = 0.0;
  FUN_800372f8((int)param_1,0x16);
  param_1[0x58] = param_1[0x58] | 0x2000;
  if (*(int *)(param_2 + 0x14) == 0x49b23) {
    FUN_800201ac(0xc5c,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b7b7c
 * EN v1.0 Address: 0x801B7720
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801B7B7C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7b7c(int param_1)
{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  if ((*(byte *)((int)puVar1 + 0x1d) & 4) != 0) {
    *(byte *)((int)puVar1 + 0x1d) = *(byte *)((int)puVar1 + 0x1d) & 0xfb;
  }
  FUN_800238c4(*puVar1);
  FUN_800238c4(puVar1[1]);
  (&DAT_803dcb88)[*(byte *)((int)puVar1 + 0x1f)] = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b7be0
 * EN v1.0 Address: 0x801B7780
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B7BE0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7be0(int param_1)
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
 * Function: FUN_801b7c14
 * EN v1.0 Address: 0x801B77A8
 * EN v1.0 Size: 1168b
 * EN v1.1 Address: 0x801B7C14
 * EN v1.1 Size: 1272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7c14(short *param_1)
{
  byte bVar1;
  float fVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  short sVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  float local_88;
  float local_84;
  float local_80;
  short local_7c [6];
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [17];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar8 = *(int *)(param_1 + 0x26);
  iVar9 = *(int *)(param_1 + 0x5c);
  bVar1 = *(byte *)(iVar9 + 0x1d);
  if ((bVar1 & 1) == 0) {
    piVar3 = *(int **)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4);
    pfVar7 = (float *)piVar3[10];
    if ((pfVar7 != (float *)0x0) && ((bVar1 & 4) != 0)) {
      if (FLOAT_803e5710 <= *pfVar7) {
        *(byte *)(iVar9 + 0x1d) = bVar1 & 0xfb;
      }
    }
    *(ushort *)(iVar9 + 0x18) = *(short *)(iVar9 + 0x18) - (ushort)DAT_803dc070;
    if (*(short *)(iVar9 + 0x18) < 1) {
      FUN_80027a90((double)FLOAT_803e571c,piVar3,0,-1,0,0x10);
      *(undefined2 *)(iVar9 + 0x1a) = *(undefined2 *)(iVar8 + 0x1c);
      if (*(short *)(iVar9 + 0x1a) < 0xf) {
        *(undefined2 *)(iVar9 + 0x1a) = 0xf;
      }
      *(byte *)(iVar9 + 0x1d) = *(byte *)(iVar9 + 0x1d) | 1;
      FUN_8000bb38((uint)param_1,0x1f7);
      *(undefined *)(iVar9 + 0x1c) = 0x14;
    }
  }
  else {
    if ((bVar1 & 4) == 0) {
      *(byte *)(iVar9 + 0x1d) = bVar1 | 4;
      uStack_1c = FUN_80022264(0x14,0x28);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar9 + 0x10) = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5730);
      uStack_14 = FUN_80022264(6,10);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(iVar9 + 0x14) =
           (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5730) / FLOAT_803e5714;
    }
    *(ushort *)(iVar9 + 0x1a) = *(short *)(iVar9 + 0x1a) - (ushort)DAT_803dc070;
    *(byte *)(iVar9 + 0x1c) = *(char *)(iVar9 + 0x1c) - DAT_803dc070;
    if (*(char *)(iVar9 + 0x1c) < '\x01') {
      FUN_8000bb38((uint)param_1,0x9f);
    }
    if (*(short *)(iVar9 + 0x1a) < 1) {
      FUN_80027a90((double)FLOAT_803e5718,
                   *(int **)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4),0,-1,0,
                   0x10);
      *(undefined2 *)(iVar9 + 0x18) = *(undefined2 *)(iVar8 + 0x1a);
      if (*(short *)(iVar9 + 0x18) < 0xf) {
        *(undefined2 *)(iVar9 + 0x18) = 0xf;
      }
      *(byte *)(iVar9 + 0x1d) = *(byte *)(iVar9 + 0x1d) & 0xfe;
      FUN_8000bb38((uint)param_1,0x1f6);
    }
  }
  iVar8 = FUN_800395a4((int)param_1,0);
  sVar6 = -*(short *)(iVar8 + 10) + 0x100;
  if (0x800 < sVar6) {
    sVar6 = -*(short *)(iVar8 + 10) + -0x700;
  }
  *(short *)(iVar8 + 10) = -sVar6;
  iVar8 = FUN_800395a4((int)param_1,1);
  sVar6 = -*(short *)(iVar8 + 10) + 0xa0;
  if (0x800 < sVar6) {
    sVar6 = -*(short *)(iVar8 + 10) + -0x760;
  }
  *(short *)(iVar8 + 10) = -sVar6;
  iVar8 = FUN_8002bac4();
  local_70 = -*(float *)(param_1 + 6);
  local_6c = -*(float *)(param_1 + 8);
  local_68 = -*(float *)(param_1 + 10);
  local_7c[0] = -*param_1;
  local_7c[1] = 0;
  local_7c[2] = 0;
  FUN_80021c64(afStack_64,(int)local_7c);
  FUN_80022790((double)*(float *)(iVar8 + 0xc),(double)*(float *)(iVar8 + 0x10),
               (double)*(float *)(iVar8 + 0x14),afStack_64,&local_80,&local_84,&local_88);
  if ((*(byte *)(iVar9 + 0x1d) & 2) != 0) {
    local_84 = *(float *)(param_1 + 8) - *(float *)(iVar8 + 0x10);
    if (local_84 < FLOAT_803e5720) {
      local_84 = -local_84;
    }
    if (local_84 < FLOAT_803e5724) {
      local_88 = local_88 * local_88;
      if (local_88 <= *(float *)(iVar9 + 8)) {
        iVar4 = *(int *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4);
        uStack_14 = (int)*(short *)(*(int *)(iVar4 + (*(ushort *)(iVar4 + 0x18) >> 1 & 1) * 4 + 4) +
                                   (uint)*(byte *)(iVar9 + 0x1e) * 0x10) ^ 0x80000000;
        local_18 = 0x43300000;
        if (local_80 <=
            *(float *)(param_1 + 4) *
            (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5730)) {
          FUN_80036548(iVar8,(int)param_1,'\v',4,0);
        }
      }
    }
  }
  if ((*(byte *)(iVar9 + 0x1d) & 4) != 0) {
    *(float *)(iVar9 + 0x10) = *(float *)(iVar9 + 0x14) * FLOAT_803dc074 + *(float *)(iVar9 + 0x10);
    if (*(float *)(iVar9 + 0x10) <= FLOAT_803e5728) {
      if (*(float *)(iVar9 + 0x10) < FLOAT_803e5714) {
        uStack_14 = FUN_80022264(6,10);
        fVar2 = FLOAT_803e5714;
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        *(float *)(iVar9 + 0x14) =
             (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5730) / FLOAT_803e5714;
        *(float *)(iVar9 + 0x10) = fVar2;
      }
    }
    else {
      uStack_14 = FUN_80022264(6,10);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(iVar9 + 0x14) =
           -(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5730) / FLOAT_803e5714;
      *(float *)(iVar9 + 0x10) = FLOAT_803e5728;
    }
  }
  uVar5 = FUN_80020078(0x1f0);
  if (uVar5 == 0) {
    *(byte *)(iVar9 + 0x1d) = *(byte *)(iVar9 + 0x1d) & 0xfd;
  }
  else {
    *(byte *)(iVar9 + 0x1d) = *(byte *)(iVar9 + 0x1d) | 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b810c
 * EN v1.0 Address: 0x801B7C38
 * EN v1.0 Size: 876b
 * EN v1.1 Address: 0x801B810C
 * EN v1.1 Size: 516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b810c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
{
  undefined uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar5;
  int *piVar6;
  double dVar7;
  undefined8 uVar8;
  
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  piVar6 = *(int **)(param_9 + 0x5c);
  piVar5 = *(int **)(*(int *)(param_9 + 0x3e) + *(char *)((int)param_9 + 0xad) * 4);
  uVar4 = 0;
  FUN_80027a90((double)FLOAT_803e5720,piVar5,0,-1,0,0);
  FUN_80027a44((double)FLOAT_803e5710,piVar5,0);
  *(undefined2 *)(piVar6 + 6) = *(undefined2 *)(param_10 + 0x1a);
  if (*(short *)(piVar6 + 6) < 0xf) {
    *(undefined2 *)(piVar6 + 6) = 0xf;
  }
  *(undefined2 *)((int)piVar6 + 0x1a) = *(undefined2 *)(param_10 + 0x1c);
  if (*(short *)((int)piVar6 + 0x1a) < 0xf) {
    *(undefined2 *)((int)piVar6 + 0x1a) = 0xf;
  }
  dVar7 = (double)FLOAT_803e5720;
  piVar6[2] = (int)(float)(dVar7 * (double)*(float *)(param_9 + 4));
  piVar6[2] = (int)((float)piVar6[2] * (float)piVar6[2]);
  piVar6[3] = (int)(float)(dVar7 * (double)*(float *)(param_9 + 4));
  piVar6[3] = (int)((float)piVar6[3] * (float)piVar6[3]);
  uVar2 = FUN_80020078(0x1f0);
  if (uVar2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = 2;
  }
  *(undefined *)((int)piVar6 + 0x1d) = uVar1;
  for (iVar3 = 0; iVar3 < 4; iVar3 = iVar3 + 1) {
    if ((&DAT_803dcb88)[iVar3] == '\0') {
      (&DAT_803dcb88)[iVar3] = 1;
      *(char *)((int)piVar6 + 0x1f) = (char)iVar3;
      iVar3 = 4;
    }
  }
  iVar3 = FUN_80023d8c(0x28,0x12);
  *piVar6 = iVar3;
  uVar8 = FUN_8001f7e0(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar6,0xc,
                       *(short *)(&DAT_803dcb80 + (uint)*(byte *)((int)piVar6 + 0x1f) * 2) * 0x28,
                       0x28,uVar4,in_r8,in_r9,in_r10);
  iVar3 = FUN_80023d8c(0x28,0x12);
  piVar6[1] = iVar3;
  FUN_8001f7e0(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar6[1],0xc,
               (*(short *)(&DAT_803dcb80 + (uint)*(byte *)((int)piVar6 + 0x1f) * 2) + 1) * 0x28,0x28
               ,uVar4,in_r8,in_r9,in_r10);
  param_9[0x58] = param_9[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b8310
 * EN v1.0 Address: 0x801B7FA4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B8310
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b8310(int param_1)
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
 * Function: FUN_801b8344
 * EN v1.0 Address: 0x801B7FCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B8344
 * EN v1.1 Size: 1344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b8344(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b8884
 * EN v1.0 Address: 0x801B7FD0
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801B8884
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b8884(undefined2 *param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar2 + 0xa0) = *(undefined4 *)(param_2 + 0x14);
  *(byte *)(iVar2 + 0xac) = *(byte *)(iVar2 + 0xac) | 4;
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)(param_1 + 0x1b) = 0;
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0xa10;
  }
  iVar1 = FUN_8002e1ac(*(int *)(iVar2 + 0xa0));
  *(int *)(iVar2 + 0x9c) = iVar1;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}
