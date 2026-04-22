#include "ghidra_import.h"
#include "main/main.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern undefined4 FUN_80020000();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_800217c8();
extern undefined4 FUN_80021b8c();
extern uint FUN_80022264();
extern undefined4 FUN_8002b95c();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002cf80();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern int FUN_80036974();
extern int FUN_80036f50();
extern void* FUN_80037048();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_800375e4();
extern int FUN_800395a4();
extern undefined4 FUN_8003b700();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80041110();
extern int FUN_80065fcc();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de940;
extern undefined4 DAT_803de944;
extern undefined4 DAT_803de946;
extern undefined4 DAT_803de948;
extern undefined4* DAT_803de958;
extern f64 DOUBLE_803e6e38;
extern f64 DOUBLE_803e6e40;
extern f64 DOUBLE_803e6e50;
extern f64 DOUBLE_803e6e70;
extern f64 DOUBLE_803e6ea8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de950;
extern f32 FLOAT_803e6dd0;
extern f32 FLOAT_803e6ddc;
extern f32 FLOAT_803e6de0;
extern f32 FLOAT_803e6de8;
extern f32 FLOAT_803e6df0;
extern f32 FLOAT_803e6df8;
extern f32 FLOAT_803e6dfc;
extern f32 FLOAT_803e6e00;
extern f32 FLOAT_803e6e04;
extern f32 FLOAT_803e6e08;
extern f32 FLOAT_803e6e14;
extern f32 FLOAT_803e6e18;
extern f32 FLOAT_803e6e1c;
extern f32 FLOAT_803e6e20;
extern f32 FLOAT_803e6e24;
extern f32 FLOAT_803e6e28;
extern f32 FLOAT_803e6e2c;
extern f32 FLOAT_803e6e30;
extern f32 FLOAT_803e6e48;
extern f32 FLOAT_803e6e4c;
extern f32 FLOAT_803e6e60;
extern f32 FLOAT_803e6e64;
extern f32 FLOAT_803e6e68;
extern f32 FLOAT_803e6e78;
extern f32 FLOAT_803e6e7c;
extern f32 FLOAT_803e6e80;
extern f32 FLOAT_803e6e84;
extern f32 FLOAT_803e6e88;
extern f32 FLOAT_803e6e8c;
extern f32 FLOAT_803e6e98;
extern f32 FLOAT_803e6e9c;
extern f32 FLOAT_803e6ea0;

/*
 * --INFO--
 *
 * Function: FUN_801fd3a4
 * EN v1.0 Address: 0x801FD3A4
 * EN v1.0 Size: 720b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd3a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  char cVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  double dVar5;
  
  cVar1 = *(char *)(*(int *)(param_9 + 0x4c) + 0x19);
  if (cVar1 == '\x02') {
    iVar3 = *(int *)(param_9 + 0xb8);
    DAT_803de944 = DAT_803de944 - (short)(int)FLOAT_803dc074;
    uVar2 = FUN_80020078((int)*(short *)(iVar3 + 2));
    if (((uVar2 == 0) && (DAT_803de944 < 0xc9)) &&
       ((*(char *)(iVar3 + 0xb) == DAT_803de946 && (uVar2 = FUN_80022264(0,2), uVar2 == 0)))) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x391,0,4,0xffffffff,0);
    }
  }
  else if (*(short *)(param_9 + 0x46) == 0x3c5) {
    iVar3 = *(int *)(param_9 + 0xb8);
    *(short *)(iVar3 + 6) = *(short *)(iVar3 + 6) - (short)(int)FLOAT_803dc074;
    *(float *)(param_9 + 0xc) =
         *(float *)(param_9 + 0x24) * FLOAT_803dc074 + *(float *)(param_9 + 0xc);
    *(float *)(param_9 + 0x10) =
         *(float *)(param_9 + 0x28) * FLOAT_803dc074 + *(float *)(param_9 + 0x10);
    dVar5 = (double)FLOAT_803dc074;
    *(float *)(param_9 + 0x14) =
         (float)((double)*(float *)(param_9 + 0x2c) * dVar5 + (double)*(float *)(param_9 + 0x14));
    if (*(short *)(iVar3 + 6) < 1) {
      FUN_8002cc9c(dVar5,(double)*(float *)(param_9 + 0x2c),param_3,param_4,param_5,param_6,param_7,
                   param_8,param_9);
    }
  }
  else if (cVar1 == '\0') {
    iVar3 = *(int *)(param_9 + 0xb8);
    DAT_803de944 = DAT_803de944 - (short)(int)FLOAT_803dc074;
    uVar2 = FUN_80020078(0x522);
    if ((((uVar2 == 0) && (DAT_803de944 < 0xc9)) && (*(char *)(iVar3 + 0xb) == DAT_803de946)) &&
       (uVar2 = FUN_80022264(0,2), uVar2 == 0)) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x391,0,4,0xffffffff,0);
    }
  }
  else if (cVar1 == '\x01') {
    psVar4 = *(short **)(param_9 + 0xb8);
    uVar2 = FUN_80020078((int)*psVar4);
    if (uVar2 != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x390,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x390,0,4,0xffffffff,0);
      uVar2 = FUN_80022264(0,1);
      if (uVar2 != 0) {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x391,0,4,0xffffffff,0);
      }
    }
    iVar3 = FUN_80036974(param_9,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((short)iVar3 != 0) {
      uVar2 = FUN_80020078((int)*psVar4);
      FUN_800201ac((int)*psVar4,1 - uVar2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd674
 * EN v1.0 Address: 0x801FD674
 * EN v1.0 Size: 280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd674(undefined2 *param_1,int param_2)
{
  undefined2 *puVar1;
  
  puVar1 = *(undefined2 **)(param_1 + 0x5c);
  if (param_1[0x23] == 0x3c5) {
    puVar1[3] = 0x78;
    *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e6dd0;
    FUN_80035eec((int)param_1,0xe,1,0);
  }
  else {
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  }
  *puVar1 = *(undefined2 *)(param_2 + 0x1e);
  puVar1[1] = *(undefined2 *)(param_2 + 0x20);
  puVar1[2] = 100;
  *(char *)((int)puVar1 + 0xb) = (char)*(undefined2 *)(param_2 + 0x1a);
  if (*(char *)(param_2 + 0x19) == '\x01') {
    *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e6dd0;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  DAT_803de940 = FUN_80013ee8(0xa5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd78c
 * EN v1.0 Address: 0x801FD78C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd78c(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd7bc
 * EN v1.0 Address: 0x801FD7BC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd7bc(int param_1)
{
  FUN_8003b9ec(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd7e8
 * EN v1.0 Address: 0x801FD7E8
 * EN v1.0 Size: 192b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd7e8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fd8a8
 * EN v1.0 Address: 0x801FD8A8
 * EN v1.0 Size: 296b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd8a8(int param_1)
{
  int iVar1;
  uint uVar2;
  short sVar4;
  int iVar3;
  short *psVar5;
  double dVar6;
  
  psVar5 = *(short **)(param_1 + 0xb8);
  sVar4 = 1;
  iVar1 = FUN_8002bac4();
  if (iVar1 != 0) {
    if ((int)psVar5[1] != 0xffffffff) {
      uVar2 = FUN_80020078((int)psVar5[1]);
      sVar4 = (short)uVar2;
    }
    uVar2 = FUN_80020078((int)*psVar5);
    if ((((short)uVar2 == 0) && (*(char *)(psVar5 + 2) == '\0')) && (sVar4 != 0)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(DAT_803de948);
      if ((iVar3 != 0) &&
         (dVar6 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18)),
         dVar6 < (double)FLOAT_803e6de8)) {
        FUN_800201ac((int)*psVar5,1);
        *(undefined *)(psVar5 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd9d0
 * EN v1.0 Address: 0x801FD9D0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd9d0(int param_1)
{
  if (*(int *)(param_1 + 0x74) != 0) {
    FUN_80041110();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd9fc
 * EN v1.0 Address: 0x801FD9FC
 * EN v1.0 Size: 296b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd9fc(int param_1)
{
  byte bVar1;
  
  bVar1 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  if (bVar1 == 2) {
    DAT_803de948 = 0x83b;
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 != 0) {
        DAT_803de948 = 0x123;
        goto LAB_801fda80;
      }
    }
    else if (bVar1 < 4) {
      DAT_803de948 = 0x83c;
      goto LAB_801fda80;
    }
    DAT_803de948 = 0x123;
  }
LAB_801fda80:
  FUN_801fd8a8(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fdb24
 * EN v1.0 Address: 0x801FDB24
 * EN v1.0 Size: 456b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fdb24(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  float local_18 [3];
  
  psVar4 = *(short **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if ((*(char *)((int)psVar4 + 5) < '\0') ||
     (((int)psVar4[1] != 0xffffffff && (uVar1 = FUN_80020078((int)psVar4[1]), uVar1 == 0)))) {
    uVar1 = FUN_80020078((int)*psVar4);
    *(byte *)((int)psVar4 + 5) = (byte)((uVar1 & 1) << 7) | *(byte *)((int)psVar4 + 5) & 0x7f;
    if ((uVar1 & 1) == 0) {
      *(char *)(psVar4 + 2) = (char)*(undefined2 *)(*(int *)(param_1 + 0x4c) + 0x1a);
    }
  }
  else if ((*(char *)(psVar4 + 2) < '\x01') && (-1 < *(char *)((int)psVar4 + 5))) {
    if ((int)*psVar4 != 0xffffffff) {
      FUN_800201ac((int)*psVar4,1);
      *(byte *)((int)psVar4 + 5) = *(byte *)((int)psVar4 + 5) & 0x7f | 0x80;
    }
  }
  else {
    iVar2 = FUN_8002ba84();
    if ((iVar2 != 0) &&
       ((local_18[0] = FLOAT_803e6df0, (*(byte *)((int)psVar4 + 5) >> 6 & 1) != 0 ||
        (iVar3 = FUN_80036f50(5,param_1,local_18), iVar3 == 0)))) {
      if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,4);
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_80041110();
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fdcec
 * EN v1.0 Address: 0x801FDCEC
 * EN v1.0 Size: 880b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fdcec(uint param_1)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined auStack_58 [8];
  undefined4 local_50;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36));
  dVar5 = local_40 - DOUBLE_803e6e38;
  *(float *)(iVar4 + 0xc) =
       FLOAT_803dc074 * ((FLOAT_803e6df8 * *(float *)(iVar4 + 0x10)) / FLOAT_803e6df8) +
       *(float *)(iVar4 + 0xc);
  fVar1 = (float)dVar5;
  if (FLOAT_803e6dfc < *(float *)(iVar4 + 0xc)) {
    uVar2 = FUN_80022264(0x32,100);
    local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(float *)(iVar4 + 0x10) = (float)(local_40 - DOUBLE_803e6e40);
    uVar2 = FUN_80022264(0x15e,800);
    local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x1a) ^ 0x80000000);
    *(float *)(iVar4 + 8) =
         FLOAT_803e6e00 /
         ((float)(local_30 - DOUBLE_803e6e40) / (float)(local_38 - DOUBLE_803e6e40));
    *(float *)(iVar4 + 0xc) = FLOAT_803e6e04;
    FUN_8000bb38(param_1,0x111);
    fVar1 = FLOAT_803e6e08;
  }
  dVar6 = (double)fVar1;
  local_30 = (double)(longlong)(int)*(float *)(iVar4 + 0xc);
  local_38 = (double)CONCAT44(0x43300000,(int)(short)(int)*(float *)(iVar4 + 0xc) ^ 0x80000000);
  dVar5 = (double)FUN_802945e0();
  FLOAT_803de950 = (float)dVar5;
  *(float *)(param_1 + 8) =
       FLOAT_803e6e14 * *(float *)(iVar4 + 8) +
       FLOAT_803e6e18 * *(float *)(iVar4 + 8) * (float)dVar5;
  if (((FLOAT_803e6e1c < *(float *)(iVar4 + 0xc)) && (*(float *)(iVar4 + 0xc) < FLOAT_803e6e20)) &&
     (local_50 = *(undefined4 *)(iVar4 + 8), (*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x3a2,auStack_58,2,0xffffffff,0);
  }
  fVar1 = *(float *)(iVar4 + 0xc);
  if (FLOAT_803e6e24 < fVar1) {
    local_30 = (double)(longlong)(int)(FLOAT_803e6e08 * FLOAT_803de950);
    local_38 = (double)CONCAT44(0x43300000,
                                (int)(short)(int)(FLOAT_803e6e08 * FLOAT_803de950) ^ 0x80000000);
    dVar6 = (double)(float)(local_38 - DOUBLE_803e6e40);
  }
  if (fVar1 < FLOAT_803e6e28) {
    dVar6 = (double)(FLOAT_803e6e08 * (fVar1 / FLOAT_803e6e28));
  }
  dVar5 = (double)FLOAT_803e6e04;
  if ((dVar5 <= dVar6) && (dVar5 = dVar6, (double)FLOAT_803e6e08 < dVar6)) {
    dVar5 = (double)FLOAT_803e6e08;
  }
  local_40 = (double)(longlong)(int)dVar5;
  *(char *)(param_1 + 0x36) = (char)(int)dVar5;
  iVar3 = FUN_800395a4(param_1,0);
  if (iVar3 != 0) {
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 10) ^ 0x80000000);
    fVar1 = (float)(local_30 - DOUBLE_803e6e40) + FLOAT_803e6df8;
    if (FLOAT_803e6e2c <= fVar1) {
      fVar1 = fVar1 - FLOAT_803e6e2c;
    }
    local_38 = (double)(longlong)(int)fVar1;
    *(short *)(iVar3 + 10) = (short)(int)fVar1;
  }
  iVar3 = FUN_800395a4(param_1,1);
  if (iVar3 != 0) {
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 10) ^ 0x80000000);
    fVar1 = (float)(local_30 - DOUBLE_803e6e40) + FLOAT_803e6e30;
    if (FLOAT_803e6e2c <= fVar1) {
      fVar1 = fVar1 - FLOAT_803e6e2c;
    }
    *(short *)(iVar3 + 10) = (short)(int)fVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe05c
 * EN v1.0 Address: 0x801FE05C
 * EN v1.0 Size: 124b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe05c(void)
{
  int iVar1;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (in_r8 != '\0') {
    FUN_8003b700(0xff,0xe6,0xd7);
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe0d8
 * EN v1.0 Address: 0x801FE0D8
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe0d8(uint param_1)
{
  FUN_801fdcec(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe0f8
 * EN v1.0 Address: 0x801FE0F8
 * EN v1.0 Size: 268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe0f8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fe204
 * EN v1.0 Address: 0x801FE204
 * EN v1.0 Size: 92b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe204(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  (**(code **)(*DAT_803dd6fc + 0x14))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe260
 * EN v1.0 Address: 0x801FE260
 * EN v1.0 Size: 340b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe260(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fe3b4
 * EN v1.0 Address: 0x801FE3B4
 * EN v1.0 Size: 272b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe3b4(int param_1,int param_2)
{
  double dVar1;
  uint uVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(undefined2 *)(pfVar3 + 3) = *(undefined2 *)(param_2 + 0x1e);
  uVar2 = FUN_80022264(10,0x19);
  dVar1 = DOUBLE_803e6e50;
  *pfVar3 = FLOAT_803e6e4c *
            (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6e50);
  *(undefined2 *)((int)pfVar3 + 0xe) = 0x14;
  *(float *)(param_1 + 0x10) =
       *(float *)(param_2 + 0xc) +
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) - dVar1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  uVar2 = FUN_80022264(0x1e,0x3c);
  pfVar3[1] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6e50);
  uVar2 = FUN_80022264(100,200);
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6e50);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe4c4
 * EN v1.0 Address: 0x801FE4C4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe4c4(void)
{
  FUN_80013e4c(DAT_803de958);
  DAT_803de958 = (undefined4*)0x0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe4f0
 * EN v1.0 Address: 0x801FE4F0
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe4f0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fe540
 * EN v1.0 Address: 0x801FE540
 * EN v1.0 Size: 368b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe540(int param_1)
{
  uint uVar1;
  byte bVar3;
  int iVar2;
  short *psVar4;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 4) == '\0') &&
     (uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0xb8) + 2)), uVar1 != 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  FUN_80041110();
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    bVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
    if (bVar3 == 2) {
      psVar4 = *(short **)(param_1 + 0xb8);
      iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x83b);
      if (iVar2 != 0) {
        FUN_800201ac((int)*psVar4,1);
        FUN_800201ac((int)psVar4[1],0);
        *(undefined *)(psVar4 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    else if ((bVar3 < 2) && (bVar3 != 0)) {
      psVar4 = *(short **)(param_1 + 0xb8);
      iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x123);
      if (iVar2 != 0) {
        FUN_800201ac((int)*psVar4,1);
        FUN_800201ac((int)psVar4[1],0);
        *(undefined *)(psVar4 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe6b0
 * EN v1.0 Address: 0x801FE6B0
 * EN v1.0 Size: 244b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe6b0(undefined2 *param_1,int param_2)
{
  uint uVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  *psVar2 = *(short *)(param_2 + 0x1e);
  psVar2[1] = *(short *)(param_2 + 0x20);
  *(undefined *)(psVar2 + 2) = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80020078((int)*psVar2);
  if (uVar1 != 0) {
    *(undefined *)(psVar2 + 2) = 1;
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe7a4
 * EN v1.0 Address: 0x801FE7A4
 * EN v1.0 Size: 432b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe7a4(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ushort *local_38;
  uint local_34;
  uint local_30;
  ushort local_2c [4];
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_30 = 0;
  local_34 = 0;
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
LAB_801fe91c:
  while( true ) {
    while( true ) {
      do {
        iVar2 = FUN_800375e4(param_1,&local_30,(uint *)&local_38,&local_34);
        if (iVar2 == 0) {
          return;
        }
      } while (local_30 != 0x11);
      if (local_34 != 0x12) break;
      if ((*(byte *)(iVar4 + 0x119) & 0x20) == 0) {
        FUN_8003709c(param_1,0x24);
      }
      FUN_80035ff8(param_1);
      *(undefined *)(iVar4 + 0x118) = 0xb;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if ((int)local_34 < 0x12) {
      if (local_34 != 0x10) goto code_r0x801fe7fc;
      goto LAB_801fe8ac;
    }
    if (local_34 == 0x14) break;
    if ((int)local_34 < 0x14) {
      FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
      uVar1 = (uint)*(short *)(iVar3 + 0x2c);
      if (0 < (int)uVar1) {
        FUN_80020000(uVar1);
      }
      FUN_8002cf80(param_1);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      FUN_8003709c(param_1,0x24);
    }
  }
  goto LAB_801fe8b8;
code_r0x801fe7fc:
  if (0xf < (int)local_34) {
    *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(iVar4 + 0x10c);
    *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(iVar4 + 0x110);
    *(float *)(param_1 + 0x2c) = -*(float *)(iVar4 + 0x114);
    local_20 = FLOAT_803e6e60;
    local_1c = FLOAT_803e6e60;
    local_18 = FLOAT_803e6e60;
    local_24 = FLOAT_803e6e64;
    local_2c[2] = 0;
    local_2c[1] = 0;
    local_2c[0] = *local_38;
    FUN_80021b8c(local_2c,(float *)(param_1 + 0x24));
LAB_801fe8ac:
    FUN_800372f8(param_1,0x24);
LAB_801fe8b8:
    *(undefined *)(iVar4 + 0x118) = 5;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80036018(param_1);
  }
  goto LAB_801fe91c;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe954
 * EN v1.0 Address: 0x801FE954
 * EN v1.0 Size: 580b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe954(short *param_1,undefined4 *param_2)
{
  float fVar1;
  undefined uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  float afStack_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar5 = *(int *)(param_1 + 0x26);
  *(undefined *)((int)param_2 + 0x119) = 0;
  *param_1 = (ushort)*(byte *)(iVar5 + 0x1b) << 8;
  param_1[1] = 0;
  param_1[2] = 0;
  uStack_1c = (uint)*(byte *)(iVar5 + 0x1a);
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6e70) * FLOAT_803e6e68;
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  uVar3 = FUN_80020078((int)*(short *)(iVar5 + 0x1c));
  if (uVar3 == 0) {
    uVar2 = 1;
  }
  else {
    uVar2 = 3;
  }
  *(undefined *)(param_2 + 0x46) = uVar2;
  if ((*(char *)(param_2 + 0x46) == '\x01') &&
     (iVar4 = FUN_801feb98((double)FLOAT_803e6e60,(double)FLOAT_803e6e60,(int)param_1,afStack_28,1),
     iVar4 == 0)) {
    *(undefined *)(param_2 + 0x46) = 2;
  }
  if (*(char *)(iVar5 + 0x26) != '\0') {
    *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 1;
    if (*(char *)(iVar5 + 0x26) == '\x02') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 2;
    }
    if (*(char *)(iVar5 + 0x26) == '\x03') {
      *(undefined *)(param_2 + 0x46) = 10;
    }
    if (*(char *)(iVar5 + 0x26) == '\x04') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 4;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) & 0xfe;
    }
    if (*(char *)(iVar5 + 0x26) == '\x05') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 8;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x10;
    }
    if (*(char *)(iVar5 + 0x26) == '\x06') {
      FUN_8002b95c((int)param_1,1);
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 8;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x10;
    }
    if (*(char *)(iVar5 + 0x26) == '\a') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x20;
    }
  }
  uVar3 = FUN_80020078((int)*(short *)(iVar5 + 0x24));
  if (uVar3 == 0) {
    uVar2 = 0xc;
  }
  else {
    uVar2 = 5;
  }
  *(undefined *)(param_2 + 0x46) = uVar2;
  if (*(char *)(param_2 + 0x46) == '\x05') {
    FUN_800372f8((int)param_1,0x24);
  }
  fVar1 = FLOAT_803e6e60;
  *(float *)(param_1 + 0x12) = FLOAT_803e6e60;
  *(float *)(param_1 + 0x14) = fVar1;
  *(float *)(param_1 + 0x16) = fVar1;
  param_1[0x7c] = 0;
  param_1[0x7d] = 0;
  *param_2 = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801feb98
 * EN v1.0 Address: 0x801FEB98
 * EN v1.0 Size: 532b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801feb98(double param_1,double param_2,int param_3,float *param_4,int param_5)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  undefined4 *local_18 [3];
  
  *param_4 = FLOAT_803e6e60;
  iVar6 = FUN_80065fcc((double)(float)((double)*(float *)(param_3 + 0xc) + param_1),
                       (double)*(float *)(param_3 + 0x10),
                       (double)(float)((double)*(float *)(param_3 + 0x14) + param_2),param_3,
                       local_18,0,0);
  if (iVar6 != 0) {
    fVar1 = FLOAT_803e6e78;
    fVar2 = FLOAT_803e6e78;
    if (0 < iVar6) {
      do {
        fVar4 = *(float *)*local_18[0] - *(float *)(param_3 + 0x10);
        if (*(char *)((float *)*local_18[0] + 5) == '\x0e') {
          fVar3 = fVar2;
          if (fVar2 < FLOAT_803e6e60) {
            fVar3 = -fVar2;
          }
          fVar5 = fVar4;
          if (fVar4 < FLOAT_803e6e60) {
            fVar5 = -fVar4;
          }
          if (fVar5 < fVar3) {
            fVar2 = fVar4;
          }
        }
        else {
          fVar3 = fVar1;
          if (fVar1 < FLOAT_803e6e60) {
            fVar3 = -fVar1;
          }
          fVar5 = fVar4;
          if (fVar4 < FLOAT_803e6e60) {
            fVar5 = -fVar4;
          }
          if (fVar5 < fVar3) {
            fVar1 = fVar4;
          }
        }
        local_18[0] = local_18[0] + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (param_5 == 0) {
      if (FLOAT_803e6e78 != fVar1) {
        *param_4 = fVar1;
        return 0;
      }
      if (FLOAT_803e6e78 != fVar2) {
        *param_4 = fVar2;
        return 1;
      }
      *param_4 = FLOAT_803e6e7c;
    }
    else {
      if (FLOAT_803e6e78 != fVar2) {
        fVar4 = fVar1;
        if (fVar1 < FLOAT_803e6e60) {
          fVar4 = -fVar1;
        }
        fVar3 = fVar2;
        if (fVar2 < FLOAT_803e6e60) {
          fVar3 = -fVar2;
        }
        if ((fVar4 < fVar3) && (fVar2 <= FLOAT_803e6e60)) {
          *param_4 = fVar1;
          return 1;
        }
        *param_4 = fVar2;
        return 0;
      }
      if (FLOAT_803e6e78 != fVar1) {
        *param_4 = fVar1;
        return 1;
      }
      *param_4 = FLOAT_803e6e7c;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801fedac
 * EN v1.0 Address: 0x801FEDAC
 * EN v1.0 Size: 628b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fedac(void)
{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  float *pfVar5;
  int iVar6;
  short *psVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double in_f28;
  double in_f29;
  double dVar11;
  double in_f30;
  double in_f31;
  double dVar12;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  uint local_78 [2];
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
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
  uVar13 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar13 >> 0x20);
  pfVar5 = (float *)uVar13;
  dVar11 = (double)FLOAT_803e6e60;
  dVar9 = dVar11;
  puVar4 = FUN_80037048(0x14,(int *)local_78);
  dVar12 = (double)FLOAT_803e6e80;
  for (iVar6 = 0; fVar1 = FLOAT_803e6e98, iVar6 < (int)local_78[0]; iVar6 = iVar6 + 1) {
    psVar7 = (short *)*puVar4;
    dVar8 = (double)(*(float *)(psVar7 + 8) - *(float *)(iVar3 + 0x10));
    if ((dVar8 <= dVar12) && ((double)FLOAT_803e6e84 <= dVar8)) {
      fVar1 = *(float *)(psVar7 + 6) - *(float *)(iVar3 + 0xc);
      fVar2 = *(float *)(psVar7 + 10) - *(float *)(iVar3 + 0x14);
      dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
      uStack_6c = (uint)*(byte *)(*(int *)(psVar7 + 0x26) + 0x19);
      local_70 = 0x43300000;
      dVar10 = (double)(FLOAT_803e6e88 *
                       (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e6e70));
      if (dVar8 < dVar10) {
        dVar10 = (double)((float)((double)(float)(dVar10 - dVar8) / dVar10) *
                         FLOAT_803e6e8c * *(float *)(psVar7 + 4));
        uStack_6c = (int)*psVar7 ^ 0x80000000;
        local_70 = 0x43300000;
        dVar8 = (double)FUN_802945e0();
        dVar9 = (double)(float)(dVar10 * dVar8 + dVar9);
        uStack_64 = (int)*psVar7 ^ 0x80000000;
        local_68 = 0x43300000;
        dVar8 = (double)FUN_80294964();
        dVar11 = (double)(float)(dVar10 * dVar8 + dVar11);
      }
    }
    puVar4 = puVar4 + 1;
  }
  if (local_78[0] != 0) {
    uStack_6c = local_78[0] ^ 0x80000000;
    local_68 = 0x43300000;
    local_70 = 0x43300000;
    dVar12 = (double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e6ea8;
    *pfVar5 = -(FLOAT_803e6e98 *
                (float)(dVar9 / (double)(float)((double)CONCAT44(0x43300000,uStack_6c) -
                                               DOUBLE_803e6ea8)) - *pfVar5);
    pfVar5[2] = -(fVar1 * (float)(dVar11 / (double)(float)dVar12) - pfVar5[2]);
    fVar1 = FLOAT_803e6e9c;
    *pfVar5 = *pfVar5 * FLOAT_803e6e9c;
    pfVar5[2] = pfVar5[2] * fVar1;
    uStack_64 = uStack_6c;
    dVar9 = FUN_80293900((double)(*pfVar5 * *pfVar5 + pfVar5[2] * pfVar5[2]));
    if ((double)FLOAT_803e6ea0 < dVar9) {
      fVar1 = (float)((double)FLOAT_803e6ea0 / dVar9);
      *pfVar5 = *pfVar5 * fVar1;
      pfVar5[2] = pfVar5[2] * fVar1;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ff020
 * EN v1.0 Address: 0x801FF020
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ff020(int param_1)
{
  FUN_8003709c(param_1,0x24);
  return;
}
