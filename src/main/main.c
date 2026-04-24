#include "ghidra_import.h"
#include "main/dll/CF/laser.h"
#include "main/dll/anim_internal.h"
#include "main/main.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern undefined4 FUN_80035fe8();
extern undefined4 FUN_800360d4();
extern undefined4 FUN_800360f0();
extern int FUN_800369d0();
extern int FUN_80037008();
extern void* FUN_80037134();
extern undefined4 FUN_80037180();
extern undefined4 FUN_8003735c();
extern int FUN_80037584();
extern int FUN_80039520();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern int FUN_800632f4();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
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
 * Function: FUN_801fd398
 * EN v1.0 Address: 0x801FD398
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x801FD3A4
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd398(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
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
    uVar2 = FUN_80017690((int)*(short *)(iVar3 + 2));
    if (((uVar2 == 0) && (DAT_803de944 < 0xc9)) &&
       ((*(char *)(iVar3 + 0xb) == DAT_803de946 && (uVar2 = FUN_80017760(0,2), uVar2 == 0)))) {
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
      FUN_80017ac8(dVar5,(double)*(float *)(param_9 + 0x2c),param_3,param_4,param_5,param_6,param_7,
                   param_8,param_9);
    }
  }
  else if (cVar1 == '\0') {
    iVar3 = *(int *)(param_9 + 0xb8);
    DAT_803de944 = DAT_803de944 - (short)(int)FLOAT_803dc074;
    uVar2 = FUN_80017690(0x522);
    if ((((uVar2 == 0) && (DAT_803de944 < 0xc9)) && (*(char *)(iVar3 + 0xb) == DAT_803de946)) &&
       (uVar2 = FUN_80017760(0,2), uVar2 == 0)) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x391,0,4,0xffffffff,0);
    }
  }
  else if (cVar1 == '\x01') {
    psVar4 = *(short **)(param_9 + 0xb8);
    uVar2 = FUN_80017690((int)*psVar4);
    if (uVar2 != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x390,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x390,0,4,0xffffffff,0);
      uVar2 = FUN_80017760(0,1);
      if (uVar2 != 0) {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x391,0,4,0xffffffff,0);
      }
    }
    iVar3 = FUN_800369d0(param_9,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((short)iVar3 != 0) {
      uVar2 = FUN_80017690((int)*psVar4);
      FUN_80017698((int)*psVar4,1 - uVar2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd6ec
 * EN v1.0 Address: 0x801FD6EC
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x801FD674
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd6ec(undefined2 *param_1,int param_2)
{
  undefined2 *puVar1;
  
  puVar1 = *(undefined2 **)(param_1 + 0x5c);
  if (param_1[0x23] == 0x3c5) {
    puVar1[3] = 0x78;
    *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e6dd0;
    FUN_80035fe8((int)param_1,0xe,1,0);
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
  DAT_803de940 = FUN_80006b14(0xa5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd7d0
 * EN v1.0 Address: 0x801FD7D0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801FD78C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd7d0(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd804
 * EN v1.0 Address: 0x801FD804
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801FD7BC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd804(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd824
 * EN v1.0 Address: 0x801FD824
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FD7E8
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd824(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fd828
 * EN v1.0 Address: 0x801FD828
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801FD8A8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd828(int param_1)
{
  int iVar1;
  uint uVar2;
  short sVar4;
  int iVar3;
  short *psVar5;
  double dVar6;
  
  psVar5 = *(short **)(param_1 + 0xb8);
  sVar4 = 1;
  iVar1 = FUN_80017a98();
  if (iVar1 != 0) {
    if ((int)psVar5[1] != 0xffffffff) {
      uVar2 = FUN_80017690((int)psVar5[1]);
      sVar4 = (short)uVar2;
    }
    uVar2 = FUN_80017690((int)*psVar5);
    if ((((short)uVar2 == 0) && (*(char *)(psVar5 + 2) == '\0')) && (sVar4 != 0)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(DAT_803de948);
      if ((iVar3 != 0) &&
         (dVar6 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18)),
         dVar6 < (double)FLOAT_803e6de8)) {
        FUN_80017698((int)*psVar5,1);
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
 * Function: FUN_801fd938
 * EN v1.0 Address: 0x801FD938
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801FD9D0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd938(int param_1)
{
  if (*(int *)(param_1 + 0x74) != 0) {
    FUN_800400b0();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fd964
 * EN v1.0 Address: 0x801FD964
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801FD9FC
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd964(int param_1)
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
  FUN_801fd828(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fdae0
 * EN v1.0 Address: 0x801FDAE0
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x801FDB24
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fdae0(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  float local_18 [3];
  
  psVar4 = *(short **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if ((*(char *)((int)psVar4 + 5) < '\0') ||
     (((int)psVar4[1] != 0xffffffff && (uVar1 = FUN_80017690((int)psVar4[1]), uVar1 == 0)))) {
    uVar1 = FUN_80017690((int)*psVar4);
    *(byte *)((int)psVar4 + 5) = (byte)((uVar1 & 1) << 7) | *(byte *)((int)psVar4 + 5) & 0x7f;
    if ((uVar1 & 1) == 0) {
      *(char *)(psVar4 + 2) = (char)*(undefined2 *)(*(int *)(param_1 + 0x4c) + 0x1a);
    }
  }
  else if ((*(char *)(psVar4 + 2) < '\x01') && (-1 < *(char *)((int)psVar4 + 5))) {
    if ((int)*psVar4 != 0xffffffff) {
      FUN_80017698((int)*psVar4,1);
      *(byte *)((int)psVar4 + 5) = *(byte *)((int)psVar4 + 5) & 0x7f | 0x80;
    }
  }
  else {
    iVar2 = FUN_80017a90();
    if ((iVar2 != 0) &&
       ((local_18[0] = FLOAT_803e6df0, (*(byte *)((int)psVar4 + 5) >> 6 & 1) != 0 ||
        (iVar3 = FUN_80037008(5,param_1,local_18), iVar3 == 0)))) {
      if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,4);
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_800400b0();
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fdc60
 * EN v1.0 Address: 0x801FDC60
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x801FDCEC
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fdc60(uint param_1)
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
    uVar2 = FUN_80017760(0x32,100);
    local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(float *)(iVar4 + 0x10) = (float)(local_40 - DOUBLE_803e6e40);
    uVar2 = FUN_80017760(0x15e,800);
    local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x1a) ^ 0x80000000);
    *(float *)(iVar4 + 8) =
         FLOAT_803e6e00 /
         ((float)(local_30 - DOUBLE_803e6e40) / (float)(local_38 - DOUBLE_803e6e40));
    *(float *)(iVar4 + 0xc) = FLOAT_803e6e04;
    FUN_80006824(param_1,0x111);
    fVar1 = FLOAT_803e6e08;
  }
  dVar6 = (double)fVar1;
  local_30 = (double)(longlong)(int)*(float *)(iVar4 + 0xc);
  local_38 = (double)CONCAT44(0x43300000,(int)(short)(int)*(float *)(iVar4 + 0xc) ^ 0x80000000);
  dVar5 = (double)FUN_80293f90();
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
  iVar3 = FUN_80039520(param_1,0);
  if (iVar3 != 0) {
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 10) ^ 0x80000000);
    fVar1 = (float)(local_30 - DOUBLE_803e6e40) + FLOAT_803e6df8;
    if (FLOAT_803e6e2c <= fVar1) {
      fVar1 = fVar1 - FLOAT_803e6e2c;
    }
    local_38 = (double)(longlong)(int)fVar1;
    *(short *)(iVar3 + 10) = (short)(int)fVar1;
  }
  iVar3 = FUN_80039520(param_1,1);
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
 * Function: FUN_801fdfb0
 * EN v1.0 Address: 0x801FDFB0
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801FE05C
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fdfb0(void)
{
  int iVar1;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (in_r8 != '\0') {
    FUN_8003b56c(0xff,0xe6,0xd7);
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe000
 * EN v1.0 Address: 0x801FE000
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801FE0D8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe000(uint param_1)
{
  FUN_801fdc60(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe020
 * EN v1.0 Address: 0x801FE020
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FE0F8
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe020(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fe024
 * EN v1.0 Address: 0x801FE024
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801FE204
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe024(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  (**(code **)(*DAT_803dd6fc + 0x14))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe080
 * EN v1.0 Address: 0x801FE080
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FE260
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe080(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fe084
 * EN v1.0 Address: 0x801FE084
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801FE3B4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe084(int param_1,int param_2)
{
  double dVar1;
  uint uVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(undefined2 *)(pfVar3 + 3) = *(undefined2 *)(param_2 + 0x1e);
  uVar2 = FUN_80017760(10,0x19);
  dVar1 = DOUBLE_803e6e50;
  *pfVar3 = FLOAT_803e6e4c *
            (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6e50);
  *(undefined2 *)((int)pfVar3 + 0xe) = 0x14;
  *(float *)(param_1 + 0x10) =
       *(float *)(param_2 + 0xc) +
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) - dVar1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  uVar2 = FUN_80017760(0x1e,0x3c);
  pfVar3[1] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6e50);
  uVar2 = FUN_80017760(100,200);
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6e50);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe194
 * EN v1.0 Address: 0x801FE194
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801FE4C4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe194(void)
{
  FUN_80006b0c(DAT_803de958);
  DAT_803de958 = (undefined4*)0x0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe1c0
 * EN v1.0 Address: 0x801FE1C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FE4F0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe1c0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801fe1c4
 * EN v1.0 Address: 0x801FE1C4
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x801FE540
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe1c4(int param_1)
{
  LaserObject *obj;
  LaserState *state;
  uint uVar1;
  byte bVar3;
  int iVar2;
  
  obj = (LaserObject *)param_1;
  state = obj->state;
  if ((state->sequenceLatched == '\0') &&
     (uVar1 = FUN_80017690((int)state->primarySequenceId), uVar1 != 0)) {
    obj->statusFlags = obj->statusFlags & ~LASER_OBJECT_STATUS_08;
  }
  else {
    obj->statusFlags = obj->statusFlags | LASER_OBJECT_STATUS_08;
  }
  FUN_800400b0();
  if ((obj->statusFlags & 1) != 0) {
    bVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)obj->modeIndex);
    if (bVar3 == 2) {
      iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x83b);
      if (iVar2 != 0) {
        FUN_80017698((int)state->primarySequenceId,1);
        FUN_80017698((int)state->secondarySequenceId,0);
        state->sequenceLatched = 1;
        obj->statusFlags = obj->statusFlags | LASER_OBJECT_STATUS_08;
      }
    }
    else if ((bVar3 < 2) && (bVar3 != 0)) {
      iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x123);
      if (iVar2 != 0) {
        FUN_80017698((int)state->primarySequenceId,1);
        FUN_80017698((int)state->secondarySequenceId,0);
        state->sequenceLatched = 1;
        obj->statusFlags = obj->statusFlags | LASER_OBJECT_STATUS_08;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe324
 * EN v1.0 Address: 0x801FE324
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801FE6B0
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe324(undefined2 *param_1,int param_2)
{
  LaserObject *obj;
  LaserState *state;
  uint uVar1;
  
  obj = (LaserObject *)param_1;
  state = obj->state;
  state->primarySequenceId = *(short *)(param_2 + 0x1e);
  state->secondarySequenceId = *(short *)(param_2 + 0x20);
  state->sequenceLatched = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80017690((int)state->primarySequenceId);
  if (uVar1 != 0) {
    state->sequenceLatched = 1;
    obj->statusFlags = obj->statusFlags | LASER_OBJECT_STATUS_08;
  }
  obj->objectFlags = obj->objectFlags | 0x6000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe3b0
 * EN v1.0 Address: 0x801FE3B0
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801FE7A4
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe3b0(int param_1)
{
  AnimBehaviorObject *obj;
  AnimBehaviorConfig *config;
  AnimBehaviorState *runtimeState;
  uint uVar1;
  int iVar2;
  ushort *local_38;
  uint local_34;
  uint local_30;
  ushort local_2c [4];
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  obj = (AnimBehaviorObject *)param_1;
  config = obj->config;
  runtimeState = obj->runtimeState;
  local_30 = 0;
  local_34 = 0;
LAB_801fe91c:
  while( true ) {
    while( true ) {
      do {
        iVar2 = FUN_80037584(param_1,&local_30,(uint *)&local_38,&local_34);
        if (iVar2 == 0) {
          return;
        }
      } while (local_30 != 0x11);
      if (local_34 != 0x12) break;
      if ((runtimeState->behaviorFlags & 0x20) == 0) {
        FUN_80037180(param_1,0x24);
      }
      FUN_800360d4(param_1);
      runtimeState->state = 0xb;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if ((int)local_34 < 0x12) {
      if (local_34 != 0x10) goto code_r0x801fe7fc;
      goto LAB_801fe8ac;
    }
    if (local_34 == 0x14) break;
    if ((int)local_34 < 0x14) {
      FUN_80017698((int)config->primaryConditionId,1);
      uVar1 = (uint)config->activationEventId;
      if (0 < (int)uVar1) {
        FUN_80017688(uVar1);
      }
      FUN_80017ad0(param_1);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      FUN_80037180(param_1,0x24);
    }
  }
  goto LAB_801fe8b8;
code_r0x801fe7fc:
  if (0xf < (int)local_34) {
    *(float *)(param_1 + 0x24) = runtimeState->reboundVelocityX;
    *(float *)(param_1 + 0x28) = runtimeState->reboundVelocityY;
    *(float *)(param_1 + 0x2c) = -runtimeState->reboundVelocityZ;
    local_20 = FLOAT_803e6e60;
    local_1c = FLOAT_803e6e60;
    local_18 = FLOAT_803e6e60;
    local_24 = FLOAT_803e6e64;
    local_2c[2] = 0;
    local_2c[1] = 0;
    local_2c[0] = *local_38;
    FUN_80017748(local_2c,(float *)(param_1 + 0x24));
LAB_801fe8ac:
    FUN_8003735c(param_1,0x24);
LAB_801fe8b8:
    runtimeState->state = 5;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_800360f0(param_1);
  }
  goto LAB_801fe91c;
}

/*
 * --INFO--
 *
 * Function: FUN_801fe540
 * EN v1.0 Address: 0x801FE540
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x801FE954
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe540(short *param_1,undefined4 *param_2)
{
  AnimBehaviorConfig *config;
  AnimBehaviorState *runtimeState;
  float fVar1;
  undefined uVar2;
  uint uVar3;
  int iVar4;
  float afStack_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  config = ((AnimBehaviorObject *)param_1)->config;
  runtimeState = (AnimBehaviorState *)param_2;
  runtimeState->behaviorFlags = 0;
  *param_1 = (ushort)config->facingAngleByte << 8;
  param_1[1] = 0;
  param_1[2] = 0;
  uStack_1c = (uint)config->speedScaleByte;
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6e70) * FLOAT_803e6e68;
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  uVar3 = FUN_80017690((int)config->primaryConditionId);
  if (uVar3 == 0) {
    uVar2 = 1;
  }
  else {
    uVar2 = 3;
  }
  runtimeState->state = uVar2;
  if ((runtimeState->state == 1) &&
     (iVar4 = FUN_801fe750((double)FLOAT_803e6e60,(double)FLOAT_803e6e60,(int)param_1,afStack_28,1),
     iVar4 == 0)) {
    runtimeState->state = 2;
  }
  if (config->behaviorMode != '\0') {
    runtimeState->behaviorFlags = runtimeState->behaviorFlags | 1;
    if (config->behaviorMode == 2) {
      runtimeState->behaviorFlags = runtimeState->behaviorFlags | 2;
    }
    if (config->behaviorMode == 3) {
      runtimeState->state = 10;
    }
    if (config->behaviorMode == 4) {
      runtimeState->behaviorFlags = runtimeState->behaviorFlags | 4;
      runtimeState->behaviorFlags = runtimeState->behaviorFlags & 0xfe;
    }
    if (config->behaviorMode == 5) {
      runtimeState->behaviorFlags = runtimeState->behaviorFlags | 8;
      runtimeState->behaviorFlags = runtimeState->behaviorFlags | 0x10;
    }
    if (config->behaviorMode == 6) {
      FUN_80017a78((int)param_1,1);
      runtimeState->behaviorFlags = runtimeState->behaviorFlags | 8;
      runtimeState->behaviorFlags = runtimeState->behaviorFlags | 0x10;
    }
    if (config->behaviorMode == 7) {
      runtimeState->behaviorFlags = runtimeState->behaviorFlags | 0x20;
    }
  }
  uVar3 = FUN_80017690((int)config->readyConditionId);
  if (uVar3 == 0) {
    uVar2 = 0xc;
  }
  else {
    uVar2 = 5;
  }
  runtimeState->state = uVar2;
  if (runtimeState->state == 5) {
    FUN_8003735c((int)param_1,0x24);
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
 * Function: FUN_801fe750
 * EN v1.0 Address: 0x801FE750
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801FEB98
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801fe750(double param_1,double param_2,int param_3,float *param_4,int param_5)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  undefined4 *local_18 [3];
  
  *param_4 = FLOAT_803e6e60;
  iVar6 = FUN_800632f4((double)(float)((double)*(float *)(param_3 + 0xc) + param_1),
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
 * Function: FUN_801fe924
 * EN v1.0 Address: 0x801FE924
 * EN v1.0 Size: 584b
 * EN v1.1 Address: 0x801FEDAC
 * EN v1.1 Size: 628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fe924(void)
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
  puVar4 = FUN_80037134(0x14,(int *)local_78);
  dVar12 = (double)FLOAT_803e6e80;
  for (iVar6 = 0; fVar1 = FLOAT_803e6e98, iVar6 < (int)local_78[0]; iVar6 = iVar6 + 1) {
    AnimBehaviorObject *obj;
    AnimBehaviorConfig *config;
    
    psVar7 = (short *)*puVar4;
    obj = (AnimBehaviorObject *)psVar7;
    config = obj->config;
    dVar8 = (double)(*(float *)(psVar7 + 8) - *(float *)(iVar3 + 0x10));
    if ((dVar8 <= dVar12) && ((double)FLOAT_803e6e84 <= dVar8)) {
      fVar1 = *(float *)(psVar7 + 6) - *(float *)(iVar3 + 0xc);
      fVar2 = *(float *)(psVar7 + 10) - *(float *)(iVar3 + 0x14);
      dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
      uStack_6c = (uint)config->forceRadiusByte;
      local_70 = 0x43300000;
      dVar10 = (double)(FLOAT_803e6e88 *
                       (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e6e70));
      if (dVar8 < dVar10) {
        dVar10 = (double)((float)((double)(float)(dVar10 - dVar8) / dVar10) *
                         FLOAT_803e6e8c * *(float *)(psVar7 + 4));
        uStack_6c = (int)*psVar7 ^ 0x80000000;
        local_70 = 0x43300000;
        dVar8 = (double)FUN_80293f90();
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
 * Function: FUN_801feb6c
 * EN v1.0 Address: 0x801FEB6C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801FF020
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801feb6c(int param_1)
{
  FUN_80037180(param_1,0x24);
  return;
}
