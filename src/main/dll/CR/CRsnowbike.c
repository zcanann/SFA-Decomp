#include "ghidra_import.h"
#include "main/dll/CR/CRsnowbike.h"

extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068d0();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80006c88();
extern undefined4 FUN_80017680();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern int FUN_80017a5c();
extern undefined4 FUN_80017a6c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80035d58();
extern undefined4 ObjHits_PollPriorityHitEffectWithCooldown();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80048000();
extern undefined4 FUN_8004800c();
extern undefined4 FUN_80053c98();
extern int FUN_8005b024();
extern undefined8 FUN_80080f14();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_80080f3c();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8012e250();
extern undefined4 FUN_801d8308();
extern undefined4 FUN_801da7f8();

extern undefined4 DAT_803dccc8;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de878;
extern undefined4 DAT_803de880;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e61c0;
extern f32 FLOAT_803e61c8;
extern f32 FLOAT_803e61cc;
extern f32 FLOAT_803e61d0;
extern f32 FLOAT_803e61d8;
extern f32 FLOAT_803e61dc;
extern f32 FLOAT_803e61e0;
extern f32 FLOAT_803e61e8;
extern f32 FLOAT_803e61ec;
extern f32 FLOAT_803e61f0;
extern f32 FLOAT_803e61f4;
extern f32 FLOAT_803e61f8;
extern f32 FLOAT_803e61fc;
extern f32 FLOAT_803e6200;
extern f32 FLOAT_803e6204;
extern f32 FLOAT_803e6208;
extern f32 FLOAT_803e620c;
extern f32 FLOAT_803e6210;
extern f32 FLOAT_803e6214;

/*
 * --INFO--
 *
 * Function: FUN_801dafdc
 * EN v1.0 Address: 0x801DAFDC
 * EN v1.0 Size: 1440b
 * EN v1.1 Address: 0x801DB048
 * EN v1.1 Size: 1080b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dafdc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  byte bVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  undefined8 uVar7;
  
  piVar6 = *(int **)(param_9 + 0xb8);
  iVar5 = *(int *)(param_9 + 0x4c);
  bVar1 = *(byte *)(piVar6 + 5);
  if (bVar1 == 1) {
    if (-1 < *(char *)((int)piVar6 + 0x15)) {
      FUN_800068d0(param_9,0x9e);
      *(byte *)((int)piVar6 + 0x15) = *(byte *)((int)piVar6 + 0x15) & 0x7f | 0x80;
    }
    if ((*(ushort *)(param_9 + 0xb0) & 0x800) != 0) {
      piVar6[4] = (int)((float)piVar6[4] + FLOAT_803dc074);
      if ((float)piVar6[4] <= FLOAT_803e61c8) {
        uVar4 = 0;
      }
      else {
        uVar4 = 2;
        piVar6[4] = (int)((float)piVar6[4] - FLOAT_803e61c8);
      }
      piVar6[3] = (int)((float)piVar6[3] + FLOAT_803dc074);
      if (FLOAT_803e61cc < (float)piVar6[3]) {
        piVar6[3] = (int)((float)piVar6[3] - FLOAT_803e61cc);
        FUN_80081110(param_9,2,uVar4,0,(undefined4 *)0x0);
      }
    }
  }
  else {
    if (bVar1 == 0) {
      if (((*(byte *)(param_9 + 0xaf) & 1) != 0) &&
         (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x194), iVar3 != 0)) {
        FUN_80017680(0x194);
        uVar7 = FUN_80017698((int)*(short *)(iVar5 + 0x20),1);
        uVar4 = FUN_80017ae8();
        if ((uVar4 & 0xff) != 0) {
          puVar2 = FUN_80017aa4(0x20,0x55);
          *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
          *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
          *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
          *(undefined *)(puVar2 + 2) = 2;
          *(undefined *)((int)puVar2 + 5) = *(undefined *)(*(int *)(param_9 + 0x4c) + 5);
          *(undefined *)((int)puVar2 + 7) = *(undefined *)(*(int *)(param_9 + 0x4c) + 7);
          iVar3 = FUN_80017a5c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,puVar2);
          *piVar6 = iVar3;
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        *(undefined *)(piVar6 + 5) = 2;
      }
    }
    else if (2 < bVar1) goto LAB_801db270;
    iVar3 = *(int *)(param_9 + 0xb8);
    *(float *)(iVar3 + 4) = *(float *)(iVar3 + 4) + FLOAT_803dc074;
    if ((FLOAT_803e61c0 <= *(float *)(iVar3 + 4)) &&
       (*(float *)(iVar3 + 4) = *(float *)(iVar3 + 4) - FLOAT_803e61c0,
       (*(ushort *)(param_9 + 0xb0) & 0x800) != 0)) {
      FUN_80081110(param_9,0,2,0,(undefined4 *)0x0);
    }
  }
LAB_801db270:
  if (*(char *)(piVar6 + 5) == '\x01') {
    uVar4 = FUN_80017690(0x193);
    if ((uVar4 == 0) && (*(short *)(iVar5 + 0x1e) == 0x95)) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if (*(char *)(piVar6 + 5) == '\x02') {
      FUN_80017a6c(param_9,0,0,0,'\0','\b');
    }
    else if ((*(char *)(piVar6 + 5) == '\0') && (uVar4 = FUN_80017690(0x194), uVar4 == 0)) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
    }
    iVar3 = FUN_80017a90();
    if ((iVar3 != 0) && ((*(byte *)(param_9 + 0xaf) & 4) != 0)) {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_9,1,4);
    }
  }
  if (FLOAT_803e61d0 < (float)piVar6[2]) {
    piVar6[2] = (int)((float)piVar6[2] - FLOAT_803dc074);
    if ((*(ushort *)(param_9 + 0xb0) & 0x800) != 0) {
      FUN_80081110(param_9,3,0,0,(undefined4 *)0x0);
    }
    if (((float)piVar6[2] <= FLOAT_803e61d0) && (*(char *)(piVar6 + 5) == '\x02')) {
      *(undefined *)(piVar6 + 5) = 1;
      FUN_80017698((int)*(short *)(iVar5 + 0x1e),1);
      uVar4 = FUN_80017690(400);
      if ((uVar4 == 0) ||
         ((uVar4 = FUN_80017690(0x191), uVar4 == 0 || (uVar4 = FUN_80017690(0x192), uVar4 == 0)))) {
        FUN_80006824(0,0x409);
      }
      else {
        FUN_80006824(0,0x7e);
      }
    }
  }
  ObjHits_PollPriorityHitEffectWithCooldown(param_9,8,0xff,0xff,0x78,0x129,(float *)&DAT_803de878);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801db57c
 * EN v1.0 Address: 0x801DB57C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DB480
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801db57c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801db580
 * EN v1.0 Address: 0x801DB580
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801DB594
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801db580(undefined4 param_1)
{
  ObjHits_PollPriorityHitEffectWithCooldown(param_1,8,0xff,0xff,0x78,0x280,(float *)&DAT_803de880);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801db5b8
 * EN v1.0 Address: 0x801DB5B8
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801DB5CC
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801db5b8(short *param_1,int param_2)
{
  float fVar1;
  
  param_1[2] = (*(byte *)(param_2 + 0x18) - 0x7f) * 0x80;
  param_1[1] = (*(byte *)(param_2 + 0x19) - 0x7f) * 0x80;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_2 + 0x1c);
  fVar1 = *(float *)(param_1 + 4);
  FUN_80035d58((int)param_1,(short)(int)(FLOAT_803e61d8 * fVar1),
               (short)(int)(FLOAT_803e61dc * fVar1),(short)(int)(FLOAT_803e61e0 * fVar1));
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801db670
 * EN v1.0 Address: 0x801DB670
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x801DB688
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801db670(int param_1,undefined4 param_2,int param_3)
{
  byte bVar2;
  uint uVar1;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar2 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar2 == 2) {
      FUN_801db7b4(param_1,5);
    }
    else if (bVar2 < 2) {
      if (bVar2 != 0) {
        FUN_801db7b4(param_1,7);
      }
    }
    else if (bVar2 < 4) {
      *(byte *)(iVar4 + 0x1f) = *(byte *)(iVar4 + 0x1f) | 2;
    }
  }
  *(byte *)(iVar4 + 0x1f) = *(byte *)(iVar4 + 0x1f) | 1;
  FUN_80017698(0x60f,0);
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_80017a98();
  if (*(char *)(iVar3 + 0x1d) == '\x05') {
    FUN_80017698(0x60f,1);
    bVar2 = FUN_80006b44();
    if (bVar2 != 0) {
      uVar1 = FUN_80017690(0x7a);
      if (uVar1 != 0) {
        FUN_80017698(0x85,1);
      }
      *(float *)(iVar3 + 0x10) = FLOAT_803e61e8;
      *(undefined *)(iVar3 + 0x1d) = 0;
      FUN_80006824(0,0x10a);
      FUN_800067c0((int *)0xef,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801db7b4
 * EN v1.0 Address: 0x801DB7B4
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801DB7E8
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801db7b4(int param_1,undefined param_2)
{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar2 + 0x1d) = param_2;
  cVar1 = *(char *)(iVar2 + 0x1d);
  if (cVar1 == '\x02') {
    *(undefined *)(iVar2 + 0x1d) = 0;
  }
  else if (cVar1 == '\x05') {
    FUN_80017698(0x2b8,1);
    FUN_80017698(0x4bd,0);
    FUN_80017698(0x85,0);
    FUN_80006b54(0x1d,0x96);
    FUN_800067c0((int *)0xef,1);
    FUN_80006b50();
  }
  else if (cVar1 == '\x03') {
    FUN_80006b54(0x1d,0x3c);
    *(undefined *)(iVar2 + 0x1d) = 0;
    FUN_800067c0((int *)0xc7,1);
    FUN_80006b50();
  }
  else if (cVar1 == '\x06') {
    FUN_800067c0((int *)0xef,0);
    *(undefined *)(iVar2 + 0x1d) = 0;
    *(float *)(iVar2 + 0x14) = FLOAT_803e61e8;
    FUN_80006b4c();
  }
  else if (cVar1 == '\x04') {
    *(undefined *)(iVar2 + 0x1d) = 0;
    FUN_800067c0((int *)0xc7,0);
    FUN_80006b4c();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801db8c4
 * EN v1.0 Address: 0x801DB8C4
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801DB904
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801db8c4(void)
{
  FUN_80006b4c();
  FUN_80048000();
  FUN_800067c0((int *)0xc4,0);
  FUN_800067c0((int *)0x36,0);
  FUN_800067c0((int *)0xef,0);
  FUN_800067c0((int *)0x22,0);
  FUN_800067c0((int *)0xc7,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801db924
 * EN v1.0 Address: 0x801DB924
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DB964
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801db924(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801db94c
 * EN v1.0 Address: 0x801DB94C
 * EN v1.0 Size: 3672b
 * EN v1.1 Address: 0x801DB998
 * EN v1.1 Size: 2732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801db94c(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
  float fVar1;
  int iVar2;
  char cVar5;
  uint uVar3;
  int iVar4;
  byte bVar6;
  undefined4 uVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar8;
  undefined8 uVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double dVar10;
  
  pfVar8 = *(float **)(param_9 + 0xb8);
  iVar2 = FUN_80017a98();
  if (*(int *)(param_9 + 0xf4) != 0) {
    uVar9 = FUN_80080f28(7,'\0');
    uVar9 = FUN_80080f14(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    if (*(int *)(param_9 + 0xf4) == 2) {
      uVar9 = FUN_80006724(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x4f,0,
                           in_r7,in_r8,in_r9,in_r10);
      uVar9 = FUN_80006724(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x50,0,
                           in_r7,in_r8,in_r9,in_r10);
      FUN_80006724(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x245,0,in_r7,
                   in_r8,in_r9,in_r10);
      cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))(0xe,5);
      if (cVar5 == '\0') {
        FUN_80006724(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x51,0,
                     in_r7,in_r8,in_r9,in_r10);
      }
      else {
        FUN_80006724(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x246,0
                     ,in_r7,in_r8,in_r9,in_r10);
      }
    }
    else {
      uVar9 = FUN_80006728(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x4f,0,
                           in_r7,in_r8,in_r9,in_r10);
      uVar9 = FUN_80006728(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x50,0,
                           in_r7,in_r8,in_r9,in_r10);
      FUN_80006728(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x245,0,in_r7,
                   in_r8,in_r9,in_r10);
      cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))(0xe,5);
      if (cVar5 == '\0') {
        FUN_80006728(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x51
                     ,0,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        FUN_80006728(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                     0x246,0,in_r7,in_r8,in_r9,in_r10);
      }
    }
    *(undefined4 *)(param_9 + 0xf4) = 0;
  }
  if ((-1 < *(char *)((int)pfVar8 + 0x22)) && (uVar3 = FUN_80017690(0xc53), uVar3 != 0)) {
    (**(code **)(*DAT_803dd72c + 0x50))(0xe,10,1);
    *(byte *)((int)pfVar8 + 0x22) = *(byte *)((int)pfVar8 + 0x22) & 0x7f | 0x80;
  }
  if (*(char *)((int)pfVar8 + 0x1e) != '\x0e') {
    iVar4 = FUN_8005b024();
    if (iVar4 != 0xe) {
      return;
    }
    bVar6 = (**(code **)(*DAT_803dd72c + 0x40))(0xe);
    FUN_80017a98();
    if (bVar6 == 1) {
      uVar3 = FUN_80017690(0x5f3);
      if (uVar3 != 0) {
        (**(code **)(*DAT_803dd72c + 0x44))(0xe,2);
      }
    }
    else if (((bVar6 != 0) && (bVar6 < 6)) && (uVar3 = FUN_80017690(0x2d0), uVar3 != 0)) {
      (**(code **)(*DAT_803dd72c + 0x44))(0xe,6);
    }
  }
  if ((pfVar8[5] == FLOAT_803e61f0) || ((*(ushort *)(iVar2 + 0xb0) & 0x1000) != 0)) {
    if ((pfVar8[4] != FLOAT_803e61f0) && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
      if (FLOAT_803e61e8 == pfVar8[4]) {
        (**(code **)(*DAT_803dd6cc + 8))(0x73,1);
      }
      pfVar8[4] = pfVar8[4] - FLOAT_803dc074;
      if (pfVar8[4] <= FLOAT_803e61f0) {
        FUN_80017698(0x640,1);
        pfVar8[4] = FLOAT_803e61f0;
        FUN_80017698(0x2b8,0);
        FUN_80017698(0x4bd,1);
        FUN_80017698(0x81,0);
        FUN_80017698(0x82,0);
        FUN_80017698(0x83,0);
        FUN_80017698(0x84,0);
      }
    }
  }
  else {
    if (FLOAT_803e61e8 == pfVar8[5]) {
      (**(code **)(*DAT_803dd6cc + 8))(0x73,1);
    }
    pfVar8[5] = pfVar8[5] - FLOAT_803dc074;
    fVar1 = FLOAT_803e61f0;
    if (pfVar8[5] <= FLOAT_803e61f0) {
      pfVar8[5] = FLOAT_803e61f0;
      pfVar8[4] = fVar1;
      FUN_80017698(0x2b8,0);
      FUN_80017698(0x4bd,1);
      FUN_80017698(0x81,0);
      FUN_80017698(0x82,0);
      FUN_80017698(0x83,0);
      FUN_80017698(0x84,0);
      FUN_80017698(0x63e,1);
      FUN_80017698(1999,1);
    }
  }
  dVar10 = (double)*(float *)(iVar2 + 0x14);
  iVar2 = FUN_8005b024();
  *(char *)((int)pfVar8 + 0x1e) = (char)iVar2;
  uVar3 = FUN_80017690(0xcdc);
  if (uVar3 == 0) {
    pfVar8[1] = FLOAT_803e6204;
    pfVar8[2] = FLOAT_803e6200;
  }
  else {
    if ((double)FLOAT_803e61f0 < (double)pfVar8[3]) {
      FUN_80006c88((double)pfVar8[3],dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x429);
      pfVar8[3] = pfVar8[3] - FLOAT_803dc074;
      if (pfVar8[3] < FLOAT_803e61f0) {
        pfVar8[3] = FLOAT_803e61f0;
      }
    }
    cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))(0xe,1);
    if (cVar5 == '\0') {
      cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))(0xe,5);
      if (cVar5 == '\0') {
        pfVar8[1] = FLOAT_803e61f4;
        pfVar8[2] = FLOAT_803e61f8;
      }
      else {
        pfVar8[1] = FLOAT_803e61fc;
        pfVar8[2] = FLOAT_803e6200;
        if (*(int *)(param_9 + 0xf8) != 0) {
          FUN_80080f3c((double)FLOAT_803e61ec,1);
          *(undefined4 *)(param_9 + 0xf8) = 0;
        }
      }
    }
    else {
      pfVar8[1] = FLOAT_803e61f4;
      pfVar8[2] = FLOAT_803e61f8;
    }
  }
  dVar10 = (double)*pfVar8;
  if ((double)pfVar8[1] != dVar10) {
    *pfVar8 = (float)((double)pfVar8[2] * (double)FLOAT_803dc074 + dVar10);
    if (FLOAT_803e61f0 <= pfVar8[2]) {
      if (pfVar8[1] < *pfVar8) {
        *pfVar8 = pfVar8[1];
      }
    }
    else if (*pfVar8 < pfVar8[1]) {
      *pfVar8 = pfVar8[1];
    }
    dVar10 = (double)*pfVar8;
    param_3 = (double)FLOAT_803e620c;
    param_4 = (double)FLOAT_803e6210;
    param_5 = (double)FLOAT_803e6214;
    FUN_8004800c((double)(float)((double)FLOAT_803e6208 + dVar10),dVar10,param_3,param_4,param_5,0);
  }
  uVar3 = FUN_80017690(0x7d);
  if (uVar3 == 0) {
    uVar3 = FUN_80017690(0x7e);
    if (uVar3 == 0) {
      uVar3 = FUN_80017690(0x7f);
      if (uVar3 != 0) {
        FUN_80017698(0x7f,0);
        if (*(short *)(&DAT_803dccc8 + (uint)*(byte *)(pfVar8 + 7) * 2) == 0x7f) {
          *(byte *)(pfVar8 + 7) = *(byte *)(pfVar8 + 7) + 1;
        }
        else {
          *(undefined *)(pfVar8 + 7) = 0;
        }
      }
    }
    else {
      FUN_80017698(0x7e,0);
      if (*(short *)(&DAT_803dccc8 + (uint)*(byte *)(pfVar8 + 7) * 2) == 0x7e) {
        *(byte *)(pfVar8 + 7) = *(byte *)(pfVar8 + 7) + 1;
      }
      else {
        *(undefined *)(pfVar8 + 7) = 0;
      }
    }
  }
  else {
    FUN_80017698(0x7d,0);
    if (*(short *)(&DAT_803dccc8 + (uint)*(byte *)(pfVar8 + 7) * 2) == 0x7d) {
      *(byte *)(pfVar8 + 7) = *(byte *)(pfVar8 + 7) + 1;
    }
    else {
      *(undefined *)(pfVar8 + 7) = 0;
    }
  }
  if (2 < *(byte *)(pfVar8 + 7)) {
    FUN_80017698(0x80,1);
    *(undefined *)(pfVar8 + 7) = 0;
  }
  if ((*(byte *)((int)pfVar8 + 0x1f) & 1) != 0) {
    *(byte *)((int)pfVar8 + 0x1f) = *(byte *)((int)pfVar8 + 0x1f) & 0xfe;
    FUN_80017698(0x60f,1);
    uVar3 = FUN_80017690(0x7a);
    if (uVar3 == 0) {
      uVar3 = FUN_80017690(0x627);
      if ((uVar3 != 0) && (uVar3 = FUN_80017690(0x63e), uVar3 != 0)) {
        FUN_80017698(0x61c,1);
      }
    }
    else {
      uVar3 = FUN_80017690(0x61c);
      if (uVar3 != 0) {
        FUN_80017698(0x85,1);
      }
    }
  }
  if (*(char *)((int)pfVar8 + 0x1d) == '\0') {
    uVar3 = FUN_80017690(0x60e);
    if (uVar3 != 0) {
      FUN_80017698(0x60e,0);
      FUN_8012e250();
    }
  }
  else if ((*(char *)((int)pfVar8 + 0x1d) == '\x05') && (uVar3 = FUN_80017690(0x60e), uVar3 != 0)) {
    FUN_80017698(0x60e,0);
    FUN_80006b4c();
    uVar3 = FUN_80017690(0x7a);
    if (uVar3 != 0) {
      FUN_80017698(0x85,1);
    }
    pfVar8[4] = FLOAT_803e61e8;
    (**(code **)(*DAT_803dd6cc + 8))(0x73,1);
    *(undefined *)((int)pfVar8 + 0x1d) = 0;
    FUN_80006824(0,0x10a);
  }
  uVar3 = FUN_80017690(0x647);
  if (uVar3 != 0) {
    FUN_80017698(0x612,1);
    FUN_80017698(0x90b,1);
    FUN_80017698(0x87,1);
  }
  uVar3 = FUN_80017690(0xbde);
  if (uVar3 != 0) {
    FUN_80017698(0x2c6,1);
    FUN_80017698(0x2ce,1);
    FUN_80017698(0xbdc,1);
  }
  uVar3 = FUN_80017690(0xbe5);
  if (uVar3 != 0) {
    FUN_80017698(0xbdf,1);
    FUN_80017698(0xbe1,1);
    FUN_80017698(0xbe3,1);
  }
  iVar2 = *(int *)(param_9 + 0xb8);
  FUN_80017a98();
  if (*(char *)(iVar2 + 0x1d) == '\x05') {
    FUN_80017698(0x60f,1);
    bVar6 = FUN_80006b44();
    if (bVar6 != 0) {
      uVar3 = FUN_80017690(0x7a);
      if (uVar3 != 0) {
        FUN_80017698(0x85,1);
      }
      *(float *)(iVar2 + 0x10) = FLOAT_803e61e8;
      *(undefined *)(iVar2 + 0x1d) = 0;
      FUN_80006824(0,0x10a);
      FUN_800067c0((int *)0xef,0);
    }
  }
  uVar3 = FUN_80017690(0x4d0);
  if ((uVar3 == 0) && (uVar3 = FUN_80017690(0x2b5), uVar3 != 0)) {
    FUN_80017698(0x4d0,1);
    uVar7 = 1;
    iVar2 = *DAT_803dd72c;
    uVar9 = (**(code **)(iVar2 + 0x50))(0xe,2);
    FUN_80053c98(uVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x50,'\0',uVar7,iVar2,
                 in_r7,in_r8,in_r9,in_r10);
    (**(code **)(*DAT_803dd72c + 0x50))(0xe,1,0);
  }
  iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar2 == 0) {
    if (*(char *)(pfVar8 + 8) != '3') {
      *(undefined *)(pfVar8 + 8) = 0x33;
      FUN_800067c0((int *)0x33,1);
    }
    if (*(char *)((int)pfVar8 + 0x21) != '\"') {
      *(undefined *)((int)pfVar8 + 0x21) = 0x22;
      FUN_800067c0((int *)0x22,1);
    }
  }
  else {
    if (*(char *)(pfVar8 + 8) != '-') {
      *(undefined *)(pfVar8 + 8) = 0x2d;
      FUN_800067c0((int *)0x2d,1);
    }
    if (*(char *)((int)pfVar8 + 0x21) != -1) {
      *(undefined *)((int)pfVar8 + 0x21) = 0xff;
      FUN_800067c0((int *)0x22,0);
    }
  }
  FUN_801d8308(pfVar8 + 6,1,-1,-1,0xe1e,(int *)0x36);
  FUN_801d8308(pfVar8 + 6,2,-1,-1,0xcbb,(int *)0xc4);
  if ((*(byte *)((int)pfVar8 + 0x1f) & 2) != 0) {
    FUN_80017698(0x60e,1);
    *(byte *)((int)pfVar8 + 0x1f) = *(byte *)((int)pfVar8 + 0x1f) & 0xfd;
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void sc_levelcontrol_hitDetect(void) {}
void sc_levelcontrol_release(void) {}
void sc_levelcontrol_initialise(void) {}
void sc_musictree_free(void) {}
void sc_musictree_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int sc_levelcontrol_getExtraSize(void) { return 0x24; }
int sc_levelcontrol_func08(void) { return 0x0; }
int sc_musictree_getExtraSize(void) { return 0x50; }
int sc_musictree_func08(void) { return 0x0; }

/* Pattern wrappers. */
u8 sc_levelcontrol_func11(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x1d); }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E5554;
extern void fn_8003B8F4(f32);
#pragma peephole off
void sc_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E5554); }
#pragma peephole reset
