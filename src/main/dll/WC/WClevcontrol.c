#include "ghidra_import.h"
#include "main/dll/WC/WClevcontrol.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006b94();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006c10();
extern uint FUN_80017690();
extern byte FUN_80017a20();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a4c();
extern undefined4 FUN_80017a98();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetTargetMask();
extern int ObjHits_GetPriorityHitWithPosition();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8004036c();
extern undefined4 FUN_80053754();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_80061a80();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_801ee198();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294bd4();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e6938;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e6908;
extern f32 FLOAT_803e690c;
extern f32 FLOAT_803e6924;
extern f32 FLOAT_803e6928;
extern f32 FLOAT_803e692c;
extern f32 FLOAT_803e6930;
extern f32 FLOAT_803e6940;
extern f32 FLOAT_803e6944;
extern f32 FLOAT_803e6948;
extern f32 FLOAT_803e694c;
extern f32 FLOAT_803e6950;
extern f32 FLOAT_803e6954;
extern f32 FLOAT_803e6958;

/*
 * --INFO--
 *
 * Function: FUN_801ee668
 * EN v1.0 Address: 0x801EE668
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801EE880
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ee668(ushort *param_1,int param_2)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  
  (**(code **)(*DAT_803dd6e4 + 0x20))((int)*(short *)(param_2 + 0x6a));
  dVar3 = (double)FUN_80294964();
  dVar4 = (double)FUN_80293f90();
  fVar1 = FLOAT_803e6908;
  if (*(int *)(param_2 + 0x10) != 0) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2e) ^ 0x80000000) -
                   DOUBLE_803e6938) / FLOAT_803e6924;
  }
  *(float *)(param_2 + 0x60) =
       FLOAT_803dc074 * (fVar1 - *(float *)(param_2 + 0x60)) * FLOAT_803e6928 +
       *(float *)(param_2 + 0x60);
  fVar1 = FLOAT_803e692c;
  dVar5 = (double)FLOAT_803e692c;
  dVar2 = -(double)*(float *)(param_2 + 0x60);
  *(float *)(param_2 + 0x78) = *(float *)(param_2 + 0x60);
  *(float *)(param_2 + 0x7c) = fVar1;
  (**(code **)(*DAT_803dd6e4 + 0x28))
            ((double)(((float)(dVar4 * dVar2 + (double)(float)(dVar5 * -dVar3)) * FLOAT_803dc074) /
                     FLOAT_803e6930),
             (double)(((float)(dVar3 * dVar2 + (double)(float)(dVar5 * dVar4)) * FLOAT_803dc074) /
                     FLOAT_803e6930));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ee7bc
 * EN v1.0 Address: 0x801EE7BC
 * EN v1.0 Size: 832b
 * EN v1.1 Address: 0x801EE9EC
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ee7bc(short *param_1,int param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  double dVar1;
  int iVar2;
  int iVar3;
  short sVar4;
  uint uVar5;
  double dVar6;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar2 = *(int *)(param_2 + 0x74) * -6000;
  iVar2 = iVar2 / 0x46 + (iVar2 >> 0x1f);
  iVar2 = iVar2 - (iVar2 >> 0x1f);
  iVar3 = *(int *)(param_2 + 0x70) * -12000;
  iVar3 = iVar3 / 0x46 + (iVar3 >> 0x1f);
  *(short *)(param_2 + 0x2c) =
       (short)(int)-(((float)((double)CONCAT44(0x43300000,*(int *)(param_2 + 0x70) << 3 ^ 0x80000000
                                              ) - DOUBLE_803e6938) / FLOAT_803e6930) *
                     FLOAT_803dc074 -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2c) ^ 0x80000000
                                            ) - DOUBLE_803e6938));
  *(short *)(param_2 + 0x2c) =
       *(short *)(param_2 + 0x2c) -
       (short)((int)((int)*(short *)(param_2 + 0x2c) * (uint)DAT_803dc070) >> 5);
  uVar5 = iVar2 - (uint)(ushort)param_1[1];
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  param_1[1] = (short)(int)(FLOAT_803e6940 *
                            (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) -
                                   DOUBLE_803e6938) * FLOAT_803dc074 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) -
                                  DOUBLE_803e6938));
  dVar1 = DOUBLE_803e6938;
  uVar5 = (iVar3 - (iVar3 >> 0x1f)) - (uint)*(ushort *)(param_2 + 0x2e);
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  dVar6 = (double)FLOAT_803e6940;
  *(short *)(param_2 + 0x2e) =
       (short)(int)(dVar6 * (double)((float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) -
                                            DOUBLE_803e6938) * FLOAT_803dc074) +
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(param_2 + 0x2e) ^ 0x80000000) -
                                  DOUBLE_803e6938));
  sVar4 = param_1[1];
  if (sVar4 < -8000) {
    sVar4 = -8000;
  }
  else if (8000 < sVar4) {
    sVar4 = 8000;
  }
  param_1[1] = sVar4;
  sVar4 = *(short *)(param_2 + 0x2e);
  if (sVar4 < -13000) {
    sVar4 = -13000;
  }
  else if (13000 < sVar4) {
    sVar4 = 13000;
  }
  *(short *)(param_2 + 0x2e) = sVar4;
  *param_1 = *(short *)(param_2 + 0x2c) + 0x4000;
  param_1[2] = *(short *)(param_2 + 0x2e);
  if (param_1[0x50] != 0xf) {
    FUN_800305f8((double)FLOAT_803e6908,dVar1,dVar6,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0xf,0,
                 iVar2,param_5,param_6,param_7,param_8);
  }
  iVar2 = FUN_8002fc3c((double)FLOAT_803e6944,(double)FLOAT_803dc074);
  if (iVar2 != 0) {
    *(undefined *)(param_2 + 0x65) = 0;
  }
  param_1[0x7a] = 0;
  param_1[0x7b] = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801eeafc
 * EN v1.0 Address: 0x801EEAFC
 * EN v1.0 Size: 1232b
 * EN v1.1 Address: 0x801EECA0
 * EN v1.1 Size: 1024b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801eeafc(ushort *param_1,int param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  ushort uVar4;
  short sVar5;
  uint uVar6;
  double dVar7;
  undefined8 uVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double dVar11;
  
  iVar2 = *(int *)(param_2 + 0x74) * -6000;
  iVar2 = iVar2 / 0x46 + (iVar2 >> 0x1f);
  iVar2 = iVar2 - (iVar2 >> 0x1f);
  iVar3 = *(int *)(param_2 + 0x70) * -12000;
  iVar3 = iVar3 / 0x46 + (iVar3 >> 0x1f);
  *(short *)(param_2 + 0x2c) =
       (short)(int)-(((float)((double)CONCAT44(0x43300000,*(int *)(param_2 + 0x70) << 3 ^ 0x80000000
                                              ) - DOUBLE_803e6938) / FLOAT_803e6930) *
                     FLOAT_803dc074 -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2c) ^ 0x80000000
                                            ) - DOUBLE_803e6938));
  *(short *)(param_2 + 0x2c) =
       *(short *)(param_2 + 0x2c) -
       (short)((int)((int)*(short *)(param_2 + 0x2c) * (uint)DAT_803dc070) >> 5);
  uVar6 = iVar2 - (uint)param_1[1];
  if (0x8000 < (int)uVar6) {
    uVar6 = uVar6 - 0xffff;
  }
  if ((int)uVar6 < -0x8000) {
    uVar6 = uVar6 + 0xffff;
  }
  param_1[1] = (ushort)(int)(FLOAT_803e6940 *
                             (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                    DOUBLE_803e6938) * FLOAT_803dc074 +
                            (float)((double)CONCAT44(0x43300000,(int)(short)param_1[1] ^ 0x80000000)
                                   - DOUBLE_803e6938));
  uVar6 = (iVar3 - (iVar3 >> 0x1f)) - (uint)*(ushort *)(param_2 + 0x2e);
  if (0x8000 < (int)uVar6) {
    uVar6 = uVar6 - 0xffff;
  }
  if ((int)uVar6 < -0x8000) {
    uVar6 = uVar6 + 0xffff;
  }
  dVar10 = (double)FLOAT_803e6940;
  *(short *)(param_2 + 0x2e) =
       (short)(int)(dVar10 * (double)((float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                             DOUBLE_803e6938) * FLOAT_803dc074) +
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(param_2 + 0x2e) ^ 0x80000000) -
                                  DOUBLE_803e6938));
  uVar4 = param_1[1];
  if ((short)uVar4 < -8000) {
    uVar4 = 0xe0c0;
  }
  else if (8000 < (short)uVar4) {
    uVar4 = 8000;
  }
  param_1[1] = uVar4;
  sVar5 = *(short *)(param_2 + 0x2e);
  if (sVar5 < -13000) {
    sVar5 = -13000;
  }
  else if (13000 < sVar5) {
    sVar5 = 13000;
  }
  *(short *)(param_2 + 0x2e) = sVar5;
  *param_1 = *(short *)(param_2 + 0x2c) + 0x4000;
  param_1[2] = *(ushort *)(param_2 + 0x2e);
  dVar9 = (double)FLOAT_803e6948;
  dVar7 = (double)FLOAT_803e6944;
  dVar11 = (double)(float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,
                                                                    (int)(short)param_1[1] ^
                                                                    0x80000000) - DOUBLE_803e6938) +
                          dVar7);
  if (dVar11 <= (double)FLOAT_803e694c) {
    if (param_1[0x50] != 0x100) {
      FUN_800305f8((double)FLOAT_803e6908,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0x100,0
                   ,iVar2,param_5,param_6,param_7,param_8);
    }
  }
  else {
    dVar7 = dVar11;
    if (param_1[0x50] != 5) {
      FUN_800305f8((double)FLOAT_803e6908,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,5,0,
                   iVar2,param_5,param_6,param_7,param_8);
      dVar7 = dVar11;
    }
  }
  dVar9 = (double)FLOAT_803dc074;
  uVar8 = FUN_8002fc3c(dVar7,dVar9);
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0x4c);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 0x50);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0x54);
  bVar1 = false;
  if (*(char *)(param_2 + 0x80) < '\0') {
    uVar6 = FUN_80006c10(0);
    if ((uVar6 & 0x100) == 0) {
      *(byte *)(param_2 + 0x80) = *(byte *)(param_2 + 0x80) & 0x7f;
    }
    else if (*(char *)(param_2 + 100) == '\0') {
      bVar1 = true;
      *(undefined *)(param_2 + 100) = 0x28;
    }
  }
  else {
    uVar6 = FUN_80006c10(0);
    if (((uVar6 & 0x100) != 0) &&
       (*(byte *)(param_2 + 0x80) = *(byte *)(param_2 + 0x80) & 0x7f | 0x80,
       *(char *)(param_2 + 100) < '\x14')) {
      bVar1 = true;
      *(undefined *)(param_2 + 100) = 0x28;
    }
  }
  if (bVar1) {
    FUN_801ee198(uVar8,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801eefcc
 * EN v1.0 Address: 0x801EEFCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801EF0A0
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801eefcc(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801eefd0
 * EN v1.0 Address: 0x801EEFD0
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801EF188
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801eefd0(uint param_1,int param_2)
{
  int iVar1;
  byte bVar3;
  uint uVar2;
  int local_38;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  float local_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 auStack_20 [5];
  
  iVar1 = ObjHits_GetPriorityHitWithPosition(param_1,&local_38,(int *)0x0,(uint *)0x0,&uStack_28,&uStack_24,auStack_20);
  if (((iVar1 != 0) && (bVar3 = FUN_80017a20(param_1), bVar3 == 0)) &&
     (*(short *)(local_38 + 0x46) != 0x119)) {
    FUN_80017a28(param_1,0xaf,200,0,0,1);
    FUN_80006b94((double)FLOAT_803e6950);
    FUN_80006824(0,0x125);
    uVar2 = FUN_80017690(0xf1e);
    if (uVar2 != 0) {
      FUN_80006824(param_1,0x491);
    }
    *(undefined2 *)(param_1 + 2) = 4000;
    *(undefined *)(param_2 + 0x65) = 1;
    local_2c = FLOAT_803e690c;
    local_34 = 0;
    local_32 = 0;
    local_30 = 0;
    if (*(short *)(local_38 + 0x46) == 0x9a) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      iVar1 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0xa9,&local_34,0x200001,0xffffffff,0);
        iVar1 = iVar1 + 1;
      } while (iVar1 < 10);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ef1a4
 * EN v1.0 Address: 0x801EF1A4
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801EF35C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ef1a4(int param_1)
{
  (**(code **)(**(int **)(*(int *)(*(int *)(param_1 + 0xb8) + 0x10) + 0x68) + 0x24))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ef1e0
 * EN v1.0 Address: 0x801EF1E0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801EF394
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ef1e0(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = *(undefined4 *)(iVar1 + 0x4c);
  *param_3 = *(undefined4 *)(iVar1 + 0x50);
  *param_4 = *(undefined4 *)(iVar1 + 0x54);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ef200
 * EN v1.0 Address: 0x801EF200
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801EF3B8
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ef200(int param_1)
{
  undefined4 uVar1;
  
  uVar1 = ObjPath_GetPointModelMtx(param_1,3);
  FUN_8004036c(uVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ef228
 * EN v1.0 Address: 0x801EF228
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801EF484
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ef228(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (*(int *)(iVar1 + 0x18) != 0) {
    FUN_80053754();
    *(undefined4 *)(iVar1 + 0x18) = 0;
  }
  if (*(int *)(iVar1 + 0x1c) != 0) {
    FUN_80053754();
    *(undefined4 *)(iVar1 + 0x1c) = 0;
  }
  FUN_80006b0c(*(undefined **)(iVar1 + 0x14));
  *(undefined4 *)(iVar1 + 0x14) = 0;
  ObjGroup_RemoveObject(param_1,10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ef2c0
 * EN v1.0 Address: 0x801EF2C0
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x801EF518
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ef2c0(int param_1)
{
  char in_r8;
  float *pfVar1;
  float afStack_48 [16];
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  if (in_r8 == -1) {
    FUN_8003b818(param_1);
    ObjPath_GetPointWorldPosition(param_1,3,pfVar1,pfVar1 + 1,pfVar1 + 2,0);
    if (*(int *)(param_1 + 0x30) != 0) {
      *pfVar1 = *pfVar1 - FLOAT_803dda58;
      pfVar1[2] = pfVar1[2] - FLOAT_803dda5c;
      FUN_80017a4c(*(short **)(param_1 + 0x30),afStack_48);
      FUN_80247bf8(afStack_48,pfVar1,pfVar1);
    }
  }
  else if (in_r8 == '\0') {
    *pfVar1 = *(float *)(param_1 + 0xc);
    pfVar1[1] = *(float *)(param_1 + 0x10);
    pfVar1[2] = *(float *)(param_1 + 0x14);
  }
  else {
    FUN_8003b818(param_1);
    ObjPath_GetPointWorldPosition(param_1,3,pfVar1,pfVar1 + 1,pfVar1 + 2,0);
    if (*(int *)(param_1 + 0x30) != 0) {
      *pfVar1 = *pfVar1 - FLOAT_803dda58;
      pfVar1[2] = pfVar1[2] - FLOAT_803dda5c;
      FUN_80017a4c(*(short **)(param_1 + 0x30),afStack_48);
      FUN_80247bf8(afStack_48,pfVar1,pfVar1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ef3f8
 * EN v1.0 Address: 0x801EF3F8
 * EN v1.0 Size: 1416b
 * EN v1.1 Address: 0x801EF65C
 * EN v1.1 Size: 652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ef3f8(ushort *param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  char cVar1;
  double dVar2;
  float fVar3;
  char cVar5;
  undefined4 *puVar4;
  int iVar6;
  int iVar7;
  int local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  if ((*(char *)(iVar7 + 0x6e) == '\0') && (*(char *)(param_1 + 0x56) != '\v')) {
    FUN_8011e868(6);
    cVar5 = FUN_80006bd0(0);
    *(int *)(iVar7 + 0x70) = (int)cVar5;
    cVar5 = FUN_80006bc8(0);
    *(int *)(iVar7 + 0x74) = (int)cVar5;
    if (*(int *)(iVar7 + 0x10) == 0) {
      puVar4 = ObjGroup_GetObjects(3,local_38);
      for (iVar6 = 0; iVar6 < local_38[0]; iVar6 = iVar6 + 1) {
        param_3 = puVar4[iVar6];
        if (*(short *)(param_3 + 0x46) == 0x8e) {
          *(int *)(iVar7 + 0x10) = param_3;
          iVar6 = local_38[0];
        }
      }
    }
    param_1[0x7a] = 0;
    param_1[0x7b] = 0;
    cVar5 = *(char *)(iVar7 + 0x65);
    *(byte *)(iVar7 + 100) = *(char *)(iVar7 + 100) - DAT_803dc070;
    if (*(char *)(iVar7 + 100) < '\0') {
      *(undefined *)(iVar7 + 100) = 0;
    }
    cVar1 = *(char *)(iVar7 + 0x65);
    if (cVar1 == '\x01') {
      FUN_801ee7bc((short *)param_1,iVar7,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    else if (cVar1 < '\x01') {
      if (-1 < cVar1) {
        FUN_801eeafc(param_1,iVar7,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_801eefd0((uint)param_1,iVar7);
      }
    }
    else if (cVar1 < '\x04') {
      param_1[0x7a] = 0;
      param_1[0x7b] = 1;
    }
    fVar3 = FLOAT_803e6954;
    dVar2 = DOUBLE_803e6938;
    uStack_2c = (int)(short)param_1[2] ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(iVar7 + 0x5c) =
         *(float *)(iVar7 + 0x5c) +
         ((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e6938) * FLOAT_803dc074) /
         FLOAT_803e6954;
    uStack_24 = (int)(short)param_1[1] ^ 0x80000000;
    local_28 = 0x43300000;
    *(float *)(iVar7 + 0x58) =
         *(float *)(iVar7 + 0x58) +
         ((float)((double)CONCAT44(0x43300000,uStack_24) - dVar2) * FLOAT_803dc074) / fVar3;
    fVar3 = FLOAT_803e6958;
    *(float *)(iVar7 + 0x5c) =
         -(FLOAT_803dc074 * *(float *)(iVar7 + 0x5c) * FLOAT_803e6958 - *(float *)(iVar7 + 0x5c));
    *(float *)(iVar7 + 0x58) =
         -(FLOAT_803dc074 * *(float *)(iVar7 + 0x58) * fVar3 - *(float *)(iVar7 + 0x58));
    fVar3 = FLOAT_803e6950;
    iVar6 = (int)(FLOAT_803e6950 * *(float *)(iVar7 + 0x58));
    local_20 = (longlong)iVar6;
    param_1[1] = param_1[1] - (short)iVar6;
    *(float *)(param_1 + 8) = fVar3 * *(float *)(iVar7 + 0x58) + *(float *)(iVar7 + 0x50);
    *(float *)(param_1 + 10) = fVar3 * *(float *)(iVar7 + 0x5c) + *(float *)(iVar7 + 0x54);
    *(ushort *)(iVar7 + 0x6c) = *(short *)(iVar7 + 0x6c) + (ushort)DAT_803dc070;
    if (*(char *)(iVar7 + 0x65) != cVar5) {
      *(undefined2 *)(iVar7 + 0x6c) = 0;
    }
    FUN_801ee668(param_1,iVar7);
  }
  else {
    param_1[3] = param_1[3] | 0x4000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ef980
 * EN v1.0 Address: 0x801EF980
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801EF8E8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ef980(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ef984
 * EN v1.0 Address: 0x801EF984
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801EF9AC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ef984(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801EED7C(void) {}
void fn_801EEDA8(void) {}
void fn_801EEDD4(void) {}
void fn_801EF020(void) {}
void fn_801EF358(void) {}
void fn_801EF35C(void) {}
void fn_801EF370(void) {}
void fn_801EF3A4(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801EEDAC(void) { return 0x0; }
int fn_801EEDD8(void) { return 0x2; }
int fn_801EEDFC(void) { return 0x0; }
int fn_801EEE04(void) { return 0x0; }
int fn_801EEE2C(void) { return 0x0; }
int fn_801EEE34(void) { return 0x0; }
int fn_801EEE3C(void) { return 0x84; }
int fn_801EEE44(void) { return 0x43; }
int fn_801EF360(void) { return 0x8; }
int fn_801EF368(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E5CC8;
extern void fn_8003B8F4(f32);
#pragma peephole off
void fn_801EF374(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E5CC8); }
#pragma peephole reset

extern f32 lbl_803E5C70;
void fn_801EEDB4(int unused, f32 *p) { f32 v = lbl_803E5C70; *p = v; }
