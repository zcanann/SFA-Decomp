#include "ghidra_import.h"
#include "main/dll/DB/DBbonedust.h"
#include "main/dll/DB/DBstealerworm.h"

extern undefined4 FUN_800066e0();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_800068fc();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern uint FUN_80017760();
extern int FUN_8001792c();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a54();
extern undefined8 FUN_80017a7c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017b00();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053754();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_8005d0ac();
extern undefined4 FUN_80080f5c();
extern undefined4 FUN_80080f60();
extern undefined4 FUN_80080f64();
extern undefined4 FUN_80080f68();
extern undefined4 FUN_80080f70();
extern undefined4 FUN_80080f74();
extern undefined4 FUN_80080f78();
extern undefined4 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern double FUN_80081014();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_801d8308();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_802c2b78;
extern undefined4 DAT_802c2b7c;
extern undefined4 DAT_802c2b80;
extern undefined4 DAT_802c2b84;
extern undefined4 DAT_802c2b88;
extern undefined4 DAT_802c2b8c;
extern undefined4 DAT_802c2b90;
extern undefined4 DAT_802c2b94;
extern undefined4 DAT_802c2b98;
extern undefined4 DAT_802c2b9c;
extern undefined4 DAT_802c2ba0;
extern undefined4 DAT_802c2ba4;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcce0;
extern undefined4 DAT_803dcce4;
extern undefined4 DAT_803dcce8;
extern undefined4 DAT_803dccec;
extern undefined4 DAT_803dccf0;
extern undefined4 DAT_803dccf4;
extern undefined4 DAT_803dccf8;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de898;
extern undefined4 DAT_803de89c;
extern undefined4 DAT_803de8a0;
extern undefined4 DAT_803de8ac;
extern undefined4 DAT_803de8ad;
extern undefined4 DAT_803de8b0;
extern undefined4 DAT_803de8b4;
extern undefined4 DAT_803de8b8;
extern undefined4 DAT_803de8c0;
extern undefined4 DAT_803de8c8;
extern f64 DOUBLE_803e6458;
extern f64 DOUBLE_803e6480;
extern f64 DOUBLE_803e64c0;
extern f64 DOUBLE_803e64f8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de8a4;
extern f32 FLOAT_803de8a8;
extern f32 FLOAT_803e6360;
extern f32 FLOAT_803e6364;
extern f32 FLOAT_803e6388;
extern f32 FLOAT_803e63bc;
extern f32 FLOAT_803e63d0;
extern f32 FLOAT_803e6428;
extern f32 FLOAT_803e643c;
extern f32 FLOAT_803e644c;
extern f32 FLOAT_803e6460;
extern f32 FLOAT_803e6464;
extern f32 FLOAT_803e6468;
extern f32 FLOAT_803e646c;
extern f32 FLOAT_803e6470;
extern f32 FLOAT_803e6474;
extern f32 FLOAT_803e6478;
extern f32 FLOAT_803e6488;
extern f32 FLOAT_803e648c;
extern f32 FLOAT_803e6490;
extern f32 FLOAT_803e6494;
extern f32 FLOAT_803e6498;
extern f32 FLOAT_803e649c;
extern f32 FLOAT_803e64a0;
extern f32 FLOAT_803e64a4;
extern f32 FLOAT_803e64a8;
extern f32 FLOAT_803e64ac;
extern f32 FLOAT_803e64b0;
extern f32 FLOAT_803e64b4;
extern f32 FLOAT_803e64b8;
extern f32 FLOAT_803e64bc;
extern f32 FLOAT_803e64c8;
extern f32 FLOAT_803e64cc;
extern f32 FLOAT_803e64d0;
extern f32 FLOAT_803e64d4;
extern f32 FLOAT_803e64d8;
extern f32 FLOAT_803e64dc;
extern f32 FLOAT_803e64e0;
extern f32 FLOAT_803e64e4;
extern f32 FLOAT_803e64e8;
extern f32 FLOAT_803e64ec;
extern f32 FLOAT_803e64f0;
extern f32 FLOAT_803e64f4;
extern undefined bRam803dcce1;
extern undefined2 bRam803dcce2;
extern undefined bRam803dcce5;
extern undefined2 bRam803dcce6;
extern undefined bRam803dcce9;
extern undefined2 bRam803dccea;
extern undefined bRam803dcced;
extern undefined2 bRam803dccee;
extern undefined bRam803dccf1;
extern undefined2 bRam803dccf2;
extern undefined bRam803dccf5;
extern undefined2 bRam803dccf6;
extern undefined bRam803de8b9;
extern undefined2 bRam803de8ba;
extern undefined uRam803de8b1;
extern undefined2 uRam803de8b2;
extern undefined uRam803de8b5;
extern undefined2 uRam803de8b6;

/*
 * --INFO--
 *
 * Function: FUN_801e1588
 * EN v1.0 Address: 0x801E1588
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x801E18DC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e1588(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *(undefined4 *)(param_9 + 0xf4) = 7;
  uVar1 = FUN_80017690(0x9f);
  if (((uVar1 != 0) && (uVar1 = FUN_80017690(0xa0), uVar1 == 0)) &&
     (uVar1 = FUN_80017690(0x91c), uVar1 != 0)) {
    DAT_803de8ac = '\x01';
    FUN_80017698(0xa0,1);
    param_1 = (**(code **)(*DAT_803dd6cc + 8))(10,1);
  }
  FUN_801e1588(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3);
  if ((DAT_803de8ac != '\0') && (iVar2 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar2 != 0)) {
    (**(code **)(*DAT_803dd6cc + 0xc))(0x50,1);
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
    *(undefined *)(iVar3 + 0x70) = 3;
    DAT_803de8ac = '\0';
  }
  (**(code **)(*DAT_803dd6e4 + 0x28))((double)FLOAT_803e6460,(double)FLOAT_803e6364);
  (**(code **)(*DAT_803dd6e4 + 0x20))(0);
  dVar4 = (double)FUN_80293f90();
  if (*(char *)(iVar3 + 0x81) == '\0') {
    if ((double)FLOAT_803e6464 <= dVar4) {
      if ((double)FLOAT_803e6468 < dVar4) {
        uVar1 = FUN_80017690(0xa71);
        if (uVar1 == 0) {
          FUN_80006824(param_9,0x145);
        }
        *(undefined *)(iVar3 + 0x81) = 1;
      }
    }
    else {
      uVar1 = FUN_80017690(0xa71);
      if (uVar1 == 0) {
        FUN_80006824(param_9,0x144);
      }
      *(undefined *)(iVar3 + 0x81) = 1;
    }
  }
  else if (((double)FLOAT_803e646c < dVar4) && (dVar4 < (double)FLOAT_803e6470)) {
    *(undefined *)(iVar3 + 0x81) = 0;
  }
  *(short *)(param_9 + 4) = (short)(int)((double)FLOAT_803e6474 * dVar4);
  *(short *)(iVar3 + 0x68) =
       (short)(int)(FLOAT_803e6478 * FLOAT_803dc074 +
                   (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x68)) -
                          DOUBLE_803e6480));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e1884
 * EN v1.0 Address: 0x801E1884
 * EN v1.0 Size: 1624b
 * EN v1.1 Address: 0x801E1B78
 * EN v1.1 Size: 1316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e1884(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  int *piVar13;
  int iVar14;
  int iVar15;
  double dVar16;
  
  fVar12 = DAT_802c2ba4;
  fVar11 = DAT_802c2ba0;
  fVar10 = DAT_802c2b9c;
  fVar9 = DAT_802c2b98;
  fVar8 = DAT_802c2b94;
  fVar7 = DAT_802c2b90;
  fVar6 = DAT_802c2b8c;
  fVar5 = DAT_802c2b88;
  fVar4 = DAT_802c2b84;
  fVar3 = DAT_802c2b80;
  fVar2 = DAT_802c2b7c;
  fVar1 = DAT_802c2b78;
  FUN_8005d0ac(0);
  FUN_80080f60(1);
  FUN_80080f5c(0x29,0x4b,0xa9);
  FUN_80080f80(7,1,0);
  dVar16 = FUN_80081014();
  if ((double)FLOAT_803e6364 < dVar16) {
    FLOAT_803de8a4 = FLOAT_803e643c;
    FLOAT_803de8a8 = FLOAT_803e643c;
  }
  FLOAT_803de8a8 = -(FLOAT_803e644c * FLOAT_803dc074 - FLOAT_803de8a8);
  if (FLOAT_803de8a8 < FLOAT_803e6364) {
    FLOAT_803de8a8 = FLOAT_803e6364;
  }
  DAT_803de8b8 = (byte)(int)(FLOAT_803de8a8 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)DAT_803dccec - (uint)DAT_803dcce8 ^
                                                      0x80000000) - DOUBLE_803e6458) +
                            (float)((double)CONCAT44(0x43300000,DAT_803dcce8 ^ 0x80000000) -
                                   DOUBLE_803e6458));
  bRam803de8b9 = (byte)(int)(FLOAT_803de8a8 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)bRam803dcced - (uint)bRam803dcce9 ^
                                                      0x80000000) - DOUBLE_803e6458) +
                            (float)((double)CONCAT44(0x43300000,bRam803dcce9 ^ 0x80000000) -
                                   DOUBLE_803e6458));
  bRam803de8ba = (byte)(int)(FLOAT_803de8a8 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)bRam803dccee - (uint)bRam803dccea ^
                                                      0x80000000) - DOUBLE_803e6458) +
                            (float)((double)CONCAT44(0x43300000,bRam803dccea ^ 0x80000000) -
                                   DOUBLE_803e6458));
  FUN_80080f7c(7,DAT_803de8b8,bRam803de8b9,bRam803de8ba,0x40,0x40);
  DAT_803de8b4 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)DAT_803dcce4 - (uint)DAT_803dcce0 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,DAT_803dcce0 ^ 0x80000000) -
                             DOUBLE_803e6458));
  uRam803de8b5 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dcce5 - (uint)bRam803dcce1 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,bRam803dcce1 ^ 0x80000000) -
                             DOUBLE_803e6458));
  uRam803de8b6 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dcce6 - (uint)bRam803dcce2 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,bRam803dcce2 ^ 0x80000000) -
                             DOUBLE_803e6458));
  FUN_80080f74(7,DAT_803de8b4,uRam803de8b5,uRam803de8b6);
  DAT_803de8b0 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)DAT_803dccf4 - (uint)DAT_803dccf0 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,DAT_803dccf0 ^ 0x80000000) -
                             DOUBLE_803e6458));
  uRam803de8b1 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dccf5 - (uint)bRam803dccf1 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,bRam803dccf1 ^ 0x80000000) -
                             DOUBLE_803e6458));
  uRam803de8b2 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dccf6 - (uint)bRam803dccf2 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,bRam803dccf2 ^ 0x80000000) -
                             DOUBLE_803e6458));
  FUN_80080f78(7,DAT_803de8b0,uRam803de8b1,uRam803de8b2);
  DAT_803de8ad = (undefined)(int)(FLOAT_803de8a8 * FLOAT_803e6478 + FLOAT_803e6488);
  FUN_80080f68(1);
  FUN_80080f64((double)(FLOAT_803de8a8 * (fVar10 - fVar7) + fVar7),
               (double)(FLOAT_803de8a8 * (fVar11 - fVar8) + fVar8),
               (double)(FLOAT_803de8a8 * (fVar12 - fVar9) + fVar9),(double)FLOAT_803e63bc);
  if (*(char *)(param_2 + 0xab) == '\0') {
    FUN_80080f70((double)fVar1,(double)fVar2,(double)fVar3,7);
  }
  else {
    FUN_80080f70((double)fVar4,(double)fVar5,(double)fVar6,7);
  }
  piVar13 = (int *)FUN_80017a54(param_1);
  dVar16 = (double)FLOAT_803e648c;
  for (iVar15 = 0; iVar15 < (int)(uint)*(byte *)(*piVar13 + 0xf8); iVar15 = iVar15 + 1) {
    iVar14 = FUN_8001792c(*piVar13,iVar15);
    if (*(char *)(iVar14 + 0x29) == '\x01') {
      *(char *)(iVar14 + 0xc) = (char)(int)(dVar16 * (double)FLOAT_803de8a8);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e1edc
 * EN v1.0 Address: 0x801E1EDC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E209C
 * EN v1.1 Size: 764b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801e1edc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,int param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e1ee4
 * EN v1.0 Address: 0x801E1EE4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E2398
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e1ee4(void)
{
  return DAT_803de8a0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e1eec
 * EN v1.0 Address: 0x801E1EEC
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801E2464
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e1eec(uint param_1)
{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar3 + 0x29) == '\x01') {
    cVar1 = *(char *)(iVar3 + 0x7a);
    if (((cVar1 == '\0') || (cVar1 == '\x01')) || (cVar1 == '\x02')) {
      *(char *)(iVar3 + 0x7c) = *(char *)(iVar3 + 0x7c) + '\x01';
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    if ('\x01' < *(char *)(iVar3 + 0x29)) {
      FUN_80006824(param_1,0x3f);
    }
    *(char *)(iVar3 + 0x2b) = *(char *)(iVar3 + 0x2b) + '\x01';
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801e1f70
 * EN v1.0 Address: 0x801E1F70
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801E2508
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e1f70(int param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (DAT_803de898 != 0) {
    FUN_80053754();
    DAT_803de898 = 0;
  }
  if (DAT_803de89c != 0) {
    FUN_80053754();
    DAT_803de89c = 0;
  }
  ObjGroup_RemoveObject(param_1,3);
  if ((*(char *)(iVar1 + 0x80) != '\0') && (param_2 == 0)) {
    *(undefined *)(iVar1 + 0x80) = 0;
  }
  DAT_803de8a0 = 0;
  FUN_800067c0(*(int **)(iVar1 + 0x9c),0);
  FUN_800067c0(*(int **)(iVar1 + 0x98),0);
  FUN_80017698(0xac8,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e2034
 * EN v1.0 Address: 0x801E2034
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x801E25CC
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e2034(void)
{
  int iVar1;
  char in_r8;
  int iVar2;
  undefined auStack_48 [6];
  undefined2 local_42;
  float local_3c;
  float local_38;
  float local_34;
  longlong local_30;
  longlong local_28;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (in_r8 != '\0') {
    if (*(char *)(iVar2 + 0x70) < '\x02') {
      local_30 = (longlong)(int)*(float *)(iVar2 + 0x88);
      local_42 = (undefined2)(int)*(float *)(iVar2 + 0x88);
      local_34 = FLOAT_803e6494;
      local_38 = FLOAT_803e6498;
      local_3c = FLOAT_803e649c;
      (**(code **)(*DAT_803dd708 + 8))(iVar1,0xa3,auStack_48,2,0xffffffff,0);
      local_28 = (longlong)(int)*(float *)(iVar2 + 0x8c);
      local_42 = (undefined2)(int)*(float *)(iVar2 + 0x8c);
      local_3c = FLOAT_803e64a0;
      (**(code **)(*DAT_803dd708 + 8))(iVar1,0xa3,auStack_48,2,0xffffffff,0);
    }
    FUN_8003b818(iVar1);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e20e4
 * EN v1.0 Address: 0x801E20E4
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801E26E4
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e20e4(int param_1)
{
  byte bVar1;
  int iVar2;
  undefined auStack_28 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(char *)(iVar2 + 0x85) != '\0') && (*(int *)(iVar2 + 0x4c) != 0)) {
    local_20 = FLOAT_803e63d0;
    local_22 = 0xc0a;
    local_1c = FLOAT_803e6364;
    local_18 = FLOAT_803e6388;
    local_14 = FLOAT_803e6360;
    for (bVar1 = 0; bVar1 < DAT_803dc070; bVar1 = bVar1 + 1) {
      (**(code **)(*DAT_803dd708 + 8))
                (*(undefined4 *)(iVar2 + 0x4c),0x7aa,auStack_28,2,0xffffffff,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e217c
 * EN v1.0 Address: 0x801E217C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E279C
 * EN v1.1 Size: 568b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e217c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e2180
 * EN v1.0 Address: 0x801E2180
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E29D4
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e2180(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e2184
 * EN v1.0 Address: 0x801E2184
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E2B60
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e2184(void)
{
  return DAT_803de8c0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e218c
 * EN v1.0 Address: 0x801E218C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E2B70
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e218c(int param_1)
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
 * Function: FUN_801e21b4
 * EN v1.0 Address: 0x801E21B4
 * EN v1.0 Size: 1364b
 * EN v1.1 Address: 0x801E2BBC
 * EN v1.1 Size: 1212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e21b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  float *pfVar6;
  double in_f31;
  double dVar7;
  double in_ps31_1;
  int local_68;
  undefined auStack_64 [6];
  undefined2 local_5e;
  float local_5c;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  float fStack_44;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar1 = FUN_8028683c();
  pfVar6 = *(float **)(uVar1 + 0xb8);
  iVar2 = (**(code **)(**(int **)(*(int *)(uVar1 + 0x30) + 0x68) + 0x24))();
  iVar3 = (**(code **)(**(int **)(*(int *)(uVar1 + 0x30) + 0x68) + 0x28))();
  if (((*(char *)(pfVar6 + 3) != '\0') && (iVar3 < 6)) && (*(short *)(uVar1 + 0x46) != 0x69c)) {
    FUN_800068c4(uVar1,0x2c6);
  }
  iVar4 = DBbonedust_getState(*(int *)(uVar1 + 0x30));
  if ((iVar4 < 2) && (*(char *)(pfVar6 + 3) < '\x01')) {
    *pfVar6 = *pfVar6 - FLOAT_803dc074;
    if (*pfVar6 <= FLOAT_803e64ac) {
      uVar5 = FUN_80017760(10,0x19);
      dVar7 = (double)FLOAT_803e64a8;
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        local_58 = *(float *)(uVar1 + 0x18);
        local_54 = *(float *)(uVar1 + 0x1c);
        local_50[0] = *(float *)(uVar1 + 0x20);
        local_5c = (float)dVar7;
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x9f,auStack_64,0x200001,0xffffffff,0);
      }
      fStack_44 = (float)FUN_80017760(0x5a,0xf0);
      fStack_44 = -fStack_44;
      local_48 = 0x43300000;
      *pfVar6 = (float)((double)CONCAT44(0x43300000,fStack_44) - DOUBLE_803e64c0);
    }
    if ((2 < iVar2) && (*(char *)(uVar1 + 0xad) == '\x01')) {
      local_5c = FLOAT_803e64b0;
      local_5e = 0xc0a;
      ObjPath_GetPointWorldPosition(uVar1,0,&local_58,&local_54,local_50,0);
      local_58 = local_58 - *(float *)(uVar1 + 0x18);
      local_54 = local_54 - *(float *)(uVar1 + 0x1c);
      local_50[0] = local_50[0] - *(float *)(uVar1 + 0x20);
      for (iVar4 = 0; iVar4 < (int)(uint)DAT_803dc070; iVar4 = iVar4 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x7aa,auStack_64,2,0xffffffff,0);
      }
    }
  }
  if (*(int *)(uVar1 + 0x30) != 0) {
    if ((*(short *)(uVar1 + 0x46) != 0x69c) && (*(int *)(*(int *)(uVar1 + 0x30) + 0xf4) < 4)) {
      fStack_44 = -pfVar6[2];
      local_48 = 0x43300000;
      pfVar6[1] = (float)((double)CONCAT44(0x43300000,fStack_44) - DOUBLE_803e64c0) / FLOAT_803e64b4
      ;
      if (pfVar6[1] < FLOAT_803e64ac) {
        pfVar6[1] = -pfVar6[1];
      }
      if (pfVar6[1] < FLOAT_803e64b8) {
        pfVar6[1] = FLOAT_803e64b8;
      }
    }
    *(uint *)(uVar1 + 0xf4) = *(int *)(uVar1 + 0xf4) - (uint)DAT_803dc070;
    if (*(int *)(uVar1 + 0xf4) < 0) {
      *(undefined4 *)(uVar1 + 0xf4) = 0;
    }
    if (((((((iVar3 == 1) &&
            (iVar3 = ObjHits_GetPriorityHit(uVar1,&local_68,(int *)0x0,(uint *)0x0), iVar3 != 0)) &&
           (*(int *)(uVar1 + 0xf4) == 0)) &&
          ((local_68 != 0 && (iVar3 = FUN_80017a98(), local_68 != iVar3)))) &&
         ((*(short *)(local_68 + 0x46) != 0x69c &&
          ((*(short *)(local_68 + 0x46) != 0x9a &&
           (*(undefined4 *)(uVar1 + 0xf4) = 0x14, *(int *)(uVar1 + 0x30) != 0)))))) &&
        ((iVar2 == 2 || (iVar2 == 5)))) && (*(short *)(uVar1 + 0x46) == 0x69c)) {
      FUN_80017a28(uVar1,0xf,200,0,0,1);
      FUN_80006824(uVar1,0x2c7);
      *(char *)(pfVar6 + 3) = *(char *)(pfVar6 + 3) + -1;
      if (*(char *)(pfVar6 + 3) < '\x01') {
        *(undefined *)(pfVar6 + 3) = 0;
        (**(code **)(**(int **)(*(int *)(uVar1 + 0x30) + 0x68) + 0x20))();
        ObjHits_DisableObject(uVar1);
        *(ushort *)(uVar1 + 6) = *(ushort *)(uVar1 + 6) | 0x4000;
        FUN_8008112c((double)FLOAT_803e64bc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     uVar1,1,1,1,0,1,1,0);
        FUN_80006824(uVar1,0x2c8);
      }
    }
    if (*(int *)(uVar1 + 0xf4) == 0) {
      *(undefined *)(*(int *)(uVar1 + 0x54) + 0x6e) = 6;
      *(undefined *)(*(int *)(uVar1 + 0x54) + 0x6f) = 1;
      *(undefined4 *)(*(int *)(uVar1 + 0x54) + 0x48) = 0x10;
      *(undefined4 *)(*(int *)(uVar1 + 0x54) + 0x4c) = 0x10;
    }
    else {
      *(undefined *)(*(int *)(uVar1 + 0x54) + 0x6c) = 0;
    }
    fStack_44 = -pfVar6[2];
    local_48 = 0x43300000;
    uStack_3c = (int)*(short *)(uVar1 + 4) ^ 0x80000000;
    local_40 = 0x43300000;
    iVar2 = (int)-((float)((double)CONCAT44(0x43300000,fStack_44) - DOUBLE_803e64c0) *
                   FLOAT_803dc074 -
                  (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e64c0));
    local_38 = (longlong)iVar2;
    *(short *)(uVar1 + 4) = (short)iVar2;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e2708
 * EN v1.0 Address: 0x801E2708
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801E3078
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e2708(int param_1,int param_2)
{
  uint uVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  uVar1 = FUN_80017760(0x5a,0xf0);
  *pfVar2 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e64c0);
  pfVar2[1] = FLOAT_803e64a8;
  pfVar2[2] = 1.68156e-42;
  *(undefined *)(pfVar2 + 3) = 4;
  *(char *)(param_1 + 0xad) = (char)*(undefined2 *)(param_2 + 0x1a);
  if (*(short *)(param_1 + 0x46) != 0x69c) {
    DAT_803de8c0 = param_1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e27a0
 * EN v1.0 Address: 0x801E27A0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801E3128
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e27a0(int param_1)
{
  ObjGroup_RemoveObject(param_1,3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e27c4
 * EN v1.0 Address: 0x801E27C4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801E314C
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e27c4(int param_1)
{
  int iVar1;
  char in_r8;
  int iVar2;
  byte bVar3;
  undefined auStack_28 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [3];
  
  if (in_r8 != '\0') {
    iVar2 = *(int *)(param_1 + 0xb8);
    FUN_8003b818(param_1);
    iVar1 = *(int *)(param_1 + 0x30);
    if ((((iVar1 != 0) && (*(short *)(iVar1 + 0x46) == 0x8e)) &&
        (iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x2c))(), iVar1 != 0)) && (iVar1 != 2)) {
      *(float *)(iVar2 + 8) = *(float *)(iVar2 + 8) - FLOAT_803dc074;
      if (*(float *)(iVar2 + 8) <= FLOAT_803e64cc) {
        *(float *)(iVar2 + 8) = *(float *)(iVar2 + 8) + FLOAT_803e64d0;
      }
      *(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) - FLOAT_803dc074;
      if (*(float *)(iVar2 + 0xc) <= FLOAT_803e64cc) {
        *(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) + FLOAT_803e64c8;
      }
      local_20 = FLOAT_803e64d4;
      local_22 = 0xc0a;
      ObjPath_GetPointWorldPosition(param_1,0xd,&local_1c,&local_18,local_14,0);
      local_1c = local_1c - *(float *)(param_1 + 0x18);
      local_18 = local_18 - *(float *)(param_1 + 0x1c);
      local_14[0] = local_14[0] - *(float *)(param_1 + 0x20);
      for (bVar3 = 0; bVar3 < DAT_803dc070; bVar3 = bVar3 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7aa,auStack_28,2,0xffffffff,0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e2940
 * EN v1.0 Address: 0x801E2940
 * EN v1.0 Size: 1892b
 * EN v1.1 Address: 0x801E32D4
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e2940(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined2 *puVar6;
  int iVar7;
  uint *puVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar9;
  int iVar10;
  int iVar11;
  double dVar12;
  double in_f29;
  double dVar13;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  uint local_88;
  int local_84;
  int local_80;
  float local_7c;
  float local_78;
  float local_74;
  uint uStack_70;
  int local_6c;
  uint auStack_68 [2];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
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
  uVar1 = FUN_8028683c();
  iVar11 = 0;
  iVar2 = FUN_80017a98();
  iVar10 = *(int *)(uVar1 + 0x30);
  iVar3 = DAT_803de8c8;
  if (iVar10 != 0) {
    iVar3 = FUN_801e1ee4();
    iVar3 = DBbonedust_getState(iVar3);
    if (iVar3 == 2) {
      dVar12 = (double)FUN_8001771c((float *)(iVar2 + 0x18),(float *)(uVar1 + 0x18));
      if ((double)FLOAT_803e64d8 <= dVar12) {
        FUN_8000680c(uVar1,0x40);
      }
      else {
        FUN_80006824(uVar1,0x312);
      }
    }
    iVar3 = *(int *)(iVar10 + 0xf4);
    piVar9 = *(int **)(uVar1 + 0xb8);
    if (*piVar9 == 0) {
      iVar4 = FUN_80017b00(&local_80,&local_84);
      for (; local_80 < local_84; local_80 = local_80 + 1) {
        iVar7 = *(int *)(iVar4 + local_80 * 4);
        if (*(short *)(iVar7 + 0x46) == 0x8c) {
          *piVar9 = iVar7;
          local_80 = local_84;
        }
      }
    }
    puVar8 = &uStack_70;
    iVar4 = ObjMsg_Pop(uVar1,&local_88,auStack_68,puVar8);
    if (iVar4 != 0) {
      if (local_88 == 0x130002) {
        iVar11 = 1;
      }
      else if ((0x130001 < (int)local_88) && ((int)local_88 < 0x130004)) {
        iVar11 = 2;
      }
    }
    iVar4 = (**(code **)(**(int **)(iVar10 + 0x68) + 0x28))(iVar10);
    if (((1 < iVar4) && (*(int *)(uVar1 + 0xf8) < 1)) && ((iVar3 - 3U < 2 || (iVar3 == 5)))) {
      puVar8 = (uint *)0x0;
      iVar4 = ObjHits_GetPriorityHit(uVar1,&local_6c,(int *)0x0,(uint *)0x0);
      if ((iVar4 != 0) && (*(short *)(local_6c + 0x46) != 0x114)) {
        puVar8 = (uint *)0x0;
        in_r7 = 0;
        in_r8 = 1;
        FUN_80017a28(uVar1,0xf,200,0,0,1);
        FUN_80006824(uVar1,0x37);
        *(char *)(piVar9 + 1) = *(char *)(piVar9 + 1) + -1;
        if (*(char *)(piVar9 + 1) < '\x01') {
          (**(code **)(**(int **)(iVar10 + 0x68) + 0x20))(iVar10);
          *(undefined4 *)(uVar1 + 0xf8) = 300;
          ObjHits_DisableObject(uVar1);
        }
      }
    }
    if (0 < *(int *)(uVar1 + 0xf8)) {
      *(uint *)(uVar1 + 0xf8) = *(int *)(uVar1 + 0xf8) - (uint)DAT_803dc070;
    }
    if ((iVar3 == 8) &&
       (*(int *)(uVar1 + 0xf4) = *(int *)(uVar1 + 0xf4) + 1, 10 < *(int *)(uVar1 + 0xf4))) {
      *(undefined4 *)(uVar1 + 0xf4) = 0;
    }
    if ((iVar3 == 5) && (DAT_803de8c8 != 5)) {
      FUN_800305f8((double)FLOAT_803e64cc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   uVar1,1,0,puVar8,in_r7,in_r8,in_r9,in_r10);
      DAT_803dccf8 = '\0';
    }
    if ((((*(short *)(uVar1 + 0xa0) == 1) && (FLOAT_803e64dc <= *(float *)(uVar1 + 0x98))) &&
        (DAT_803dccf8 == '\0')) && (uVar5 = FUN_80017ae8(), (uVar5 & 0xff) != 0)) {
      DAT_803dccf8 = '\x01';
      *(uint *)(uVar1 + 0xf4) = *(int *)(uVar1 + 0xf4) + (uint)DAT_803dc070;
      FUN_80006824(uVar1,0x38);
      *(float *)(uVar1 + 0x10) = *(float *)(uVar1 + 0x10) + FLOAT_803e64e0;
      *(float *)(uVar1 + 0x14) = *(float *)(uVar1 + 0x14) - FLOAT_803e64e4;
      FUN_800068fc(uVar1,&local_74,&local_78,&local_7c);
      *(float *)(uVar1 + 0x10) = *(float *)(uVar1 + 0x10) - FLOAT_803e64e0;
      dVar12 = (double)*(float *)(uVar1 + 0x14);
      *(float *)(uVar1 + 0x14) = (float)(dVar12 + (double)FLOAT_803e64e4);
      puVar6 = FUN_80017aa4(0x18,0x114);
      *(undefined *)(puVar6 + 3) = 0xff;
      *(undefined *)((int)puVar6 + 7) = 0xff;
      *(undefined *)(puVar6 + 2) = 2;
      *(undefined *)((int)puVar6 + 5) = 1;
      *(float *)(puVar6 + 4) = local_74;
      *(float *)(puVar6 + 6) = local_78;
      *(float *)(puVar6 + 8) = local_7c;
      puVar8 = (uint *)0xffffffff;
      in_r7 = 0;
      iVar10 = FUN_80017ae4(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,
                            0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      dVar15 = (double)(*(float *)(iVar2 + 0x18) - *(float *)(iVar10 + 0xc));
      dVar14 = (double)((*(float *)(iVar2 + 0x1c) - FLOAT_803e64e8) - *(float *)(iVar10 + 0x10));
      dVar13 = (double)(*(float *)(iVar2 + 0x20) - *(float *)(iVar10 + 0x14));
      dVar12 = FUN_80293900((double)(float)(dVar13 * dVar13 +
                                           (double)(float)(dVar15 * dVar15 +
                                                          (double)(float)(dVar14 * dVar14))));
      dVar12 = (double)(float)((double)FLOAT_803e64e8 / dVar12);
      *(float *)(iVar10 + 0x24) = (float)(dVar15 * dVar12);
      *(float *)(iVar10 + 0x28) = (float)(dVar14 * dVar12);
      *(float *)(iVar10 + 0x2c) = (float)(dVar13 * dVar12);
      *(undefined4 *)(iVar10 + 0xf4) = 0x78;
      *(int *)(iVar10 + 0xf8) = *piVar9;
    }
    if ((iVar11 == 1) && (uVar5 = FUN_80017ae8(), (uVar5 & 0xff) != 0)) {
      FUN_80006824(uVar1,0x38);
      iVar2 = FUN_80017a98();
      puVar6 = FUN_80017aa4(0x18,0x138);
      *(float *)(puVar6 + 4) = FLOAT_803e64ec + *(float *)(iVar2 + 0x18);
      uStack_5c = FUN_80017760(0xfffffffa,6);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      *(float *)(puVar6 + 6) =
           FLOAT_803e64e0 +
           *(float *)(iVar2 + 0x1c) +
           (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e64f8);
      uStack_54 = FUN_80017760(0xfffffffa,6);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      dVar12 = (double)(*(float *)(iVar2 + 0x20) +
                       (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e64f8));
      *(float *)(puVar6 + 8) = (float)((double)FLOAT_803e64f0 + dVar12);
      *(undefined *)(puVar6 + 2) = 2;
      *(undefined *)((int)puVar6 + 5) = 1;
      *(undefined *)(puVar6 + 3) = 0xff;
      *(undefined *)((int)puVar6 + 7) = 0xff;
      puVar8 = (uint *)0xffffffff;
      in_r7 = 0;
      FUN_80017ae4(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,0xff,
                   0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    }
    dVar12 = (double)FLOAT_803dc074;
    iVar2 = FUN_8002fc3c((double)FLOAT_803e64f4,dVar12);
    if ((*(short *)(uVar1 + 0xa0) == 1) && (iVar2 != 0)) {
      FUN_800305f8((double)FLOAT_803e64cc,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                   uVar1,0,0,puVar8,in_r7,in_r8,in_r9,in_r10);
    }
  }
  DAT_803de8c8 = iVar3;
  FUN_80286888();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801E2568(void) {}
void fn_801E256C(void) {}
void fn_801E32CC(void) {}
void fn_801E3300(void) {}
void fn_801E3410(void) {}
void fn_801E3414(void) {}
void fn_801E3418(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801E1F08(void) { return 0xb4; }
int fn_801E1F10(void) { return 0x0; }
int fn_801E2578(void) { return 0x10; }
int fn_801E2B28(void) { return 0x10; }
int fn_801E2B30(void) { return 0x1; }
int fn_801E32BC(void) { return 0x0; }
int fn_801E32C4(void) { return 0x0; }
int fn_801E341C(void) { return 0x10; }

/* sda21 accessors. */
extern u32 lbl_803DDC20;
extern u32 lbl_803DDC40;
u32 fn_801E1DA8(void) { return lbl_803DDC20; }
u32 fn_801E2570(void) { return lbl_803DDC40; }
