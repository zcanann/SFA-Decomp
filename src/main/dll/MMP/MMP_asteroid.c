#include "ghidra_import.h"
#include "main/dll/MMP/MMP_asteroid.h"

extern undefined4 FUN_800068c4();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern int FUN_800480a0();
extern int fn_80056800();
extern undefined4 FUN_80055ee8();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern uint FUN_80060058();
extern undefined4 FUN_800600b4();
extern undefined4 FUN_800600c4();
extern int FUN_800600d4();
extern int FUN_800600e4();
extern undefined4 FUN_8006069c();
extern undefined4 FUN_80135814();
extern undefined4 FUN_80194b10();
extern undefined4 FUN_80242114();
extern undefined8 FUN_8028682c();
extern uint FUN_8028683c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286888();
extern double FUN_80293900();

extern undefined4 DAT_80322fb8;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dca60;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803de780;
extern f64 DOUBLE_803e4ca8;
extern f64 DOUBLE_803e4cc0;
extern f64 DOUBLE_803e4cd8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4c98;
extern f32 FLOAT_803e4ca0;
extern f32 FLOAT_803e4cb0;
extern f32 FLOAT_803e4cb8;
extern f32 FLOAT_803e4cc8;
extern f32 FLOAT_803e4ccc;
extern f32 FLOAT_803e4cd0;
extern f32 FLOAT_803e4cd4;
extern f32 FLOAT_803e4ce0;
extern f32 FLOAT_803e4ce4;
extern f32 FLOAT_803e4ce8;
extern f32 FLOAT_803e4cec;
extern f32 FLOAT_803e4cf0;
extern f32 FLOAT_803e4cf4;

/*
 * --INFO--
 *
 * Function: FUN_80195008
 * EN v1.0 Address: 0x80195008
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801950E0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80195008(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int iVar5;
  
  fVar1 = FLOAT_803e4c98;
  iVar5 = *(int *)(param_1 + 0xb8);
  uVar4 = *(undefined4 *)(param_1 + 0x4c);
  *(float *)(iVar5 + 0x40) = FLOAT_803e4c98;
  *(float *)(iVar5 + 0x44) = fVar1;
  *(float *)(iVar5 + 0x48) = fVar1;
  if (param_2 == 0) {
    iVar2 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
    puVar3 = (undefined4 *)FUN_8005af70(iVar2);
    if ((puVar3 != (undefined4 *)0x0) && (*(int *)(iVar5 + 4) != 0)) {
      FUN_801950d4(uVar4,iVar5,puVar3);
    }
  }
  if (*(uint *)(iVar5 + 0xc) != 0) {
    FUN_80017814(*(uint *)(iVar5 + 0xc));
  }
  ObjGroup_RemoveObject(param_1,0x51);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801950ac
 * EN v1.0 Address: 0x801950AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019518C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801950ac(int param_1)
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
 * Function: FUN_801950d4
 * EN v1.0 Address: 0x801950D4
 * EN v1.0 Size: 1052b
 * EN v1.1 Address: 0x801951BC
 * EN v1.1 Size: 968b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801950d4(undefined4 param_1,undefined4 param_2,undefined4 *param_3)
{
  ushort uVar1;
  float fVar2;
  int iVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  undefined2 *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  undefined8 uVar17;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  
  uVar17 = FUN_8028682c();
  iVar3 = (int)((ulonglong)uVar17 >> 0x20);
  iVar8 = (int)uVar17;
  iVar12 = 0;
  iVar11 = 0;
  for (iVar10 = 0; iVar10 < (int)(uint)*(ushort *)((int)param_3 + 0x9a); iVar10 = iVar10 + 1) {
    puVar4 = (ushort *)FUN_800600c4((int)param_3,iVar10);
    uVar5 = FUN_80060058((int)puVar4);
    dVar16 = DOUBLE_803e4ca8;
    if ((int)*(char *)(iVar3 + 0x28) == uVar5) {
      local_a8 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x10) + iVar12) ^ 0x80000000);
      puVar4[3] = (ushort)(int)(*(float *)(iVar8 + 0x44) + (float)(local_a8 - DOUBLE_803e4ca8));
      local_98 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x14) + iVar12) ^ 0x80000000);
      puVar4[4] = (ushort)(int)(*(float *)(iVar8 + 0x44) + (float)(local_98 - dVar16));
      iVar12 = iVar12 + 2;
      uVar1 = puVar4[10];
      dVar15 = (double)FLOAT_803e4ca0;
      iVar6 = iVar11;
      for (uVar5 = (uint)*puVar4; (int)uVar5 < (int)(uint)uVar1; uVar5 = uVar5 + 1) {
        puVar4 = (ushort *)FUN_800600b4((int)param_3,uVar5);
        iVar14 = 3;
        iVar13 = iVar6;
        do {
          puVar9 = (undefined2 *)(param_3[0x16] + (uint)*puVar4 * 6);
          local_90 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar8 + 0xc) + iVar6) ^ 0x80000000);
          *puVar9 = (short)(int)(dVar15 * (double)*(float *)(iVar8 + 0x40) +
                                (double)(float)(local_90 - dVar16));
          local_a0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar8 + 0xc) + iVar6 + 2) ^
                                      0x80000000);
          puVar9[1] = (short)(int)(dVar15 * (double)*(float *)(iVar8 + 0x44) +
                                  (double)(float)(local_a0 - dVar16));
          local_88 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar8 + 0xc) + iVar6 + 4) ^
                                      0x80000000);
          puVar9[2] = (short)(int)(dVar15 * (double)*(float *)(iVar8 + 0x48) +
                                  (double)(float)(local_88 - dVar16));
          iVar6 = iVar6 + 6;
          iVar13 = iVar13 + 6;
          iVar11 = iVar11 + 6;
          puVar4 = puVar4 + 1;
          iVar14 = iVar14 + -1;
        } while (iVar14 != 0);
        iVar6 = iVar13;
      }
    }
  }
  FUN_80242114(param_3[0x16],(uint)*(ushort *)(param_3 + 0x24) * 6);
  iVar10 = 0;
  for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)((int)param_3 + 0xa1); iVar11 = iVar11 + 1) {
    iVar12 = FUN_800600d4((int)param_3,iVar11);
    iVar6 = FUN_800600e4((int)param_3,(uint)*(byte *)(iVar12 + 0x13));
    iVar6 = FUN_800480a0(iVar6,0);
    dVar16 = DOUBLE_803e4ca8;
    fVar2 = FLOAT_803e4ca0;
    if ((uint)*(byte *)(iVar6 + 5) == (int)*(char *)(iVar3 + 0x28)) {
      local_80 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x28) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 6) =
           (short)(int)(FLOAT_803e4ca0 * *(float *)(iVar8 + 0x40) +
                       (float)(local_80 - DOUBLE_803e4ca8));
      local_90 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x2c) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 0xc) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x40) + (float)(local_90 - dVar16));
      local_a0 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar8 + 0x30) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 8) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x44) + (float)(local_a0 - dVar16));
      *(short *)(iVar12 + 0xe) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x44) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar8 + 0x34) + iVar10) ^
                                                0x80000000) - dVar16));
      *(short *)(iVar12 + 10) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x48) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar8 + 0x38) + iVar10) ^
                                                0x80000000) - dVar16));
      *(short *)(iVar12 + 0x10) =
           (short)(int)(fVar2 * *(float *)(iVar8 + 0x48) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar8 + 0x3c) + iVar10) ^
                                                0x80000000) - dVar16));
    }
    iVar10 = iVar10 + 2;
  }
  uVar7 = FUN_8006069c();
  *param_3 = uVar7;
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801954f0
 * EN v1.0 Address: 0x801954F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80195584
 * EN v1.1 Size: 4624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801954f0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801954f4
 * EN v1.0 Address: 0x801954F4
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x80196794
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801954f4(int param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  ObjGroup_AddObject(param_1,0x51);
  iVar1 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar1 == 0x49cb7) {
LAB_80196824:
    *(undefined2 *)(iVar2 + 0x4e) = 0x4b7;
  }
  else {
    if (iVar1 < 0x49cb7) {
      if (iVar1 == 0x49275) goto LAB_80196824;
      if (0x49274 < iVar1) {
        return;
      }
      if (iVar1 != 0x46406) {
        return;
      }
    }
    else {
      if (iVar1 == 0x4c797) goto LAB_80196824;
      if (0x4c796 < iVar1) {
        return;
      }
      if (iVar1 != 0x4bab1) {
        return;
      }
    }
    *(undefined2 *)(iVar2 + 0x4e) = 0x7d;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801955a4
 * EN v1.0 Address: 0x801955A4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80196854
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801955a4(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x1a);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801955c8
 * EN v1.0 Address: 0x801955C8
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80196880
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801955c8(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_78;
  float local_74;
  undefined auStack_70 [12];
  float local_64;
  float local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 2) & 1) == 0) {
    iVar2 = *(int *)(param_1 + 0x4c);
    uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x34));
    if (uVar1 != 0) {
      FUN_80017698((int)*(short *)(iVar2 + 0x32),1);
      *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 1;
      dVar5 = (double)FLOAT_803e4cb8;
      dVar4 = DOUBLE_803e4cc0;
      for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar2 + 0x2c); iVar3 = iVar3 + 1) {
        uStack_54 = FUN_80017760((int)*(short *)(iVar2 + 0x2e),(int)*(short *)(iVar2 + 0x28));
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_78 = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - dVar4));
        uStack_4c = FUN_80017760((int)*(short *)(iVar2 + 0x30),(int)*(short *)(iVar2 + 0x2a));
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_74 = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar4));
        uStack_44 = FUN_80017760((int)*(short *)(iVar2 + 0x18),(int)*(short *)(iVar2 + 0x1e));
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_64 = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar4);
        uStack_3c = FUN_80017760((int)*(short *)(iVar2 + 0x1a),(int)*(short *)(iVar2 + 0x20));
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_60 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4);
        uStack_34 = FUN_80017760((int)*(short *)(iVar2 + 0x1c),(int)*(short *)(iVar2 + 0x22));
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_5c = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar4);
        (**(code **)(*DAT_803dd708 + 8))
                  (param_1,(int)*(short *)(iVar2 + 0x24),auStack_70,2,0xffffffff,&local_78);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80195704
 * EN v1.0 Address: 0x80195704
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x80196A30
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80195704(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x32));
  *(bool *)(iVar2 + 2) = uVar1 != 0;
  ObjGroup_AddObject(param_1,0x1a);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019575c
 * EN v1.0 Address: 0x8019575C
 * EN v1.0 Size: 996b
 * EN v1.1 Address: 0x80196A9C
 * EN v1.1 Size: 1036b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019575c(undefined2 *param_1,int param_2,int param_3)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  *(float *)(param_1 + 6) =
       *(float *)(param_2 + 0x26c) * *(float *)(param_1 + 4) + *(float *)(param_3 + 8);
  *(float *)(param_1 + 8) =
       *(float *)(param_2 + 0x270) * *(float *)(param_1 + 4) + *(float *)(param_3 + 0xc);
  *(float *)(param_1 + 10) =
       *(float *)(param_2 + 0x274) * *(float *)(param_1 + 4) + *(float *)(param_3 + 0x10);
  *param_1 = *(undefined2 *)(param_3 + 0x1a);
  param_1[1] = *(undefined2 *)(param_3 + 0x1c);
  param_1[2] = *(undefined2 *)(param_3 + 0x1e);
  dVar2 = DOUBLE_803e4cd8;
  fVar1 = FLOAT_803e4cc8;
  if ((*(byte *)(param_3 + 0x3c) & 1) == 0) {
    *(float *)(param_1 + 0x12) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x20) ^ 0x80000000) -
                DOUBLE_803e4cd8) / FLOAT_803e4cc8;
    *(float *)(param_1 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x22) ^ 0x80000000) - dVar2)
         / fVar1;
    *(float *)(param_1 + 0x16) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x24) ^ 0x80000000) - dVar2)
         / fVar1;
  }
  else {
    dVar6 = (double)((float)((double)CONCAT44(0x43300000,
                                              (int)*(short *)(param_3 + 0x20) ^ 0x80000000) -
                            DOUBLE_803e4cd8) / FLOAT_803e4cc8);
    dVar5 = (double)(*(float *)(param_1 + 6) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x42) ^ 0x80000000
                                            ) - DOUBLE_803e4cd8));
    dVar4 = (double)(*(float *)(param_1 + 8) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x44) ^ 0x80000000
                                            ) - DOUBLE_803e4cd8));
    dVar3 = (double)(*(float *)(param_1 + 10) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x46) ^ 0x80000000
                                            ) - DOUBLE_803e4cd8));
    dVar2 = FUN_80293900((double)(float)(dVar3 * dVar3 +
                                        (double)(float)(dVar5 * dVar5 +
                                                       (double)(float)(dVar4 * dVar4))));
    if ((double)FLOAT_803e4ccc != dVar2) {
      dVar5 = (double)(float)(dVar5 / dVar2);
      dVar4 = (double)(float)(dVar4 / dVar2);
      dVar3 = (double)(float)(dVar3 / dVar2);
    }
    *(float *)(param_1 + 0x12) = (float)(dVar6 * dVar5);
    *(float *)(param_1 + 0x14) = (float)(dVar6 * dVar4);
    *(float *)(param_1 + 0x16) = (float)(dVar6 * dVar3);
  }
  dVar2 = DOUBLE_803e4cd8;
  *(float *)(param_2 + 0x278) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2c) ^ 0x80000000) -
              DOUBLE_803e4cd8);
  *(float *)(param_2 + 0x27c) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2e) ^ 0x80000000) - dVar2);
  *(float *)(param_2 + 0x280) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x30) ^ 0x80000000) - dVar2);
  if (FLOAT_803e4ccc < *(float *)(param_1 + 0x12)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 1;
  }
  if (FLOAT_803e4ccc < *(float *)(param_1 + 0x16)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 2;
  }
  if (FLOAT_803e4ccc < *(float *)(param_2 + 0x278)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 4;
  }
  if (FLOAT_803e4ccc < *(float *)(param_2 + 0x27c)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 8;
  }
  if (FLOAT_803e4ccc < *(float *)(param_2 + 0x280)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 0x10;
  }
  dVar2 = DOUBLE_803e4cd8;
  fVar1 = FLOAT_803e4cd0;
  *(float *)(param_2 + 0x284) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x32) ^ 0x80000000) -
              DOUBLE_803e4cd8) / FLOAT_803e4cd0;
  *(float *)(param_2 + 0x288) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x34) ^ 0x80000000) - dVar2) /
       fVar1;
  *(float *)(param_2 + 0x28c) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x36) ^ 0x80000000) - dVar2) /
       fVar1;
  fVar1 = FLOAT_803e4cd4;
  *(float *)(param_2 + 0x290) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x26) ^ 0x80000000) - dVar2) /
       FLOAT_803e4cd4;
  *(float *)(param_2 + 0x294) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x28) ^ 0x80000000) - dVar2) /
       fVar1;
  *(float *)(param_2 + 0x298) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2a) ^ 0x80000000) - dVar2) /
       fVar1;
  *(undefined2 *)(param_2 + 0x29c) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80195b40
 * EN v1.0 Address: 0x80195B40
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80196EA8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80195b40(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80195b74
 * EN v1.0 Address: 0x80195B74
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80196ED8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80195b74(int param_1)
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
 * Function: FUN_80195b9c
 * EN v1.0 Address: 0x80195B9C
 * EN v1.0 Size: 1704b
 * EN v1.1 Address: 0x80196F0C
 * EN v1.1 Size: 1752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80195b9c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  short sVar5;
  int iVar4;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  undefined auStack_a8 [12];
  float local_9c;
  float local_98;
  float local_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined8 local_88;
  undefined8 local_80;
  longlong local_78;
  undefined4 local_70;
  uint uStack_6c;
  undefined8 local_68;
  
  iVar9 = *(int *)(param_9 + 0x5c);
  bVar1 = *(byte *)(iVar9 + 0x29e);
  if ((bVar1 & 2) == 0) {
    iVar8 = *(int *)(param_9 + 0x26);
    if ((bVar1 & 1) == 0) {
      if (*(char *)((int)param_9 + 0xad) == '\0') {
        uVar6 = FUN_80017690((int)*(short *)(iVar8 + 0x40));
        if ((uVar6 != 0) || (*(short *)(iVar8 + 0x40) == -1)) {
          *(byte *)(iVar9 + 0x29e) = *(byte *)(iVar9 + 0x29e) | 1;
          FUN_80017698((int)*(short *)(iVar8 + 0x3e),1);
          DAT_803de780 = '\x01';
        }
      }
      else if (DAT_803de780 != '\0') {
        *(byte *)(iVar9 + 0x29e) = bVar1 | 1;
      }
      *(undefined *)(param_9 + 0x1b) = 0;
    }
    else {
      *(undefined *)(param_9 + 0x1b) = 0xff;
      sVar5 = *(short *)(iVar9 + 0x29c) + (ushort)DAT_803dc070;
      *(short *)(iVar9 + 0x29c) = sVar5;
      if ((int)(uint)*(ushort *)(iVar8 + 0x38) <= (int)sVar5) {
        *(byte *)(iVar9 + 0x29e) = *(byte *)(iVar9 + 0x29e) | 2;
      }
      uVar6 = (uint)*(ushort *)(iVar8 + 0x3a);
      if (((int)uVar6 < (int)*(short *)(iVar9 + 0x29c)) &&
         (uVar7 = *(ushort *)(iVar8 + 0x38) - uVar6, uVar7 != 0)) {
        local_88 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        iVar4 = (int)(FLOAT_803e4ce4 *
                     (FLOAT_803e4ce0 -
                     (float)((double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar9 + 0x29c) - uVar6 ^ 0x80000000) -
                            DOUBLE_803e4cd8) / (float)(local_88 - DOUBLE_803e4cd8)));
        if (iVar4 < 0x100) {
          if (iVar4 < 0) {
            iVar4 = 0;
          }
        }
        else {
          iVar4 = 0xff;
        }
        *(char *)(param_9 + 0x1b) = (char)iVar4;
      }
      *(float *)(param_9 + 0x12) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x290) + *(float *)(param_9 + 0x12);
      *(float *)(param_9 + 0x14) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x294) + *(float *)(param_9 + 0x14);
      *(float *)(param_9 + 0x16) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x298) + *(float *)(param_9 + 0x16);
      *(float *)(iVar9 + 0x278) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x284) + *(float *)(iVar9 + 0x278);
      *(float *)(iVar9 + 0x27c) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x288) + *(float *)(iVar9 + 0x27c);
      *(float *)(iVar9 + 0x280) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x28c) + *(float *)(iVar9 + 0x280);
      if ((*(byte *)(iVar9 + 0x29f) & 1) == 0) {
        if (FLOAT_803e4ccc < *(float *)(param_9 + 0x12)) {
          *(float *)(param_9 + 0x12) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(param_9 + 0x12) < FLOAT_803e4ccc) {
        *(float *)(param_9 + 0x12) = FLOAT_803e4ccc;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 2) == 0) {
        if (FLOAT_803e4ccc < *(float *)(param_9 + 0x16)) {
          *(float *)(param_9 + 0x16) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(param_9 + 0x16) < FLOAT_803e4ccc) {
        *(float *)(param_9 + 0x16) = FLOAT_803e4ccc;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 4) == 0) {
        if (FLOAT_803e4ccc < *(float *)(iVar9 + 0x278)) {
          *(float *)(iVar9 + 0x278) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(iVar9 + 0x278) < FLOAT_803e4ccc) {
        *(float *)(iVar9 + 0x278) = FLOAT_803e4ccc;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 8) == 0) {
        if (FLOAT_803e4ccc < *(float *)(iVar9 + 0x27c)) {
          *(float *)(iVar9 + 0x27c) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(iVar9 + 0x27c) < FLOAT_803e4ccc) {
        *(float *)(iVar9 + 0x27c) = FLOAT_803e4ccc;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 0x10) == 0) {
        if (FLOAT_803e4ccc < *(float *)(iVar9 + 0x280)) {
          *(float *)(iVar9 + 0x280) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(iVar9 + 0x280) < FLOAT_803e4ccc) {
        *(float *)(iVar9 + 0x280) = FLOAT_803e4ccc;
      }
      *(float *)(param_9 + 6) =
           *(float *)(param_9 + 0x12) * FLOAT_803dc074 + *(float *)(param_9 + 6);
      *(float *)(param_9 + 8) =
           *(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(param_9 + 8);
      *(float *)(param_9 + 10) =
           *(float *)(param_9 + 0x16) * FLOAT_803dc074 + *(float *)(param_9 + 10);
      dVar11 = DOUBLE_803e4cd8;
      local_80 = (double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000);
      iVar4 = (int)(*(float *)(iVar9 + 0x278) * FLOAT_803dc074 + (float)(local_80 - DOUBLE_803e4cd8)
                   );
      local_88 = (double)(longlong)iVar4;
      *param_9 = (short)iVar4;
      uStack_8c = (int)param_9[1] ^ 0x80000000;
      local_90 = 0x43300000;
      iVar4 = (int)(*(float *)(iVar9 + 0x27c) * FLOAT_803dc074 +
                   (float)((double)CONCAT44(0x43300000,uStack_8c) - dVar11));
      local_78 = (longlong)iVar4;
      param_9[1] = (short)iVar4;
      uStack_6c = (int)param_9[2] ^ 0x80000000;
      local_70 = 0x43300000;
      iVar4 = (int)(*(float *)(iVar9 + 0x280) * FLOAT_803dc074 +
                   (float)((double)CONCAT44(0x43300000,uStack_6c) - dVar11));
      local_68 = (double)(longlong)iVar4;
      param_9[2] = (short)iVar4;
      if ((*(byte *)(iVar8 + 0x3c) & 2) != 0) {
        (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_9,iVar9);
        (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar9);
        (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar9);
        if (*(char *)(iVar9 + 0x261) != '\0') {
          dVar14 = -(double)*(float *)(param_9 + 0x12);
          dVar13 = -(double)*(float *)(param_9 + 0x14);
          dVar15 = -(double)*(float *)(param_9 + 0x16);
          dVar11 = FUN_80293900((double)(float)(dVar15 * dVar15 +
                                               (double)(float)(dVar14 * dVar14 +
                                                              (double)(float)(dVar13 * dVar13))));
          if ((double)FLOAT_803e4ccc != dVar11) {
            dVar10 = (double)(float)((double)FLOAT_803e4ce0 / dVar11);
            dVar14 = (double)(float)(dVar14 * dVar10);
            dVar13 = (double)(float)(dVar13 * dVar10);
            dVar15 = (double)(float)(dVar15 * dVar10);
          }
          fVar2 = *(float *)(iVar9 + 0x6c);
          fVar3 = *(float *)(iVar9 + 0x70);
          dVar10 = (double)(FLOAT_803e4ce8 *
                           (float)(dVar15 * (double)fVar3 +
                                  (double)(float)(dVar14 * (double)*(float *)(iVar9 + 0x68) +
                                                 (double)(float)(dVar13 * (double)fVar2))));
          *(float *)(param_9 + 0x12) = (float)((double)*(float *)(iVar9 + 0x68) * dVar10);
          *(float *)(param_9 + 0x14) = (float)((double)fVar2 * dVar10);
          *(float *)(param_9 + 0x16) = (float)((double)fVar3 * dVar10);
          *(float *)(param_9 + 0x12) = (float)((double)*(float *)(param_9 + 0x12) - dVar14);
          *(float *)(param_9 + 0x14) = (float)((double)*(float *)(param_9 + 0x14) - dVar13);
          *(float *)(param_9 + 0x16) = (float)((double)*(float *)(param_9 + 0x16) - dVar15);
          *(float *)(param_9 + 0x14) = (float)((double)*(float *)(param_9 + 0x14) * dVar11);
          *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803e4cec;
          *(float *)(param_9 + 0x12) = (float)((double)*(float *)(param_9 + 0x12) * dVar11);
          *(float *)(param_9 + 0x16) = (float)((double)*(float *)(param_9 + 0x16) * dVar11);
          fVar2 = FLOAT_803e4cf0;
          *(float *)(param_9 + 0x12) = *(float *)(param_9 + 0x12) * FLOAT_803e4cf0;
          *(float *)(param_9 + 0x16) = *(float *)(param_9 + 0x16) * fVar2;
        }
      }
      if (((*(byte *)(iVar8 + 0x3c) & 4) != 0) && (*(char *)(param_9 + 0x1b) == -1)) {
        dVar15 = (double)(*(float *)(param_9 + 6) - *(float *)(param_9 + 0x40));
        dVar14 = (double)(*(float *)(param_9 + 8) - *(float *)(param_9 + 0x42));
        dVar13 = (double)(*(float *)(param_9 + 10) - *(float *)(param_9 + 0x44));
        uVar6 = 0;
        dVar10 = (double)FLOAT_803e4cf4;
        dVar11 = DOUBLE_803e4cd8;
        do {
          local_68 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          dVar12 = (double)(float)((double)(float)(local_68 - dVar11) * dVar10);
          local_9c = (float)(dVar15 * dVar12 + (double)*(float *)(param_9 + 0x40));
          local_98 = (float)(dVar14 * dVar12 + (double)*(float *)(param_9 + 0x42));
          local_94 = (float)(dVar13 * dVar12 + (double)*(float *)(param_9 + 0x44));
          (**(code **)(*DAT_803dd708 + 8))(param_9,1000,auStack_a8,0x200001,0xffffffff,0);
          uVar6 = uVar6 + 1;
        } while ((int)uVar6 < 2);
      }
    }
  }
  else {
    if ((param_9[3] & 0x2000U) != 0) {
      FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    *(undefined *)(param_9 + 0x1b) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80196244
 * EN v1.0 Address: 0x80196244
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x801975E4
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80196244(undefined2 *param_1,int param_2)
{
  float fVar1;
  undefined uVar2;
  uint uVar3;
  int iVar4;
  undefined local_18 [12];
  
  local_18[0] = 5;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  fVar1 = FLOAT_803e4ccc;
  iVar4 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar4 + 0x26c) = FLOAT_803e4ccc;
  *(float *)(iVar4 + 0x270) = fVar1;
  *(float *)(iVar4 + 0x274) = fVar1;
  FUN_8019575c(param_1,iVar4,param_2);
  uVar3 = FUN_80017690((int)*(short *)(param_2 + 0x3e));
  if (uVar3 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = 2;
  }
  *(undefined *)(iVar4 + 0x29e) = uVar2;
  DAT_803de780 = 0;
  if ((*(byte *)(param_2 + 0x3c) & 2) != 0) {
    (**(code **)(*DAT_803dd728 + 4))(iVar4,0,0x40002,1);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar4,1,&DAT_80322fb8,&DAT_803dca60,local_18);
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar4);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019635c
 * EN v1.0 Address: 0x8019635C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019771C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019635c(int param_1)
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
 * Function: FUN_80196384
 * EN v1.0 Address: 0x80196384
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x80197750
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80196384(int param_1)
{
  uint uVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  int *piVar5;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((((*(byte *)(piVar5 + 5) >> 5 & 1) == 0) &&
      (uVar1 = FUN_80017690((int)*(short *)(iVar4 + 0x20)), uVar1 != 0)) &&
     ((*(byte *)(piVar5 + 5) >> 6 & 1) == 0)) {
    *(byte *)(piVar5 + 5) = *(byte *)(piVar5 + 5) & 0xdf | 0x20;
    piVar5[4] = 0;
  }
  if (((*(byte *)(piVar5 + 5) >> 5 & 1) != 0) && (*piVar5 != 0)) {
    iVar2 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
    iVar2 = FUN_8005af70(iVar2);
    if ((iVar2 != 0) &&
       (((*(ushort *)(iVar2 + 4) & 8) != 0 &&
        (psVar3 = (short *)FUN_80055ee8(), psVar3 != (short *)0x0)))) {
      iVar2 = fn_80056800((int)*psVar3);
      piVar5[4] = piVar5[4] + (uint)*(byte *)(piVar5 + 1) * (uint)DAT_803dc070;
      FUN_80135814();
      if (piVar5[4] < 0) {
        piVar5[4] = 0;
      }
      else if (piVar5[2] < piVar5[4]) {
        uVar1 = (uint)*(short *)(iVar4 + 0x1e);
        if (uVar1 == 0xffffffff) {
          piVar5[4] = piVar5[3];
        }
        else {
          FUN_80017698(uVar1,1);
          *(byte *)(piVar5 + 5) = *(byte *)(piVar5 + 5) & 0xdf;
          *(byte *)(piVar5 + 5) = *(byte *)(piVar5 + 5) & 0xbf | 0x40;
          piVar5[4] = piVar5[2];
        }
      }
      *(int *)(iVar2 + 4) = piVar5[4];
    }
  }
  return;
}
