#include "ghidra_import.h"
#include "main/dll/DR/DRlaserturret.h"

extern undefined4 FUN_80006824();
extern uint FUN_80006ab0();
extern uint FUN_80006ab8();
extern undefined4 FUN_80006ac0();
extern undefined4 FUN_80006ac4();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006ba8();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int FUN_800384ec();
extern int FUN_800632f4();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011eb38();
extern double FUN_801e7be8();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern int FUN_80294d20();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcd08;
extern undefined4 DAT_803dcd0c;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803e6668;
extern undefined4 DAT_803e666c;
extern f64 DOUBLE_803e6698;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6670;
extern f32 FLOAT_803e6674;
extern f32 FLOAT_803e6678;
extern f32 FLOAT_803e667c;
extern f32 FLOAT_803e6688;
extern f32 FLOAT_803e66a0;
extern f32 FLOAT_803e66a4;
extern f32 FLOAT_803e66a8;
extern f32 FLOAT_803e66ac;
extern f32 FLOAT_803e66b0;
extern f32 FLOAT_803e66b4;
extern f32 FLOAT_803e66b8;

/*
 * --INFO--
 *
 * Function: FUN_801e6b10
 * EN v1.0 Address: 0x801E6B10
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x801E6CDC
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801e6b10(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  short *psVar3;
  int local_18;
  float local_14 [3];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  local_14[0] = FLOAT_803e6670;
  if ((*(char *)(param_2 + 0x27a) != '\0') && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x7ef,local_14,0x50,0);
  }
  *(undefined *)(iVar2 + 0x9d6) = 0;
  *(float *)(param_2 + 0x280) = FLOAT_803e6674;
  if (*(char *)(iVar2 + 0x9d6) == '\0') {
    psVar3 = *(short **)(iVar2 + 0x9b0);
    local_18 = 0;
    uVar1 = FUN_80006ab0(psVar3);
    if (uVar1 == 0) {
      FUN_80006ac0(psVar3,(uint)&local_18);
    }
    local_18 = local_18 + 1;
  }
  else {
    local_18 = 0;
  }
  return local_18;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6be4
 * EN v1.0 Address: 0x801E6BE4
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801E6DAC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6be4(void)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  int unaff_r27;
  short *psVar5;
  int iVar6;
  undefined8 uVar7;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  
  uVar7 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar7 >> 0x20);
  local_2c = DAT_803e6668;
  local_28 = DAT_803e666c;
  iVar3 = FUN_80017a98();
  iVar6 = *(int *)(puVar2 + 0x5c);
  if ((*(char *)((int)uVar7 + 0x27a) != '\0') &&
     (uVar4 = FUN_80006ab0(*(short **)(iVar6 + 0x9b0)), uVar4 != 0)) {
    iVar3 = (**(code **)(*DAT_803dd71c + 0x14))
                      ((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                       (double)*(float *)(iVar3 + 0x14),&local_2c,2,0xffffffff);
    if (iVar3 != -1) {
      unaff_r27 = (**(code **)(*DAT_803dd71c + 0x1c))();
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(unaff_r27 + 8);
      fVar1 = FLOAT_803e6678;
      *(float *)(puVar2 + 8) = FLOAT_803e6678 + *(float *)(unaff_r27 + 0xc);
      *(undefined4 *)(puVar2 + 10) = *(undefined4 *)(unaff_r27 + 0x10);
      *puVar2 = (short)((int)*(char *)(unaff_r27 + 0x2c) << 8);
      *(float *)(iVar6 + 0x9bc) = fVar1 + *(float *)(unaff_r27 + 0xc);
      *(undefined2 *)(iVar6 + 0x9ca) = 0;
      *(undefined *)(iVar6 + 0x9d3) = *(undefined *)(unaff_r27 + 0x19);
    }
    if (*(char *)(unaff_r27 + 0x19) == '\f') {
      local_30 = 1;
      psVar5 = *(short **)(iVar6 + 0x9b0);
      uVar4 = FUN_80006ab8(psVar5);
      if (uVar4 == 0) {
        FUN_80006ac4(psVar5,(uint)&local_30);
      }
    }
    else {
      local_34 = 2;
      psVar5 = *(short **)(iVar6 + 0x9b0);
      uVar4 = FUN_80006ab8(psVar5);
      if (uVar4 == 0) {
        FUN_80006ac4(psVar5,(uint)&local_34);
      }
    }
    *(float *)((int)uVar7 + 0x280) = FLOAT_803e6674;
    *(byte *)(iVar6 + 0x9d4) = *(byte *)(iVar6 + 0x9d4) | 0x20;
  }
  *(undefined *)(iVar6 + 0x9d6) = 0xff;
  if (*(char *)(iVar6 + 0x9d6) == -1) {
    psVar5 = *(short **)(iVar6 + 0x9b0);
    local_38 = 0;
    uVar4 = FUN_80006ab0(psVar5);
    if (uVar4 == 0) {
      FUN_80006ac0(psVar5,(uint)&local_38);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6da4
 * EN v1.0 Address: 0x801E6DA4
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801E6F80
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e6da4(void)
{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_80017690(0x617);
  if (uVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = 6;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6ddc
 * EN v1.0 Address: 0x801E6DDC
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x801E6FB8
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e6ddc(int param_1)
{
  byte bVar1;
  int iVar2;
  int local_18;
  int local_14;
  int local_10 [2];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(undefined *)(iVar2 + 0x9d6) = 0;
  ObjHits_DisableObject(param_1);
  iVar2 = *(int *)(iVar2 + 0x9b4);
  (**(code **)(**(int **)(iVar2 + 0x68) + 0x54))(iVar2,local_10,&local_14,&local_18);
  local_14 = local_14 - local_10[0];
  bVar1 = FUN_80006b44();
  if (((bVar1 != 0) || (local_18 <= local_14)) || (local_10[0] != 0)) {
    FUN_80006b4c();
    FUN_8011eb38(0);
    FUN_80017698(0x626,0);
    if (local_14 < local_18) {
      FUN_80017698(0x625,1);
    }
    else {
      FUN_80017698(0x624,1);
    }
    FUN_8011e800(2);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),6,0);
    (**(code **)(*DAT_803dd6f4 + 4))(0,0xf3,0,0,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6f2c
 * EN v1.0 Address: 0x801E6F2C
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x801E7100
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801e6f2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  short *psVar4;
  int iVar5;
  double dVar6;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar1 = FUN_80017a98();
  iVar5 = *(int *)(param_9 + 0x5c);
  *(undefined *)(iVar5 + 0x9d6) = 0xff;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e667c;
  if (param_9[0x50] != 0) {
    FUN_800305f8((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  ObjHits_EnableObject((int)param_9);
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
  uVar2 = FUN_80017690(0x617);
  if (uVar2 == 0) {
    local_28[0] = 1;
    psVar4 = *(short **)(iVar5 + 0x9b0);
    uVar2 = FUN_80006ab8(psVar4);
    if (uVar2 == 0) {
      FUN_80006ac4(psVar4,(uint)local_28);
    }
    uVar3 = 7;
  }
  else {
    FUN_801e7be8(param_9,iVar1,0);
    uStack_1c = (uint)*(ushort *)(iVar5 + 0x9ca);
    local_20 = 0x43300000;
    dVar6 = (double)FUN_80293f90();
    *(float *)(param_9 + 8) =
         (float)((double)*(float *)(iVar5 + 0x9b8) * dVar6 + (double)*(float *)(iVar5 + 0x9bc));
    uVar2 = (uint)*(ushort *)(iVar5 + 0x9ca) + (uint)DAT_803dc070 * 0x100;
    if (0xffff < uVar2) {
      uStack_1c = FUN_80017760(0xf,0x23);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar5 + 0x9b8) =
           FLOAT_803e6688 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6698);
    }
    *(short *)(iVar5 + 0x9ca) = (short)uVar2;
    if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
      iVar1 = FUN_80294d20(iVar1);
      if (iVar1 < 1) {
        uVar2 = FUN_80017760(0,2);
        (**(code **)(*DAT_803dd6d4 + 0x48))(uVar2,param_9,0xffffffff);
        FUN_80006ba8(0,0x100);
      }
      else {
        FUN_80017698(0x61d,1);
        FUN_80006ba8(0,0x100);
      }
    }
    uVar3 = 0;
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_801e719c
 * EN v1.0 Address: 0x801E719C
 * EN v1.0 Size: 1492b
 * EN v1.1 Address: 0x801E72F8
 * EN v1.1 Size: 1052b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e719c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  ushort *puVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  undefined4 local_28;
  int local_24 [9];
  
  uVar12 = FUN_80286840();
  puVar5 = (ushort *)((ulonglong)uVar12 >> 0x20);
  iVar8 = (int)uVar12;
  iVar6 = FUN_80017a98();
  iVar10 = *(int *)(puVar5 + 0x5c);
  if (*(char *)(iVar8 + 0x27a) != '\0') {
    local_24[2] = FUN_80017760(500,1000);
    local_24[2] = local_24[2] ^ 0x80000000;
    local_24[1] = 0x43300000;
    *(float *)(iVar10 + 0x9c0) = (float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e6698)
    ;
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) & 0xf7;
  }
  if ((*(byte *)(iVar10 + 0x9d4) & 8) == 0) {
    if ((puVar5[0x50] != 0x12) && (puVar5[0x50] != 0)) {
      FUN_800305f8((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar5,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(float *)(iVar8 + 0x2a0) = FLOAT_803e667c;
    }
  }
  else if (*(char *)(iVar8 + 0x346) != '\0') {
    if ((puVar5[0x50] != 0x11) || ((double)*(float *)(iVar8 + 0x2a0) <= (double)FLOAT_803e6674)) {
      if (puVar5[0x50] != 0) {
        FUN_800305f8((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     puVar5,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      }
    }
    else {
      FUN_800305f8((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar5,0x12,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    *(float *)(iVar8 + 0x2a0) = FLOAT_803e667c;
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) & 0xf7;
    local_24[2] = FUN_80017760(500,1000);
    local_24[2] = local_24[2] ^ 0x80000000;
    local_24[1] = 0x43300000;
    *(float *)(iVar10 + 0x9c0) = (float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e6698)
    ;
  }
  *(float *)(iVar10 + 0x9c0) = *(float *)(iVar10 + 0x9c0) - FLOAT_803dc074;
  if ((*(float *)(iVar10 + 0x9c0) <= FLOAT_803e6674) && ((*(byte *)(iVar10 + 0x9d4) & 8) == 0)) {
    FUN_80006824((uint)puVar5,0x40d);
    if (puVar5[0x50] == 0x12) {
      FUN_800305f8((double)FLOAT_803e66a0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar5,0x11,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(float *)(iVar8 + 0x2a0) = FLOAT_803e66a4;
    }
    else {
      uVar7 = FUN_80017760(0,1);
      FUN_800305f8((double)FLOAT_803e6674,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar5,(int)*(short *)(&DAT_803dcd08 + uVar7 * 2),0,in_r6,in_r7,in_r8,in_r9,
                   in_r10);
      *(undefined4 *)(iVar8 + 0x2a0) = *(undefined4 *)(&DAT_803dcd0c + uVar7 * 4);
    }
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) | 8;
  }
  uVar7 = FUN_80017690(0x617);
  if (uVar7 == 0) {
    local_28 = 4;
    psVar9 = *(short **)(iVar10 + 0x9b0);
    uVar7 = FUN_80006ab8(psVar9);
    if (uVar7 == 0) {
      FUN_80006ac4(psVar9,(uint)&local_28);
    }
  }
  else {
    dVar11 = FUN_801e7be8(puVar5,iVar6,0);
    fVar1 = FLOAT_803e6674;
    if ((double)FLOAT_803e66b0 < dVar11) {
      fVar1 = FLOAT_803e66ac;
    }
    *(float *)(iVar8 + 0x280) =
         FLOAT_803e66a8 * (fVar1 - *(float *)(iVar8 + 0x280)) * FLOAT_803dc074 +
         *(float *)(iVar8 + 0x280);
    if (FLOAT_803e66b4 < *(float *)(iVar8 + 0x280)) {
      *(float *)(iVar8 + 0x280) = FLOAT_803e6674;
    }
    *(float *)(iVar8 + 0x280) = FLOAT_803e6674;
    iVar6 = FUN_800632f4((double)*(float *)(puVar5 + 6),(double)*(float *)(puVar5 + 8),
                         (double)*(float *)(puVar5 + 10),puVar5,local_24,0,0);
    fVar4 = FLOAT_803e6678;
    fVar3 = FLOAT_803e6674;
    iVar8 = 0;
    fVar1 = FLOAT_803e66b8;
    if (0 < iVar6) {
      do {
        fVar2 = **(float **)(local_24[0] + iVar8) - *(float *)(puVar5 + 8);
        if (fVar2 < fVar3) {
          fVar2 = -fVar2;
        }
        if (fVar2 < fVar1) {
          *(float *)(iVar10 + 0x9bc) = fVar4 + **(float **)(local_24[0] + iVar8);
          fVar1 = fVar2;
        }
        iVar8 = iVar8 + 4;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    local_24[2] = (int)*(ushort *)(iVar10 + 0x9ca);
    local_24[1] = 0x43300000;
    dVar11 = (double)FUN_80293f90();
    *(float *)(puVar5 + 8) =
         (float)((double)*(float *)(iVar10 + 0x9b8) * dVar11 + (double)*(float *)(iVar10 + 0x9bc));
    uVar7 = (uint)*(ushort *)(iVar10 + 0x9ca) + (uint)DAT_803dc070 * 0x100;
    if (0xffff < uVar7) {
      local_24[2] = FUN_80017760(0xf,0x23);
      local_24[2] = local_24[2] ^ 0x80000000;
      local_24[1] = 0x43300000;
      *(float *)(iVar10 + 0x9b8) =
           FLOAT_803e6688 * (float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e6698);
    }
    *(short *)(iVar10 + 0x9ca) = (short)uVar7;
    iVar6 = FUN_800384ec((int)puVar5);
    if (iVar6 != 0) {
      uVar7 = FUN_80017760(0,2);
      (**(code **)(*DAT_803dd6d4 + 0x48))(uVar7,puVar5,0xffffffff);
    }
  }
  FUN_8028688c();
  return;
}
