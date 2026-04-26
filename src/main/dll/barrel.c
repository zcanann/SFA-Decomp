#include "ghidra_import.h"
#include "main/dll/barrel.h"

extern undefined4 FUN_80006824();
extern int FUN_80017730();
extern uint FUN_80017760();
extern undefined4 FUN_800305f8();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008111c();
extern double FUN_80293900();
extern uint countLeadingZeros();

extern undefined4 DAT_803ad270;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd734;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3b70;
extern f64 DOUBLE_803e3ba8;
extern f32 FLOAT_803e3b50;
extern f32 FLOAT_803e3b54;
extern f32 FLOAT_803e3b7c;
extern f32 FLOAT_803e3b88;
extern f32 FLOAT_803e3b8c;
extern f32 FLOAT_803e3b90;
extern f32 FLOAT_803e3b94;
extern f32 FLOAT_803e3b98;
extern f32 FLOAT_803e3b9c;
extern f32 FLOAT_803e3ba0;
extern f32 FLOAT_803e3ba4;
extern f32 FLOAT_803e3bb0;
extern f32 FLOAT_803e3bb4;
extern f32 FLOAT_803e3bb8;
extern f32 FLOAT_803e3bbc;

/*
 * --INFO--
 *
 * Function: FUN_80161f0c
 * EN v1.0 Address: 0x80161F0C
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x80161FA4
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80161f0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  double dVar3;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [2];
  
  iVar2 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,6,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b88;
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar2 + 0x48) - FLOAT_803e3b94),*(int *)(iVar2 + 0x38),&local_28,
             &local_24,&local_20);
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e3b94 + *(float *)(iVar2 + 0x48)),*(int *)(iVar2 + 0x38),&local_1c,
             &local_18,local_14);
  local_28 = local_28 - local_1c;
  local_24 = local_24 - local_18;
  local_20 = local_20 - local_14[0];
  dVar3 = FUN_80293900((double)(local_28 * local_28 + local_20 * local_20));
  local_28 = (float)dVar3;
  iVar1 = FUN_80017730();
  *(short *)(param_9 + 2) = (short)iVar1 * ((short)((int)*(char *)(iVar2 + 0x45) << 1) + -1);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801620c0
 * EN v1.0 Address: 0x801620C0
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x801620F0
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801620c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [2];
  
  iVar3 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b88;
  (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar3 + 0x48) - FLOAT_803e3b94),*(int *)(iVar3 + 0x38),&local_28,
             &local_24,&local_20);
  (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e3b94 + *(float *)(iVar3 + 0x48)),*(int *)(iVar3 + 0x38),&local_1c,
             &local_18,local_14);
  local_28 = local_28 - local_1c;
  local_24 = local_24 - local_18;
  local_20 = local_20 - local_14[0];
  dVar4 = FUN_80293900((double)(local_28 * local_28 + local_20 * local_20));
  local_28 = (float)dVar4;
  iVar1 = FUN_80017730();
  *(short *)(param_9 + 2) = (short)iVar1 * ((short)((int)*(char *)(iVar3 + 0x45) << 1) + -1);
  if (*(char *)(param_10 + 0x346) == '\0') {
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
 * Function: FUN_8016228c
 * EN v1.0 Address: 0x8016228C
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x80162254
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_8016228c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  double dVar3;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [2];
  
  iVar2 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,2,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b7c;
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar2 + 0x48) - FLOAT_803e3b94),*(int *)(iVar2 + 0x38),&local_28,
             &local_24,&local_20);
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e3b94 + *(float *)(iVar2 + 0x48)),*(int *)(iVar2 + 0x38),&local_1c,
             &local_18,local_14);
  local_28 = local_28 - local_1c;
  local_24 = local_24 - local_18;
  local_20 = local_20 - local_14[0];
  dVar3 = FUN_80293900((double)(local_28 * local_28 + local_20 * local_20));
  local_28 = (float)dVar3;
  iVar1 = FUN_80017730();
  *(short *)(param_9 + 2) = (short)iVar1 * ((short)((int)*(char *)(iVar2 + 0x45) << 1) + -1);
  return *(char *)(param_10 + 0x346) != '\0';
}

/*
 * --INFO--
 *
 * Function: FUN_80162450
 * EN v1.0 Address: 0x80162450
 * EN v1.0 Size: 1140b
 * EN v1.1 Address: 0x801623B8
 * EN v1.1 Size: 968b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80162450(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  ushort local_58;
  undefined auStack_56 [2];
  ushort local_54 [2];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c [2];
  uint uStack_34;
  undefined8 local_30;
  
  iVar5 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,3,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b88;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,9);
  uStack_34 = *(char *)(iVar5 + 0x45) * -2 + 1U ^ 0x80000000;
  local_3c[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar5 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_10 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e3b70)),
             *(int *)(iVar5 + 0x38),iVar5 + 0x48);
  if (FLOAT_803e3b8c <= *(float *)(iVar5 + 0x48)) {
    if (FLOAT_803e3b90 < *(float *)(iVar5 + 0x48)) {
      *(float *)(iVar5 + 0x48) = FLOAT_803e3b90;
    }
  }
  else {
    *(float *)(iVar5 + 0x48) = FLOAT_803e3b8c;
  }
  (**(code **)(**(int **)(*(int *)(iVar5 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar5 + 0x48) - FLOAT_803e3b94),*(int *)(iVar5 + 0x38),&local_50,
             &local_4c,&local_48);
  (**(code **)(**(int **)(*(int *)(iVar5 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e3b94 + *(float *)(iVar5 + 0x48)),*(int *)(iVar5 + 0x38),&local_44,
             &local_40,local_3c);
  local_50 = local_50 - local_44;
  local_4c = local_4c - local_40;
  local_48 = local_48 - local_3c[0];
  dVar6 = FUN_80293900((double)(local_50 * local_50 + local_48 * local_48));
  local_50 = (float)dVar6;
  iVar3 = FUN_80017730();
  uStack_34 = (int)(short)((short)iVar3 * ((short)((int)*(char *)(iVar5 + 0x45) << 1) + -1)) ^
              0x80000000;
  local_3c[1] = 176.0;
  iVar3 = (int)(-(FLOAT_803e3b98 * *(float *)(param_9 + 0x4c) - FLOAT_803e3b54) *
               (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e3b70));
  local_30 = (double)(longlong)iVar3;
  param_9[1] = (short)iVar3;
  if (*(char *)(param_10 + 0x346) == '\0') {
    uVar4 = 0;
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x14))
              (param_9,*(undefined4 *)(param_10 + 0x2d0),0x10,local_54,auStack_56,&local_58);
    *(char *)(iVar5 + 0x45) = '\x01' - *(char *)(iVar5 + 0x45);
    uVar2 = countLeadingZeros((int)*(char *)(iVar5 + 0x45));
    *param_9 = *(short *)(iVar5 + 0x58) + (short)((uVar2 >> 5) << 0xf);
    uVar2 = FUN_80017760(0x32,100);
    local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    fVar1 = (float)((double)CONCAT44(0x43300000,*(char *)(iVar5 + 0x45) * 2 - 1U ^ 0x80000000) -
                   DOUBLE_803e3b70) * ((float)(local_30 - DOUBLE_803e3b70) / FLOAT_803e3b9c);
    if ((local_54[0] < 4) || (0xb < local_54[0])) {
      uVar2 = (uint)local_58;
      if (uVar2 < 0x1f5) {
        local_30 = (double)CONCAT44(0x43300000,uVar2);
        fVar1 = fVar1 * (FLOAT_803e3b54 + (float)(local_30 - DOUBLE_803e3ba8) / FLOAT_803e3ba0);
      }
      else {
        local_30 = (double)CONCAT44(0x43300000,uVar2);
        fVar1 = fVar1 * (FLOAT_803e3b54 + (float)(local_30 - DOUBLE_803e3ba8) / FLOAT_803e3b9c);
      }
    }
    *(float *)(iVar5 + 0x54) = *(float *)(iVar5 + 0x48) - fVar1;
    fVar1 = FLOAT_803e3b54;
    if (FLOAT_803e3b54 < *(float *)(iVar5 + 0x54)) {
      fVar1 = *(float *)(iVar5 + 0x54);
    }
    *(float *)(iVar5 + 0x54) = fVar1;
    fVar1 = FLOAT_803e3ba4;
    if (*(float *)(iVar5 + 0x54) < FLOAT_803e3ba4) {
      fVar1 = *(float *)(iVar5 + 0x54);
    }
    *(float *)(iVar5 + 0x54) = fVar1;
    uVar4 = 4;
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_801628c4
 * EN v1.0 Address: 0x801628C4
 * EN v1.0 Size: 692b
 * EN v1.1 Address: 0x80162780
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801628c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34 [2];
  uint uStack_2c;
  
  iVar4 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,0);
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
    FUN_80006824(param_9,0x27b);
  }
  uStack_2c = *(char *)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
  local_34[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x28))
            ((double)(FLOAT_803e3bb0 *
                     *(float *)(param_10 + 0x2a0) *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e3b70)),
             *(int *)(iVar4 + 0x38),iVar4 + 0x48);
  if (FLOAT_803e3b8c <= *(float *)(iVar4 + 0x48)) {
    if (*(float *)(iVar4 + 0x48) <= FLOAT_803e3b90) {
      bVar1 = false;
    }
    else {
      *(float *)(iVar4 + 0x48) = FLOAT_803e3b90;
      bVar1 = true;
    }
  }
  else {
    *(float *)(iVar4 + 0x48) = FLOAT_803e3b8c;
    bVar1 = true;
  }
  if (bVar1) {
    uVar2 = 7;
  }
  else {
    (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
              ((double)(*(float *)(iVar4 + 0x48) - FLOAT_803e3b94),*(int *)(iVar4 + 0x38),&local_48,
               &local_44,&local_40);
    (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
              ((double)(FLOAT_803e3b94 + *(float *)(iVar4 + 0x48)),*(int *)(iVar4 + 0x38),&local_3c,
               &local_38,local_34);
    local_48 = local_48 - local_3c;
    local_44 = local_44 - local_38;
    local_40 = local_40 - local_34[0];
    dVar5 = FUN_80293900((double)(local_48 * local_48 + local_40 * local_40));
    local_48 = (float)dVar5;
    iVar3 = FUN_80017730();
    *(short *)(param_9 + 2) = (short)iVar3 * ((short)((int)*(char *)(iVar4 + 0x45) << 1) + -1);
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80162b78
 * EN v1.0 Address: 0x80162B78
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x801629C4
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80162b78(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  ushort local_48;
  undefined auStack_46 [2];
  ushort local_44 [2];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  uint uStack_24;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b88;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  uStack_24 = *(char *)(iVar3 + 0x45) * -2 + 1U ^ 0x80000000;
  local_2c[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_10 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e3b70)),
             *(int *)(iVar3 + 0x38),iVar3 + 0x48);
  if (FLOAT_803e3b8c <= *(float *)(iVar3 + 0x48)) {
    if (FLOAT_803e3b90 < *(float *)(iVar3 + 0x48)) {
      *(float *)(iVar3 + 0x48) = FLOAT_803e3b90;
    }
  }
  else {
    *(float *)(iVar3 + 0x48) = FLOAT_803e3b8c;
  }
  (**(code **)(*DAT_803dd738 + 0x14))
            (param_9,*(undefined4 *)(param_10 + 0x2d0),0x10,local_44,auStack_46,&local_48);
  if ((((local_44[0] < 4) || (0xb < local_44[0])) || (local_48 < 0x191)) ||
     ((*(float *)(iVar3 + 0x48) <= FLOAT_803e3b98 || (FLOAT_803e3bb4 <= *(float *)(iVar3 + 0x48)))))
  {
    if (((int)*(char *)(iVar3 + 0x45) ==
         ((uint)(byte)((*(float *)(iVar3 + 0x54) <= *(float *)(iVar3 + 0x48)) << 1) << 0x1c) >> 0x1d
        ) || (*(char *)(param_10 + 0x346) == '\0')) {
      if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
        *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
        FUN_80006824(param_9,0x27b);
      }
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)(*(float *)(iVar3 + 0x48) - FLOAT_803e3b94),*(int *)(iVar3 + 0x38),
                 &local_40,&local_3c,&local_38);
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)(FLOAT_803e3b94 + *(float *)(iVar3 + 0x48)),*(int *)(iVar3 + 0x38),
                 &local_34,&local_30,local_2c);
      local_40 = local_40 - local_34;
      local_3c = local_3c - local_30;
      local_38 = local_38 - local_2c[0];
      dVar4 = FUN_80293900((double)(local_40 * local_40 + local_38 * local_38));
      local_40 = (float)dVar4;
      iVar2 = FUN_80017730();
      *(short *)(param_9 + 2) = (short)iVar2 * ((short)((int)*(char *)(iVar3 + 0x45) << 1) + -1);
      uVar1 = 0;
    }
    else {
      uVar1 = 3;
    }
  }
  else {
    uVar1 = 3;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80162ec0
 * EN v1.0 Address: 0x80162EC0
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x80162CA0
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80162ec0(short *param_1)
{
  float fVar1;
  undefined uVar3;
  uint uVar2;
  float *pfVar4;
  int iVar5;
  undefined2 uVar6;
  int iVar7;
  float *pfVar8;
  undefined auStack_38 [4];
  float local_34;
  float local_30;
  int local_2c [7];
  
  iVar7 = *(int *)(param_1 + 0x5c);
  pfVar4 = (float *)ObjGroup_GetObjects(0x17,local_2c);
  if (local_2c[0] != 0) {
    pfVar8 = *(float **)(iVar7 + 0x40c);
    pfVar8[0xd] = 0.0;
    pfVar8[0xf] = FLOAT_803e3bb8;
    for (iVar7 = 0; iVar7 < local_2c[0]; iVar7 = iVar7 + 1) {
      iVar5 = (**(code **)(**(int **)((int)*pfVar4 + 0x68) + 0x30))
                        ((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                         (double)*(float *)(param_1 + 10),*pfVar4,&local_30,&local_34,auStack_38);
      if ((iVar5 != 0) && (local_30 < pfVar8[0xf])) {
        pfVar8[0xd] = *pfVar4;
        pfVar8[0xf] = local_30;
        pfVar8[0x10] = local_34;
      }
      pfVar4 = pfVar4 + 1;
    }
    if (pfVar8[0xd] != 0.0) {
      pfVar8[0xe] = pfVar8[0xd];
      pfVar8[0x12] = pfVar8[0x10];
      (**(code **)(**(int **)((int)pfVar8[0xe] + 0x68) + 0x20))(pfVar8[0xe],pfVar8 + 3);
      (**(code **)(**(int **)((int)pfVar8[0xe] + 0x68) + 0x24))
                ((double)pfVar8[0x12],pfVar8[0xe],pfVar8 + 7,pfVar8 + 8,pfVar8 + 9);
      uVar6 = (**(code **)(**(int **)((int)pfVar8[0xe] + 0x68) + 0x34))();
      *(undefined2 *)(pfVar8 + 0x16) = uVar6;
      pfVar8[0x13] = pfVar8[0x12];
      *(undefined *)((int)pfVar8 + 0x46) = 0;
      pfVar8[1] = pfVar8[8];
      pfVar8[2] = *(float *)(param_1 + 8);
      *pfVar8 = pfVar8[1] - pfVar8[2];
      iVar7 = (int)*param_1 - (uint)*(ushort *)(pfVar8 + 0x16);
      if (0x8000 < iVar7) {
        iVar7 = iVar7 + -0xffff;
      }
      if (iVar7 < -0x8000) {
        iVar7 = iVar7 + 0xffff;
      }
      uVar3 = 0;
      if ((iVar7 < 0x3ffd) && (-0x3ffd < iVar7)) {
        uVar3 = 1;
      }
      *(undefined *)((int)pfVar8 + 0x45) = uVar3;
      uVar2 = countLeadingZeros((int)*(char *)((int)pfVar8 + 0x45));
      *param_1 = *(short *)(pfVar8 + 0x16) + (short)((uVar2 >> 5) << 0xf);
      uVar2 = FUN_80017760(10,0x3c);
      pfVar8[0x15] = -((float)((double)CONCAT44(0x43300000,
                                                *(char *)((int)pfVar8 + 0x45) * 2 - 1U ^ 0x80000000)
                              - DOUBLE_803e3b70) *
                       ((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3b70) /
                       FLOAT_803e3bbc) - pfVar8[0x12]);
      fVar1 = FLOAT_803e3b54;
      if (FLOAT_803e3b54 < pfVar8[0x15]) {
        fVar1 = pfVar8[0x15];
      }
      pfVar8[0x15] = fVar1;
      fVar1 = FLOAT_803e3ba4;
      if (pfVar8[0x15] < FLOAT_803e3ba4) {
        fVar1 = pfVar8[0x15];
      }
      pfVar8[0x15] = fVar1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: cannonclaw_release
 * EN v1.0 Address: 0x801631C0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80162F5C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cannonclaw_release(int param_1)
{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,3);
  (**(code **)(*DAT_803dd738 + 0x40))(param_1,uVar1,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80163220
 * EN v1.0 Address: 0x80163220
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x80162FB8
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163220(int param_1)
{
  char in_r8;
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
    if (FLOAT_803e3b50 < *(float *)(iVar1 + 0x50)) {
      (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x52a,0,100,0);
    }
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_8008111c((double)FLOAT_803e3b54,(double)*(float *)(iVar2 + 1000),param_1,3,(int *)0x0);
    }
    if ((*(ushort *)(iVar2 + 0x400) & 0x100) != 0) {
      FUN_8008111c((double)FLOAT_803e3b54,(double)*(float *)(iVar2 + 1000),param_1,4,(int *)0x0);
      *(ushort *)(iVar2 + 0x400) = *(ushort *)(iVar2 + 0x400) & 0xfeff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80163308
 * EN v1.0 Address: 0x80163308
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801630B4
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163308(int param_1)
{
  (**(code **)(*DAT_803dd70c + 0xc))(param_1,*(undefined4 *)(param_1 + 0xb8),&DAT_803ad270);
  return;
}
