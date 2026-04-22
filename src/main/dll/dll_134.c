#include "ghidra_import.h"
#include "main/dll/dll_134.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_8016980c();

extern undefined4 DAT_80321050;
extern undefined4 DAT_80321054;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern f32 FLOAT_803e3cf8;
extern f32 FLOAT_803e3d10;
extern f32 FLOAT_803e3d14;
extern f32 FLOAT_803e3d1c;
extern f32 FLOAT_803e3d20;
extern f32 FLOAT_803e3d24;
extern f32 FLOAT_803e3d28;

/*
 * --INFO--
 *
 * Function: FUN_80167d90
 * EN v1.0 Address: 0x80167D90
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80167d90(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80167dd8
 * EN v1.0 Address: 0x80167DD8
 * EN v1.0 Size: 92b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80167dd8(int param_1,int param_2)
{
  int iVar1;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    iVar1 = *(int *)(param_1 + 0xb8);
    *(undefined *)(iVar1 + 0x405) = 0;
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f2),1);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80167e34
 * EN v1.0 Address: 0x80167E34
 * EN v1.0 Size: 348b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80167e34(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)
{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27b) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      if (*(int *)(param_9 + 0x4c) == 0) {
        FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        return 0;
      }
      return 4;
    }
  }
  else {
    *(undefined *)(*(int *)(iVar1 + 0x40c) + 0x4b) = 0;
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,7);
    FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    *(ushort *)(iVar1 + 0x400) = *(ushort *)(iVar1 + 0x400) | 0x20;
    *(float *)(iVar1 + 1000) = FLOAT_803e3d10;
    *(float *)(iVar1 + 0x3ec) = FLOAT_803e3d14;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80167f90
 * EN v1.0 Address: 0x80167F90
 * EN v1.0 Size: 124b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80167f90(undefined4 param_1,int param_2)
{
  float fVar1;
  
  fVar1 = FLOAT_803e3cf8;
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(char *)(param_2 + 0x27b) == '\0') {
      if (*(char *)(param_2 + 0x346) != '\0') {
        return 6;
      }
    }
    else {
      *(float *)(param_2 + 0x284) = FLOAT_803e3cf8;
      *(float *)(param_2 + 0x280) = fVar1;
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8016800c
 * EN v1.0 Address: 0x8016800C
 * EN v1.0 Size: 432b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8016800c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3d1c;
  fVar1 = FLOAT_803e3cf8;
  dVar4 = (double)FLOAT_803e3cf8;
  *(float *)(param_10 + 0x280) = FLOAT_803e3cf8;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,5,0,param_12,
                 param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x1000) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xffffefff;
    FUN_8016980c(param_9,2);
  }
  iVar3 = *(int *)(iVar2 + 0x40c);
  if ((*(byte *)(iVar3 + 0x4b) & 1) == 0) {
    FUN_8000bb38(param_9,0x274);
    FUN_8000bb38(param_9,0x277);
    FUN_8000bb38(param_9,0x232);
    *(byte *)(iVar3 + 0x4b) = *(byte *)(iVar3 + 0x4b) | 1;
    if (*(short *)(iVar2 + 0x3f0) == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = (**(code **)(*DAT_803dd738 + 0x4c))(param_9,6,0xffffffff,0);
    }
    if (iVar2 != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x2c))
                ((double)FLOAT_803e3cf8,(double)FLOAT_803e3d10,(double)FLOAT_803e3cf8);
    }
  }
  if (((*(byte *)(iVar3 + 0x4b) & 2) == 0) && (FLOAT_803e3d20 < *(float *)(param_9 + 0x98))) {
    FUN_8000bb38(param_9,0x233);
    *(byte *)(iVar3 + 0x4b) = *(byte *)(iVar3 + 0x4b) | 2;
  }
  *(char *)(param_9 + 0x36) =
       (char)(int)(FLOAT_803e3d24 * (FLOAT_803e3d10 - *(float *)(param_9 + 0x98)));
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801681bc
 * EN v1.0 Address: 0x801681BC
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801681bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,8,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    FUN_8000bb38((uint)param_9,0x277);
  }
  *param_9 = *param_9 + 0x222;
  *(undefined *)(param_10 + 0x34d) = 1;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3d28;
  *(float *)(param_10 + 0x280) = FLOAT_803e3cf8;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80168250
 * EN v1.0 Address: 0x80168250
 * EN v1.0 Size: 152b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80168250(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)DAT_80321050,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(iVar2 + 0x4a) = 4;
  }
  *(undefined4 *)(param_10 + 0x2a0) =
       *(undefined4 *)(&DAT_80321054 + (uint)*(byte *)(iVar2 + 0x4a) * 4);
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801682e8
 * EN v1.0 Address: 0x801682E8
 * EN v1.0 Size: 136b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801682e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,3,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    FUN_8000bb38(param_9,0x277);
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3d28;
  *(float *)(param_10 + 0x280) = FLOAT_803e3cf8;
  return 0;
}
