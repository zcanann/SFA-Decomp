// Function: FUN_8016800c
// Entry: 8016800c
// Size: 432 bytes

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

