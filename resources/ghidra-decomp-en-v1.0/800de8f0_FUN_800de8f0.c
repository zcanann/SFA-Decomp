// Function: FUN_800de8f0
// Entry: 800de8f0
// Size: 428 bytes

void FUN_800de8f0(int param_1,int param_2)

{
  double dVar1;
  
  if ((param_2 != 0) && (param_2 != *(int *)(param_1 + 0xa4))) {
    *(int *)(param_1 + 0xa4) = param_2;
    *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
    dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    *(float *)(param_1 + 0xc4) =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e0628) * dVar1);
    *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
    dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2d) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    *(float *)(param_1 + 0xe4) =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e0628) * dVar1);
    *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
    dVar1 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    *(float *)(param_1 + 0x104) =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e0628) * dVar1);
  }
  return;
}

