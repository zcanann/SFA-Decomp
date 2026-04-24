// Function: FUN_800da980
// Entry: 800da980
// Size: 1628 bytes

bool FUN_800da980(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  double dVar2;
  
  if (*(int *)(param_1 + 0x80) == 0) {
    *(undefined4 *)(param_1 + 0xa0) = param_2;
    *(undefined4 *)(param_1 + 0xa4) = param_3;
    *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
    *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa0) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xc0) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xc4) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
    *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa0) +
                                                                                 0x2d) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xe0) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2d) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xe4) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    *(undefined4 *)(param_1 + 0xf8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
    *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
    dVar2 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa0) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0x100) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    dVar2 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0x104) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
  }
  else {
    *(undefined4 *)(param_1 + 0xa0) = param_2;
    *(undefined4 *)(param_1 + 0xa4) = param_3;
    *(undefined4 *)(param_1 + 0xa8) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
    *(undefined4 *)(param_1 + 0xac) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xb0) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa0) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xb4) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    *(undefined4 *)(param_1 + 200) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
    *(undefined4 *)(param_1 + 0xcc) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2d) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xd0) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa0) +
                                                                                 0x2d) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xd4) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    *(undefined4 *)(param_1 + 0xe8) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
    *(undefined4 *)(param_1 + 0xec) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
    dVar2 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa4) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xf0) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
    dVar2 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)(*(int *)(param_1 +
                                                                                          0xa0) +
                                                                                 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e05e0)) /
                                         FLOAT_803e05d8));
    *(float *)(param_1 + 0xf4) =
         FLOAT_803e05d0 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e))
                                - DOUBLE_803e05e8) * dVar2);
  }
  iVar1 = FUN_800da23c(param_1,param_4);
  if (iVar1 == 0) {
    *(code **)(param_1 + 0x94) = FUN_80010dc0;
    *(undefined **)(param_1 + 0x98) = &LAB_80010d54;
    *(int *)(param_1 + 0x84) = param_1 + 0xa8;
    *(int *)(param_1 + 0x88) = param_1 + 200;
    *(int *)(param_1 + 0x8c) = param_1 + 0xe8;
    *(undefined4 *)(param_1 + 0x90) = 8;
    FUN_80010a6c(param_1);
  }
  return iVar1 != 0;
}

