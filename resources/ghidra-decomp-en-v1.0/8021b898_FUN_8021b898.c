// Function: FUN_8021b898
// Entry: 8021b898
// Size: 1796 bytes

undefined4 FUN_8021b898(int param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  double dVar3;
  
  if (((param_1 != 0) && (*(int *)(param_1 + 0xa0) != 0)) && (*(int *)(param_1 + 0xa4) != 0)) {
    *(int *)(param_1 + 0x9c) = *(int *)(param_1 + 0xa0);
    *(undefined4 *)(param_1 + 0xa0) = *(undefined4 *)(param_1 + 0xa4);
    FUN_80003494(param_1 + 0xa8,param_1 + 0xb8,0x10);
    FUN_80003494(param_1 + 200,param_1 + 0xd8,0x10);
    FUN_80003494(param_1 + 0xe8,param_1 + 0xf8,0x10);
    if (*(int *)(param_1 + 0x80) == 0) {
      iVar1 = FUN_8021b738(*(undefined4 *)(param_1 + 0xa0),0xffffffff,param_2);
    }
    else {
      iVar1 = FUN_8021b5d8(*(undefined4 *)(param_1 + 0xa0),0xffffffff,param_2);
    }
    if (iVar1 == -1) {
      *(undefined4 *)(param_1 + 0xa4) = 0;
    }
    else {
      uVar2 = (**(code **)(*DAT_803dca9c + 0x1c))();
      *(undefined4 *)(param_1 + 0xa4) = uVar2;
      if (*(int *)(param_1 + 0xa4) != 0) {
        if (*(int *)(param_1 + 0x80) == 0) {
          *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
          *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
          dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0xc0) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa4) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0xc4) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa4) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
          *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
          dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2d) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0xe0) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa4) + 0x2d) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0xe4) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa4) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          *(undefined4 *)(param_1 + 0xf8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
          *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
          dVar3 = (double)FUN_80294204((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0x100) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          dVar3 = (double)FUN_80294204((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa4) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0x104) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa4) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
        }
        else {
          *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
          *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 8);
          dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0xc0) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0x9c) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0xc4) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0x9c) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
          *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 0xc);
          dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2d) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0xe0) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0x9c) + 0x2d) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0xe4) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0x9c) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          *(undefined4 *)(param_1 + 0xf8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
          *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 0x10);
          dVar3 = (double)FUN_80294204((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0x100) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
          dVar3 = (double)FUN_80294204((double)((FLOAT_803e6a54 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0x9c) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e6a60)) / FLOAT_803e6a58));
          *(float *)(param_1 + 0x104) =
               FLOAT_803e6a38 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0x9c) +
                                                                       0x2e)) - DOUBLE_803e6a68) *
                      dVar3);
        }
        if (*(int *)(param_1 + 0x90) != 0) {
          FUN_80010904(param_1);
        }
        if (*(int *)(param_1 + 0x80) == 0) {
          FUN_80010320((double)FLOAT_803e6a48,param_1);
        }
        else {
          FUN_80010320((double)FLOAT_803e6a70,param_1);
        }
        return 0;
      }
    }
  }
  return 1;
}

