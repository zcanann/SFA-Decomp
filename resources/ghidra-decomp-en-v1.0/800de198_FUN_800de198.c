// Function: FUN_800de198
// Entry: 800de198
// Size: 1876 bytes

undefined4 FUN_800de198(int param_1,undefined4 param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  if (((param_1 != 0) && (*(int *)(param_1 + 0xa0) != 0)) && (*(int *)(param_1 + 0xa4) != 0)) {
    *(int *)(param_1 + 0x9c) = *(int *)(param_1 + 0xa0);
    *(undefined4 *)(param_1 + 0xa0) = *(undefined4 *)(param_1 + 0xa4);
    FUN_80003494(param_1 + 0xa8,param_1 + 0xb8,0x10);
    FUN_80003494(param_1 + 200,param_1 + 0xd8,0x10);
    FUN_80003494(param_1 + 0xe8,param_1 + 0xf8,0x10);
    if (*(int *)(param_1 + 0x80) == 0) {
      uVar1 = FUN_800de040(*(undefined4 *)(param_1 + 0xa0),0xffffffff,param_2);
    }
    else {
      uVar1 = FUN_800ddee8(*(undefined4 *)(param_1 + 0xa0),0xffffffff,param_2);
    }
    if (uVar1 == 0xffffffff) {
      *(undefined4 *)(param_1 + 0xa4) = 0;
    }
    else {
      if ((int)uVar1 < 0) {
        iVar5 = 0;
      }
      else {
        iVar4 = DAT_803dd478 + -1;
        iVar3 = 0;
        while (iVar3 <= iVar4) {
          iVar2 = iVar4 + iVar3 >> 1;
          iVar5 = (&DAT_803a17e8)[iVar2];
          if (*(uint *)(iVar5 + 0x14) < uVar1) {
            iVar3 = iVar2 + 1;
          }
          else {
            if (*(uint *)(iVar5 + 0x14) <= uVar1) goto LAB_800de2c0;
            iVar4 = iVar2 + -1;
          }
        }
        iVar5 = 0;
      }
LAB_800de2c0:
      *(int *)(param_1 + 0xa4) = iVar5;
      if (*(int *)(param_1 + 0xa4) != 0) {
        if (*(int *)(param_1 + 0x80) == 0) {
          *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
          *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0xc0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa4) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0xc4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa4) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
          *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2d) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0xe0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa4) + 0x2d) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0xe4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa4) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          *(undefined4 *)(param_1 + 0xf8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
          *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
          dVar6 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0x100) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          dVar6 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa4) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0x104) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa4) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
        }
        else {
          *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
          *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 8);
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0xc0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0x9c) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0xc4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0x9c) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
          *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 0xc);
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2d) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0xe0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0x9c) + 0x2d) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0xe4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0x9c) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          *(undefined4 *)(param_1 + 0xf8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
          *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 0x10);
          dVar6 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0x100) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0xa0) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
          dVar6 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,
                                                                         (int)*(char *)(*(int *)(
                                                  param_1 + 0x9c) + 0x2c) << 8 ^ 0x80000000) -
                                                  DOUBLE_803e0620)) / FLOAT_803e0618));
          *(float *)(param_1 + 0x104) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(*(int *)(param_1 + 0x9c) +
                                                                       0x2e)) - DOUBLE_803e0628) *
                      dVar6);
        }
        if (*(int *)(param_1 + 0x90) != 0) {
          FUN_80010904(param_1);
        }
        if (*(int *)(param_1 + 0x80) == 0) {
          FUN_80010320((double)FLOAT_803e0634,param_1);
        }
        else {
          FUN_80010320((double)FLOAT_803e0630,param_1);
        }
        return 0;
      }
    }
  }
  return 1;
}

