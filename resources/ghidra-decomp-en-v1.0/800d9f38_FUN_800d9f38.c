// Function: FUN_800d9f38
// Entry: 800d9f38
// Size: 772 bytes

undefined4 FUN_800d9f38(int param_1,int param_2)

{
  undefined4 uVar1;
  double dVar2;
  
  if (((*(int *)(param_1 + 0xa0) == 0) || (*(int *)(param_1 + 0xa4) == 0)) || (param_2 == 0)) {
    uVar1 = 1;
  }
  else {
    *(int *)(param_1 + 0xa4) = param_2;
    if (*(int *)(param_1 + 0x80) == 0) {
      *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(param_2 + 8);
      dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)(param_2 + 0x2c)
                                                                     << 8 ^ 0x80000000) -
                                                   DOUBLE_803e05e0)) / FLOAT_803e05d8));
      *(float *)(param_1 + 0xc4) =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar2);
      *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(param_2 + 0xc);
      dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)(param_2 + 0x2d)
                                                                     << 8 ^ 0x80000000) -
                                                   DOUBLE_803e05e0)) / FLOAT_803e05d8));
      *(float *)(param_1 + 0xe4) =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar2);
      *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(param_2 + 0x10);
      dVar2 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)(param_2 + 0x2c)
                                                                     << 8 ^ 0x80000000) -
                                                   DOUBLE_803e05e0)) / FLOAT_803e05d8));
      *(float *)(param_1 + 0x104) =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar2);
    }
    else {
      *(undefined4 *)(param_1 + 0xa8) = *(undefined4 *)(param_2 + 8);
      dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)(param_2 + 0x2c)
                                                                     << 8 ^ 0x80000000) -
                                                   DOUBLE_803e05e0)) / FLOAT_803e05d8));
      *(float *)(param_1 + 0xb0) =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar2);
      *(undefined4 *)(param_1 + 200) = *(undefined4 *)(param_2 + 0xc);
      dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)(param_2 + 0x2d)
                                                                     << 8 ^ 0x80000000) -
                                                   DOUBLE_803e05e0)) / FLOAT_803e05d8));
      *(float *)(param_1 + 0xd0) =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar2);
      *(undefined4 *)(param_1 + 0xe8) = *(undefined4 *)(param_2 + 0x10);
      dVar2 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)(param_2 + 0x2c)
                                                                     << 8 ^ 0x80000000) -
                                                   DOUBLE_803e05e0)) / FLOAT_803e05d8));
      *(float *)(param_1 + 0xf0) =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar2);
    }
    uVar1 = 0;
  }
  return uVar1;
}

