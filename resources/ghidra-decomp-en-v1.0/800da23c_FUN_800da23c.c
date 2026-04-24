// Function: FUN_800da23c
// Entry: 800da23c
// Size: 1772 bytes

undefined4 FUN_800da23c(float *param_1,float param_2)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  
  fVar1 = param_1[0x28];
  if (((fVar1 == 0.0) || (param_1[0x29] == 0.0)) || (param_2 == 0.0)) {
    uVar2 = 1;
  }
  else {
    if (param_1[0x20] == 0.0) {
      param_1[0x27] = fVar1;
      param_1[0x28] = param_1[0x29];
      param_1[0x29] = param_2;
      FUN_80003494(param_1 + 0x2a,param_1 + 0x2e,0x10);
      FUN_80003494(param_1 + 0x32,param_1 + 0x36,0x10);
      FUN_80003494(param_1 + 0x3a,param_1 + 0x3e,0x10);
      param_1[0x2e] = *(float *)((int)param_1[0x28] + 8);
      param_1[0x2f] = *(float *)((int)param_1[0x29] + 8);
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x28] + 0x2c) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x30] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x29] + 0x2c) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x31] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      param_1[0x36] = *(float *)((int)param_1[0x28] + 0xc);
      param_1[0x37] = *(float *)((int)param_1[0x29] + 0xc);
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x28] + 0x2d) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x38] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x29] + 0x2d) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x39] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      param_1[0x3e] = *(float *)((int)param_1[0x28] + 0x10);
      param_1[0x3f] = *(float *)((int)param_1[0x29] + 0x10);
      dVar3 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x28] + 0x2c) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x40] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      dVar3 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x29] + 0x2c) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x41] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      if ((param_1[0x24] != 0.0) && (FUN_80010904(param_1), FLOAT_803e05c8 <= *param_1)) {
        *param_1 = FLOAT_803e05cc;
      }
    }
    else {
      param_1[0x27] = fVar1;
      param_1[0x28] = param_1[0x29];
      param_1[0x29] = param_2;
      FUN_80003494(param_1 + 0x2e,param_1 + 0x2a,0x10);
      FUN_80003494(param_1 + 0x36,param_1 + 0x32,0x10);
      FUN_80003494(param_1 + 0x3e,param_1 + 0x3a,0x10);
      param_1[0x2a] = *(float *)((int)param_1[0x29] + 8);
      param_1[0x2b] = *(float *)((int)param_1[0x28] + 8);
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x29] + 0x2c) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x2c] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x28] + 0x2c) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x2d] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      param_1[0x32] = *(float *)((int)param_1[0x29] + 0xc);
      param_1[0x33] = *(float *)((int)param_1[0x28] + 0xc);
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x29] + 0x2d) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x34] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x28] + 0x2d) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x35] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      param_1[0x3a] = *(float *)((int)param_1[0x29] + 0x10);
      param_1[0x3b] = *(float *)((int)param_1[0x28] + 0x10);
      dVar3 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x29] + 0x2c) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x3c] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      dVar3 = (double)FUN_80294204((double)((FLOAT_803e05d4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(char *)((int)param_1[
                                                  0x28] + 0x2c) << 8 ^ 0x80000000) - DOUBLE_803e05e0
                                                  )) / FLOAT_803e05d8));
      param_1[0x3d] =
           FLOAT_803e05d0 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                  DOUBLE_803e05e8) * dVar3);
      if ((param_1[0x24] != 0.0) && (FUN_80010904(param_1), *param_1 <= FLOAT_803e05f0)) {
        *param_1 = FLOAT_803e05f4;
      }
    }
    uVar2 = 0;
  }
  return uVar2;
}

