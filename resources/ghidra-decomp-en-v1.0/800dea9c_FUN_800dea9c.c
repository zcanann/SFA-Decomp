// Function: FUN_800dea9c
// Entry: 800dea9c
// Size: 956 bytes

/* WARNING: Removing unreachable block (ram,0x800dee3c) */

undefined4 FUN_800dea9c(float *param_1,float param_2)

{
  undefined4 uVar1;
  float fVar2;
  char cVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (param_2 == param_1[0x20]) {
    uVar1 = 0;
  }
  else if ((param_1[0x28] == 0.0) || (param_1[0x27] == 0.0)) {
    uVar1 = 1;
  }
  else {
    dVar6 = (double)*param_1;
    param_1[0x20] = param_2;
    fVar2 = param_1[0x27];
    param_1[0x27] = param_1[0x29];
    param_1[0x29] = fVar2;
    param_1[0x2e] = *(float *)((int)param_1[0x28] + 8);
    param_1[0x2f] = *(float *)((int)param_1[0x29] + 8);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)((int)param_1[0x28]
                                                                                 + 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    param_1[0x30] =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                DOUBLE_803e0628) * dVar5);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)((int)param_1[0x29]
                                                                                 + 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    param_1[0x31] =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                DOUBLE_803e0628) * dVar5);
    param_1[0x36] = *(float *)((int)param_1[0x28] + 0xc);
    param_1[0x37] = *(float *)((int)param_1[0x29] + 0xc);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)((int)param_1[0x28]
                                                                                 + 0x2d) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    param_1[0x38] =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                DOUBLE_803e0628) * dVar5);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)((int)param_1[0x29]
                                                                                 + 0x2d) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    param_1[0x39] =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                DOUBLE_803e0628) * dVar5);
    param_1[0x3e] = *(float *)((int)param_1[0x28] + 0x10);
    param_1[0x3f] = *(float *)((int)param_1[0x29] + 0x10);
    dVar5 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)((int)param_1[0x28]
                                                                                 + 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    param_1[0x40] =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_1[0x28] + 0x2e)) -
                                DOUBLE_803e0628) * dVar5);
    dVar5 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(char *)((int)param_1[0x29]
                                                                                 + 0x2c) << 8 ^
                                                                   0x80000000) - DOUBLE_803e0620)) /
                                         FLOAT_803e0618));
    param_1[0x41] =
         FLOAT_803e0610 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_1[0x29] + 0x2e)) -
                                DOUBLE_803e0628) * dVar5);
    cVar3 = FUN_800dee58(param_1);
    if (cVar3 == '\0') {
      param_1[0x25] = (float)FUN_80010dc0;
      param_1[0x26] = (float)&LAB_80010d54;
      param_1[0x21] = (float)(param_1 + 0x2a);
      param_1[0x22] = (float)(param_1 + 0x32);
      param_1[0x23] = (float)(param_1 + 0x3a);
      param_1[0x24] = 1.121039e-44;
      FUN_80010a6c(param_1);
      *param_1 = (float)dVar6;
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return uVar1;
}

