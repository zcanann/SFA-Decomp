// Function: FUN_801ee248
// Entry: 801ee248
// Size: 364 bytes

/* WARNING: Removing unreachable block (ram,0x801ee398) */

void FUN_801ee248(undefined4 param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  (**(code **)(*DAT_803dca64 + 0x20))((int)*(short *)(param_2 + 0x6a));
  dVar4 = (double)FUN_80294204((double)((FLOAT_803e5c84 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_2 + 0x6a) ^
                                                                 0x80000000) - DOUBLE_803e5ca0)) /
                                       FLOAT_803e5c88));
  dVar5 = (double)FUN_80293e80((double)((FLOAT_803e5c84 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_2 + 0x6a) ^
                                                                 0x80000000) - DOUBLE_803e5ca0)) /
                                       FLOAT_803e5c88));
  fVar1 = FLOAT_803e5c70;
  if (*(int *)(param_2 + 0x10) != 0) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2e) ^ 0x80000000) -
                   DOUBLE_803e5ca0) / FLOAT_803e5c8c;
  }
  *(float *)(param_2 + 0x60) =
       FLOAT_803db414 * (fVar1 - *(float *)(param_2 + 0x60)) * FLOAT_803e5c90 +
       *(float *)(param_2 + 0x60);
  fVar1 = FLOAT_803e5c94;
  dVar6 = (double)FLOAT_803e5c94;
  dVar3 = -(double)*(float *)(param_2 + 0x60);
  *(float *)(param_2 + 0x78) = *(float *)(param_2 + 0x60);
  *(float *)(param_2 + 0x7c) = fVar1;
  (**(code **)(*DAT_803dca64 + 0x28))
            ((double)(((float)(dVar5 * dVar3 + (double)(float)(dVar6 * -dVar4)) * FLOAT_803db414) /
                     FLOAT_803e5c98),
             (double)(((float)(dVar4 * dVar3 + (double)(float)(dVar6 * dVar5)) * FLOAT_803db414) /
                     FLOAT_803e5c98));
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

