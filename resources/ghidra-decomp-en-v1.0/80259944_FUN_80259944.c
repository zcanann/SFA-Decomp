// Function: FUN_80259944
// Entry: 80259944
// Size: 212 bytes

void FUN_80259944(double param_1,double param_2,double param_3,int param_4)

{
  double dVar1;
  double dVar2;
  double dVar3;
  
  param_1 = -param_1;
  param_2 = -param_2;
  dVar1 = (double)(float)((double)FLOAT_803e7698 - param_3);
  dVar3 = (double)((float)(dVar1 * dVar1) + (float)(param_1 * param_1) + (float)(param_2 * param_2))
  ;
  if ((double)FLOAT_803e7680 < dVar3) {
    dVar2 = 1.0 / SQRT(dVar3);
    dVar2 = DOUBLE_803e76b8 * dVar2 * (DOUBLE_803e76c0 - dVar3 * dVar2 * dVar2);
    dVar2 = DOUBLE_803e76b8 * dVar2 * (DOUBLE_803e76c0 - dVar3 * dVar2 * dVar2);
    dVar3 = (double)(float)(dVar3 * DOUBLE_803e76b8 * dVar2 *
                                    (DOUBLE_803e76c0 - dVar3 * dVar2 * dVar2));
  }
  dVar3 = (double)(float)((double)FLOAT_803e7698 / dVar3);
  *(float *)(param_4 + 0x34) = (float)(param_1 * dVar3);
  *(float *)(param_4 + 0x38) = (float)(param_2 * dVar3);
  *(float *)(param_4 + 0x3c) = (float)(dVar1 * dVar3);
  dVar1 = (double)FLOAT_803e76c8;
  *(float *)(param_4 + 0x28) = (float)(dVar1 * param_1);
  *(float *)(param_4 + 0x2c) = (float)(dVar1 * param_2);
  *(float *)(param_4 + 0x30) = (float)(dVar1 * -param_3);
  return;
}

