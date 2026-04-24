// Function: FUN_8025a0a8
// Entry: 8025a0a8
// Size: 212 bytes

void FUN_8025a0a8(double param_1,double param_2,double param_3,int param_4)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  
  dVar1 = -param_1;
  dVar2 = -param_2;
  dVar3 = (double)(float)((double)FLOAT_803e8330 - param_3);
  dVar5 = (double)((float)(dVar3 * dVar3) + (float)(dVar1 * dVar1) + (float)(dVar2 * dVar2));
  if ((double)FLOAT_803e8318 < dVar5) {
    dVar4 = 1.0 / SQRT(dVar5);
    dVar4 = DOUBLE_803e8350 * dVar4 * (DOUBLE_803e8358 - dVar5 * dVar4 * dVar4);
    dVar4 = DOUBLE_803e8350 * dVar4 * (DOUBLE_803e8358 - dVar5 * dVar4 * dVar4);
    dVar5 = (double)(float)(dVar5 * DOUBLE_803e8350 * dVar4 *
                                    (DOUBLE_803e8358 - dVar5 * dVar4 * dVar4));
  }
  dVar5 = (double)(float)((double)FLOAT_803e8330 / dVar5);
  *(float *)(param_4 + 0x34) = (float)(dVar1 * dVar5);
  *(float *)(param_4 + 0x38) = (float)(dVar2 * dVar5);
  *(float *)(param_4 + 0x3c) = (float)(dVar3 * dVar5);
  dVar3 = (double)FLOAT_803e8360;
  *(float *)(param_4 + 0x28) = (float)(dVar3 * dVar1);
  *(float *)(param_4 + 0x2c) = (float)(dVar3 * dVar2);
  *(float *)(param_4 + 0x30) = (float)(dVar3 * -param_3);
  return;
}

