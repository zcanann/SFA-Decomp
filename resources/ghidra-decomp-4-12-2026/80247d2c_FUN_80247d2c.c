// Function: FUN_80247d2c
// Entry: 80247d2c
// Size: 208 bytes

void FUN_80247d2c(double param_1,double param_2,double param_3,double param_4,float *param_5)

{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  
  dVar3 = FUN_80294f2c((double)(FLOAT_803e82dc * (float)((double)FLOAT_803e82d8 * param_1)));
  dVar4 = (double)FLOAT_803e82c8;
  fVar1 = (float)(dVar4 / dVar3);
  *param_5 = (float)((double)fVar1 / param_2);
  fVar2 = FLOAT_803e82d0;
  dVar3 = (double)(float)(dVar4 / (double)(float)(param_4 - param_3));
  param_5[1] = FLOAT_803e82d0;
  param_5[2] = fVar2;
  param_5[3] = fVar2;
  param_5[4] = fVar2;
  param_5[5] = fVar1;
  param_5[6] = fVar2;
  param_5[7] = fVar2;
  param_5[8] = fVar2;
  param_5[9] = fVar2;
  param_5[10] = (float)(-param_3 * dVar3);
  param_5[0xb] = (float)(dVar3 * -(double)(float)(param_4 * param_3));
  param_5[0xc] = fVar2;
  param_5[0xd] = fVar2;
  param_5[0xe] = FLOAT_803e82d4;
  param_5[0xf] = fVar2;
  return;
}

