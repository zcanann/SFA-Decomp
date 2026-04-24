// Function: FUN_80247aa4
// Entry: 80247aa4
// Size: 204 bytes

void FUN_80247aa4(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,float *param_7)

{
  float fVar1;
  double dVar2;
  double dVar3;
  
  dVar2 = FUN_80294f2c((double)(FLOAT_803e82c4 * (float)((double)FLOAT_803e82c0 * param_1)));
  dVar3 = (double)FLOAT_803e82b0;
  *param_7 = (float)(param_3 * (double)(float)((double)(float)(dVar3 / dVar2) / param_2));
  fVar1 = FLOAT_803e82b4;
  param_7[1] = FLOAT_803e82b4;
  param_7[2] = (float)-param_5;
  param_7[3] = fVar1;
  param_7[4] = fVar1;
  param_7[5] = (float)((double)(float)(dVar3 / dVar2) * param_4);
  param_7[6] = (float)-param_6;
  param_7[7] = fVar1;
  param_7[8] = fVar1;
  param_7[9] = fVar1;
  param_7[10] = FLOAT_803e82bc;
  param_7[0xb] = fVar1;
  return;
}

