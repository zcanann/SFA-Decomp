// Function: FUN_80247dfc
// Entry: 80247dfc
// Size: 152 bytes

void FUN_80247dfc(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,float *param_7)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  double dVar6;
  
  fVar4 = FLOAT_803e82cc;
  fVar3 = FLOAT_803e82c8;
  fVar1 = FLOAT_803e82c8 / (float)(param_4 - param_3);
  fVar2 = FLOAT_803e82c8 / (float)(param_1 - param_2);
  *param_7 = FLOAT_803e82cc * fVar1;
  fVar5 = FLOAT_803e82d0;
  param_7[1] = FLOAT_803e82d0;
  dVar6 = (double)(fVar3 / (float)(param_6 - param_5));
  param_7[2] = fVar5;
  param_7[3] = fVar1 * -(float)(param_4 + param_3);
  param_7[4] = fVar5;
  param_7[5] = fVar4 * fVar2;
  param_7[6] = fVar5;
  param_7[7] = fVar2 * -(float)(param_1 + param_2);
  param_7[8] = fVar5;
  param_7[9] = fVar5;
  param_7[10] = (float)((double)FLOAT_803e82d4 * dVar6);
  param_7[0xb] = (float)(-param_6 * dVar6);
  param_7[0xc] = fVar5;
  param_7[0xd] = fVar5;
  param_7[0xe] = fVar5;
  param_7[0xf] = fVar3;
  return;
}

