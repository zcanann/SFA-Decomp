// Function: FUN_8024740c
// Entry: 8024740c
// Size: 136 bytes

void FUN_8024740c(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,double param_8,float *param_9)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  
  fVar5 = FLOAT_803e7620;
  fVar3 = FLOAT_803e7618;
  fVar1 = FLOAT_803e7618 / (float)(param_4 - param_3);
  fVar2 = FLOAT_803e7618 / (float)(param_1 - param_2);
  *param_9 = (float)((double)(FLOAT_803e7620 * fVar1) * param_5);
  fVar4 = FLOAT_803e761c;
  param_9[1] = FLOAT_803e761c;
  param_9[2] = fVar4;
  param_9[3] = (float)(param_7 +
                      (double)(float)(param_5 * (double)(fVar1 * -(float)(param_4 + param_3))));
  param_9[4] = fVar4;
  param_9[5] = (float)((double)(fVar5 * fVar2) * param_6);
  param_9[6] = fVar4;
  param_9[7] = (float)(param_8 +
                      (double)(float)(param_6 * (double)(fVar2 * -(float)(param_1 + param_2))));
  param_9[8] = fVar4;
  param_9[9] = fVar4;
  param_9[10] = fVar4;
  param_9[0xb] = fVar3;
  return;
}

