// Function: FUN_80032090
// Entry: 80032090
// Size: 276 bytes

uint FUN_80032090(double param_1,double param_2,double param_3,double param_4,float *param_5,
                 float *param_6,float *param_7,float *param_8,float *param_9,float *param_10,
                 float *param_11)

{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  
  dVar4 = (double)(*param_5 - *param_6);
  dVar5 = (double)(param_5[2] - param_6[2]);
  *param_9 = (float)(dVar4 * (double)*param_7 + (double)(float)(dVar5 * (double)param_7[2]));
  dVar3 = (double)*param_9;
  if (param_4 < dVar3) {
    *param_10 = (*param_8 - *param_5) * (*param_8 - *param_5) +
                (param_8[2] - param_5[2]) * (param_8[2] - param_5[2]);
    fVar1 = (float)(param_1 + param_3);
    *param_11 = fVar1;
    return ((uint)(byte)((*param_10 <= fVar1 * fVar1) << 1) << 0x1c) >> 0x1d;
  }
  if (dVar3 < (double)FLOAT_803de910) {
    *param_10 = (float)(dVar4 * dVar4 + (double)(float)(dVar5 * dVar5));
    fVar1 = (float)(param_1 + param_2);
    *param_11 = fVar1;
    return ((uint)(byte)((*param_10 <= fVar1 * fVar1) << 1) << 0x1c) >> 0x1d;
  }
  fVar1 = (float)((double)*param_7 * -dVar3 + dVar4);
  fVar2 = (float)((double)param_7[2] * -dVar3 + dVar5);
  *param_10 = fVar1 * fVar1 + fVar2 * fVar2;
  fVar1 = (float)((double)*param_9 / param_4) * (float)(param_3 - param_2) +
          (float)(param_1 + param_2);
  *param_11 = fVar1;
  return ((uint)(byte)((*param_10 <= fVar1 * fVar1) << 1) << 0x1c) >> 0x1d;
}

