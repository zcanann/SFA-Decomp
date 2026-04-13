// Function: FUN_80010de0
// Entry: 80010de0
// Size: 108 bytes

double FUN_80010de0(double param_1,float *param_2,float *param_3)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar4 = (double)param_2[2];
  dVar3 = (double)*param_2;
  dVar2 = (double)(param_2[3] +
                  (float)(dVar4 + (double)(float)((double)FLOAT_803df2e0 * dVar3 +
                                                 (double)(float)((double)FLOAT_803df318 *
                                                                (double)param_2[1]))));
  dVar1 = (double)((float)((double)FLOAT_803df318 * dVar4 +
                          (double)(float)((double)FLOAT_803df2e8 * dVar3 +
                                         (double)(float)((double)FLOAT_803df2e4 * (double)param_2[1]
                                                        ))) - param_2[3]);
  if (param_3 != (float *)0x0) {
    *param_3 = (float)(param_1 * (double)(float)((double)FLOAT_803df2e0 * dVar1 +
                                                (double)(float)((double)(float)((double)
                                                  FLOAT_803df2e4 * dVar2) * param_1)) + dVar4);
  }
  return (double)(float)(param_1 * (double)(float)(param_1 * (double)(float)(dVar2 * param_1 + dVar1
                                                                            ) + dVar4) + dVar3);
}

