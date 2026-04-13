// Function: FUN_80010c84
// Entry: 80010c84
// Size: 128 bytes

double FUN_80010c84(double param_1,float *param_2,float *param_3)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar5 = (double)param_2[2];
  dVar4 = (double)param_2[1];
  dVar6 = -(double)*param_2;
  dVar3 = (double)(param_2[3] +
                  (float)((double)FLOAT_803df2e8 * dVar5 +
                         (double)(float)((double)FLOAT_803df2e4 * dVar4 + dVar6)));
  dVar1 = (double)FLOAT_803df2e0;
  dVar2 = (double)((float)((double)FLOAT_803df2dc * dVar5 +
                          (double)(float)(dVar1 * (double)*param_2 +
                                         (double)(float)((double)FLOAT_803df314 * dVar4))) -
                  param_2[3]);
  dVar5 = (double)(float)(dVar6 + dVar5);
  if (param_3 != (float *)0x0) {
    *param_3 = (float)(param_1 * (double)(float)(dVar1 * dVar2 +
                                                (double)(float)((double)(float)((double)
                                                  FLOAT_803df2e4 * dVar3) * param_1)) + dVar5);
  }
  return (double)(FLOAT_803df2f8 *
                 (float)(param_1 * (double)(float)(param_1 * (double)(float)(dVar3 * param_1 + dVar2
                                                                            ) + dVar5) +
                        (double)(float)(dVar1 * dVar4)));
}

