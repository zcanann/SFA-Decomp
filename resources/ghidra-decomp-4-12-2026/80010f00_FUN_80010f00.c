// Function: FUN_80010f00
// Entry: 80010f00
// Size: 140 bytes

double FUN_80010f00(double param_1,float *param_2,float *param_3)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  dVar8 = (double)param_2[2];
  dVar2 = (double)FLOAT_803df2e4;
  dVar6 = (double)param_2[1];
  dVar7 = (double)*param_2;
  dVar3 = (double)(param_2[3] +
                  (float)((double)FLOAT_803df2e8 * dVar8 + (double)(float)(dVar2 * dVar6 + -dVar7)))
  ;
  dVar4 = (double)(float)((double)(float)(dVar2 * dVar8) +
                         (double)(float)(dVar2 * dVar7 +
                                        (double)(float)((double)FLOAT_803df2ec * dVar6)));
  dVar5 = (double)(float)((double)FLOAT_803df2e8 * dVar7 + (double)(float)(dVar2 * dVar8));
  dVar1 = (double)FLOAT_803df2dc;
  if (param_3 != (float *)0x0) {
    *param_3 = FLOAT_803df2f0 *
               (float)(param_1 * (double)(float)((double)FLOAT_803df2e0 * dVar4 +
                                                (double)(float)((double)(float)(dVar2 * dVar3) *
                                                               param_1)) + dVar5);
  }
  return (double)(FLOAT_803df2f0 *
                 (float)(param_1 * (double)(float)(param_1 * (double)(float)(dVar3 * param_1 + dVar4
                                                                            ) + dVar5) +
                        (double)(float)(dVar8 + (double)(float)(dVar1 * dVar6 + dVar7))));
}

