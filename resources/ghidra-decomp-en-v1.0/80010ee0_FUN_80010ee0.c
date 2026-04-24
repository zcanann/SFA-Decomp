// Function: FUN_80010ee0
// Entry: 80010ee0
// Size: 140 bytes

double FUN_80010ee0(double param_1,float *param_2,float *param_3)

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
  dVar2 = (double)FLOAT_803de664;
  dVar6 = (double)param_2[1];
  dVar7 = (double)*param_2;
  dVar3 = (double)(param_2[3] +
                  (float)((double)FLOAT_803de668 * dVar8 + (double)(float)(dVar2 * dVar6 + -dVar7)))
  ;
  dVar4 = (double)(float)((double)(float)(dVar2 * dVar8) +
                         (double)(float)(dVar2 * dVar7 +
                                        (double)(float)((double)FLOAT_803de66c * dVar6)));
  dVar5 = (double)(float)((double)FLOAT_803de668 * dVar7 + (double)(float)(dVar2 * dVar8));
  dVar1 = (double)FLOAT_803de65c;
  if (param_3 != (float *)0x0) {
    *param_3 = FLOAT_803de670 *
               (float)(param_1 * (double)(float)((double)FLOAT_803de660 * dVar4 +
                                                (double)(float)((double)(float)(dVar2 * dVar3) *
                                                               param_1)) + dVar5);
  }
  return (double)(FLOAT_803de670 *
                 (float)(param_1 * (double)(float)(param_1 * (double)(float)(dVar3 * param_1 + dVar4
                                                                            ) + dVar5) +
                        (double)(float)(dVar8 + (double)(float)(dVar1 * dVar6 + dVar7))));
}

