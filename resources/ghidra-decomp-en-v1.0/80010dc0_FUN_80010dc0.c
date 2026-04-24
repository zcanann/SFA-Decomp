// Function: FUN_80010dc0
// Entry: 80010dc0
// Size: 108 bytes

double FUN_80010dc0(double param_1,float *param_2,float *param_3)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar4 = (double)param_2[2];
  dVar3 = (double)*param_2;
  dVar2 = (double)(param_2[3] +
                  (float)(dVar4 + (double)(float)((double)FLOAT_803de660 * dVar3 +
                                                 (double)(float)((double)FLOAT_803de698 *
                                                                (double)param_2[1]))));
  dVar1 = (double)((float)((double)FLOAT_803de698 * dVar4 +
                          (double)(float)((double)FLOAT_803de668 * dVar3 +
                                         (double)(float)((double)FLOAT_803de664 * (double)param_2[1]
                                                        ))) - param_2[3]);
  if (param_3 != (float *)0x0) {
    *param_3 = (float)(param_1 * (double)(float)((double)FLOAT_803de660 * dVar1 +
                                                (double)(float)((double)(float)((double)
                                                  FLOAT_803de664 * dVar2) * param_1)) + dVar4);
  }
  return (double)(float)(param_1 * (double)(float)(param_1 * (double)(float)(dVar2 * param_1 + dVar1
                                                                            ) + dVar4) + dVar3);
}

