// Function: FUN_80010c64
// Entry: 80010c64
// Size: 128 bytes

double FUN_80010c64(double param_1,float *param_2,float *param_3)

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
                  (float)((double)FLOAT_803de668 * dVar5 +
                         (double)(float)((double)FLOAT_803de664 * dVar4 + dVar6)));
  dVar1 = (double)FLOAT_803de660;
  dVar2 = (double)((float)((double)FLOAT_803de65c * dVar5 +
                          (double)(float)(dVar1 * (double)*param_2 +
                                         (double)(float)((double)FLOAT_803de694 * dVar4))) -
                  param_2[3]);
  dVar5 = (double)(float)(dVar6 + dVar5);
  if (param_3 != (float *)0x0) {
    *param_3 = (float)(param_1 * (double)(float)(dVar1 * dVar2 +
                                                (double)(float)((double)(float)((double)
                                                  FLOAT_803de664 * dVar3) * param_1)) + dVar5);
  }
  return (double)(FLOAT_803de678 *
                 (float)(param_1 * (double)(float)(param_1 * (double)(float)(dVar3 * param_1 + dVar2
                                                                            ) + dVar5) +
                        (double)(float)(dVar1 * dVar4)));
}

