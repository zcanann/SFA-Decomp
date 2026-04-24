// Function: FUN_801c1698
// Entry: 801c1698
// Size: 168 bytes

double FUN_801c1698(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,float *param_7,float *param_8,float *param_9)

{
  double dVar1;
  double dVar2;
  double dVar3;
  
  dVar2 = (double)(float)(param_4 - param_1);
  dVar3 = (double)(float)(param_6 - param_3);
  dVar1 = (double)FLOAT_803e4dfc;
  if ((dVar1 != dVar2) || (dVar1 != dVar3)) {
    dVar1 = (double)((float)(dVar2 * (double)(float)((double)*param_7 - param_1) +
                            (double)(float)(dVar3 * (double)(float)((double)*param_9 - param_3))) /
                    (float)(dVar2 * dVar2 + (double)(float)(dVar3 * dVar3)));
  }
  if ((double)FLOAT_803e4dfc <= dVar1) {
    if (dVar1 < (double)FLOAT_803e4e18) {
      *param_7 = (float)(dVar1 * dVar2 + param_1);
      *param_8 = (float)(dVar1 * (double)(float)(param_5 - param_2) + param_2);
      *param_9 = (float)(dVar1 * dVar3 + param_3);
    }
    else {
      *param_7 = (float)param_4;
      *param_8 = (float)param_5;
      *param_9 = (float)param_6;
    }
  }
  else {
    *param_7 = (float)param_1;
    *param_8 = (float)param_2;
    *param_9 = (float)param_3;
  }
  return dVar1;
}

