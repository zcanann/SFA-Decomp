// Function: FUN_800e4e68
// Entry: 800e4e68
// Size: 324 bytes

/* WARNING: Removing unreachable block (ram,0x800e4f9c) */
/* WARNING: Removing unreachable block (ram,0x800e4e70) */

double FUN_800e4e68(double param_1,double param_2,double param_3,float *param_4)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  
  dVar5 = (double)param_4[3];
  dVar4 = (double)*param_4;
  dVar8 = (double)(float)(dVar5 - dVar4);
  dVar6 = (double)param_4[4];
  dVar3 = (double)param_4[1];
  dVar9 = (double)(float)(dVar6 - dVar3);
  dVar7 = (double)param_4[5];
  dVar2 = (double)param_4[2];
  dVar10 = (double)(float)(dVar7 - dVar2);
  dVar1 = (double)FLOAT_803e12b8;
  if (((dVar1 != dVar8) || (dVar1 != dVar9)) || (dVar1 != dVar10)) {
    dVar1 = (double)((float)(dVar10 * (double)(float)(param_3 - dVar2) +
                            (double)(float)(dVar8 * (double)(float)(param_1 - dVar4) +
                                           (double)(float)(dVar9 * (double)(float)(param_2 - dVar3))
                                           )) /
                    (float)(dVar10 * dVar10 +
                           (double)(float)(dVar8 * dVar8 + (double)(float)(dVar9 * dVar9))));
  }
  if ((double)FLOAT_803e12b8 <= dVar1) {
    if (dVar1 <= (double)FLOAT_803e12b4) {
      dVar5 = (double)(float)(dVar1 * dVar8 + dVar4);
      dVar6 = (double)(float)(dVar1 * dVar9 + dVar3);
      dVar7 = (double)(float)(dVar1 * dVar10 + dVar2);
      dVar1 = (double)((float)(dVar7 - param_3) * (float)(dVar7 - param_3) +
                      (float)(dVar5 - param_1) * (float)(dVar5 - param_1) +
                      (float)(dVar6 - param_2) * (float)(dVar6 - param_2));
    }
    else {
      dVar1 = -(double)((float)(dVar7 - param_3) * (float)(dVar7 - param_3) +
                       (float)(dVar5 - param_1) * (float)(dVar5 - param_1) +
                       (float)(dVar6 - param_2) * (float)(dVar6 - param_2));
    }
  }
  else {
    dVar1 = -(double)((float)(dVar2 - param_3) * (float)(dVar2 - param_3) +
                     (float)(dVar4 - param_1) * (float)(dVar4 - param_1) +
                     (float)(dVar3 - param_2) * (float)(dVar3 - param_2));
    dVar5 = dVar4;
    dVar6 = dVar3;
    dVar7 = dVar2;
  }
  param_4[6] = (float)dVar5;
  param_4[7] = (float)dVar6;
  param_4[8] = (float)dVar7;
  return dVar1;
}

