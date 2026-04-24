// Function: FUN_80155818
// Entry: 80155818
// Size: 328 bytes

/* WARNING: Removing unreachable block (ram,0x80155940) */
/* WARNING: Removing unreachable block (ram,0x80155828) */

void FUN_80155818(double param_1,double param_2,float *param_3,float *param_4)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  float local_24;
  
  dVar2 = (double)(param_4[6] - FLOAT_803e36b8);
  if ((param_2 <= dVar2) && (dVar2 = param_2, param_2 < (double)(FLOAT_803e36bc + param_4[5]))) {
    dVar2 = (double)(FLOAT_803e36bc + param_4[5]);
  }
  dVar4 = (double)param_4[4];
  if (dVar4 <= (double)FLOAT_803e3698) {
    dVar3 = (double)(float)((double)FLOAT_803e36b8 + dVar4);
    fVar1 = FLOAT_803e36c0;
  }
  else {
    dVar3 = (double)FLOAT_803e36b8;
    fVar1 = (float)(dVar4 - dVar3);
  }
  dVar4 = (double)fVar1;
  if ((param_1 <= dVar4) && (dVar4 = param_1, param_1 < dVar3)) {
    dVar4 = dVar3;
  }
  param_3[1] = (float)dVar2;
  local_38 = FLOAT_803e3698;
  local_34 = FLOAT_803e369c;
  local_30 = FLOAT_803e3698;
  FUN_80247fb0(&local_38,param_4,local_2c);
  FUN_80247ef8(local_2c,local_2c);
  *param_3 = (float)(dVar4 * (double)local_2c[0] + (double)param_4[7]);
  param_3[2] = (float)(dVar4 * (double)local_24 + (double)param_4[8]);
  fVar1 = FLOAT_803e36c4;
  *param_3 = FLOAT_803e36c4 * *param_4 + *param_3;
  param_3[1] = fVar1 * param_4[1] + param_3[1];
  param_3[2] = fVar1 * param_4[2] + param_3[2];
  return;
}

