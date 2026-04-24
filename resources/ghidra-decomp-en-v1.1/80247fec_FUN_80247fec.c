// Function: FUN_80247fec
// Entry: 80247fec
// Size: 212 bytes

void FUN_80247fec(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  double dVar2;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  
  local_18 = -*param_1;
  local_14 = -param_1[1];
  local_10 = -param_1[2];
  FUN_80247ef8(&local_18,&local_18);
  FUN_80247ef8(param_2,&local_24);
  dVar2 = FUN_80247f90(&local_18,&local_24);
  fVar1 = FLOAT_803e82e8;
  *param_3 = (float)((double)(FLOAT_803e82e8 * local_24) * dVar2) - local_18;
  param_3[1] = (float)((double)(fVar1 * local_20) * dVar2) - local_14;
  param_3[2] = (float)((double)(fVar1 * local_1c) * dVar2) - local_10;
  FUN_80247ef8(param_3,param_3);
  return;
}

