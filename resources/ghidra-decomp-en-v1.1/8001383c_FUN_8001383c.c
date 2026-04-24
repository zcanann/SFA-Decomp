// Function: FUN_8001383c
// Entry: 8001383c
// Size: 112 bytes

void FUN_8001383c(short *param_1,uint param_2)

{
  short sVar1;
  
  FUN_80003494(*(int *)(param_1 + 6) + (int)param_1[4] * (int)param_1[2],param_2,(int)param_1[2]);
  sVar1 = param_1[4];
  param_1[4] = sVar1 + 1;
  if ((short)(sVar1 + 1) == param_1[1]) {
    param_1[4] = 0;
  }
  *param_1 = *param_1 + 1;
  return;
}

