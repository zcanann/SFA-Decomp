// Function: FUN_800137c8
// Entry: 800137c8
// Size: 116 bytes

void FUN_800137c8(short *param_1,uint param_2)

{
  short sVar1;
  
  FUN_80003494(param_2,*(int *)(param_1 + 6) + (int)param_1[5] * (int)param_1[2],(int)param_1[2]);
  sVar1 = param_1[5];
  param_1[5] = sVar1 + 1;
  if ((short)(sVar1 + 1) == param_1[1]) {
    param_1[5] = 0;
  }
  *param_1 = *param_1 + -1;
  return;
}

