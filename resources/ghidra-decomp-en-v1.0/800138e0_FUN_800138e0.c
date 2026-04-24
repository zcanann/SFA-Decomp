// Function: FUN_800138e0
// Entry: 800138e0
// Size: 120 bytes

void FUN_800138e0(short *param_1,undefined4 param_2)

{
  short sVar1;
  
  sVar1 = param_1[4];
  param_1[4] = sVar1 + -1;
  if ((short)(sVar1 + -1) < 0) {
    param_1[4] = param_1[1] + -1;
  }
  FUN_80003494(param_2,*(int *)(param_1 + 6) + (int)param_1[4] * (int)param_1[2]);
  *param_1 = *param_1 + -1;
  return;
}

