// Function: FUN_80013958
// Entry: 80013958
// Size: 112 bytes

void FUN_80013958(short *param_1)

{
  short sVar1;
  
  FUN_80003494(*(int *)(param_1 + 6) + (int)param_1[4] * (int)param_1[2]);
  sVar1 = param_1[4];
  param_1[4] = sVar1 + 1;
  if ((short)(sVar1 + 1) == param_1[1]) {
    param_1[4] = 0;
  }
  *param_1 = *param_1 + 1;
  return;
}

