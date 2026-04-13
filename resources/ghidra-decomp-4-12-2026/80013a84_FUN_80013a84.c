// Function: FUN_80013a84
// Entry: 80013a84
// Size: 56 bytes

void FUN_80013a84(undefined4 *param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  param_1[1] = (int)param_3 >> 3;
  if ((param_3 & 7) != 0) {
    param_1[1] = param_1[1] + 1;
  }
  param_1[2] = param_3;
  param_1[3] = param_4;
  *param_1 = param_2;
  param_1[4] = 0;
  return;
}

