// Function: FUN_80016c80
// Entry: 80016c80
// Size: 84 bytes

void FUN_80016c80(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  if (param_1[5] != 0) {
    FUN_800238c4(param_1[5]);
    param_1[5] = 0;
  }
  return;
}

