// Function: FUN_8001388c
// Entry: 8001388c
// Size: 40 bytes

void FUN_8001388c(undefined2 *param_1,undefined4 param_2,undefined2 param_3,undefined2 param_4)

{
  *(undefined4 *)(param_1 + 6) = param_2;
  *param_1 = 0;
  param_1[1] = param_3;
  param_1[2] = param_4;
  param_1[4] = 0;
  param_1[5] = 0;
  return;
}

