// Function: FUN_80286978
// Entry: 80286978
// Size: 24 bytes

void FUN_80286978(undefined *param_1,undefined param_2)

{
  *param_1 = param_2;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0xffffffff;
  return;
}

