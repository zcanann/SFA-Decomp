// Function: FUN_80231058
// Entry: 80231058
// Size: 28 bytes

void FUN_80231058(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 0x24) = *param_2;
  *(undefined4 *)(param_1 + 0x28) = param_2[1];
  *(undefined4 *)(param_1 + 0x2c) = param_2[2];
  return;
}

