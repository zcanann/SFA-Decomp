// Function: FUN_80035960
// Entry: 80035960
// Size: 20 bytes

void FUN_80035960(int param_1,undefined param_2)

{
  if (*(int *)(param_1 + 0x54) == 0) {
    return;
  }
  *(undefined *)(*(int *)(param_1 + 0x54) + 0xb5) = param_2;
  return;
}

