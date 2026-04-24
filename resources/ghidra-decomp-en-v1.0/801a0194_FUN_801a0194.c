// Function: FUN_801a0194
// Entry: 801a0194
// Size: 80 bytes

void FUN_801a0194(int param_1)

{
  if (**(int **)(param_1 + 0xb8) != 0) {
    FUN_8001cb3c();
  }
  if (*(int *)(param_1 + 0xc4) != 0) {
    FUN_80037cb0(*(int *)(param_1 + 0xc4),param_1);
  }
  return;
}

