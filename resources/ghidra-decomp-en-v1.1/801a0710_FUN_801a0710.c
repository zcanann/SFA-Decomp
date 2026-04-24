// Function: FUN_801a0710
// Entry: 801a0710
// Size: 80 bytes

void FUN_801a0710(int param_1)

{
  if (**(uint **)(param_1 + 0xb8) != 0) {
    FUN_8001cc00(*(uint **)(param_1 + 0xb8));
  }
  if (*(int *)(param_1 + 0xc4) != 0) {
    FUN_80037da8(*(int *)(param_1 + 0xc4),param_1);
  }
  return;
}

