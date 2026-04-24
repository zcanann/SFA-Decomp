// Function: FUN_8017322c
// Entry: 8017322c
// Size: 84 bytes

void FUN_8017322c(int param_1)

{
  if (*(int *)(param_1 + 0xc4) != 0) {
    FUN_80037cb0(*(int *)(param_1 + 0xc4),param_1);
  }
  (**(code **)(*DAT_803dca78 + 0x18))(param_1);
  return;
}

