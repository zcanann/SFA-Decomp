// Function: FUN_801736d8
// Entry: 801736d8
// Size: 84 bytes

void FUN_801736d8(int param_1)

{
  if (*(int *)(param_1 + 0xc4) != 0) {
    FUN_80037da8(*(int *)(param_1 + 0xc4),param_1);
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

