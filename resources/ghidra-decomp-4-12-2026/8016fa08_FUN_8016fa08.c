// Function: FUN_8016fa08
// Entry: 8016fa08
// Size: 96 bytes

void FUN_8016fa08(int param_1)

{
  if (**(uint **)(param_1 + 0xb8) != 0) {
    FUN_8001f448(**(uint **)(param_1 + 0xb8));
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  FUN_8003709c(param_1,2);
  return;
}

