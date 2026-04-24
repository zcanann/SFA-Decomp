// Function: FUN_801aa6c0
// Entry: 801aa6c0
// Size: 76 bytes

void FUN_801aa6c0(int param_1)

{
  if ((**(char **)(param_1 + 0xb8) == '\x03') || (**(char **)(param_1 + 0xb8) == '\x04')) {
    FUN_8004c380();
  }
  (**(code **)(*DAT_803dd6e8 + 0x60))();
  return;
}

