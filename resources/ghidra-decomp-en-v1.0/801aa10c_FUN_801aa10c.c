// Function: FUN_801aa10c
// Entry: 801aa10c
// Size: 76 bytes

void FUN_801aa10c(int param_1)

{
  if ((**(char **)(param_1 + 0xb8) == '\x03') || (**(char **)(param_1 + 0xb8) == '\x04')) {
    FUN_8004c204();
  }
  (**(code **)(*DAT_803dca68 + 0x60))();
  return;
}

