// Function: FUN_80038f1c
// Entry: 80038f1c
// Size: 28 bytes

void FUN_80038f1c(char param_1,int param_2)

{
  if (param_1 != '\0') {
    return;
  }
  DAT_803dcc00 = (byte)(param_2 << 7) | DAT_803dcc00 & 0x7f;
  return;
}

