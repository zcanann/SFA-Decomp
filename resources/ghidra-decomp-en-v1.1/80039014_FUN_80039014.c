// Function: FUN_80039014
// Entry: 80039014
// Size: 28 bytes

void FUN_80039014(char param_1,int param_2)

{
  if (param_1 != '\0') {
    return;
  }
  DAT_803dd880 = (byte)(param_2 << 7) | DAT_803dd880 & 0x7f;
  return;
}

