// Function: FUN_80295bc8
// Entry: 80295bc8
// Size: 40 bytes

uint FUN_80295bc8(int param_1)

{
  if (param_1 != 0) {
    return (uint)(-(int)*(char *)(param_1 + 0xad) | (int)*(char *)(param_1 + 0xad)) >> 0x1f;
  }
  return 0;
}

