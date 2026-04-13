// Function: FUN_80296328
// Entry: 80296328
// Size: 40 bytes

uint FUN_80296328(int param_1)

{
  if (param_1 != 0) {
    return (uint)(-(int)*(char *)(param_1 + 0xad) | (int)*(char *)(param_1 + 0xad)) >> 0x1f;
  }
  return 0;
}

