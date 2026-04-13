// Function: FUN_80089094
// Entry: 80089094
// Size: 40 bytes

byte FUN_80089094(int param_1)

{
  if (DAT_803dddac != 0) {
    return *(byte *)(DAT_803dddac + param_1 * 0xa4 + 0xc1) >> 7;
  }
  return 0;
}

