// Function: FUN_80088e08
// Entry: 80088e08
// Size: 40 bytes

byte FUN_80088e08(int param_1)

{
  if (DAT_803dd12c != 0) {
    return *(byte *)(DAT_803dd12c + param_1 * 0xa4 + 0xc1) >> 7;
  }
  return 0;
}

