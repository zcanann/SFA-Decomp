// Function: FUN_800890bc
// Entry: 800890bc
// Size: 36 bytes

undefined FUN_800890bc(int param_1)

{
  if (DAT_803dddac != 0) {
    return *(undefined *)(DAT_803dddac + param_1 * 0xa4 + 0xc0);
  }
  return 0xff;
}

