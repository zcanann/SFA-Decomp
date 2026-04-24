// Function: FUN_80089428
// Entry: 80089428
// Size: 64 bytes

undefined FUN_80089428(int param_1)

{
  if (DAT_803dddac == 0) {
    return 0;
  }
  if (*(char *)(DAT_803dddac + param_1 * 0xa4 + 0xc1) < '\0') {
    return 0;
  }
  return *(undefined *)(DAT_803dddc8 + 0x37);
}

