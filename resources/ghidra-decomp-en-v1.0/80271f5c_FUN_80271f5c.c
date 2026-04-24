// Function: FUN_80271f5c
// Entry: 80271f5c
// Size: 84 bytes

undefined4 FUN_80271f5c(uint param_1)

{
  param_1 = param_1 & 0xff;
  if ((((&DAT_803bd391)[param_1 * 0x30] != '\x04') && ((DAT_803de260 & 1 << param_1) != 0)) &&
     ((float)(&DAT_803bd368)[param_1 * 0xc] < (float)(&DAT_803bd36c)[param_1 * 0xc])) {
    return 1;
  }
  return 0;
}

