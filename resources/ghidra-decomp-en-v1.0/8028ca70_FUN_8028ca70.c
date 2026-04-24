// Function: FUN_8028ca70
// Entry: 8028ca70
// Size: 64 bytes

uint FUN_8028ca70(uint param_1)

{
  if (DAT_803d8878 <= param_1) {
    if ((param_1 < DAT_803d8878 + 0x4000) && ((DAT_803d85d8 & 3) != 0)) {
      return param_1;
    }
  }
  return param_1 & 0x3fffffff | 0x80000000;
}

