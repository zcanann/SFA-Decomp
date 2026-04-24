// Function: FUN_8028d1d0
// Entry: 8028d1d0
// Size: 64 bytes

uint FUN_8028d1d0(uint param_1)

{
  if (DAT_803d94d8 <= param_1) {
    if ((param_1 < DAT_803d94d8 + 0x4000) && ((DAT_803d9238 & 3) != 0)) {
      return param_1;
    }
  }
  return param_1 & 0x3fffffff | 0x80000000;
}

