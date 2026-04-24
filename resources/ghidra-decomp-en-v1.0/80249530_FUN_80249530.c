// Function: FUN_80249530
// Entry: 80249530
// Size: 180 bytes

undefined4 FUN_80249530(uint param_1)

{
  if (param_1 == 0x20400) {
    DAT_803ddf38 = param_1;
    return 1;
  }
  param_1 = param_1 & 0xffffff;
  if (((param_1 == 0x62800) || (param_1 == 0x23a00)) || (param_1 == 0xb5a01)) {
    return 0;
  }
  DAT_803ddf3c = DAT_803ddf3c + 1;
  if (DAT_803ddf3c == 2) {
    if (param_1 == DAT_803ddf38) {
      DAT_803ddf38 = param_1;
      return 1;
    }
    DAT_803ddf38 = param_1;
    return 2;
  }
  if ((param_1 != 0x31100) && (*(int *)(DAT_803ddf08 + 8) != 5)) {
    DAT_803ddf38 = param_1;
    return 3;
  }
  DAT_803ddf38 = param_1;
  return 2;
}

