// Function: FUN_80249c94
// Entry: 80249c94
// Size: 180 bytes

undefined4 FUN_80249c94(uint param_1)

{
  uint uVar1;
  
  if (param_1 == 0x20400) {
    DAT_803debb8 = param_1;
    return 1;
  }
  uVar1 = param_1 & 0xffffff;
  if (((uVar1 == 0x62800) || (uVar1 == 0x23a00)) || (uVar1 == 0xb5a01)) {
    return 0;
  }
  DAT_803debbc = DAT_803debbc + 1;
  if (DAT_803debbc == 2) {
    if (uVar1 == DAT_803debb8) {
      DAT_803debb8 = uVar1;
      return 1;
    }
    DAT_803debb8 = uVar1;
    return 2;
  }
  DAT_803debb8 = uVar1;
  if ((uVar1 != 0x31100) && (*(int *)(DAT_803deb88 + 8) != 5)) {
    return 3;
  }
  return 2;
}

