// Function: FUN_800e7e40
// Entry: 800e7e40
// Size: 84 bytes

void FUN_800e7e40(uint param_1,char param_2)

{
  uint uVar1;
  
  uVar1 = 1 << (param_1 & 0xff);
  if ((DAT_803a31d4 & uVar1) == 0) {
    return;
  }
  if (param_2 != '\0') {
    DAT_803a31d8 = DAT_803a31d8 | uVar1;
    return;
  }
  DAT_803a31d8 = DAT_803a31d8 & ~uVar1;
  return;
}

