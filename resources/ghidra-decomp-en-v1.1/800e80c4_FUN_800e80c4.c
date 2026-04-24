// Function: FUN_800e80c4
// Entry: 800e80c4
// Size: 84 bytes

void FUN_800e80c4(uint param_1,char param_2)

{
  uint uVar1;
  
  uVar1 = 1 << (param_1 & 0xff);
  if ((DAT_803a3e34 & uVar1) == 0) {
    return;
  }
  if (param_2 != '\0') {
    DAT_803a3e38 = DAT_803a3e38 | uVar1;
    return;
  }
  DAT_803a3e38 = DAT_803a3e38 & ~uVar1;
  return;
}

