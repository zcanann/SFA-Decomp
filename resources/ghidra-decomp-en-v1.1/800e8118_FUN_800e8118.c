// Function: FUN_800e8118
// Entry: 800e8118
// Size: 68 bytes

undefined4 FUN_800e8118(uint param_1)

{
  uint uVar1;
  
  uVar1 = 1 << (param_1 & 0xff);
  if (((DAT_803a3e34 & uVar1) != 0) && ((DAT_803a3e38 & uVar1) != 0)) {
    return 1;
  }
  return 0;
}

