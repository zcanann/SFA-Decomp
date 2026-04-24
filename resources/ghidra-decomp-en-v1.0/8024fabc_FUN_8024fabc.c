// Function: FUN_8024fabc
// Entry: 8024fabc
// Size: 28 bytes

void FUN_8024fabc(uint param_1)

{
  uint uVar1;
  
  uVar1 = read_volatile_4(DAT_cc006c04);
  write_volatile_4(DAT_cc006c04,(param_1 & 0xff) << 8 | uVar1 & 0xffff00ff);
  return;
}

