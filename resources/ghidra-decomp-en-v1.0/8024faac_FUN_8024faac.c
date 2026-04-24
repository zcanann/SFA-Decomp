// Function: FUN_8024faac
// Entry: 8024faac
// Size: 16 bytes

uint FUN_8024faac(void)

{
  uint uVar1;
  
  uVar1 = read_volatile_4(DAT_cc006c04);
  return uVar1 & 0xff;
}

