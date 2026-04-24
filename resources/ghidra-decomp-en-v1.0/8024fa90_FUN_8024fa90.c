// Function: FUN_8024fa90
// Entry: 8024fa90
// Size: 28 bytes

void FUN_8024fa90(uint param_1)

{
  uint uVar1;
  
  uVar1 = read_volatile_4(DAT_cc006c04);
  write_volatile_4(DAT_cc006c04,param_1 & 0xff | uVar1 & 0xffffff00);
  return;
}

