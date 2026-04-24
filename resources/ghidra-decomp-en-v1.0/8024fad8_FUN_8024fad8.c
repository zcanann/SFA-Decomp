// Function: FUN_8024fad8
// Entry: 8024fad8
// Size: 16 bytes

uint FUN_8024fad8(void)

{
  uint uVar1;
  
  uVar1 = read_volatile_4(DAT_cc006c04);
  return uVar1 >> 8 & 0xff;
}

