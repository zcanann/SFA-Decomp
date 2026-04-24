// Function: FUN_8024fa80
// Entry: 8024fa80
// Size: 16 bytes

uint FUN_8024fa80(void)

{
  uint uVar1;
  
  uVar1 = read_volatile_4(DAT_cc006c00);
  return uVar1 >> 1 & 1;
}

