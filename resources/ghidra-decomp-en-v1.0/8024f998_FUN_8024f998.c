// Function: FUN_8024f998
// Entry: 8024f998
// Size: 20 bytes

uint FUN_8024f998(void)

{
  uint uVar1;
  
  uVar1 = read_volatile_4(DAT_cc006c00);
  return uVar1 >> 6 & 1 ^ 1;
}

