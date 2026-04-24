// Function: FUN_8024f79c
// Entry: 8024f79c
// Size: 24 bytes

void FUN_8024f79c(void)

{
  ushort uVar1;
  
  uVar1 = read_volatile_2(DAT_cc005036);
  write_volatile_2(DAT_cc005036,uVar1 & 0x7fff);
  return;
}

