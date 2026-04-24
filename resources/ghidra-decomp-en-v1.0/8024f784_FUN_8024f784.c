// Function: FUN_8024f784
// Entry: 8024f784
// Size: 24 bytes

void FUN_8024f784(void)

{
  ushort uVar1;
  
  uVar1 = read_volatile_2(DAT_cc005036);
  write_volatile_2(DAT_cc005036,uVar1 | 0x8000);
  return;
}

