// Function: FUN_8025100c
// Entry: 8025100c
// Size: 64 bytes

void FUN_8025100c(void)

{
  ushort uVar1;
  
  FUN_8024377c();
  uVar1 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar1 & 0xff57 | 4);
  FUN_802437a4();
  return;
}

