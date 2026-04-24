// Function: FUN_80250fc4
// Entry: 80250fc4
// Size: 72 bytes

void FUN_80250fc4(void)

{
  ushort uVar1;
  
  FUN_8024377c();
  uVar1 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar1 & 0xff57 | 0x801);
  DAT_803de060 = 0;
  FUN_802437a4();
  return;
}

