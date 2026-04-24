// Function: FUN_802525e4
// Entry: 802525e4
// Size: 108 bytes

uint FUN_802525e4(int param_1,int param_2)

{
  uint uVar1;
  
  FUN_8024377c();
  uVar1 = DAT_8032e244 & 0xfc0000ff | param_1 << 0x10 | param_2 << 8;
  write_volatile_4(DAT_cc006430,uVar1);
  DAT_8032e244 = uVar1;
  FUN_802437a4();
  return uVar1;
}

