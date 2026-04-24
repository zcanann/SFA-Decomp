// Function: FUN_8024b2dc
// Entry: 8024b2dc
// Size: 68 bytes

void FUN_8024b2dc(void)

{
  undefined4 uVar1;
  
  FUN_80248744();
  write_volatile_4(DAT_cc006000,0x2a);
  uVar1 = read_volatile_4(DAT_cc006004);
  write_volatile_4(DAT_cc006004,uVar1);
  DAT_803ddf30 = 0;
  DAT_803ddf40 = 0;
  return;
}

