// Function: FUN_80050f2c
// Entry: 80050f2c
// Size: 200 bytes

void FUN_80050f2c(void)

{
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025ba40(DAT_803dcd90,0xf,6,8,0xf);
  FUN_8025bac0(DAT_803dcd90,7,7,7,7);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,3);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

