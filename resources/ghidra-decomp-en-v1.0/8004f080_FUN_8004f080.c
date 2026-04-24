// Function: FUN_8004f080
// Entry: 8004f080
// Size: 560 bytes

void FUN_8004f080(void)

{
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,0xff,0xff,0xff);
  FUN_8025ba40(DAT_803dcd90,0xf,0,4,0xf);
  FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,3);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  FUN_8025b71c(DAT_803dcd90 + 1);
  FUN_8025c0c4(DAT_803dcd90 + 1,0xff,0xff,0xff);
  FUN_8025ba40(DAT_803dcd90 + 1,4,0xf,0xf,0);
  FUN_8025bac0(DAT_803dcd90 + 1,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90 + 1,0,0);
  FUN_8025bb44(DAT_803dcd90 + 1,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90 + 1,0,0,0,1,0);
  FUN_8025b71c(DAT_803dcd90 + 2);
  FUN_8025c0c4(DAT_803dcd90 + 2,0xff,0xff,4);
  FUN_8025ba40(DAT_803dcd90 + 2,0,6,0xb,0xf);
  FUN_8025bac0(DAT_803dcd90 + 2,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90 + 2,0,0);
  FUN_8025bb44(DAT_803dcd90 + 2,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90 + 2,0,0,0,1,0);
  DAT_803dcd30 = 1;
  DAT_803dcd6a = DAT_803dcd6a + '\x03';
  DAT_803dcd90 = DAT_803dcd90 + 3;
  return;
}

