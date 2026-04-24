// Function: FUN_800523d0
// Entry: 800523d0
// Size: 284 bytes

void FUN_800523d0(void)

{
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,0xff,0xff,4);
  FUN_8025bef8(DAT_803dcd90,0,0);
  if ((DAT_803dcd6a == '\0') || (DAT_803dcd30 == '\0')) {
    FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,10);
    FUN_8025bac0(DAT_803dcd90,7,7,7,5);
  }
  else {
    FUN_8025ba40(DAT_803dcd90,0xf,0,10,0xf);
    FUN_8025bac0(DAT_803dcd90,7,0,5,7);
  }
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

