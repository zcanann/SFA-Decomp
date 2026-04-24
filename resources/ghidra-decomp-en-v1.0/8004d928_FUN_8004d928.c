// Function: FUN_8004d928
// Entry: 8004d928
// Size: 300 bytes

void FUN_8004d928(void)

{
  FUN_8006c75c(DAT_803dcd8c);
  FUN_80257f10(DAT_803dcd88,0,0,0x24,0,0x7d);
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025be20(DAT_803dcd90,6);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
  FUN_8025ba40(DAT_803dcd90,0xf,8,0xe,0);
  FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
  DAT_803dcd69 = DAT_803dcd69 + '\x01';
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd84 = 0x27;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd8c = DAT_803dcd8c + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

