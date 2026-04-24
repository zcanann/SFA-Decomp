// Function: FUN_80050ff4
// Entry: 80050ff4
// Size: 252 bytes

void FUN_80050ff4(char param_1)

{
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,0xff,0xff,4);
  FUN_8025bef8(DAT_803dcd90,0,0);
  if (param_1 == '\0') {
    FUN_8025ba40(DAT_803dcd90,0xf,1,10,6);
  }
  else {
    FUN_8025ba40(DAT_803dcd90,0xf,1,4,6);
  }
  FUN_8025bac0(DAT_803dcd90,7,7,7,7);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,3);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

