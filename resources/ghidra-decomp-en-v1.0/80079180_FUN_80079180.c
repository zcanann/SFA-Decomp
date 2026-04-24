// Function: FUN_80079180
// Entry: 80079180
// Size: 212 bytes

void FUN_80079180(void)

{
  FUN_8025c0c4(DAT_803dd030,0xff,0xff,4);
  FUN_8025b71c(DAT_803dd030);
  FUN_8025ba40(DAT_803dd030,0xf,0xf,0xf,10);
  FUN_8025bac0(DAT_803dd030,7,7,7,5);
  FUN_8025bef8(DAT_803dd030,0,0);
  FUN_8025bb44(DAT_803dd030,0,0,0,1,0);
  FUN_8025bc04(DAT_803dd030,0,0,0,1,0);
  DAT_803dd009 = DAT_803dd009 + '\x01';
  DAT_803dd00b = DAT_803dd00b + '\x01';
  DAT_803dd030 = DAT_803dd030 + 1;
  return;
}

