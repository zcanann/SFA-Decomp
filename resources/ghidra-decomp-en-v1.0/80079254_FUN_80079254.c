// Function: FUN_80079254
// Entry: 80079254
// Size: 212 bytes

void FUN_80079254(void)

{
  FUN_8025c0c4(DAT_803dd030,0xff,0xff,4);
  FUN_8025b71c(DAT_803dd030);
  FUN_8025ba40(DAT_803dd030,0xf,0,4,0xf);
  FUN_8025bac0(DAT_803dd030,7,0,2,7);
  FUN_8025bef8(DAT_803dd030,0,0);
  FUN_8025bb44(DAT_803dd030,0,0,0,1,0);
  FUN_8025bc04(DAT_803dd030,0,0,0,1,0);
  DAT_803dd009 = DAT_803dd009 + '\x01';
  DAT_803dd00b = DAT_803dd00b + '\x01';
  DAT_803dd030 = DAT_803dd030 + 1;
  return;
}

