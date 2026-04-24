// Function: FUN_80078fa4
// Entry: 80078fa4
// Size: 264 bytes

void FUN_80078fa4(void)

{
  FUN_8025c0c4(DAT_803dd030,DAT_803dd02c,DAT_803dd028,0xff);
  FUN_8025b71c(DAT_803dd030);
  FUN_8025ba40(DAT_803dd030,4,0xf,0xf,0xf);
  FUN_8025bac0(DAT_803dd030,7,2,4,7);
  FUN_8025bef8(DAT_803dd030,0,0);
  FUN_8025bb44(DAT_803dd030,0,0,0,1,0);
  FUN_8025bc04(DAT_803dd030,0,0,0,1,0);
  FUN_80257f10(DAT_803dd02c,1,4,0x3c,0,0x7d);
  DAT_803dd00a = DAT_803dd00a + '\x01';
  DAT_803dd00b = DAT_803dd00b + '\x01';
  DAT_803dd028 = DAT_803dd028 + 1;
  DAT_803dd02c = DAT_803dd02c + 1;
  DAT_803dd030 = DAT_803dd030 + 1;
  return;
}

