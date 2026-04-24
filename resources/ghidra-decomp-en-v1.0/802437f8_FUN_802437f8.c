// Function: FUN_802437f8
// Entry: 802437f8
// Size: 116 bytes

void FUN_802437f8(void)

{
  DAT_803dde38 = &DAT_80003040;
  FUN_800033a8(&DAT_80003040,0,0x80);
  DAT_800000c4 = 0;
  DAT_800000c8 = 0;
  write_volatile_4(DAT_cc003004,0xf0);
  FUN_80243b44(0xffffffe0);
  FUN_80240bc4(4,&LAB_80243f98);
  return;
}

