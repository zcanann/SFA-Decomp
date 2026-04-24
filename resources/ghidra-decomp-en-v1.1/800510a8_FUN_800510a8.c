// Function: FUN_800510a8
// Entry: 800510a8
// Size: 200 bytes

void FUN_800510a8(void)

{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c1a4(DAT_803dda10,0xf,6,8,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

