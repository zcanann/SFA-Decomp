// Function: FUN_80078f78
// Entry: 80078f78
// Size: 212 bytes

void FUN_80078f78(void)

{
  FUN_8025c828(DAT_803ddcb0,0xff,0xff,4);
  FUN_8025be80(DAT_803ddcb0);
  FUN_8025c1a4(DAT_803ddcb0,0xf,0,10,0xf);
  FUN_8025c224(DAT_803ddcb0,7,0,5,7);
  FUN_8025c65c(DAT_803ddcb0,0,0);
  FUN_8025c2a8(DAT_803ddcb0,0,0,0,1,0);
  FUN_8025c368(DAT_803ddcb0,0,0,0,1,0);
  DAT_803ddcb0 = DAT_803ddcb0 + 1;
  DAT_803ddc8b = DAT_803ddc8b + '\x01';
  DAT_803ddc89 = DAT_803ddc89 + '\x01';
  return;
}

