// Function: FUN_80079120
// Entry: 80079120
// Size: 264 bytes

void FUN_80079120(void)

{
  FUN_8025c828(DAT_803ddcb0,DAT_803ddcac,DAT_803ddca8,0xff);
  FUN_8025be80(DAT_803ddcb0);
  FUN_8025c1a4(DAT_803ddcb0,4,0xf,0xf,0xf);
  FUN_8025c224(DAT_803ddcb0,7,2,4,7);
  FUN_8025c65c(DAT_803ddcb0,0,0);
  FUN_8025c2a8(DAT_803ddcb0,0,0,0,1,0);
  FUN_8025c368(DAT_803ddcb0,0,0,0,1,0);
  FUN_80258674(DAT_803ddcac,1,4,0x3c,0,0x7d);
  DAT_803ddcb0 = DAT_803ddcb0 + 1;
  DAT_803ddc8b = DAT_803ddc8b + '\x01';
  DAT_803ddcac = DAT_803ddcac + 1;
  DAT_803ddc8a = DAT_803ddc8a + '\x01';
  DAT_803ddca8 = DAT_803ddca8 + 1;
  return;
}

