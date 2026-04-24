// Function: FUN_8004f1fc
// Entry: 8004f1fc
// Size: 560 bytes

void FUN_8004f1fc(void)

{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0,4,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025be80(DAT_803dda10 + 1);
  FUN_8025c828(DAT_803dda10 + 1,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10 + 1,4,0xf,0xf,0);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025be80(DAT_803dda10 + 2);
  FUN_8025c828(DAT_803dda10 + 2,0xff,0xff,4);
  FUN_8025c1a4(DAT_803dda10 + 2,0,6,0xb,0xf);
  FUN_8025c224(DAT_803dda10 + 2,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 2,0,0);
  FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 3;
  DAT_803dd9ea = DAT_803dd9ea + '\x03';
  return;
}

