// Function: FUN_8005254c
// Entry: 8005254c
// Size: 284 bytes

void FUN_8005254c(void)

{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if ((DAT_803dd9ea == '\0') || (DAT_803dd9b0 == '\0')) {
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,10);
    FUN_8025c224(DAT_803dda10,7,7,7,5);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0,10,0xf);
    FUN_8025c224(DAT_803dda10,7,0,5,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

