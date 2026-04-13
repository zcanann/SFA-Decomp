// Function: FUN_80051170
// Entry: 80051170
// Size: 252 bytes

void FUN_80051170(char param_1)

{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_1 == '\0') {
    FUN_8025c1a4(DAT_803dda10,0xf,1,10,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,1,4,6);
  }
  FUN_8025c224(DAT_803dda10,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

