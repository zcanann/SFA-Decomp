// Function: FUN_800519e4
// Entry: 800519e4
// Size: 664 bytes

void FUN_800519e4(int param_1,float *param_2,int param_3)

{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_2 == (float *)0x0) {
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,0x7d);
  }
  else {
    FUN_8025d8c4(param_2,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,DAT_803dda00);
    DAT_803dda00 = DAT_803dda00 + 3;
  }
  if (param_3 == 0) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,0xf);
  }
  else if (param_3 == 8) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,6);
  }
  else if (param_3 == 4) {
    FUN_8025c1a4(DAT_803dda10,8,0xf,0xf,0);
  }
  else if (param_3 == 6) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,0,0xf);
  }
  else if (param_3 == 9) {
    FUN_8025c1a4(DAT_803dda10,8,0,1,0xf);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,8,0,1,0xf);
  }
  if (DAT_803dd9eb == '\0') {
    FUN_8025c224(DAT_803dda10,7,4,5,7);
    DAT_803dd9eb = '\x01';
  }
  else {
    FUN_8025c224(DAT_803dda10,7,4,0,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dd9f8 = DAT_803dd9f8 + 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

