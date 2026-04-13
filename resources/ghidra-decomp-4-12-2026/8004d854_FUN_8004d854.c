// Function: FUN_8004d854
// Entry: 8004d854
// Size: 592 bytes

void FUN_8004d854(void)

{
  double dVar1;
  int local_20;
  float local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  float local_8;
  
  local_1c = DAT_802c2590;
  local_18 = DAT_802c2594;
  local_14 = DAT_802c2598;
  local_10 = DAT_802c259c;
  local_c = DAT_802c25a0;
  local_8 = (float)DAT_802c25a4;
  dVar1 = FUN_8006c7ec();
  local_1c = (float)((double)FLOAT_803df75c * dVar1);
  local_8 = local_1c;
  if (DAT_803dda08 < 1) {
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08,DAT_803dda0c + 1);
  }
  else {
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + -1,DAT_803dda0c + 1);
  }
  FUN_8025bb48(DAT_803dd9fc,0,0);
  FUN_8025b9e8(2,&local_1c,-3);
  FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,3,2,0,0,0,0,0);
  FUN_8006c760(&local_20);
  if (local_20 != 0) {
    if (*(char *)(local_20 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_20 + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)(local_20 + 0x20),*(uint **)(local_20 + 0x40),DAT_803dda0c + 1);
    }
  }
  FUN_8025d8c4((float *)&DAT_80397480,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,8);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8006c86c(DAT_803dda0c);
  DAT_803dd9fc = DAT_803dd9fc + 1;
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  DAT_803dd9e8 = DAT_803dd9e8 + '\x01';
  return;
}

