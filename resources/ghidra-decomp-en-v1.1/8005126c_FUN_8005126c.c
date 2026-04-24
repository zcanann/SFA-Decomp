// Function: FUN_8005126c
// Entry: 8005126c
// Size: 600 bytes

void FUN_8005126c(int param_1,char param_2,uint param_3)

{
  float afStack_78 [12];
  float afStack_48 [15];
  
  if (DAT_803dd9e8 == '\0') {
    FUN_8025be80(DAT_803dda10);
  }
  if (param_2 == '\0') {
    FUN_80247a7c((double)FLOAT_803df7c0,(double)FLOAT_803df7c0,(double)FLOAT_803df74c,afStack_78);
    FUN_80247a48((double)FLOAT_803df75c,(double)FLOAT_803df75c,(double)FLOAT_803df748,afStack_48);
    FUN_80247618(afStack_48,afStack_78,afStack_78);
    FUN_8025d8c4(afStack_78,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,1,0x1e,0,DAT_803dda00);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  }
  else {
    FUN_8025bec8(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08 + -1,DAT_803dda0c,0xff);
  }
  FUN_8025c224(DAT_803dda10,7,4,3,7);
  if (param_2 == '\0') {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,0xf);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,8,4,0xf);
  }
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  if ((param_3 & 1) == 0) {
    FUN_8025c6b4(3,0,0,0,1);
  }
  else {
    FUN_8025c6b4(3,2,2,2,1);
  }
  FUN_8025c65c(DAT_803dda10,0,3);
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

