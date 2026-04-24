// Function: FUN_800516a4
// Entry: 800516a4
// Size: 832 bytes

void FUN_800516a4(int param_1,float *param_2)

{
  undefined4 uStack_18;
  int local_14;
  byte bStack_10;
  byte bStack_f;
  byte abStack_e [6];
  
  FUN_80089ab8(0,&bStack_10,&bStack_f,abStack_e);
  if (param_2 == (float *)0x0) {
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,0x7d);
  }
  else {
    FUN_8025d8c4(param_2,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,DAT_803dda00);
    DAT_803dda00 = DAT_803dda00 + 3;
  }
  FUN_8004c104((char *)&bStack_10,'\x01','\0',&local_14,&uStack_18);
  FUN_8025c584(DAT_803dda10,local_14);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c1a4(DAT_803dda10,0xf,0xe,10,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  FUN_8025be80(DAT_803dda10 + 1);
  FUN_8025c828(DAT_803dda10 + 1,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c1a4(DAT_803dda10 + 1,0,10,0xb,0xf);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025be80(DAT_803dda10 + 2);
  FUN_8025c828(DAT_803dda10 + 2,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10 + 2,0,0);
  FUN_8025c1a4(DAT_803dda10 + 2,0xf,0,8,0xf);
  FUN_8025c224(DAT_803dda10 + 2,7,7,7,4);
  FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,0);
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
  DAT_803dda10 = DAT_803dda10 + 3;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x03';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

