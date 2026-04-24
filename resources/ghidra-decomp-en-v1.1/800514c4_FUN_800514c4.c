// Function: FUN_800514c4
// Entry: 800514c4
// Size: 480 bytes

void FUN_800514c4(int param_1,char param_2)

{
  undefined4 uStack_78;
  int local_74;
  char local_70;
  char local_6f;
  char local_6e;
  float afStack_6c [12];
  float afStack_3c [13];
  
  FUN_80247a7c((double)FLOAT_803df7c0,(double)FLOAT_803df7c0,(double)FLOAT_803df74c,afStack_6c);
  FUN_80247a48((double)FLOAT_803df75c,(double)FLOAT_803df75c,(double)FLOAT_803df748,afStack_3c);
  FUN_80247618(afStack_3c,afStack_6c,afStack_6c);
  FUN_8025d8c4(afStack_6c,DAT_803dda00,0);
  local_70 = param_2;
  local_6f = param_2;
  local_6e = param_2;
  FUN_8004c104(&local_70,'\x01','\0',&local_74,&uStack_78);
  FUN_8025c584(DAT_803dda10,local_74);
  FUN_80258674(DAT_803dda08,1,1,0x1e,0,DAT_803dda00);
  if (DAT_803dd9e8 == '\0') {
    FUN_8025be80(DAT_803dda10);
  }
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,10);
  FUN_8025c224(DAT_803dda10,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,2);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

