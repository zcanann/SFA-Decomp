// Function: FUN_80052134
// Entry: 80052134
// Size: 1048 bytes

void FUN_80052134(undefined4 param_1,undefined4 param_2,int param_3,char *param_4,uint param_5,
                 uint param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined4 local_28;
  int local_24;
  int local_20 [8];
  
  uVar3 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar3 >> 0x20);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10,0,1);
  iVar1 = (param_5 & 0xff) * 0xc;
  FUN_8025c6b4(1,*(uint *)(&DAT_8030dac4 + iVar1),*(int *)(&DAT_8030dac8 + iVar1),
               *(uint *)(&DAT_8030dacc + iVar1),3);
  if ((float *)uVar3 == (float *)0x0) {
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,0x7d);
  }
  else {
    FUN_8025d8c4((float *)uVar3,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,DAT_803dda00);
    DAT_803dda00 = DAT_803dda00 + 3;
  }
  if ((param_6 & 0xff) == 0) {
    local_28 = *(undefined4 *)param_4;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_28);
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    if (*(int *)(iVar2 + 0x50) == 0) {
      FUN_8025c5f0(DAT_803dda10,DAT_803dd9ec);
    }
    else {
      FUN_8025c5f0(DAT_803dda10 + 1,DAT_803dd9ec);
    }
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
  }
  else {
    FUN_8004c104(param_4,'\x01','\x01',local_20,&local_24);
    FUN_8025c584(DAT_803dda10,local_20[0]);
    if (*(int *)(iVar2 + 0x50) == 0) {
      FUN_8025c5f0(DAT_803dda10,local_24);
    }
    else {
      FUN_8025c5f0(DAT_803dda10 + 1,local_24);
    }
  }
  if (param_3 == 0) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,0xf);
  }
  else if (param_3 == 8) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,4,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,8,0,1,0xf);
  }
  if (DAT_803dd9eb == '\0') {
    FUN_8025c224(DAT_803dda10,7,4,6,7);
  }
  else {
    FUN_8025c224(DAT_803dda10,7,4,0,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (iVar2 != 0) {
    if (*(char *)(iVar2 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar2 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar2 + 0x20),*(uint **)(iVar2 + 0x40),DAT_803dda0c);
    }
    if (*(int *)(iVar2 + 0x50) != 0) {
      FUN_80053dbc(iVar2,(uint *)&DAT_80378600);
      FUN_8025b054((uint *)&DAT_80378600,1);
    }
  }
  if (*(int *)(iVar2 + 0x50) != 0) {
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
    FUN_8025c224(DAT_803dda10,7,4,6,7);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  }
  DAT_803dd9eb = 1;
  DAT_803dd9f8 = DAT_803dd9f8 + 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  FUN_80286888();
  return;
}

