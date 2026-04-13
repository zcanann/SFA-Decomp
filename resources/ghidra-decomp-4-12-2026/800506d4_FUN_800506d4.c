// Function: FUN_800506d4
// Entry: 800506d4
// Size: 1232 bytes

void FUN_800506d4(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  FUN_8025be80(DAT_803dda10);
  FUN_8025d8c4((float *)uVar3,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  if ((param_5 == 0) || (param_5 == 2)) {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  }
  else {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,5);
  }
  if (DAT_803dda10 == 0) {
    uVar2 = 0xc;
  }
  else {
    uVar2 = 4;
  }
  if (param_3 == 0) {
    if (param_4 == 2) {
      FUN_8025c1a4(DAT_803dda10,0xf,uVar2,8,0xf);
    }
    else if (param_4 == 3) {
      FUN_8025c1a4(DAT_803dda10,uVar2,0xf,8,0xf);
    }
    else if (param_4 == 1) {
      FUN_8025c1a4(DAT_803dda10,0xf,0xf,8,uVar2);
    }
    else if ((param_5 == 0) || (param_5 == 1)) {
      FUN_8025c1a4(DAT_803dda10,0xf,10,8,uVar2);
    }
    else {
      FUN_8025c1a4(DAT_803dda10,0xf,0xb,8,uVar2);
    }
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    if (param_4 == 1) {
      FUN_8025c2a8(DAT_803dda10,1,0,0,1,2);
      FUN_8025c368(DAT_803dda10,1,0,0,1,2);
    }
    else {
      FUN_8025c2a8(DAT_803dda10,0,0,0,1,2);
      FUN_8025c368(DAT_803dda10,0,0,0,1,2);
    }
  }
  else if (param_3 == 1) {
    if (param_4 == 2) {
      FUN_8025c1a4(DAT_803dda10,0xf,6,8,0xf);
    }
    else if (param_4 == 3) {
      FUN_8025c1a4(DAT_803dda10,6,0xf,8,0xf);
    }
    else if (param_4 == 1) {
      FUN_8025c1a4(DAT_803dda10,0xf,0xf,8,6);
    }
    else if ((param_5 == 0) || (param_5 == 1)) {
      FUN_8025c1a4(DAT_803dda10,0xf,10,8,6);
    }
    else {
      FUN_8025c1a4(DAT_803dda10,0xf,0xb,8,6);
    }
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    if (param_4 == 1) {
      FUN_8025c2a8(DAT_803dda10,1,0,0,1,3);
      FUN_8025c368(DAT_803dda10,1,0,0,1,3);
    }
    else {
      FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
      FUN_8025c368(DAT_803dda10,0,0,0,1,3);
    }
  }
  else {
    DAT_803dd9eb = 1;
    DAT_803dd9b0 = 1;
    FUN_8025c6b4(1,0,0,0,1);
    FUN_8025c65c(DAT_803dda10,1,1);
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0xc);
    if (param_4 == 3) {
      FUN_8025c224(DAT_803dda10,7,5,4,6);
      FUN_8025c368(DAT_803dda10,1,0,0,1,0);
    }
    else {
      FUN_8025c224(DAT_803dda10,7,5,4,7);
      FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    }
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  }
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  FUN_8028688c();
  return;
}

