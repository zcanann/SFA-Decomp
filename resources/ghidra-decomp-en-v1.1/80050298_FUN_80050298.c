// Function: FUN_80050298
// Entry: 80050298
// Size: 1084 bytes

void FUN_80050298(float *param_1)

{
  float *pfVar1;
  float fVar2;
  int local_48;
  float afStack_44 [16];
  
  FUN_8025be80(DAT_803dda10);
  FUN_8025be80(DAT_803dda10 + 1);
  FUN_8025be80(DAT_803dda10 + 2);
  FUN_8025be80(DAT_803dda10 + 3);
  pfVar1 = (float *)FUN_8000f578();
  FUN_80247618(param_1 + 0xc,pfVar1,afStack_44);
  FUN_8025d8c4(afStack_44,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0x3c,0,DAT_803dda00);
  pfVar1 = (float *)FUN_8000f578();
  FUN_80247618(param_1,pfVar1,afStack_44);
  FUN_8025d8c4(afStack_44,DAT_803dda00 + 3,0);
  FUN_80258674(DAT_803dda08 + 1,0,0,0x3c,0,DAT_803dda00 + 3);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  FUN_8025c828(DAT_803dda10 + 2,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  FUN_8025c828(DAT_803dda10 + 3,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  FUN_8025c584(DAT_803dda10 + 2,6);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,8);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 1,2,8,0xc,0xf);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c2a8(DAT_803dda10 + 1,8,0,0,1,1);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 2,4,0xe,2,0xf);
  FUN_8025c224(DAT_803dda10 + 2,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 2,0,0);
  FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,2);
  FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 3,6,0xf,2,0xf);
  FUN_8025c224(DAT_803dda10 + 3,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 3,0,0);
  FUN_8025c2a8(DAT_803dda10 + 3,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10 + 3,0,0,0,1,0);
  FUN_8006c734(&local_48);
  if (local_48 != 0) {
    if (*(char *)(local_48 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_48 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(local_48 + 0x20),*(uint **)(local_48 + 0x40),DAT_803dda0c);
    }
  }
  fVar2 = param_1[0x18];
  if (fVar2 != 0.0) {
    if (*(char *)((int)fVar2 + 0x48) == '\0') {
      FUN_8025b054((uint *)((int)fVar2 + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)((int)fVar2 + 0x20),*(uint **)((int)fVar2 + 0x40),DAT_803dda0c + 1);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 6;
  DAT_803dda08 = DAT_803dda08 + 2;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  DAT_803dd9ea = DAT_803dd9ea + '\x04';
  DAT_803dda10 = DAT_803dda10 + 4;
  return;
}

