// Function: FUN_8004d3ac
// Entry: 8004d3ac
// Size: 900 bytes

void FUN_8004d3ac(void)

{
  int iVar1;
  double dVar2;
  double dVar3;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float afStack_48 [17];
  
  iVar1 = FUN_8006c8d0();
  dVar3 = (double)FLOAT_803df75c;
  FUN_80247b70((double)FLOAT_803df774,(double)FLOAT_803df778,(double)FLOAT_803df778,
               (double)FLOAT_803df774,dVar3,dVar3,dVar3,dVar3,afStack_48);
  FUN_8025d8c4(afStack_48,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c6b4(1,0,0,0,1);
  FUN_8025c65c(DAT_803dda10,1,1);
  if (DAT_803dda10 == 0) {
    FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
  }
  FUN_8025c224(DAT_803dda10,7,7,7,4);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,2);
  DAT_803dd9b0 = 1;
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
  iVar1 = FUN_8002bac4();
  if (iVar1 == 0) {
    dVar3 = (double)FLOAT_803df77c;
  }
  else {
    dVar3 = (double)FUN_8000f4a0((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                                 (double)*(float *)(iVar1 + 0x20));
  }
  dVar2 = -(double)(FLOAT_803df748 /
                   (float)(dVar3 - (double)(float)(dVar3 - (double)FLOAT_803df780)));
  local_78 = FLOAT_803df74c;
  local_74 = FLOAT_803df74c;
  local_70 = (float)dVar2;
  local_6c = (float)(dVar2 * (double)(float)(dVar3 - (double)FLOAT_803df780));
  local_68 = FLOAT_803df74c;
  local_64 = FLOAT_803df74c;
  local_60 = FLOAT_803df74c;
  local_5c = FLOAT_803df74c;
  local_58 = FLOAT_803df74c;
  local_54 = FLOAT_803df74c;
  local_50 = FLOAT_803df74c;
  local_4c = FLOAT_803df74c;
  FUN_8025d8c4(&local_78,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10,1,1);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
  FUN_8025c5f0(DAT_803dda10,0);
  FUN_8025c224(DAT_803dda10,7,2,4,6);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,1,0,0,1,0);
  DAT_803dd9b0 = 1;
  iVar1 = FUN_8006c8c8();
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
  DAT_803dd9eb = 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x02';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  return;
}

