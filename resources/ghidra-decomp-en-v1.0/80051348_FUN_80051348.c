// Function: FUN_80051348
// Entry: 80051348
// Size: 480 bytes

void FUN_80051348(int param_1,undefined param_2)

{
  undefined auStack120 [4];
  undefined4 local_74;
  undefined local_70;
  undefined local_6f;
  undefined local_6e;
  undefined auStack108 [48];
  undefined auStack60 [52];
  
  FUN_80247318((double)FLOAT_803deb40,(double)FLOAT_803deb40,(double)FLOAT_803deacc,auStack108);
  FUN_802472e4((double)FLOAT_803deadc,(double)FLOAT_803deadc,(double)FLOAT_803deac8,auStack60);
  FUN_80246eb4(auStack60,auStack108,auStack108);
  FUN_8025d160(auStack108,DAT_803dcd80,0);
  local_70 = param_2;
  local_6f = param_2;
  local_6e = param_2;
  FUN_8004bf88(&local_70,1,0,&local_74,auStack120);
  FUN_8025be20(DAT_803dcd90,local_74);
  FUN_80257f10(DAT_803dcd88,1,1,0x1e,0,DAT_803dcd80);
  if (DAT_803dcd68 == '\0') {
    FUN_8025b71c(DAT_803dcd90);
  }
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,4);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025ba40(DAT_803dcd90,0xf,8,0xe,10);
  FUN_8025bac0(DAT_803dcd90,7,7,7,7);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,2);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025a8f0(param_1 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(param_1 + 0x20,*(undefined4 *)(param_1 + 0x40));
    }
  }
  DAT_803dcd69 = DAT_803dcd69 + '\x01';
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd80 = DAT_803dcd80 + 3;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd8c = DAT_803dcd8c + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

