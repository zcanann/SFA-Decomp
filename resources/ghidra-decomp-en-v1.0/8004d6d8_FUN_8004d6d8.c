// Function: FUN_8004d6d8
// Entry: 8004d6d8
// Size: 592 bytes

void FUN_8004d6d8(void)

{
  double dVar1;
  int local_20;
  float local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  float local_8;
  
  local_1c = DAT_802c1e10;
  local_18 = DAT_802c1e14;
  local_14 = DAT_802c1e18;
  local_10 = DAT_802c1e1c;
  local_c = DAT_802c1e20;
  local_8 = (float)DAT_802c1e24;
  dVar1 = (double)FUN_8006c670();
  local_1c = (float)((double)FLOAT_803deadc * dVar1);
  local_8 = local_1c;
  if (DAT_803dcd88 < 1) {
    FUN_8025b5b8(DAT_803dcd7c,DAT_803dcd88,DAT_803dcd8c + 1);
  }
  else {
    FUN_8025b5b8(DAT_803dcd7c,DAT_803dcd88 + -1,DAT_803dcd8c + 1);
  }
  FUN_8025b3e4(DAT_803dcd7c,0,0);
  FUN_8025b284(2,&local_1c,0xfffffffd);
  FUN_8025b1e8(DAT_803dcd90,DAT_803dcd7c,0,3,2,0,0,0,0,0);
  FUN_8006c5e4(&local_20);
  if (local_20 != 0) {
    if (*(char *)(local_20 + 0x48) == '\0') {
      FUN_8025a8f0(local_20 + 0x20,DAT_803dcd8c + 1);
    }
    else {
      FUN_8025a748(local_20 + 0x20,*(undefined4 *)(local_20 + 0x40));
    }
  }
  FUN_8025d160(&DAT_80396820,DAT_803dcd80,0);
  FUN_80257f10(DAT_803dcd88,0,0,0,0,DAT_803dcd80);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
  FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,8);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,1);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  FUN_8006c6f0(DAT_803dcd8c);
  DAT_803dcd68 = DAT_803dcd68 + '\x01';
  DAT_803dcd69 = DAT_803dcd69 + '\x01';
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd7c = DAT_803dcd7c + 1;
  DAT_803dcd80 = DAT_803dcd80 + 3;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd8c = DAT_803dcd8c + 2;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

