// Function: FUN_8004fda0
// Entry: 8004fda0
// Size: 384 bytes

void FUN_8004fda0(int param_1,undefined4 param_2)

{
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025d160(param_2,DAT_803dcd80,0);
  FUN_80257f10(DAT_803dcd88,0,0,0,0,DAT_803dcd80);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
  FUN_8025be20(DAT_803dcd90,4);
  FUN_8025ba40(DAT_803dcd90,0xe,9,0,0);
  FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025bb44(DAT_803dcd90,1,1,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
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

