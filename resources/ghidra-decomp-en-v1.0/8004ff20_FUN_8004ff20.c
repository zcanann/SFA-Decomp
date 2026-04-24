// Function: FUN_8004ff20
// Entry: 8004ff20
// Size: 508 bytes

void FUN_8004ff20(int param_1)

{
  if (param_1 != 0) {
    FUN_80257f10(DAT_803dcd88,1,1,0x1e,0,0x7d);
    FUN_8025b71c(DAT_803dcd90);
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,4);
    FUN_8025ba40(DAT_803dcd90,0xf,10,0xb,8);
    FUN_8025bac0(DAT_803dcd90,7,7,7,7);
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
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
    DAT_803dcd88 = DAT_803dcd88 + 1;
    DAT_803dcd90 = DAT_803dcd90 + 1;
    DAT_803dcd8c = DAT_803dcd8c + 1;
    DAT_803dcd69 = DAT_803dcd69 + '\x01';
    DAT_803dcd6a = DAT_803dcd6a + '\x01';
    FUN_8025b71c();
    FUN_8025c0c4(DAT_803dcd90,0xff,0xff,5);
    FUN_8025ba40(DAT_803dcd90,0xf,10,0xb,0);
    FUN_8025bac0(DAT_803dcd90,7,7,7,7);
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
    FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
    DAT_803dcd90 = DAT_803dcd90 + 1;
    DAT_803dcd6a = DAT_803dcd6a + '\x01';
  }
  return;
}

