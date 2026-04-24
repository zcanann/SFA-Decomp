// Function: FUN_800147a4
// Entry: 800147a4
// Size: 184 bytes

void FUN_800147a4(void)

{
  if (DAT_803dc8e8 != (int *)0x0) {
    (**(code **)(*DAT_803dc8e8 + 8))();
  }
  if (DAT_803dc8ec != 0) {
    DAT_803dc8ec = DAT_803dc8ec + -1;
    DAT_803dc8f4 = DAT_803dc8f0;
    if (DAT_803dc8e8 != (int *)0x0) {
      FUN_80013e2c();
      DAT_803dc8e8 = (int *)0x0;
    }
    if (*(uint *)(&DAT_802c6e08 + DAT_803dc8ec * 4) == 0xffffffff) {
      DAT_803dc8e8 = (int *)0x0;
      DAT_803dc8ec = 0;
    }
    else {
      DAT_803dc8e8 = (int *)FUN_80013ec8(*(uint *)(&DAT_802c6e08 + DAT_803dc8ec * 4) & 0xffff,1);
    }
    DAT_803dc8f0 = DAT_803dc8ec;
    DAT_803dc8ec = 0;
  }
  return;
}

