// Function: FUN_80245c50
// Entry: 80245c50
// Size: 296 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80245c50(void)

{
  int iVar1;
  undefined *puVar2;
  
  DAT_803adb10 = 2;
  DAT_803adb12 = 1;
  DAT_803adb1c = 0x10;
  DAT_803adb18 = 0x10;
  DAT_803adb14 = 0;
  DAT_803adb20 = 0xffffffff;
  DAT_803adb38 = 0;
  FUN_80245d78(&DAT_803adb30);
  DAT_803adb40 = 0;
  DAT_803adb3c = 0;
  DAT_800000d8 = &DAT_803ad848;
  FUN_80242474(&DAT_803ad848);
  FUN_802422ac(&DAT_803ad848);
  DAT_803adb4c = 0x803f8478;
  DAT_803adb50 = &DAT_803e8478;
  iVar1 = 0;
  _DAT_803e8478 = 0xdeadbabe;
  puVar2 = &DAT_803ad438;
  DAT_803dde88 = 0;
  DAT_800000e4 = &DAT_803ad848;
  DAT_803dde8c = 0;
  do {
    FUN_80245d78(puVar2);
    iVar1 = iVar1 + 1;
    puVar2 = puVar2 + 8;
  } while (iVar1 < 0x20);
  FUN_80245d78(&DAT_800000dc);
  if (DAT_800000e0 == (undefined *)0x0) {
    DAT_800000dc = &DAT_803ad848;
  }
  else {
    *(undefined **)((int)DAT_800000e0 + 0x2fc) = &DAT_803ad848;
  }
  DAT_803adb48 = (int)DAT_800000e0;
  DAT_803adb44 = 0;
  DAT_800000e0 = &DAT_803ad848;
  FUN_80242474(&DAT_803adb58);
  DAT_803dde90 = 0;
  return;
}

