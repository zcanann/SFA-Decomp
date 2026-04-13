// Function: FUN_8028dc08
// Entry: 8028dc08
// Size: 204 bytes

void FUN_8028dc08(void)

{
  undefined **ppuVar1;
  
  if (DAT_803df070 == 0) {
    FUN_802866d0();
    for (ppuVar1 = &PTR_FUN_802c2020; (code *)*ppuVar1 != (code *)0x0; ppuVar1 = ppuVar1 + 1) {
      (*(code *)*ppuVar1)();
    }
    if (DAT_803df078 != (code *)0x0) {
      (*DAT_803df078)();
      DAT_803df078 = (code *)0x0;
    }
  }
  while (0 < DAT_803df074) {
    DAT_803df074 = DAT_803df074 + -1;
    (**(code **)(&DAT_803db718 + DAT_803df074 * 4))();
  }
  if (DAT_803df07c != (code *)0x0) {
    (*DAT_803df07c)();
    DAT_803df07c = (code *)0x0;
  }
  FUN_802474ac();
  return;
}

