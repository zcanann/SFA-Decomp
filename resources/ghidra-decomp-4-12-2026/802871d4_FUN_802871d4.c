// Function: FUN_802871d4
// Entry: 802871d4
// Size: 180 bytes

undefined4 FUN_802871d4(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  FUN_8028b660();
  if (0 < DAT_803d7554) {
    FUN_80003514(param_1,DAT_803d7558 * 0xc + -0x7fc28aa4,0xc);
    DAT_803d7558 = DAT_803d7558 + 1;
    DAT_803d7554 = DAT_803d7554 + -1;
    if (DAT_803d7558 == 2) {
      DAT_803d7558 = 0;
    }
    uVar1 = 1;
  }
  FUN_8028b658();
  return uVar1;
}

