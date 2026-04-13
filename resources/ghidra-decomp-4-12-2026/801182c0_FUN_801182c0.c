// Function: FUN_801182c0
// Entry: 801182c0
// Size: 372 bytes

void FUN_801182c0(void)

{
  uint uVar1;
  
  if (DAT_803de2ec == 0) {
    DAT_803de2f8 = DAT_803de2f8 ^ 1;
    FUN_8024fe60(&DAT_803a6420 + DAT_803de2f8 * 0x280,0x280);
    FUN_80243e88();
    FUN_80117f1c((undefined2 *)(&DAT_803a6420 + DAT_803de2f8 * 0x280),(short *)0x0,0xa0);
    FUN_802420e0((uint)(&DAT_803a6420 + DAT_803de2f8 * 0x280),0x280);
    FUN_80243e9c();
  }
  else {
    if (DAT_803de2ec == 1) {
      if (DAT_803de2f4 != (short *)0x0) {
        DAT_803de2f0 = DAT_803de2f4;
      }
      (*DAT_803de2e8)();
      uVar1 = FUN_8024ff18();
      DAT_803de2f4 = (short *)(uVar1 + 0x80000000);
    }
    else {
      (*DAT_803de2e8)();
      uVar1 = FUN_8024ff18();
      DAT_803de2f0 = (short *)(uVar1 + 0x80000000);
    }
    DAT_803de2f8 = DAT_803de2f8 ^ 1;
    FUN_8024fe60(&DAT_803a6420 + DAT_803de2f8 * 0x280,0x280);
    FUN_80243e88();
    if (DAT_803de2f0 != (short *)0x0) {
      FUN_802420b0((uint)DAT_803de2f0,0x280);
    }
    FUN_80117f1c((undefined2 *)(&DAT_803a6420 + DAT_803de2f8 * 0x280),DAT_803de2f0,0xa0);
    FUN_802420e0((uint)(&DAT_803a6420 + DAT_803de2f8 * 0x280),0x280);
    FUN_80243e9c();
  }
  return;
}

