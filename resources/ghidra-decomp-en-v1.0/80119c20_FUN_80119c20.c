// Function: FUN_80119c20
// Entry: 80119c20
// Size: 436 bytes

void FUN_80119c20(void)

{
  uint uVar1;
  
  if (((DAT_803dd6bc != 0) || (DAT_803dd6bd != 0)) &&
     (DAT_803dd6be = DAT_803dd6be + 1, 0xf < DAT_803dd6be)) {
    DAT_803dd6bc = 0;
    DAT_803dd6bd = 0;
    DAT_803dd6be = 0;
  }
  uVar1 = FUN_80014ee8(0);
  if ((uVar1 & 0x10) != 0) {
    if (DAT_803dd6bd == 0) {
      uVar1 = FUN_80014e70(0);
      if ((((int)(uVar1 & 0xf000) >> 8 |
           (uVar1 & 0xf00) << 4 | (uVar1 & 0xf) << 8 | (int)(uVar1 & 0xf0) >> 4) &
          (uint)*(ushort *)(&DAT_8031a814 + (uint)DAT_803dd6bc * 2)) != 0) {
        DAT_803dd6bc = DAT_803dd6bc + 1;
        DAT_803dd6be = 0;
      }
      if (DAT_803dd6bc == 5) {
        DAT_803dda28 = 1;
        FUN_8000bb18(0,0x58);
      }
    }
    if (DAT_803dd6bc == 0) {
      uVar1 = FUN_80014e70(0);
      if ((((int)(uVar1 & 0xf000) >> 8 |
           (uVar1 & 0xf00) << 4 | (uVar1 & 0xf) << 8 | (int)(uVar1 & 0xf0) >> 4) &
          (uint)*(ushort *)(&DAT_8031a820 + (uint)DAT_803dd6bd * 2)) != 0) {
        DAT_803dd6bd = DAT_803dd6bd + 1;
        DAT_803dd6be = 0;
      }
      if (DAT_803dd6bd == 5) {
        *(undefined *)(DAT_803dd6b0 + DAT_803dd6a4 * 0x24 + 0x21) = 5;
        DAT_803dd6a5 = 1;
        FUN_8000bb18(0,0x58);
      }
    }
  }
  return;
}

