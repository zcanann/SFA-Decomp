// Function: FUN_80119ec8
// Entry: 80119ec8
// Size: 436 bytes

void FUN_80119ec8(void)

{
  uint uVar1;
  
  if (((DAT_803de33c != 0) || (DAT_803de33d != 0)) &&
     (DAT_803de33e = DAT_803de33e + 1, 0xf < DAT_803de33e)) {
    DAT_803de33c = 0;
    DAT_803de33d = 0;
    DAT_803de33e = 0;
  }
  uVar1 = FUN_80014f14(0);
  if ((uVar1 & 0x10) != 0) {
    if (DAT_803de33d == 0) {
      uVar1 = FUN_80014e9c(0);
      if ((((int)(uVar1 & 0xf000) >> 8 |
           (uVar1 & 0xf00) << 4 | (uVar1 & 0xf) << 8 | (int)(uVar1 & 0xf0) >> 4) &
          (uint)*(ushort *)(&DAT_8031b464 + (uint)DAT_803de33c * 2)) != 0) {
        DAT_803de33c = DAT_803de33c + 1;
        DAT_803de33e = 0;
      }
      if (DAT_803de33c == 5) {
        DAT_803de6a8 = 1;
        FUN_8000bb38(0,0x58);
      }
    }
    if (DAT_803de33c == 0) {
      uVar1 = FUN_80014e9c(0);
      if ((((int)(uVar1 & 0xf000) >> 8 |
           (uVar1 & 0xf00) << 4 | (uVar1 & 0xf) << 8 | (int)(uVar1 & 0xf0) >> 4) &
          (uint)*(ushort *)(&DAT_8031b470 + (uint)DAT_803de33d * 2)) != 0) {
        DAT_803de33d = DAT_803de33d + 1;
        DAT_803de33e = 0;
      }
      if (DAT_803de33d == 5) {
        *(undefined *)(DAT_803de330 + DAT_803de324 * 0x24 + 0x21) = 5;
        DAT_803de325 = 1;
        FUN_8000bb38(0,0x58);
      }
    }
  }
  return;
}

