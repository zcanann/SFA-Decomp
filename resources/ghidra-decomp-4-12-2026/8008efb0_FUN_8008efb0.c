// Function: FUN_8008efb0
// Entry: 8008efb0
// Size: 100 bytes

void FUN_8008efb0(void)

{
  DAT_803dc270 = 0xffffffff;
  uRam803dc274 = 0xffffffff;
  if (DAT_803dde04 != 0) {
    FUN_800238c4(DAT_803dde04);
  }
  if (uRam803dde08 != 0) {
    FUN_800238c4(uRam803dde08);
  }
  DAT_803dde04 = 0;
  uRam803dde08 = 0;
  return;
}

