// Function: FUN_80013434
// Entry: 80013434
// Size: 160 bytes

void FUN_80013434(void)

{
  if (DAT_803387b8 < 0x3fffffff) {
    DAT_803387b8 = DAT_803387b8 + 1;
  }
  if (DAT_803387bc < 0x3fffffff) {
    DAT_803387bc = DAT_803387bc + 1;
  }
  if (DAT_803387c0 < 0x3fffffff) {
    DAT_803387c0 = DAT_803387c0 + 1;
  }
  if (DAT_803387c4 < 0x3fffffff) {
    DAT_803387c4 = DAT_803387c4 + 1;
  }
  if (DAT_803387c8 < 0x3fffffff) {
    DAT_803387c8 = DAT_803387c8 + 1;
  }
  if (0x3ffffffe < DAT_803387cc) {
    return;
  }
  DAT_803387cc = DAT_803387cc + 1;
  return;
}

