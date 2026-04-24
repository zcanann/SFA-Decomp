// Function: FUN_80013454
// Entry: 80013454
// Size: 160 bytes

void FUN_80013454(void)

{
  if (DAT_80339418 < 0x3fffffff) {
    DAT_80339418 = DAT_80339418 + 1;
  }
  if (DAT_8033941c < 0x3fffffff) {
    DAT_8033941c = DAT_8033941c + 1;
  }
  if (DAT_80339420 < 0x3fffffff) {
    DAT_80339420 = DAT_80339420 + 1;
  }
  if (DAT_80339424 < 0x3fffffff) {
    DAT_80339424 = DAT_80339424 + 1;
  }
  if (DAT_80339428 < 0x3fffffff) {
    DAT_80339428 = DAT_80339428 + 1;
  }
  if (0x3ffffffe < DAT_8033942c) {
    return;
  }
  DAT_8033942c = DAT_8033942c + 1;
  return;
}

