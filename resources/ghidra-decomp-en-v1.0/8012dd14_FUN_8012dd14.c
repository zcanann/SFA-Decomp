// Function: FUN_8012dd14
// Entry: 8012dd14
// Size: 104 bytes

void FUN_8012dd14(void)

{
  if (DAT_803dd774 == 0) {
    return;
  }
  if ((DAT_803dd77f == '\0') || (0x7e < DAT_803dd774)) {
    if (DAT_803dd77f == '\0') {
      DAT_803dd774 = DAT_803dd774 + DAT_803db410;
    }
  }
  else {
    DAT_803dd774 = DAT_803dd774 + DAT_803db410;
  }
  if (DAT_803dd774 < 0x100) {
    return;
  }
  DAT_803dba5c = 0xffffffff;
  DAT_803dd774 = 0;
  return;
}

