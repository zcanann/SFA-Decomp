// Function: FUN_8012e050
// Entry: 8012e050
// Size: 104 bytes

void FUN_8012e050(void)

{
  if (DAT_803de3f4 == 0) {
    return;
  }
  if ((DAT_803de3ff == '\0') || (0x7e < DAT_803de3f4)) {
    if (DAT_803de3ff == '\0') {
      DAT_803de3f4 = DAT_803de3f4 + DAT_803dc070;
    }
  }
  else {
    DAT_803de3f4 = DAT_803de3f4 + DAT_803dc070;
  }
  if (DAT_803de3f4 < 0x100) {
    return;
  }
  DAT_803de3f4 = 0;
  DAT_803dc6c4 = 0xffffffff;
  return;
}

