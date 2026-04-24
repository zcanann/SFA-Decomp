// Function: FUN_800cb7e8
// Entry: 800cb7e8
// Size: 296 bytes

void FUN_800cb7e8(void)

{
  double dVar1;
  
  FLOAT_803dc4b8 = FLOAT_803dc4b8 + FLOAT_803e0e38 * FLOAT_803dc074;
  if (FLOAT_803e0e40 < FLOAT_803dc4b8) {
    FLOAT_803dc4b8 = FLOAT_803e0e3c;
  }
  FLOAT_803dc4bc = FLOAT_803dc4bc + FLOAT_803e0e38 * FLOAT_803dc074;
  if (FLOAT_803e0e40 < FLOAT_803dc4bc) {
    FLOAT_803dc4bc = FLOAT_803e0e48;
  }
  DAT_803de050 = DAT_803de050 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de050) {
    DAT_803de050 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de05c = (float)dVar1;
  DAT_803de054 = DAT_803de054 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de054) {
    DAT_803de054 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de058 = (float)dVar1;
  return;
}

