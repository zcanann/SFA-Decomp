// Function: FUN_800cd0b4
// Entry: 800cd0b4
// Size: 296 bytes

void FUN_800cd0b4(void)

{
  double dVar1;
  
  FLOAT_803dc4c8 = FLOAT_803dc4c8 + FLOAT_803e0ea0 * FLOAT_803dc074;
  if (FLOAT_803e0ea8 < FLOAT_803dc4c8) {
    FLOAT_803dc4c8 = FLOAT_803e0ea4;
  }
  FLOAT_803dc4cc = FLOAT_803dc4cc + FLOAT_803e0ea0 * FLOAT_803dc074;
  if (FLOAT_803e0ea8 < FLOAT_803dc4cc) {
    FLOAT_803dc4cc = FLOAT_803e0eb0;
  }
  DAT_803de060 = DAT_803de060 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de060) {
    DAT_803de060 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de06c = (float)dVar1;
  DAT_803de064 = DAT_803de064 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de064) {
    DAT_803de064 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de068 = (float)dVar1;
  return;
}

