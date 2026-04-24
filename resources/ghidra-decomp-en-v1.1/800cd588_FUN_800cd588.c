// Function: FUN_800cd588
// Entry: 800cd588
// Size: 296 bytes

void FUN_800cd588(void)

{
  double dVar1;
  
  FLOAT_803dc4d8 = FLOAT_803dc4d8 + FLOAT_803e0f58 * FLOAT_803dc074;
  if (FLOAT_803e0f60 < FLOAT_803dc4d8) {
    FLOAT_803dc4d8 = FLOAT_803e0f5c;
  }
  FLOAT_803dc4dc = FLOAT_803dc4dc + FLOAT_803e0f58 * FLOAT_803dc074;
  if (FLOAT_803e0f60 < FLOAT_803dc4dc) {
    FLOAT_803dc4dc = FLOAT_803e0f68;
  }
  DAT_803de070 = DAT_803de070 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de070) {
    DAT_803de070 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de07c = (float)dVar1;
  DAT_803de074 = DAT_803de074 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de074) {
    DAT_803de074 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de078 = (float)dVar1;
  return;
}

