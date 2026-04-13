// Function: FUN_800c9298
// Entry: 800c9298
// Size: 296 bytes

void FUN_800c9298(void)

{
  double dVar1;
  
  FLOAT_803dc4a8 = FLOAT_803dc4a8 + FLOAT_803e0d28 * FLOAT_803dc074;
  if (FLOAT_803e0d30 < FLOAT_803dc4a8) {
    FLOAT_803dc4a8 = FLOAT_803e0d2c;
  }
  FLOAT_803dc4ac = FLOAT_803dc4ac + FLOAT_803e0d28 * FLOAT_803dc074;
  if (FLOAT_803e0d30 < FLOAT_803dc4ac) {
    FLOAT_803dc4ac = FLOAT_803e0d38;
  }
  DAT_803de040 = DAT_803de040 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de040) {
    DAT_803de040 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de04c = (float)dVar1;
  DAT_803de044 = DAT_803de044 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de044) {
    DAT_803de044 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de048 = (float)dVar1;
  return;
}

