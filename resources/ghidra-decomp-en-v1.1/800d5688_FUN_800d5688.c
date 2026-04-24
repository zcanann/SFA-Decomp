// Function: FUN_800d5688
// Entry: 800d5688
// Size: 296 bytes

void FUN_800d5688(void)

{
  double dVar1;
  
  FLOAT_803dc4e8 = FLOAT_803dc4e8 + FLOAT_803e0f90 * FLOAT_803dc074;
  if (FLOAT_803e0f98 < FLOAT_803dc4e8) {
    FLOAT_803dc4e8 = FLOAT_803e0f94;
  }
  FLOAT_803dc4ec = FLOAT_803dc4ec + FLOAT_803e0f90 * FLOAT_803dc074;
  if (FLOAT_803e0f98 < FLOAT_803dc4ec) {
    FLOAT_803dc4ec = FLOAT_803e0fa0;
  }
  DAT_803de080 = DAT_803de080 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de080) {
    DAT_803de080 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de08c = (float)dVar1;
  DAT_803de084 = DAT_803de084 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de084) {
    DAT_803de084 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de088 = (float)dVar1;
  return;
}

