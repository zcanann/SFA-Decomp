// Function: FUN_800c49bc
// Entry: 800c49bc
// Size: 296 bytes

void FUN_800c49bc(void)

{
  double dVar1;
  
  FLOAT_803dc498 = FLOAT_803dc498 + FLOAT_803e0b38 * FLOAT_803dc074;
  if (FLOAT_803e0b40 < FLOAT_803dc498) {
    FLOAT_803dc498 = FLOAT_803e0b3c;
  }
  FLOAT_803dc49c = FLOAT_803dc49c + FLOAT_803e0b38 * FLOAT_803dc074;
  if (FLOAT_803e0b40 < FLOAT_803dc49c) {
    FLOAT_803dc49c = FLOAT_803e0b48;
  }
  DAT_803de030 = DAT_803de030 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de030) {
    DAT_803de030 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de03c = (float)dVar1;
  DAT_803de034 = DAT_803de034 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de034) {
    DAT_803de034 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de038 = (float)dVar1;
  return;
}

