// Function: FUN_800c1324
// Entry: 800c1324
// Size: 296 bytes

void FUN_800c1324(void)

{
  double dVar1;
  
  FLOAT_803dc478 = FLOAT_803dc478 + FLOAT_803e0a18 * FLOAT_803dc074;
  if (FLOAT_803e0a20 < FLOAT_803dc478) {
    FLOAT_803dc478 = FLOAT_803e0a1c;
  }
  FLOAT_803dc47c = FLOAT_803dc47c + FLOAT_803e0a18 * FLOAT_803dc074;
  if (FLOAT_803e0a20 < FLOAT_803dc47c) {
    FLOAT_803dc47c = FLOAT_803e0a28;
  }
  DAT_803de010 = DAT_803de010 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de010) {
    DAT_803de010 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de01c = (float)dVar1;
  DAT_803de014 = DAT_803de014 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de014) {
    DAT_803de014 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de018 = (float)dVar1;
  return;
}

