// Function: FUN_800be18c
// Entry: 800be18c
// Size: 296 bytes

void FUN_800be18c(void)

{
  double dVar1;
  
  FLOAT_803dc458 = FLOAT_803dc458 + FLOAT_803e0900 * FLOAT_803dc074;
  if (FLOAT_803e0908 < FLOAT_803dc458) {
    FLOAT_803dc458 = FLOAT_803e0904;
  }
  FLOAT_803dc45c = FLOAT_803dc45c + FLOAT_803e0900 * FLOAT_803dc074;
  if (FLOAT_803e0908 < FLOAT_803dc45c) {
    FLOAT_803dc45c = FLOAT_803e0910;
  }
  DAT_803ddff0 = DAT_803ddff0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddff0) {
    DAT_803ddff0 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddffc = (float)dVar1;
  DAT_803ddff4 = DAT_803ddff4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddff4) {
    DAT_803ddff4 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddff8 = (float)dVar1;
  return;
}

