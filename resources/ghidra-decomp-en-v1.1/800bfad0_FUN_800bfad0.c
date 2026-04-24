// Function: FUN_800bfad0
// Entry: 800bfad0
// Size: 296 bytes

void FUN_800bfad0(void)

{
  double dVar1;
  
  FLOAT_803dc468 = FLOAT_803dc468 + FLOAT_803e0958 * FLOAT_803dc074;
  if (FLOAT_803e0960 < FLOAT_803dc468) {
    FLOAT_803dc468 = FLOAT_803e095c;
  }
  FLOAT_803dc46c = FLOAT_803dc46c + FLOAT_803e0958 * FLOAT_803dc074;
  if (FLOAT_803e0960 < FLOAT_803dc46c) {
    FLOAT_803dc46c = FLOAT_803e0968;
  }
  DAT_803de000 = DAT_803de000 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de000) {
    DAT_803de000 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de00c = (float)dVar1;
  DAT_803de004 = DAT_803de004 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de004) {
    DAT_803de004 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de008 = (float)dVar1;
  return;
}

