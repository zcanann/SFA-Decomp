// Function: FUN_8010d534
// Entry: 8010d534
// Size: 156 bytes

void FUN_8010d534(void)

{
  float fVar1;
  
  if (DAT_803de1e8 == (float *)0x0) {
    DAT_803de1e8 = (float *)FUN_80023d8c(0x2c,0xf);
  }
  fVar1 = FLOAT_803e25d4;
  *DAT_803de1e8 = FLOAT_803e25d4;
  DAT_803de1e8[1] = fVar1;
  DAT_803de1e8[2] = FLOAT_803e25f8;
  fVar1 = FLOAT_803e25cc;
  DAT_803de1e8[4] = FLOAT_803e25cc;
  DAT_803de1e8[3] = fVar1;
  DAT_803de1e8[5] = FLOAT_803e25dc;
  *(undefined *)(DAT_803de1e8 + 10) = 0;
  fVar1 = FLOAT_803e25d0;
  DAT_803de1e8[8] = FLOAT_803e25d0;
  DAT_803de1e8[7] = fVar1;
  return;
}

