// Function: FUN_8010d298
// Entry: 8010d298
// Size: 156 bytes

void FUN_8010d298(void)

{
  float fVar1;
  
  if (DAT_803dd570 == (float *)0x0) {
    DAT_803dd570 = (float *)FUN_80023cc8(0x2c,0xf,0);
  }
  fVar1 = FLOAT_803e1954;
  *DAT_803dd570 = FLOAT_803e1954;
  DAT_803dd570[1] = fVar1;
  DAT_803dd570[2] = FLOAT_803e1978;
  fVar1 = FLOAT_803e194c;
  DAT_803dd570[4] = FLOAT_803e194c;
  DAT_803dd570[3] = fVar1;
  DAT_803dd570[5] = FLOAT_803e195c;
  *(undefined *)(DAT_803dd570 + 10) = 0;
  fVar1 = FLOAT_803e1950;
  DAT_803dd570[8] = FLOAT_803e1950;
  DAT_803dd570[7] = fVar1;
  return;
}

