// Function: FUN_8010821c
// Entry: 8010821c
// Size: 136 bytes

void FUN_8010821c(int param_1)

{
  if (DAT_803de1b8 == (float *)0x0) {
    DAT_803de1b8 = (float *)FUN_80023d8c(0x38,0xf);
  }
  FUN_800033a8((int)DAT_803de1b8,0,0x38);
  DAT_803de1b8[6] = *(float *)(param_1 + 0xb4);
  *DAT_803de1b8 = FLOAT_803e2404;
  DAT_803de1b8[5] = FLOAT_803e2408;
  DAT_803de1b8[10] = FLOAT_803e242c;
  return;
}

