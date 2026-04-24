// Function: FUN_80111058
// Entry: 80111058
// Size: 108 bytes

void FUN_80111058(int param_1)

{
  if (DAT_803de240 == (float *)0x0) {
    DAT_803de240 = (float *)FUN_80023d8c(8,0xf);
  }
  *DAT_803de240 = FLOAT_803e2818;
  DAT_803de240[1] = *(float *)(*(int *)(param_1 + 0xa4) + 0x1c) - FLOAT_803e281c;
  return;
}

