// Function: FUN_80110dbc
// Entry: 80110dbc
// Size: 108 bytes

void FUN_80110dbc(int param_1)

{
  if (DAT_803dd5c8 == (float *)0x0) {
    DAT_803dd5c8 = (float *)FUN_80023cc8(8,0xf,0);
  }
  *DAT_803dd5c8 = FLOAT_803e1b98;
  DAT_803dd5c8[1] = *(float *)(*(int *)(param_1 + 0xa4) + 0x1c) - FLOAT_803e1b9c;
  return;
}

