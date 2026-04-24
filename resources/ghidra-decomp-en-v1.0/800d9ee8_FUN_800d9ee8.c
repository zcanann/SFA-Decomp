// Function: FUN_800d9ee8
// Entry: 800d9ee8
// Size: 80 bytes

void FUN_800d9ee8(float *param_1)

{
  param_1[0x27] = (float)((uint)param_1[0x27] ^ (uint)param_1[0x29]);
  param_1[0x29] = (float)((uint)param_1[0x29] ^ (uint)param_1[0x27]);
  param_1[0x27] = (float)((uint)param_1[0x27] ^ (uint)param_1[0x29]);
  if (*param_1 < FLOAT_803e05c8) {
    return;
  }
  *param_1 = FLOAT_803e05cc;
  return;
}

