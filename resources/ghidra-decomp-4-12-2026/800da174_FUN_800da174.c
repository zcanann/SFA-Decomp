// Function: FUN_800da174
// Entry: 800da174
// Size: 80 bytes

void FUN_800da174(float *param_1)

{
  param_1[0x27] = (float)((uint)param_1[0x27] ^ (uint)param_1[0x29]);
  param_1[0x29] = (float)((uint)param_1[0x29] ^ (uint)param_1[0x27]);
  param_1[0x27] = (float)((uint)param_1[0x27] ^ (uint)param_1[0x29]);
  if (*param_1 < FLOAT_803e1248) {
    return;
  }
  *param_1 = FLOAT_803e124c;
  return;
}

