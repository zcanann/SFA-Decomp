// Function: FUN_800897d4
// Entry: 800897d4
// Size: 88 bytes

void FUN_800897d4(int param_1,float *param_2,float *param_3,float *param_4)

{
  float fVar1;
  
  fVar1 = FLOAT_803df058;
  if (DAT_803dd12c == 0) {
    *param_2 = FLOAT_803df058;
    *param_3 = FLOAT_803df06c;
    *param_4 = fVar1;
    return;
  }
  param_1 = param_1 * 0xa4;
  *param_2 = *(float *)(DAT_803dd12c + param_1 + 0x90);
  *param_3 = *(float *)(DAT_803dd12c + param_1 + 0x94);
  *param_4 = *(float *)(DAT_803dd12c + param_1 + 0x98);
  return;
}

