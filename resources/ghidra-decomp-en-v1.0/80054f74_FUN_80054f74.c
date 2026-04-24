// Function: FUN_80054f74
// Entry: 80054f74
// Size: 48 bytes

void FUN_80054f74(int param_1,float *param_2)

{
  if (*(int *)(param_1 + 0x30) != 0) {
    return;
  }
  *param_2 = *param_2 + FLOAT_803dcdd8;
  param_2[2] = param_2[2] + FLOAT_803dcddc;
  return;
}

