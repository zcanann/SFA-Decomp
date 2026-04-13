// Function: FUN_800550f0
// Entry: 800550f0
// Size: 48 bytes

void FUN_800550f0(int param_1,float *param_2)

{
  if (*(int *)(param_1 + 0x30) != 0) {
    return;
  }
  *param_2 = *param_2 + FLOAT_803dda58;
  param_2[2] = param_2[2] + FLOAT_803dda5c;
  return;
}

