// Function: FUN_80021ec0
// Entry: 80021ec0
// Size: 40 bytes

void FUN_80021ec0(double param_1,int param_2)

{
  *(float *)(param_2 + 0x10) = (float)((double)*(float *)(param_2 + 0x10) * param_1);
  *(float *)(param_2 + 0x14) = (float)((double)*(float *)(param_2 + 0x14) * param_1);
  *(float *)(param_2 + 0x18) = (float)((double)*(float *)(param_2 + 0x18) * param_1);
  return;
}

