// Function: FUN_8022db24
// Entry: 8022db24
// Size: 12 bytes

void FUN_8022db24(double param_1,int param_2)

{
  *(float *)(*(int *)(param_2 + 0xb8) + 0x20) = (float)param_1;
  return;
}

