// Function: FUN_80259e00
// Entry: 80259e00
// Size: 16 bytes

void FUN_80259e00(double param_1,double param_2,double param_3,int param_4)

{
  *(float *)(param_4 + 0x1c) = (float)param_1;
  *(float *)(param_4 + 0x20) = (float)param_2;
  *(float *)(param_4 + 0x24) = (float)param_3;
  return;
}

