// Function: FUN_80026c38
// Entry: 80026c38
// Size: 16 bytes

void FUN_80026c38(double param_1,double param_2,double param_3,int param_4)

{
  *(float *)(param_4 + 8) = (float)param_1;
  *(float *)(param_4 + 0xc) = (float)param_2;
  *(float *)(param_4 + 0x10) = (float)param_3;
  return;
}

