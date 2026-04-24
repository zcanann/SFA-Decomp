// Function: FUN_80259df0
// Entry: 80259df0
// Size: 16 bytes

void FUN_80259df0(double param_1,double param_2,double param_3,int param_4)

{
  *(float *)(param_4 + 0x10) = (float)param_1;
  *(float *)(param_4 + 0x14) = (float)param_2;
  *(float *)(param_4 + 0x18) = (float)param_3;
  return;
}

