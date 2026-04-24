// Function: FUN_80259918
// Entry: 80259918
// Size: 16 bytes

void FUN_80259918(double param_1,double param_2,double param_3,int param_4)

{
  *(float *)(param_4 + 0x28) = (float)param_1;
  *(float *)(param_4 + 0x2c) = (float)param_2;
  *(float *)(param_4 + 0x30) = (float)param_3;
  return;
}

