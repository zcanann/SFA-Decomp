// Function: FUN_80259928
// Entry: 80259928
// Size: 28 bytes

void FUN_80259928(double param_1,double param_2,double param_3,int param_4)

{
  *(float *)(param_4 + 0x34) = (float)-param_1;
  *(float *)(param_4 + 0x38) = (float)-param_2;
  *(float *)(param_4 + 0x3c) = (float)-param_3;
  return;
}

