// Function: FUN_801a8678
// Entry: 801a8678
// Size: 44 bytes

void FUN_801a8678(double param_1,double param_2,double param_3,int param_4)

{
  *(float *)(param_4 + 0xc) = (float)param_1;
  *(float *)(param_4 + 0x10) = (float)param_2;
  *(float *)(param_4 + 0x14) = (float)param_3;
  FUN_800e85f4(param_4);
  return;
}

