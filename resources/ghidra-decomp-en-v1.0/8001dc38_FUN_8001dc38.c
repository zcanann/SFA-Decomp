// Function: FUN_8001dc38
// Entry: 8001dc38
// Size: 88 bytes

void FUN_8001dc38(double param_1,double param_2,int param_3)

{
  *(float *)(param_3 + 0x140) = (float)param_1;
  *(float *)(param_3 + 0x144) = (float)param_2;
  FUN_80259848((double)*(float *)(param_3 + 0x140),(double)FLOAT_803de758,param_3 + 0x68,2);
  FUN_802596ac(param_3 + 0x68,param_3 + 0x124,param_3 + 0x128,param_3 + 300);
  return;
}

