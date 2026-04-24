// Function: FUN_8000e0a0
// Entry: 8000e0a0
// Size: 108 bytes

void FUN_8000e0a0(double param_1,double param_2,double param_3,float *param_4,float *param_5,
                 float *param_6,int param_7)

{
  if (param_7 == 0) {
    *param_4 = (float)param_1;
    *param_5 = (float)param_2;
    *param_6 = (float)param_3;
  }
  else {
    FUN_800226cc(*(char *)(param_7 + 0x35) * 0x40 + -0x7fcc87f0,param_4,param_5,param_6);
  }
  return;
}

