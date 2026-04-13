// Function: FUN_8001d9b4
// Entry: 8001d9b4
// Size: 148 bytes

void FUN_8001d9b4(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,int param_7)

{
  double dVar1;
  double dVar2;
  
  *(float *)(param_7 + 0x150) = (float)param_1;
  *(float *)(param_7 + 0x154) = (float)param_2;
  *(float *)(param_7 + 0x158) = (float)param_3;
  *(float *)(param_7 + 0x15c) = (float)param_4;
  *(undefined4 *)(param_7 + 0x168) = 0;
  dVar2 = (double)(float)(param_6 * (double)FLOAT_803df410);
  dVar1 = (double)(float)(param_5 * (double)FLOAT_803df410);
  FUN_80247b70((double)*(float *)(param_7 + 0x150),(double)*(float *)(param_7 + 0x154),
               (double)*(float *)(param_7 + 0x158),(double)*(float *)(param_7 + 0x15c),dVar2,dVar1,
               dVar2,dVar1,(float *)(param_7 + 0x1b0));
  dVar1 = (double)FLOAT_803df410;
  FUN_80247b70((double)*(float *)(param_7 + 0x150),(double)*(float *)(param_7 + 0x154),
               (double)*(float *)(param_7 + 0x158),(double)*(float *)(param_7 + 0x15c),dVar1,dVar1,
               dVar1,dVar1,(float *)(param_7 + 0x1f0));
  return;
}

