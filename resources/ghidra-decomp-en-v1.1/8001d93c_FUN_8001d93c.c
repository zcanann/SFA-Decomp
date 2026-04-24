// Function: FUN_8001d93c
// Entry: 8001d93c
// Size: 120 bytes

void FUN_8001d93c(double param_1,double param_2,int param_3)

{
  double dVar1;
  
  *(float *)(param_3 + 0x148) = (float)param_1;
  *(float *)(param_3 + 0x14c) = (float)param_2;
  *(undefined4 *)(param_3 + 0x168) = 1;
  dVar1 = (double)FLOAT_803df410;
  FUN_80247aa4((double)*(float *)(param_3 + 0x148),(double)*(float *)(param_3 + 0x14c),dVar1,dVar1,
               dVar1,dVar1,(float *)(param_3 + 0x1b0));
  dVar1 = (double)FLOAT_803df410;
  FUN_80247aa4((double)*(float *)(param_3 + 0x148),(double)*(float *)(param_3 + 0x14c),dVar1,dVar1,
               dVar1,dVar1,(float *)(param_3 + 0x1f0));
  return;
}

