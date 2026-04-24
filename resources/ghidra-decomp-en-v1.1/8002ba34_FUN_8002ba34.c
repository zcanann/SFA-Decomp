// Function: FUN_8002ba34
// Entry: 8002ba34
// Size: 80 bytes

undefined4 FUN_8002ba34(double param_1,double param_2,double param_3,int param_4)

{
  int aiStack_8 [2];
  
  *(float *)(param_4 + 0xc) = (float)((double)*(float *)(param_4 + 0xc) + param_1);
  *(float *)(param_4 + 0x10) = (float)((double)*(float *)(param_4 + 0x10) + param_2);
  *(float *)(param_4 + 0x14) = (float)((double)*(float *)(param_4 + 0x14) + param_3);
  FUN_80037048(0,aiStack_8);
  return 0;
}

