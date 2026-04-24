// Function: FUN_8002b95c
// Entry: 8002b95c
// Size: 80 bytes

undefined4 FUN_8002b95c(double param_1,double param_2,double param_3,int param_4)

{
  undefined auStack8 [8];
  
  *(float *)(param_4 + 0xc) = (float)((double)*(float *)(param_4 + 0xc) + param_1);
  *(float *)(param_4 + 0x10) = (float)((double)*(float *)(param_4 + 0x10) + param_2);
  *(float *)(param_4 + 0x14) = (float)((double)*(float *)(param_4 + 0x14) + param_3);
  FUN_80036f50(0,auStack8);
  return 0;
}

