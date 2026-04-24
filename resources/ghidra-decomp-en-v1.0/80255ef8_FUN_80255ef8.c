// Function: FUN_80255ef8
// Entry: 80255ef8
// Size: 108 bytes

void FUN_80255ef8(int *param_1,int param_2,uint param_3)

{
  *param_1 = param_2;
  param_1[1] = param_2 + (param_3 - 4);
  param_1[2] = param_3;
  param_1[7] = 0;
  FUN_80255fd4(param_1,param_3 - 0x4000,param_3 >> 1 & 0x7fffffe0);
  FUN_80255f64(param_1,param_2,param_2);
  return;
}

