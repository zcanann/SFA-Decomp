// Function: FUN_8025d848
// Entry: 8025d848
// Size: 64 bytes

void FUN_8025d848(float *param_1,int param_2)

{
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = param_2 * 3 + 0x400U | 0x80000;
  FUN_8025d7b4(param_1,(float *)&DAT_cc008000);
  return;
}

